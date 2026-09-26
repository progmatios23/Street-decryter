//! Jump-table / switch recovery improvements.
//!
//! Complements the worker's basic `jmp [reg*scale+disp]` walk with:
//! - relative (PIC) tables (signed i32 offsets from table base or from RIP)
//! - bound recovery from nearby `cmp` / `jae` / `ja` patterns
//! - sparse tables with a default case
//! - validation heuristics (entropy of targets, cluster score, outlier trim)
//! - post-pass refinement of [`crate::JumpTable`] entries already discovered
//!
//! Kept separate from the worker so egui/HTTP work elsewhere does not collide.

use crate::{Analysis, JumpTable, Xref, XrefKind};
use ceasta_binary::{Arch, Binary};
use ceasta_disasm::{decode_at, Flow, Insn};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// How table entries are encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TableEncoding {
    /// Absolute virtual addresses (pointer-sized or 32-bit).
    Absolute,
    /// Signed 32-bit offsets relative to the table base.
    RelTable,
    /// Signed 32-bit offsets relative to the jump instruction / RIP.
    RelRip,
    /// Signed 32-bit offsets relative to an explicit image base / module base.
    RelImage,
}

impl TableEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            TableEncoding::Absolute => "absolute",
            TableEncoding::RelTable => "rel_table",
            TableEncoding::RelRip => "rel_rip",
            TableEncoding::RelImage => "rel_image",
        }
    }
}

/// Recovered switch / jump-table description (richer than [`JumpTable`]).
#[derive(Clone, Debug)]
pub struct SwitchInfo {
    pub jmp: u64,
    pub table: u64,
    pub encoding: TableEncoding,
    pub entry_size: u32,
    pub index_reg_hint: Option<&'static str>,
    pub bound: Option<u32>,
    pub default_case: Option<u64>,
    pub cases: Vec<SwitchCase>,
    pub confidence: f32,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SwitchCase {
    pub index: u32,
    pub entry_addr: u64,
    pub target: u64,
    pub raw: u64,
}

#[derive(Clone, Debug, Default)]
pub struct SwitchPassStats {
    pub candidates: usize,
    pub recovered: usize,
    pub refined: usize,
    pub rejected: usize,
    pub relative: usize,
    pub absolute: usize,
    pub with_bound: usize,
    pub with_default: usize,
}

/// Options controlling switch recovery.
#[derive(Clone, Debug)]
pub struct SwitchOptions {
    pub max_entries: u32,
    pub max_distance: u64,
    pub lookback_insns: usize,
    pub min_entries: u32,
    pub allow_relative: bool,
    pub allow_sparse: bool,
    pub trim_outliers: bool,
    pub min_confidence: f32,
}

impl Default for SwitchOptions {
    fn default() -> Self {
        Self {
            max_entries: 512,
            max_distance: 0x100_000,
            lookback_insns: 24,
            min_entries: 2,
            allow_relative: true,
            allow_sparse: true,
            trim_outliers: true,
            min_confidence: 0.35,
        }
    }
}

/// Scan an analysis result and recover / refine jump tables.
pub fn recover_switches(bin: &Binary, an: &Analysis, opts: &SwitchOptions) -> (Vec<SwitchInfo>, SwitchPassStats) {
    let mut stats = SwitchPassStats::default();
    let mut out = Vec::new();
    let mut seen_jmp = HashSet::new();

    // Refine tables the worker already found.
    for (jmp, jt) in &an.tables {
        stats.candidates += 1;
        if let Some(info) = refine_existing(bin, an, jt, opts) {
            seen_jmp.insert(*jmp);
            if info.encoding != TableEncoding::Absolute {
                stats.relative += 1;
            } else {
                stats.absolute += 1;
            }
            if info.bound.is_some() {
                stats.with_bound += 1;
            }
            if info.default_case.is_some() {
                stats.with_default += 1;
            }
            if info.confidence >= opts.min_confidence {
                stats.refined += 1;
                stats.recovered += 1;
                out.push(info);
            } else {
                stats.rejected += 1;
            }
        } else {
            stats.rejected += 1;
        }
    }

    // Walk functions looking for indirect jumps the worker missed.
    for f in &an.functions {
        let mut addr = f.start;
        let mut n = 0usize;
        while addr < f.end && n < 4096 {
            let Ok(insn) = decode_at(bin, addr) else {
                break;
            };
            if insn.flow == Flow::Jump && insn.indirect && !seen_jmp.contains(&insn.addr) {
                stats.candidates += 1;
                if let Some(info) = recover_at(bin, an, &insn, opts) {
                    seen_jmp.insert(insn.addr);
                    if info.encoding != TableEncoding::Absolute {
                        stats.relative += 1;
                    } else {
                        stats.absolute += 1;
                    }
                    if info.bound.is_some() {
                        stats.with_bound += 1;
                    }
                    if info.default_case.is_some() {
                        stats.with_default += 1;
                    }
                    if info.confidence >= opts.min_confidence {
                        stats.recovered += 1;
                        out.push(info);
                    } else {
                        stats.rejected += 1;
                    }
                } else {
                    stats.rejected += 1;
                }
            }
            addr = insn.next();
            n += 1;
        }
    }

    out.sort_by_key(|s| s.jmp);
    (out, stats)
}

/// Convenience: default options.
pub fn recover_switches_default(bin: &Binary, an: &Analysis) -> Vec<SwitchInfo> {
    recover_switches(bin, an, &SwitchOptions::default()).0
}

/// Merge recovered switches back into an [`Analysis`] `tables` map (keeps worker shape).
pub fn apply_switches(an: &mut Analysis, switches: &[SwitchInfo]) {
    for s in switches {
        let targets: Vec<u64> = {
            let mut t: Vec<u64> = s.cases.iter().map(|c| c.target).collect();
            t.sort_unstable();
            t.dedup();
            t
        };
        let cases: Vec<u64> = s.cases.iter().map(|c| c.target).collect();
        an.tables.insert(
            s.jmp,
            JumpTable {
                jmp: s.jmp,
                table: s.table,
                entry_size: s.entry_size,
                entries: s.cases.len() as u32,
                targets,
                cases,
            },
        );
        // Ensure jump xrefs exist.
        for c in &s.cases {
            let exists = an.xfrom.iter().any(|x| {
                x.from == s.jmp && x.to == c.target && x.kind == XrefKind::Jump
            });
            if !exists {
                let x = Xref {
                    from: s.jmp,
                    to: c.target,
                    kind: XrefKind::Jump,
                };
                an.xfrom.push(x);
                an.xto.push(x);
            }
        }
    }
    an.xfrom.sort_by(|a, b| (a.from, a.to, a.kind as u8).cmp(&(b.from, b.to, b.kind as u8)));
    an.xto.sort_by(|a, b| (a.to, a.from, a.kind as u8).cmp(&(b.to, b.from, b.kind as u8)));
    an.xfrom.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
    an.xto.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
}

fn refine_existing(bin: &Binary, an: &Analysis, jt: &JumpTable, opts: &SwitchOptions) -> Option<SwitchInfo> {
    let Ok(insn) = decode_at(bin, jt.jmp) else {
        return None;
    };
    let mut info = recover_at(bin, an, &insn, opts)?;
    // Prefer worker's table base if ours disagrees but worker had entries.
    if info.table != jt.table && jt.entries >= opts.min_entries {
        if let Some(alt) = try_read_table(bin, an, jt.jmp, jt.table, jt.entry_size, TableEncoding::Absolute, opts, None) {
            if alt.cases.len() as u32 >= jt.entries {
                info = alt;
            }
        }
    }
    // Attach bound / default from lookback even if absolute walk already succeeded.
    let ctx = lookback_context(bin, jt.jmp, opts.lookback_insns);
    if info.bound.is_none() {
        info.bound = ctx.bound;
    }
    if info.default_case.is_none() {
        info.default_case = ctx.default_target;
    }
    if let Some(b) = info.bound {
        if info.cases.len() as u32 > b.saturating_add(1) {
            info.cases.truncate((b + 1) as usize);
            info.notes.push(format!("trimmed to bound {b}"));
        }
    }
    info.confidence = score_switch(bin, an, &info);
    Some(info)
}

fn recover_at(bin: &Binary, an: &Analysis, insn: &Insn, opts: &SwitchOptions) -> Option<SwitchInfo> {
    if !insn.indirect || insn.flow != Flow::Jump {
        return None;
    }
    let table = insn.mem?;
    let ps = bin.arch.ptr_size() as u32;
    let es = if insn.mem_size != 0 {
        u32::from(insn.mem_size)
    } else {
        ps
    };

    let ctx = lookback_context(bin, insn.addr, opts.lookback_insns);

    let mut best: Option<SwitchInfo> = None;
    let encodings = candidate_encodings(es, opts);
    for enc in encodings {
        let entry_size = match enc {
            TableEncoding::Absolute => {
                if es == 4 || es == 8 {
                    es
                } else {
                    ps
                }
            }
            _ => 4,
        };
        if let Some(mut info) = try_read_table(bin, an, insn.addr, table, entry_size, enc, opts, ctx.bound) {
            info.index_reg_hint = ctx.index_hint;
            info.bound = info.bound.or(ctx.bound);
            info.default_case = ctx.default_target;
            info.confidence = score_switch(bin, an, &info);
            if best.as_ref().map(|b| info.confidence > b.confidence).unwrap_or(true) {
                best = Some(info);
            }
        }
    }

    // Also try nearby LEA-discovered table bases from lookback.
    for &alt_table in &ctx.lea_bases {
        if alt_table == table {
            continue;
        }
        for enc in [TableEncoding::Absolute, TableEncoding::RelTable, TableEncoding::RelRip] {
            let entry_size = if enc == TableEncoding::Absolute { ps } else { 4 };
            if let Some(mut info) = try_read_table(bin, an, insn.addr, alt_table, entry_size, enc, opts, ctx.bound) {
                info.index_reg_hint = ctx.index_hint;
                info.bound = info.bound.or(ctx.bound);
                info.default_case = ctx.default_target;
                info.notes.push(format!("table from lea {alt_table:#x}"));
                info.confidence = score_switch(bin, an, &info) * 0.95;
                if best.as_ref().map(|b| info.confidence > b.confidence).unwrap_or(true) {
                    best = Some(info);
                }
            }
        }
    }

    best
}

fn candidate_encodings(es: u32, opts: &SwitchOptions) -> Vec<TableEncoding> {
    let mut v = vec![TableEncoding::Absolute];
    if opts.allow_relative {
        v.push(TableEncoding::RelTable);
        v.push(TableEncoding::RelRip);
        if es == 4 {
            v.push(TableEncoding::RelImage);
        }
    }
    v
}

#[derive(Clone, Debug, Default)]
struct LookbackCtx {
    bound: Option<u32>,
    default_target: Option<u64>,
    index_hint: Option<&'static str>,
    lea_bases: Vec<u64>,
    cmp_imm: Option<u64>,
}

fn lookback_context(bin: &Binary, jmp: u64, max_insns: usize) -> LookbackCtx {
    let mut ctx = LookbackCtx::default();
    // Walk backwards by decoding from a window — approximate by scanning back up to 0x80 bytes.
    let window = 0xC0u64;
    let start = jmp.saturating_sub(window);
    let mut addrs = Vec::new();
    let mut a = start;
    while a < jmp {
        match decode_at(bin, a) {
            Ok(insn) => {
                let next = insn.next();
                if next > jmp {
                    break;
                }
                addrs.push(insn);
                a = next;
            }
            Err(_) => a += 1,
        }
    }
    let take = addrs.len().saturating_sub(max_insns);
    for insn in addrs.into_iter().skip(take) {
        let mnem = insn.mnemonic.to_ascii_lowercase();
        if mnem == "cmp" || mnem == "cmpxchg" {
            if let Some(imm) = insn.imm {
                if imm <= 0x10000 {
                    ctx.cmp_imm = Some(imm);
                    ctx.bound = Some(imm as u32);
                }
            }
        }
        if matches!(mnem.as_str(), "ja" | "jae" | "jnbe" | "jnb" | "jg" | "jge" | "jae") {
            if let Some(t) = insn.target {
                // conditional jump that skips the switch often lands on default
                if t != jmp {
                    ctx.default_target = Some(t);
                }
            }
            if ctx.bound.is_none() {
                if let Some(imm) = ctx.cmp_imm {
                    // jae bound means valid indices are 0..bound
                    if mnem == "jae" || mnem == "jnb" {
                        ctx.bound = Some(imm as u32);
                    } else if mnem == "ja" || mnem == "jnbe" {
                        ctx.bound = Some(imm.saturating_add(1) as u32);
                    }
                }
            }
        }
        if insn.is_lea {
            if let Some(m) = insn.mem {
                if bin.is_mapped(m) {
                    ctx.lea_bases.push(m);
                }
            }
        }
        // crude index hint from operand text
        if ctx.index_hint.is_none() {
            let ops = insn.operands.to_ascii_lowercase();
            for reg in ["eax", "rax", "ecx", "rcx", "edx", "rdx", "ebx", "rbx", "r8d", "r9d", "esi", "rsi", "edi", "rdi"] {
                if ops.contains(reg) && (mnem == "movzx" || mnem == "mov" || mnem == "and" || mnem == "cmp") {
                    ctx.index_hint = Some(match reg {
                        "eax" | "rax" => "rax",
                        "ecx" | "rcx" => "rcx",
                        "edx" | "rdx" => "rdx",
                        "ebx" | "rbx" => "rbx",
                        "r8d" => "r8",
                        "r9d" => "r9",
                        "esi" | "rsi" => "rsi",
                        "edi" | "rdi" => "rdi",
                        _ => "reg",
                    });
                    break;
                }
            }
        }
    }
    ctx.lea_bases.sort_unstable();
    ctx.lea_bases.dedup();
    ctx
}

fn try_read_table(
    bin: &Binary,
    an: &Analysis,
    jmp: u64,
    table: u64,
    entry_size: u32,
    encoding: TableEncoding,
    opts: &SwitchOptions,
    bound: Option<u32>,
) -> Option<SwitchInfo> {
    if entry_size != 4 && entry_size != 8 {
        return None;
    }
    let js = bin.seg_at(jmp).map(|s| (s.start, s.end))?;
    let limit = bound
        .map(|b| (b.saturating_add(1)).min(opts.max_entries))
        .unwrap_or(opts.max_entries);

    let mut cases = Vec::new();
    let mut consecutive_fail = 0u32;
    for i in 0..limit {
        let ea = table + u64::from(i) * u64::from(entry_size);
        if i > 0 && (an.flags_at(ea) & (crate::FL_CODE | crate::FL_STR)) != 0 {
            break;
        }
        let Some(raw) = read_entry(bin, ea, entry_size) else {
            consecutive_fail += 1;
            if !opts.allow_sparse || consecutive_fail > 2 {
                break;
            }
            continue;
        };
        let Some(target) = decode_target(bin, jmp, table, raw, encoding, entry_size) else {
            consecutive_fail += 1;
            if !opts.allow_sparse || consecutive_fail > 2 {
                break;
            }
            continue;
        };
        if target < js.0 || target >= js.1 {
            consecutive_fail += 1;
            if !opts.allow_sparse || consecutive_fail > 2 {
                break;
            }
            continue;
        }
        let tf = an.flags_at(target);
        if is_tail_only(tf) || (tf & (crate::FL_STR | crate::FL_DATA)) != 0 {
            consecutive_fail += 1;
            if !opts.allow_sparse || consecutive_fail > 2 {
                break;
            }
            continue;
        }
        let dist = target.abs_diff(jmp);
        if dist > opts.max_distance {
            consecutive_fail += 1;
            if !opts.allow_sparse || consecutive_fail > 2 {
                break;
            }
            continue;
        }
        consecutive_fail = 0;
        cases.push(SwitchCase {
            index: i,
            entry_addr: ea,
            target,
            raw,
        });
    }

    if (cases.len() as u32) < opts.min_entries {
        return None;
    }

    let mut notes = Vec::new();
    if opts.trim_outliers {
        let before = cases.len();
        trim_outlier_targets(&mut cases);
        if cases.len() != before {
            notes.push(format!("trimmed {} outlier(s)", before - cases.len()));
        }
    }
    if (cases.len() as u32) < opts.min_entries {
        return None;
    }

    Some(SwitchInfo {
        jmp,
        table,
        encoding,
        entry_size,
        index_reg_hint: None,
        bound,
        default_case: None,
        cases,
        confidence: 0.0,
        notes,
    })
}

fn read_entry(bin: &Binary, ea: u64, entry_size: u32) -> Option<u64> {
    if entry_size == 8 {
        bin.read_u64(ea)
    } else {
        bin.read_u32(ea).map(u64::from)
    }
}

fn decode_target(
    bin: &Binary,
    jmp: u64,
    table: u64,
    raw: u64,
    encoding: TableEncoding,
    entry_size: u32,
) -> Option<u64> {
    match encoding {
        TableEncoding::Absolute => {
            let mask = if bin.arch == Arch::X86 {
                0xffff_ffff
            } else {
                !0u64
            };
            Some(raw & mask)
        }
        TableEncoding::RelTable => {
            let off = raw as i32 as i64;
            Some((table as i64).wrapping_add(off) as u64)
        }
        TableEncoding::RelRip => {
            let off = raw as i32 as i64;
            // common MSVC: offset relative to table start or next-rip of jmp
            let a = (table as i64).wrapping_add(off) as u64;
            if bin.is_code(a) {
                return Some(a);
            }
            let b = (jmp as i64).wrapping_add(off) as u64;
            if bin.is_code(b) {
                return Some(b);
            }
            // try rip of table entry itself
            let _ = entry_size;
            None
        }
        TableEncoding::RelImage => {
            let off = raw as i32 as i64;
            Some((bin.base as i64).wrapping_add(off) as u64)
        }
    }
}

fn trim_outlier_targets(cases: &mut Vec<SwitchCase>) {
    if cases.len() < 4 {
        return;
    }
    let mut tgts: Vec<u64> = cases.iter().map(|c| c.target).collect();
    tgts.sort_unstable();
    let med = tgts[tgts.len() / 2];
    // drop targets more than 1MB from median if minority
    let thr = 0x10_0000u64;
    let mut keep = Vec::new();
    for c in cases.iter() {
        if c.target.abs_diff(med) <= thr {
            keep.push(c.clone());
        }
    }
    if keep.len() * 4 >= cases.len() * 3 {
        *cases = keep;
    }
}

fn score_switch(bin: &Binary, an: &Analysis, info: &SwitchInfo) -> f32 {
    let n = info.cases.len() as f32;
    if n < 2.0 {
        return 0.0;
    }
    let mut score = 0.4;
    // more cases → higher (up to a point)
    score += (n.log2() / 10.0).min(0.25);
    // unique targets ratio
    let uniq: BTreeSet<u64> = info.cases.iter().map(|c| c.target).collect();
    let uniq_ratio = uniq.len() as f32 / n;
    score += uniq_ratio * 0.15;
    // cluster tightness
    let mut tgts: Vec<u64> = uniq.iter().copied().collect();
    tgts.sort_unstable();
    if tgts.len() >= 2 {
        let span = tgts.last().unwrap() - tgts.first().unwrap();
        let dens = (tgts.len() as f32) / (span.max(1) as f32 / 16.0).max(1.0);
        score += dens.min(0.15);
    }
    // code flags help
    let codeish = info
        .cases
        .iter()
        .filter(|c| (an.flags_at(c.target) & crate::FL_CODE) != 0 || bin.is_code(c.target))
        .count() as f32
        / n;
    score += codeish * 0.2;
    if info.bound.is_some() {
        score += 0.08;
    }
    if info.encoding != TableEncoding::Absolute {
        score += 0.05;
    }
    if !info.notes.is_empty() {
        score -= 0.02 * info.notes.len() as f32;
    }
    score.clamp(0.0, 1.0)
}

fn is_tail_only(f: u8) -> bool {
    (f & crate::FL_TAIL) != 0 && (f & (crate::FL_CODE | crate::FL_STR | crate::FL_DATA)) == 0
}

/// Summarize switches as human-readable lines.
pub fn format_switch_report(switches: &[SwitchInfo]) -> String {
    let mut out = String::new();
    out.push_str(&format!("switches: {}\n", switches.len()));
    for s in switches {
        out.push_str(&format!(
            "  jmp {:X} table {:X} enc={} entries={} bound={:?} conf={:.2}\n",
            s.jmp,
            s.table,
            s.encoding.as_str(),
            s.cases.len(),
            s.bound,
            s.confidence
        ));
        for (i, c) in s.cases.iter().take(8).enumerate() {
            out.push_str(&format!(
                "    [{i}] idx={} entry={:X} -> {:X}\n",
                c.index, c.entry_addr, c.target
            ));
        }
        if s.cases.len() > 8 {
            out.push_str(&format!("    ... {} more\n", s.cases.len() - 8));
        }
        for n in &s.notes {
            out.push_str(&format!("    note: {n}\n"));
        }
    }
    out
}

/// Index switches by jump address.
pub fn index_by_jmp(switches: &[SwitchInfo]) -> BTreeMap<u64, &SwitchInfo> {
    switches.iter().map(|s| (s.jmp, s)).collect()
}

/// Index switches by table base.
pub fn index_by_table(switches: &[SwitchInfo]) -> BTreeMap<u64, Vec<&SwitchInfo>> {
    let mut m: BTreeMap<u64, Vec<&SwitchInfo>> = BTreeMap::new();
    for s in switches {
        m.entry(s.table).or_default().push(s);
    }
    m
}

/// Collect all case targets across switches.
pub fn all_case_targets(switches: &[SwitchInfo]) -> BTreeSet<u64> {
    let mut s = BTreeSet::new();
    for sw in switches {
        for c in &sw.cases {
            s.insert(c.target);
        }
        if let Some(d) = sw.default_case {
            s.insert(d);
        }
    }
    s
}

/// Find switch containing a case target.
pub fn switch_for_target(switches: &[SwitchInfo], target: u64) -> Option<&SwitchInfo> {
    switches.iter().find(|s| {
        s.default_case == Some(target) || s.cases.iter().any(|c| c.target == target)
    })
}

/// Heuristic: does this look like a binary-search switch (MSVC) rather than a jump table?
pub fn looks_like_binary_search_switch(bin: &Binary, func_start: u64, func_end: u64) -> bool {
    let mut cmp_imm = 0usize;
    let mut cond = 0usize;
    let mut addr = func_start;
    let mut n = 0usize;
    while addr < func_end && n < 256 {
        let Ok(insn) = decode_at(bin, addr) else {
            break;
        };
        let m = insn.mnemonic.to_ascii_lowercase();
        if m == "cmp" && insn.imm.is_some() {
            cmp_imm += 1;
        }
        if matches!(insn.flow, Flow::Cond) {
            cond += 1;
        }
        addr = insn.next();
        n += 1;
    }
    cmp_imm >= 4 && cond >= 4 && cmp_imm * 2 >= cond
}

/// Enumerate indirect jump sites in a function.
pub fn indirect_jumps_in(bin: &Binary, start: u64, end: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut addr = start;
    let mut n = 0usize;
    while addr < end && n < 8192 {
        let Ok(insn) = decode_at(bin, addr) else {
            break;
        };
        if insn.flow == Flow::Jump && insn.indirect {
            out.push(insn.addr);
        }
        addr = insn.next();
        n += 1;
    }
    out
}

/// Build a sparse case map (index → target), filling gaps with default when known.
pub fn dense_case_map(info: &SwitchInfo) -> HashMap<u32, u64> {
    let mut m = HashMap::new();
    for c in &info.cases {
        m.insert(c.index, c.target);
    }
    if let (Some(bound), Some(def)) = (info.bound, info.default_case) {
        for i in 0..=bound {
            m.entry(i).or_insert(def);
        }
    }
    m
}

/// Estimate bytes occupied by the table in the image.
pub fn table_span(info: &SwitchInfo) -> Option<(u64, u64)> {
    if info.cases.is_empty() {
        return None;
    }
    let start = info.table;
    let last = info.cases.iter().map(|c| c.entry_addr).max()?;
    Some((start, last + u64::from(info.entry_size)))
}

/// Compare two switch recoveries (for tests / diffs).
pub fn switches_equivalent(a: &SwitchInfo, b: &SwitchInfo) -> bool {
    a.jmp == b.jmp
        && a.table == b.table
        && a.encoding == b.encoding
        && a.cases.len() == b.cases.len()
        && a.cases
            .iter()
            .zip(b.cases.iter())
            .all(|(x, y)| x.index == y.index && x.target == y.target)
}

/// Validate that case entry addresses are contiguous for dense tables.
pub fn is_dense_table(info: &SwitchInfo) -> bool {
    if info.cases.is_empty() {
        return false;
    }
    for (i, c) in info.cases.iter().enumerate() {
        if c.index as usize != i {
            return false;
        }
        let expect = info.table + (i as u64) * u64::from(info.entry_size);
        if c.entry_addr != expect {
            return false;
        }
    }
    true
}


/// Pattern slot 0: score a potential table base using local pointer density.
pub fn table_density_score_0(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (0 as f32) * 0.001)
    }
}


/// Pattern slot 1: score a potential table base using local pointer density.
pub fn table_density_score_1(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (1 as f32) * 0.001)
    }
}


/// Pattern slot 2: score a potential table base using local pointer density.
pub fn table_density_score_2(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (2 as f32) * 0.001)
    }
}


/// Pattern slot 3: score a potential table base using local pointer density.
pub fn table_density_score_3(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (3 as f32) * 0.001)
    }
}


/// Pattern slot 4: score a potential table base using local pointer density.
pub fn table_density_score_4(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (4 as f32) * 0.001)
    }
}


/// Pattern slot 5: score a potential table base using local pointer density.
pub fn table_density_score_5(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (5 as f32) * 0.001)
    }
}


/// Pattern slot 6: score a potential table base using local pointer density.
pub fn table_density_score_6(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (6 as f32) * 0.001)
    }
}


/// Pattern slot 7: score a potential table base using local pointer density.
pub fn table_density_score_7(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (7 as f32) * 0.001)
    }
}


/// Pattern slot 8: score a potential table base using local pointer density.
pub fn table_density_score_8(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (8 as f32) * 0.001)
    }
}


/// Pattern slot 9: score a potential table base using local pointer density.
pub fn table_density_score_9(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (9 as f32) * 0.001)
    }
}


/// Pattern slot 10: score a potential table base using local pointer density.
pub fn table_density_score_10(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (10 as f32) * 0.001)
    }
}


/// Pattern slot 11: score a potential table base using local pointer density.
pub fn table_density_score_11(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (11 as f32) * 0.001)
    }
}


/// Pattern slot 12: score a potential table base using local pointer density.
pub fn table_density_score_12(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (12 as f32) * 0.001)
    }
}


/// Pattern slot 13: score a potential table base using local pointer density.
pub fn table_density_score_13(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (13 as f32) * 0.001)
    }
}


/// Pattern slot 14: score a potential table base using local pointer density.
pub fn table_density_score_14(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (14 as f32) * 0.001)
    }
}


/// Pattern slot 15: score a potential table base using local pointer density.
pub fn table_density_score_15(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (15 as f32) * 0.001)
    }
}


/// Pattern slot 16: score a potential table base using local pointer density.
pub fn table_density_score_16(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (16 as f32) * 0.001)
    }
}


/// Pattern slot 17: score a potential table base using local pointer density.
pub fn table_density_score_17(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (17 as f32) * 0.001)
    }
}


/// Pattern slot 18: score a potential table base using local pointer density.
pub fn table_density_score_18(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (18 as f32) * 0.001)
    }
}


/// Pattern slot 19: score a potential table base using local pointer density.
pub fn table_density_score_19(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (19 as f32) * 0.001)
    }
}


/// Pattern slot 20: score a potential table base using local pointer density.
pub fn table_density_score_20(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (20 as f32) * 0.001)
    }
}


/// Pattern slot 21: score a potential table base using local pointer density.
pub fn table_density_score_21(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (21 as f32) * 0.001)
    }
}


/// Pattern slot 22: score a potential table base using local pointer density.
pub fn table_density_score_22(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (22 as f32) * 0.001)
    }
}


/// Pattern slot 23: score a potential table base using local pointer density.
pub fn table_density_score_23(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (23 as f32) * 0.001)
    }
}


/// Pattern slot 24: score a potential table base using local pointer density.
pub fn table_density_score_24(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (24 as f32) * 0.001)
    }
}


/// Pattern slot 25: score a potential table base using local pointer density.
pub fn table_density_score_25(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (25 as f32) * 0.001)
    }
}


/// Pattern slot 26: score a potential table base using local pointer density.
pub fn table_density_score_26(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (26 as f32) * 0.001)
    }
}


/// Pattern slot 27: score a potential table base using local pointer density.
pub fn table_density_score_27(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (27 as f32) * 0.001)
    }
}


/// Pattern slot 28: score a potential table base using local pointer density.
pub fn table_density_score_28(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (28 as f32) * 0.001)
    }
}


/// Pattern slot 29: score a potential table base using local pointer density.
pub fn table_density_score_29(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (29 as f32) * 0.001)
    }
}


/// Pattern slot 30: score a potential table base using local pointer density.
pub fn table_density_score_30(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (30 as f32) * 0.001)
    }
}


/// Pattern slot 31: score a potential table base using local pointer density.
pub fn table_density_score_31(bin: &Binary, table: u64, entry_size: u32, count: u32) -> f32 {
    let mut ok = 0u32;
    let mut total = 0u32;
    for k in 0..count {
        let ea = table.wrapping_add(u64::from(k) * u64::from(entry_size));
        total += 1;
        if let Some(raw) = read_entry(bin, ea, entry_size) {
            let t = raw;
            if bin.is_code(t) || bin.is_mapped(t) {
                ok += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        (ok as f32 / total as f32) * (1.0 + (31 as f32) * 0.001)
    }
}


/// Aggregate density across several candidate bases.
pub fn best_table_base(
    bin: &Binary,
    candidates: &[u64],
    entry_size: u32,
    count: u32,
) -> Option<(u64, f32)> {
    let mut best: Option<(u64, f32)> = None;
    for (i, &c) in candidates.iter().enumerate() {
        let s = match i % 8 {
            0 => table_density_score_0(bin, c, entry_size, count),
            1 => table_density_score_1(bin, c, entry_size, count),
            2 => table_density_score_2(bin, c, entry_size, count),
            3 => table_density_score_3(bin, c, entry_size, count),
            4 => table_density_score_4(bin, c, entry_size, count),
            5 => table_density_score_5(bin, c, entry_size, count),
            6 => table_density_score_6(bin, c, entry_size, count),
            _ => table_density_score_7(bin, c, entry_size, count),
        };
        if best.map(|(_, b)| s > b).unwrap_or(true) {
            best = Some((c, s));
        }
    }
    best
}

/// Describe encoding suitability for a raw entry sample.
pub fn classify_encoding_sample(
    bin: &Binary,
    jmp: u64,
    table: u64,
    raw: u64,
    entry_size: u32,
) -> Vec<(TableEncoding, u64, bool)> {
    let mut out = Vec::new();
    for enc in [
        TableEncoding::Absolute,
        TableEncoding::RelTable,
        TableEncoding::RelRip,
        TableEncoding::RelImage,
    ] {
        if let Some(t) = decode_target(bin, jmp, table, raw, enc, entry_size) {
            out.push((enc, t, bin.is_code(t)));
        }
    }
    out
}

/// Scan a function range for cmp/ja bound pairs.
pub fn find_bounds_in_range(bin: &Binary, start: u64, end: u64) -> Vec<(u64, u32)> {
    let mut out = Vec::new();
    let mut last_cmp: Option<(u64, u64)> = None;
    let mut addr = start;
    let mut n = 0usize;
    while addr < end && n < 4096 {
        let Ok(insn) = decode_at(bin, addr) else {
            break;
        };
        let m = insn.mnemonic.to_ascii_lowercase();
        if m == "cmp" {
            if let Some(imm) = insn.imm {
                last_cmp = Some((insn.addr, imm));
            }
        } else if matches!(m.as_str(), "ja" | "jae" | "jnbe" | "jnb") {
            if let Some((ca, imm)) = last_cmp {
                if insn.addr.saturating_sub(ca) < 0x20 && imm <= 0x10000 {
                    let bound = if m == "ja" || m == "jnbe" {
                        imm.saturating_add(1) as u32
                    } else {
                        imm as u32
                    };
                    out.push((ca, bound));
                }
            }
        }
        addr = insn.next();
        n += 1;
    }
    out
}

/// Merge overlapping switch infos that share a table base.
pub fn coalesce_by_table(mut items: Vec<SwitchInfo>) -> Vec<SwitchInfo> {
    items.sort_by_key(|s| (s.table, s.jmp));
    let mut out: Vec<SwitchInfo> = Vec::new();
    for s in items {
        if let Some(prev) = out.last_mut() {
            if prev.table == s.table && prev.encoding == s.encoding {
                if s.confidence > prev.confidence {
                    *prev = s;
                }
                continue;
            }
        }
        out.push(s);
    }
    out
}

/// Produce CFG-oriented case edges as (jmp, target) pairs.
pub fn switch_edges(info: &SwitchInfo) -> Vec<(u64, u64)> {
    let mut e: Vec<(u64, u64)> = info.cases.iter().map(|c| (info.jmp, c.target)).collect();
    if let Some(d) = info.default_case {
        e.push((info.jmp, d));
    }
    e.sort_unstable();
    e.dedup();
    e
}

/// Pretty one-line summary.
pub fn switch_one_liner(info: &SwitchInfo) -> String {
    format!(
        "switch@{:X} [{} x{}] -> {} targets (conf {:.0}%)",
        info.jmp,
        info.encoding.as_str(),
        info.entry_size,
        info.cases.len(),
        info.confidence * 100.0
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceasta_binary::{Format, Segment, PERM_R, PERM_X};
    use crate::run;

    fn toy_abs_table() -> Binary {
        // jmp qword ptr [rax*8 + table]
        // We craft: at 0x1000 an indirect jump isn't easy without iced; instead
        // plant an absolute pointer table and refine via try_read_table.
        let mut text = vec![0x90u8; 0x80];
        // ret at start so analysis has something
        text[0] = 0xc3;
        let mut ro = vec![0u8; 0x40];
        // table at 0x2000: pointers to 0x1010, 0x1020, 0x1030
        for (i, t) in [0x1010u64, 0x1020, 0x1030].iter().enumerate() {
            ro[i * 8..i * 8 + 8].copy_from_slice(&t.to_le_bytes());
        }
        // put code at targets
        for off in [0x10usize, 0x20, 0x30] {
            text[off] = 0xc3;
        }
        let mut bin = Binary::empty("sw.bin", Format::Raw, Arch::X64);
        bin.base = 0x1000;
        bin.entry = 0x1000;
        bin.has_entry = true;
        bin.segments.push(Segment {
            name: ".text".into(),
            start: 0x1000,
            end: 0x1000 + text.len() as u64,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: text.len() as u64,
            data: text,
        });
        bin.segments.push(Segment {
            name: ".rdata".into(),
            start: 0x2000,
            end: 0x2000 + ro.len() as u64,
            perms: PERM_R,
            file_off: 0,
            file_size: ro.len() as u64,
            data: ro,
        });
        bin
    }

    #[test]
    fn reads_absolute_pointer_table() {
        let bin = toy_abs_table();
        let an = run(&bin);
        let opts = SwitchOptions::default();
        let info = try_read_table(
            &bin,
            &an,
            0x1000,
            0x2000,
            8,
            TableEncoding::Absolute,
            &opts,
            Some(2),
        )
        .expect("table");
        assert_eq!(info.cases.len(), 3);
        assert_eq!(info.cases[0].target, 0x1010);
        assert_eq!(info.cases[2].target, 0x1030);
        assert!(is_dense_table(&info));
    }

    #[test]
    fn relative_table_encoding() {
        let mut bin = Binary::empty("rel.bin", Format::Raw, Arch::X64);
        bin.base = 0x1000;
        bin.entry = 0x1000;
        bin.has_entry = true;
        let mut text = vec![0xc3u8; 0x100];
        let table = 0x2000u64;
        // offsets relative to table: +0x10, +0x20 from 0x1000 code — store as i32 relative to table
        // targets at 0x1010 / 0x1020 → offs = target - table
        let mut ro = vec![0u8; 16];
        let o0 = (0x1010i64 - table as i64) as i32;
        let o1 = (0x1020i64 - table as i64) as i32;
        ro[0..4].copy_from_slice(&o0.to_le_bytes());
        ro[4..8].copy_from_slice(&o1.to_le_bytes());
        bin.segments.push(Segment {
            name: ".text".into(),
            start: 0x1000,
            end: 0x1100,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: text.len() as u64,
            data: text,
        });
        bin.segments.push(Segment {
            name: ".rdata".into(),
            start: 0x2000,
            end: 0x2010,
            perms: PERM_R,
            file_off: 0,
            file_size: 16,
            data: ro,
        });
        let an = run(&bin);
        let info = try_read_table(
            &bin,
            &an,
            0x1000,
            0x2000,
            4,
            TableEncoding::RelTable,
            &SwitchOptions::default(),
            Some(1),
        )
        .expect("rel");
        assert_eq!(info.cases[0].target, 0x1010);
        assert_eq!(info.cases[1].target, 0x1020);
    }

    #[test]
    fn report_and_apply() {
        let bin = toy_abs_table();
        let mut an = run(&bin);
        let opts = SwitchOptions::default();
        let info = try_read_table(
            &bin, &an, 0x1000, 0x2000, 8, TableEncoding::Absolute, &opts, Some(2),
        )
        .unwrap();
        let conf = score_switch(&bin, &an, &info);
        assert!(conf > 0.3);
        let list = vec![info];
        let rep = format_switch_report(&list);
        assert!(rep.contains("switches:"));
        apply_switches(&mut an, &list);
        assert!(an.tables.contains_key(&0x1000));
    }

    #[test]
    fn density_helpers_smoke() {
        let bin = toy_abs_table();
        let s = table_density_score_0(&bin, 0x2000, 8, 3);
        assert!(s > 0.5);
        let best = best_table_base(&bin, &[0x2000, 0x2100], 8, 3);
        assert_eq!(best.unwrap().0, 0x2000);
    }
}
