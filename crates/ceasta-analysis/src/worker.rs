//! Analysis worker — code walk, functions, xrefs, strings, thunks.
//! Port of the C++ `worker` in `src/core/analysis.cpp` (x86/x64).

use crate::flags::{FL_CODE, FL_DATA, FL_FUNC, FL_LABEL, FL_STR, FL_TAIL};
use crate::noreturn::is_noreturn_name;
use crate::{
    Analysis, AnalysisProgress, FoundString, Function, JumpTable, Xref, XrefKind,
};
use ceasta_binary::{Arch, Binary, Format};
use ceasta_disasm::{decode_at, Flow, Insn};
use std::collections::{HashMap, HashSet};

pub fn run(bin: &Binary, progress: Option<&AnalysisProgress>) -> Option<Analysis> {
    if matches!(bin.arch, Arch::Arm64) {
        return Some(seed_only(bin));
    }
    let mut w = Worker::new(bin, progress);
    if !w.run() {
        return None;
    }
    Some(w.an)
}

fn seed_only(bin: &Binary) -> Analysis {
    let mut an = Analysis::default();
    init_segments(bin, &mut an);
    mark_import_slots(bin, &mut an);
    let mut starts = Vec::new();
    if bin.has_entry {
        starts.push(bin.entry);
    }
    starts.extend(bin.func_hints.iter().copied());
    starts.extend(bin.tls_callbacks.iter().copied());
    starts.extend(
        bin.exports
            .iter()
            .filter_map(|e| (e.addr != 0).then_some(e.addr)),
    );
    starts.sort_unstable();
    starts.dedup();
    for &s in &starts {
        if bin.is_code(s) {
            an.functions.push(Function {
                start: s,
                end: s + 1,
                insns: 0,
                name: name_for(bin, s),
                thunk: false,
                thunk_target: 0,
            });
            an.add_flags(s, FL_FUNC);
        }
    }
    scan_strings_unref(bin, &mut an);
    an
}

fn init_segments(bin: &Binary, an: &mut Analysis) {
    for s in &bin.segments {
        an.seg_start.push(s.start);
        an.flags.push(vec![0u8; s.size() as usize]);
    }
}

fn mark_import_slots(bin: &Binary, an: &mut Analysis) {
    let ps = bin.arch.ptr_size() as u32;
    for (i, imp) in bin.imports.iter().enumerate() {
        an.slot_import.insert(imp.slot, i as u32);
        if range_free(an, imp.slot, ps) {
            mark_item(an, imp.slot, ps, FL_DATA);
            an.data_sizes.insert(imp.slot, ps as u8);
        }
    }
}

fn name_for(bin: &Binary, addr: u64) -> String {
    if let Some(s) = bin
        .symbols
        .iter()
        .find(|s| s.addr == addr && !s.name.is_empty())
    {
        return s.name.clone();
    }
    if let Some(e) = bin
        .exports
        .iter()
        .find(|e| e.addr == addr && !e.name.is_empty())
    {
        return e.name.clone();
    }
    format!("sub_{addr:X}")
}

fn is_print(c: u8) -> bool {
    (0x20..0x7f).contains(&c) || matches!(c, b'\t' | b'\n' | b'\r')
}

fn is_tail_only(f: u8) -> bool {
    (f & FL_TAIL) != 0 && (f & (FL_CODE | FL_STR | FL_DATA)) == 0
}

fn range_free(an: &Analysis, a: u64, n: u32) -> bool {
    for k in 0..n {
        let addr = a + u64::from(k);
        if !an.mapped(addr) {
            return false;
        }
        let f = an.flags_at(addr);
        if f & (FL_CODE | FL_TAIL | FL_STR | FL_DATA) != 0 {
            return false;
        }
    }
    true
}

fn mark_item(an: &mut Analysis, a: u64, n: u32, head: u8) {
    an.add_flags(a, head);
    for k in 1..n {
        an.add_flags(a + u64::from(k), FL_TAIL);
    }
}

fn scan_strings_unref(bin: &Binary, an: &mut Analysis) {
    for si in 0..bin.segments.len() {
        let start = bin.segments[si].start;
        let d = bin.segments[si].data.clone();
        let mut i = 0usize;
        while i < d.len() && an.strings.len() < 500_000 {
            if an.flags[si][i] != 0 {
                i += 1;
                continue;
            }
            let a = start + i as u64;
            let mut wl = 0usize;
            while i + wl * 2 + 1 < d.len()
                && is_print(d[i + wl * 2])
                && d[i + wl * 2 + 1] == 0
                && an.flags[si][i + wl * 2] == 0
                && an.flags[si][i + wl * 2 + 1] == 0
            {
                wl += 1;
            }
            let wend = i + wl * 2;
            if wl >= 5
                && wend + 1 < d.len()
                && d[wend] == 0
                && d[wend + 1] == 0
                && an.flags[si][wend] == 0
                && an.flags[si][wend + 1] == 0
            {
                let text: String = (0..wl).map(|k| d[i + k * 2] as char).collect();
                let len = (wl * 2 + 2) as u32;
                mark_item(an, a, len, FL_STR);
                an.strings.push(FoundString {
                    addr: a,
                    len,
                    wide: true,
                    text,
                });
                i += wl * 2 + 2;
                continue;
            }
            let mut n = 0usize;
            while i + n < d.len() && is_print(d[i + n]) && an.flags[si][i + n] == 0 {
                n += 1;
            }
            if n >= 5 && i + n < d.len() && d[i + n] == 0 && an.flags[si][i + n] == 0 {
                let text = String::from_utf8_lossy(&d[i..i + n]).into_owned();
                let len = (n + 1) as u32;
                mark_item(an, a, len, FL_STR);
                an.strings.push(FoundString {
                    addr: a,
                    len,
                    wide: false,
                    text,
                });
                i += n + 1;
                continue;
            }
            i += n.max(1);
        }
    }
    an.strings.sort_by_key(|s| s.addr);
}

struct Worker<'a> {
    b: &'a Binary,
    prog: Option<&'a AnalysisProgress>,
    an: Analysis,
    func_starts: HashSet<u64>,
    weak_starts: HashSet<u64>,
    work: Vec<u64>,
    deferred: Vec<u64>,
    xrefs: Vec<Xref>,
    data_cand: HashMap<u64, u8>,
    sym_names: HashMap<u64, String>,
    thunk_cache: HashMap<u64, i32>,
    mask: u64,
    imm_refs: bool,
    cancelled: bool,
}

impl<'a> Worker<'a> {
    fn new(b: &'a Binary, prog: Option<&'a AnalysisProgress>) -> Self {
        Self {
            b,
            prog,
            an: Analysis::default(),
            func_starts: HashSet::new(),
            weak_starts: HashSet::new(),
            work: Vec::new(),
            deferred: Vec::new(),
            xrefs: Vec::new(),
            data_cand: HashMap::new(),
            sym_names: HashMap::new(),
            thunk_cache: HashMap::new(),
            mask: 0,
            imm_refs: false,
            cancelled: false,
        }
    }

    fn stop_requested(&mut self) -> bool {
        if self.prog.map(|p| p.cancelled()).unwrap_or(false) {
            self.cancelled = true;
        }
        self.cancelled
    }

    fn progress(&self, pct: i32) {
        if let Some(p) = self.prog {
            p.set_percent(pct);
        }
    }

    fn code_at(&self, a: u64) -> bool {
        self.b.is_code(a)
    }

    fn add_xref(&mut self, from: u64, to: u64, kind: XrefKind) {
        self.xrefs.push(Xref { from, to, kind });
    }

    fn add_func(&mut self, a: u64, weak: bool) {
        if !self.code_at(a) {
            return;
        }
        if self.func_starts.insert(a) {
            self.work.push(a);
            if weak {
                self.weak_starts.insert(a);
            }
        } else if !weak {
            self.weak_starts.remove(&a);
        }
    }

    fn push_code(&mut self, a: u64) {
        if self.code_at(a) {
            self.work.push(a);
        }
    }

    fn import_of_slot(&self, slot: u64) -> i32 {
        self.an
            .slot_import
            .get(&slot)
            .map(|&i| i as i32)
            .unwrap_or(-1)
    }

    fn thunk_import_at(&mut self, a: u64) -> i32 {
        if let Some(&r) = self.thunk_cache.get(&a) {
            return r;
        }
        let mut r = -1;
        if let Ok(mut insn) = decode_at(self.b, a) {
            if insn.is_endbr() {
                match decode_at(self.b, insn.next()) {
                    Ok(next) => insn = next,
                    Err(_) => {
                        self.thunk_cache.insert(a, -1);
                        return -1;
                    }
                }
            }
            if insn.flow == Flow::Jump && insn.indirect {
                if let Some(m) = insn.mem {
                    r = self.import_of_slot(m);
                }
            }
        }
        self.thunk_cache.insert(a, r);
        r
    }

    fn callee_name(&mut self, insn: &Insn) -> String {
        if insn.indirect {
            if let Some(m) = insn.mem {
                let i = self.import_of_slot(m);
                if i >= 0 {
                    return self.b.imports[i as usize].name.clone();
                }
            }
            return String::new();
        }
        let Some(t) = insn.target else {
            return String::new();
        };
        let ti = self.thunk_import_at(t);
        if ti >= 0 {
            return self.b.imports[ti as usize].name.clone();
        }
        self.sym_names.get(&t).cloned().unwrap_or_default()
    }

    fn note_data(&mut self, a: u64, size: u8) {
        if !self.code_at(a) {
            self.data_cand.entry(a).or_insert(size);
        }
    }

    fn get_pc_call(insn: &Insn) -> bool {
        insn.flow == Flow::Call && insn.target == Some(insn.next())
    }

    fn refs(&mut self, insn: &Insn) {
        if let Some(t) = insn.target {
            let kind = if insn.flow == Flow::Call && !Self::get_pc_call(insn) {
                XrefKind::Call
            } else {
                XrefKind::Jump
            };
            self.add_xref(insn.addr, t, kind);
        }
        if let Some(m) = insn.mem {
            if self.b.is_mapped(m) {
                if insn.is_lea {
                    self.add_xref(insn.addr, m, XrefKind::Offset);
                    if self.code_at(m) {
                        self.deferred.push(m);
                    }
                } else {
                    let kind = if insn.mem_write {
                        XrefKind::Write
                    } else {
                        XrefKind::Read
                    };
                    self.add_xref(insn.addr, m, kind);
                    if insn.mem_size != 0 {
                        self.note_data(m, insn.mem_size);
                    }
                }
            }
        }
        if self.imm_refs {
            if let Some(imm) = insn.imm {
                if imm >= 0x10000 && self.b.is_mapped(imm) {
                    self.add_xref(insn.addr, imm, XrefKind::Offset);
                    if self.code_at(imm) && (insn.is_push() || insn.is_move()) {
                        self.deferred.push(imm);
                    }
                }
            }
        }
    }

    fn resolve_table(&mut self, insn: &Insn) {
        if !insn.indirect || insn.flow != Flow::Jump {
            return;
        }
        let Some(table) = insn.mem else {
            return;
        };
        let ps = self.b.arch.ptr_size() as u32;
        let es = if insn.mem_size != 0 {
            u32::from(insn.mem_size)
        } else {
            ps
        };
        if es != 4 && es != 8 {
            return;
        }
        let js = match self.b.seg_at(insn.addr) {
            Some(s) => (s.start, s.end),
            None => return,
        };
        let mut targets = Vec::new();
        let mut n = 0u32;
        while n < 512 {
            let ea = table + u64::from(n) * u64::from(es);
            if n > 0 && (self.an.flags_at(ea) & (FL_CODE | FL_STR)) != 0 {
                break;
            }
            let Some(e) = (if es == 8 {
                self.b.read_u64(ea)
            } else {
                self.b.read_u32(ea).map(u64::from)
            }) else {
                break;
            };
            let t = e & self.mask;
            if t < js.0 || t >= js.1 {
                break;
            }
            let tf = self.an.flags_at(t);
            if is_tail_only(tf) || (tf & (FL_STR | FL_DATA)) != 0 {
                break;
            }
            let dist = t.abs_diff(insn.addr);
            if dist > 0x100_000 {
                break;
            }
            targets.push(t);
            n += 1;
        }
        if targets.is_empty() {
            return;
        }
        for k in 0..n {
            let ea = table + u64::from(k) * u64::from(es);
            if range_free(&self.an, ea, es) {
                mark_item(&mut self.an, ea, es, FL_DATA);
                self.an.data_sizes.insert(ea, es as u8);
            }
        }
        let cases = targets.clone();
        targets.sort_unstable();
        targets.dedup();
        self.add_xref(insn.addr, table, XrefKind::Read);
        for &t in &targets {
            self.add_xref(insn.addr, t, XrefKind::Jump);
            self.push_code(t);
            if self.weak_starts.remove(&t) {
                self.func_starts.remove(&t);
            }
        }
        self.an.tables.insert(
            insn.addr,
            JumpTable {
                jmp: insn.addr,
                table,
                entry_size: es,
                entries: n,
                targets,
                cases,
            },
        );
    }

    fn explore(&mut self, mut a: u64) {
        loop {
            if !self.code_at(a)
                || (self.an.flags_at(a) & (FL_CODE | FL_TAIL | FL_STR | FL_DATA)) != 0
            {
                return;
            }
            let Ok(insn) = decode_at(self.b, a) else {
                return;
            };
            if !self.code_at(a + u64::from(insn.size) - 1) {
                return;
            }
            for k in 1..insn.size {
                let addr = a + u64::from(k);
                let f = self.an.flags_at(addr);
                if (f & (FL_CODE | FL_TAIL | FL_STR | FL_DATA)) != 0 {
                    return;
                }
                if self.func_starts.contains(&addr) && !self.weak_starts.contains(&addr) {
                    return;
                }
            }
            mark_item(&mut self.an, a, insn.size, FL_CODE);
            self.an.insn_count += 1;
            self.refs(&insn);

            let mut stop = false;
            match insn.flow {
                Flow::Jump => {
                    if let Some(t) = insn.target {
                        if self.thunk_import_at(t) >= 0 {
                            self.add_func(t, false);
                        } else {
                            self.push_code(t);
                        }
                    } else {
                        self.resolve_table(&insn);
                    }
                    stop = true;
                }
                Flow::Cond => {
                    if let Some(t) = insn.target {
                        self.push_code(t);
                    }
                }
                Flow::Call => {
                    if let Some(t) = insn.target {
                        if !Self::get_pc_call(&insn) {
                            self.add_func(t, false);
                        }
                    }
                    let name = self.callee_name(&insn);
                    if is_noreturn_name(&name) {
                        self.an.noret_calls.insert(insn.addr);
                        stop = true;
                    }
                }
                Flow::Ret | Flow::Stop => stop = true,
                Flow::Normal => {}
            }
            if stop {
                return;
            }
            a = insn.next();
        }
    }

    fn run_work(&mut self) {
        let mut n = 0u64;
        while let Some(a) = self.work.pop() {
            n += 1;
            if (n & 1023) == 0 && self.stop_requested() {
                return;
            }
            self.explore(a);
        }
    }

    fn prologue_at_bytes(d: &[u8], wide: bool) -> bool {
        const P64: &[&[i16]] = &[
            &[0x55, 0x48, 0x89, 0xe5],
            &[0x55, 0x48, 0x8b, 0xec],
            &[0xf3, 0x0f, 0x1e, 0xfa],
            &[0x48, 0x89, 0x5c, 0x24, -1],
            &[0x48, 0x89, 0x4c, 0x24, 0x08],
            &[0x48, 0x89, 0x54, 0x24, 0x10],
            &[0x4c, 0x89, 0x44, 0x24, 0x18],
            &[0x48, 0x83, 0xec, -1],
            &[0x48, 0x81, 0xec, -1, -1, 0x00, 0x00],
            &[0x40, 0x53, 0x48, 0x83, 0xec],
        ];
        const P32: &[&[i16]] = &[
            &[0x55, 0x8b, 0xec],
            &[0x55, 0x89, 0xe5],
            &[0x8b, 0xff, 0x55, 0x8b, 0xec],
            &[0xf3, 0x0f, 0x1e, 0xfb],
        ];
        let match_pat = |p: &[i16]| -> bool {
            for (i, &b) in p.iter().enumerate() {
                if i >= d.len() {
                    return false;
                }
                if b >= 0 && d[i] != b as u8 {
                    return false;
                }
            }
            true
        };
        if wide {
            P64.iter().any(|p| match_pat(p))
        } else {
            P32.iter().any(|p| match_pat(p))
        }
    }

    fn prologue_at(&self, a: u64) -> bool {
        let mut buf = [0u8; 8];
        let n = self.b.read(a, &mut buf);
        if n == 0 {
            return false;
        }
        Self::prologue_at_bytes(&buf[..n], self.b.is64())
    }

    fn scan_prologues(&mut self) {
        let candidates: Vec<u64> = self
            .b
            .segments
            .iter()
            .enumerate()
            .filter(|(_, s)| s.exec())
            .flat_map(|(si, s)| {
                let fl = &self.an.flags[si];
                let d = &s.data;
                let mut out = Vec::new();
                for off in 0..d.len() {
                    if fl[off] != 0 {
                        continue;
                    }
                    if off > 0 && fl[off - 1] == 0 {
                        let prev = d[off - 1];
                        if prev != 0xcc && prev != 0x90 && prev != 0x00 && prev != 0xc3 {
                            continue;
                        }
                    }
                    if Self::prologue_at_bytes(&d[off..], self.b.is64()) {
                        out.push(s.start + off as u64);
                    }
                }
                out
            })
            .collect();
        for a in candidates {
            self.add_func(a, true);
        }
    }

    fn scan_reloc_ptrs(&mut self) {
        let ps = self.b.arch.ptr_size() as u32;
        let locs = self.b.ptr_locs.clone();
        for loc in locs {
            if self.code_at(loc) {
                continue;
            }
            let Some(v) = self.b.read_ptr(loc) else {
                continue;
            };
            if v == 0 || !self.b.is_mapped(v) {
                continue;
            }
            if range_free(&self.an, loc, ps) {
                mark_item(&mut self.an, loc, ps, FL_DATA);
                self.an.data_sizes.insert(loc, ps as u8);
            }
            self.add_xref(loc, v, XrefKind::Offset);
            if self.code_at(v) {
                self.deferred.push(v);
            }
        }
    }

    fn scan_data_ptrs(&mut self) {
        if !self.b.ptr_locs.is_empty() || self.b.format == Format::Raw {
            return;
        }
        let ps = self.b.arch.ptr_size() as u64;
        let segs: Vec<(u64, u64, u64, bool)> = self
            .b
            .segments
            .iter()
            .map(|s| (s.start, s.end, s.file_size, s.exec()))
            .collect();
        for (start, end, file_size, exec) in segs {
            if exec || file_size == 0 {
                continue;
            }
            let first = (start + ps - 1) / ps * ps;
            let lim = start + file_size.min(end - start);
            let mut loc = first;
            while loc + ps <= lim {
                if let Some(v) = self.b.read_ptr(loc) {
                    if self.code_at(v)
                        && (self.func_starts.contains(&v) || self.prologue_at(v))
                    {
                        let psz = ps as u32;
                        if range_free(&self.an, loc, psz) {
                            mark_item(&mut self.an, loc, psz, FL_DATA);
                            self.an.data_sizes.insert(loc, psz as u8);
                        }
                        self.add_xref(loc, v, XrefKind::Offset);
                        self.deferred.push(v);
                    }
                }
                loc += ps;
            }
        }
    }

    fn skip_padding(&self, mut p: u64, lim: u64) -> u64 {
        while p < lim {
            let Some(c) = self.b.read_u8(p) else {
                return lim;
            };
            if c == 0xcc || c == 0x90 || c == 0x00 {
                p += 1;
                continue;
            }
            if let Ok(insn) = decode_at(self.b, p) {
                if insn.is_nop() && p + u64::from(insn.size) <= lim {
                    p += u64::from(insn.size);
                    continue;
                }
            }
            break;
        }
        p.min(lim)
    }

    fn plausible_code(&self, mut a: u64, lim: u64) -> bool {
        let mut zero_ops = 0;
        for i in 0..256 {
            if a >= lim {
                return false;
            }
            let Ok(insn) = decode_at(self.b, a) else {
                return false;
            };
            if a + u64::from(insn.size) > lim {
                return false;
            }
            if insn.flow == Flow::Stop {
                return false;
            }
            if insn.size >= 2 && insn.bytes[0] == 0 && insn.bytes[1] == 0 {
                zero_ops += 1;
                if zero_ops >= 2 {
                    return false;
                }
            }
            if i == 0 && insn.bytes[0] == 0 {
                return false;
            }
            if matches!(insn.flow, Flow::Ret | Flow::Jump) {
                return i >= 1;
            }
            a = insn.next();
        }
        true
    }

    fn sweep_gaps(&mut self) {
        for _ in 0..64 {
            if self.cancelled {
                break;
            }
            let mut found = false;
            let seg_info: Vec<(usize, u64, bool)> = self
                .b
                .segments
                .iter()
                .enumerate()
                .map(|(si, s)| (si, s.start, s.exec()))
                .collect();
            for (si, start, exec) in seg_info {
                if !exec {
                    continue;
                }
                let size = self.an.flags[si].len();
                let mut off = 0usize;
                while off < size {
                    if self.an.flags[si][off] != 0 {
                        off += 1;
                        continue;
                    }
                    let mut run_end = off;
                    while run_end < size && self.an.flags[si][run_end] == 0 {
                        run_end += 1;
                    }
                    let after_code = off == 0 || {
                        let prev = self.an.flags[si][off - 1];
                        (prev & (FL_CODE | FL_TAIL)) != 0 && (prev & (FL_STR | FL_DATA)) == 0
                    };
                    if after_code {
                        let lim = start + run_end as u64;
                        let p = self.skip_padding(start + off as u64, lim);
                        if p < lim && self.plausible_code(p, lim) {
                            self.add_func(p, true);
                            self.run_work();
                            found = true;
                        }
                    }
                    off = run_end;
                }
            }
            if !found {
                break;
            }
        }
    }

    fn mark_padding(&mut self) {
        let seg_info: Vec<(usize, u64, bool)> = self
            .b
            .segments
            .iter()
            .enumerate()
            .map(|(si, s)| (si, s.start, s.exec()))
            .collect();
        for (si, start, exec) in seg_info {
            if !exec {
                continue;
            }
            let size = self.an.flags[si].len();
            let mut off = 0usize;
            while off < size {
                if self.an.flags[si][off] != 0 {
                    off += 1;
                    continue;
                }
                let mut run_end = off;
                while run_end < size && self.an.flags[si][run_end] == 0 {
                    run_end += 1;
                }
                if off > 0 && (self.an.flags[si][off - 1] & (FL_CODE | FL_TAIL)) != 0 {
                    let mut p = start + off as u64;
                    let lim = start + run_end as u64;
                    let mut pads = Vec::new();
                    while p < lim {
                        let Ok(insn) = decode_at(self.b, p) else {
                            break;
                        };
                        if p + u64::from(insn.size) > lim {
                            break;
                        }
                        if insn.is_nop() || insn.is_int3() {
                            pads.push((p, insn.size));
                            p += u64::from(insn.size);
                        } else {
                            break;
                        }
                    }
                    if p == lim {
                        for (pa, sz) in pads {
                            mark_item(&mut self.an, pa, sz, FL_CODE);
                        }
                    }
                }
                off = run_end;
            }
        }
    }

    fn build_functions(&mut self) {
        let mut starts: Vec<u64> = self.func_starts.iter().copied().collect();
        starts.sort_unstable();
        self.an.functions.reserve(starts.len());
        let mut done = 0usize;
        for &s in &starts {
            done += 1;
            if (done & 255) == 0 {
                if self.stop_requested() {
                    return;
                }
                self.progress(60 + (25 * done / starts.len().max(1)) as i32);
            }
            if (self.an.flags_at(s) & FL_CODE) == 0 {
                continue;
            }
            let mut f = Function {
                start: s,
                end: s,
                insns: 0,
                name: String::new(),
                thunk: false,
                thunk_target: 0,
            };
            let mut stack = vec![s];
            let mut seen = HashSet::new();
            while let Some(mut a) = stack.pop() {
                if seen.len() >= 200_000 {
                    break;
                }
                loop {
                    if seen.contains(&a)
                        || (self.an.flags_at(a) & FL_CODE) == 0
                        || (a != s && self.func_starts.contains(&a))
                    {
                        break;
                    }
                    let Ok(insn) = decode_at(self.b, a) else {
                        break;
                    };
                    seen.insert(a);
                    f.insns += 1;
                    f.end = f.end.max(insn.next());
                    let mut stop = false;
                    match insn.flow {
                        Flow::Jump => {
                            if let Some(t) = insn.target {
                                stack.push(t);
                            } else if let Some(tbl) = self.an.tables.get(&a) {
                                for &t in &tbl.targets {
                                    stack.push(t);
                                }
                            }
                            stop = true;
                        }
                        Flow::Cond => {
                            if let Some(t) = insn.target {
                                stack.push(t);
                            }
                        }
                        Flow::Call => {
                            stop = self.an.noret_calls.contains(&a);
                        }
                        Flow::Ret | Flow::Stop => stop = true,
                        Flow::Normal => {}
                    }
                    if stop {
                        break;
                    }
                    a = insn.next();
                }
            }

            let mut fa = s;
            let mut first = decode_at(self.b, fa).ok();
            if let Some(ref insn) = first {
                if insn.is_endbr() {
                    fa = insn.next();
                    first = decode_at(self.b, fa).ok();
                }
            }
            if let Some(ref insn) = first {
                if insn.flow == Flow::Jump && f.insns <= 2 {
                    if insn.indirect {
                        if let Some(m) = insn.mem {
                            let imp = self.import_of_slot(m);
                            if imp >= 0 {
                                f.thunk = true;
                                f.thunk_target = m;
                                self.an.thunk_import.insert(s, imp as u32);
                            }
                        }
                    } else if let Some(t) = insn.target {
                        if t != s {
                            f.thunk = true;
                            f.thunk_target = t;
                        }
                    }
                }
            }

            f.name = if let Some(n) = self.sym_names.get(&s) {
                n.clone()
            } else if f.thunk {
                if let Some(&imp) = self.an.thunk_import.get(&s) {
                    let name = &self.b.imports[imp as usize].name;
                    if !name.is_empty() {
                        format!("j_{name}")
                    } else {
                        format!("sub_{s:X}")
                    }
                } else {
                    format!("j_{:X}", f.thunk_target)
                }
            } else {
                format!("sub_{s:X}")
            };

            self.an.add_flags(s, FL_FUNC);
            self.an.functions.push(f);
        }
    }

    fn scan_strings(&mut self) {
        let reffed: HashSet<u64> = self.xrefs.iter().map(|x| x.to).collect();
        for si in 0..self.b.segments.len() {
            let start = self.b.segments[si].start;
            let exec = self.b.segments[si].exec();
            let d = self.b.segments[si].data.clone();
            let mut i = 0usize;
            while i < d.len() && self.an.strings.len() < 500_000 {
                if self.an.flags[si][i] != 0 {
                    i += 1;
                    continue;
                }
                let a = start + i as u64;
                let refd = reffed.contains(&a);
                if exec && !refd {
                    i += 1;
                    continue;
                }
                let min_wide = if refd { 3usize } else { 5 };
                let min_ascii = if refd { 2usize } else { 5 };

                let mut wl = 0usize;
                while i + wl * 2 + 1 < d.len()
                    && is_print(d[i + wl * 2])
                    && d[i + wl * 2 + 1] == 0
                    && self.an.flags[si][i + wl * 2] == 0
                    && self.an.flags[si][i + wl * 2 + 1] == 0
                {
                    wl += 1;
                }
                let wend = i + wl * 2;
                if wl >= min_wide
                    && wend + 1 < d.len()
                    && d[wend] == 0
                    && d[wend + 1] == 0
                    && self.an.flags[si][wend] == 0
                    && self.an.flags[si][wend + 1] == 0
                {
                    let text: String = (0..wl).map(|k| d[i + k * 2] as char).collect();
                    let len = (wl * 2 + 2) as u32;
                    mark_item(&mut self.an, a, len, FL_STR);
                    self.an.strings.push(FoundString {
                        addr: a,
                        len,
                        wide: true,
                        text,
                    });
                    i += wl * 2 + 2;
                    continue;
                }

                let mut n = 0usize;
                while i + n < d.len() && is_print(d[i + n]) && self.an.flags[si][i + n] == 0 {
                    n += 1;
                }
                if n >= min_ascii
                    && i + n < d.len()
                    && d[i + n] == 0
                    && self.an.flags[si][i + n] == 0
                {
                    let text = String::from_utf8_lossy(&d[i..i + n]).into_owned();
                    let len = (n + 1) as u32;
                    mark_item(&mut self.an, a, len, FL_STR);
                    self.an.strings.push(FoundString {
                        addr: a,
                        len,
                        wide: false,
                        text,
                    });
                    i += n + 1;
                    continue;
                }
                i += n.max(1);
            }
        }
        self.an.strings.sort_by_key(|s| s.addr);
    }

    fn mark_data(&mut self) {
        let mut cands: Vec<(u64, u8)> = self.data_cand.iter().map(|(&a, &s)| (a, s)).collect();
        cands.sort_unstable();
        for (addr, sz) in cands {
            if !matches!(sz, 1 | 2 | 4 | 8 | 16) {
                continue;
            }
            if range_free(&self.an, addr, u32::from(sz)) {
                mark_item(&mut self.an, addr, u32::from(sz), FL_DATA);
                self.an.data_sizes.insert(addr, sz);
            }
        }
    }

    fn run(&mut self) -> bool {
        self.mask = if self.b.is64() { !0u64 } else { 0xffff_ffff };
        self.imm_refs = matches!(self.b.format, Format::Pe | Format::Elf | Format::MachO)
            && self.b.base >= 0x10000;

        init_segments(self.b, &mut self.an);
        mark_import_slots(self.b, &mut self.an);

        for s in &self.b.symbols {
            if s.func && !s.name.is_empty() {
                self.sym_names.insert(s.addr, s.name.clone());
            }
        }
        for e in &self.b.exports {
            if e.addr != 0 && !e.name.is_empty() {
                self.sym_names.insert(e.addr, e.name.clone());
            }
        }

        self.progress(2);
        if self.b.has_entry {
            self.add_func(self.b.entry, false);
        }
        for &h in &self.b.func_hints {
            self.add_func(h, false);
        }
        for &h in &self.b.tls_callbacks {
            self.add_func(h, false);
        }
        for e in &self.b.exports {
            if e.addr != 0 {
                self.add_func(e.addr, false);
            }
        }
        self.run_work();
        if self.cancelled {
            return false;
        }
        self.progress(35);
        self.scan_reloc_ptrs();
        self.scan_data_ptrs();

        let deferred = self.deferred.clone();
        for c in deferred {
            if self.an.flags_at(c) == 0 && self.code_at(c) {
                self.add_func(c, true);
                self.run_work();
                if self.cancelled {
                    return false;
                }
            }
        }
        self.progress(45);
        self.scan_prologues();
        self.run_work();
        if self.cancelled {
            return false;
        }
        self.progress(50);
        self.sweep_gaps();
        if self.cancelled {
            return false;
        }
        self.mark_padding();
        self.progress(60);

        self.build_functions();
        if self.cancelled {
            return false;
        }
        self.progress(85);
        self.scan_strings();
        self.mark_data();
        self.progress(92);

        self.xrefs.sort_by(|x, y| {
            x.to.cmp(&y.to)
                .then(x.from.cmp(&y.from))
                .then(x.kind.cmp(&y.kind))
        });
        self.xrefs
            .dedup_by(|a, b| a.to == b.to && a.from == b.from && a.kind == b.kind);
        self.an.xto = self.xrefs.clone();
        self.an.xfrom = std::mem::take(&mut self.xrefs);
        self.an
            .xfrom
            .sort_by(|x, y| x.from.cmp(&y.from).then(x.to.cmp(&y.to)));

        let labels: Vec<u64> = self
            .an
            .xto
            .iter()
            .map(|x| x.to)
            .filter(|&t| self.an.mapped(t) && !is_tail_only(self.an.flags_at(t)))
            .collect();
        for t in labels {
            self.an.add_flags(t, FL_LABEL);
        }
        self.progress(100);
        true
    }
}
