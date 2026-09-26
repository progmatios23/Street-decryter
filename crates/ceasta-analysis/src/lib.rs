//! Static analysis over a `Binary` — functions, xrefs, strings, flags.
//!
//! Port of `src/core/analysis.{h,cpp}` for x86/x64 (ARM64 waits on the decoder).

mod flags;
mod noreturn;
mod worker;

pub use flags::{
    FL_CODE, FL_DATA, FL_FUNC, FL_LABEL, FL_STR, FL_TAIL,
};
pub use noreturn::is_noreturn_name;

use ceasta_binary::Binary;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Kind of cross-reference (matches C++ `xref_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum XrefKind {
    Call,
    Jump,
    Read,
    Write,
    Offset,
}

impl XrefKind {
    pub fn as_str(self) -> &'static str {
        match self {
            XrefKind::Call => "call",
            XrefKind::Jump => "jump",
            XrefKind::Read => "read",
            XrefKind::Write => "write",
            XrefKind::Offset => "offset",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub start: u64,
    /// One past the highest instruction byte.
    pub end: u64,
    pub insns: u32,
    pub name: String,
    pub thunk: bool,
    pub thunk_target: u64,
}

#[derive(Clone, Debug)]
pub struct FoundString {
    pub addr: u64,
    /// Bytes including the terminator.
    pub len: u32,
    pub wide: bool,
    pub text: String,
}

#[derive(Clone, Debug)]
pub struct JumpTable {
    pub jmp: u64,
    pub table: u64,
    pub entry_size: u32,
    pub entries: u32,
    pub targets: Vec<u64>,
    pub cases: Vec<u64>,
}

/// Progress callback surface (optional; mirrors C++ `analysis_progress`).
#[derive(Debug, Default)]
pub struct AnalysisProgress {
    pub percent: std::sync::atomic::AtomicI32,
    pub cancel: std::sync::atomic::AtomicBool,
}

impl AnalysisProgress {
    pub fn set_percent(&self, pct: i32) {
        self.percent
            .store(pct, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Full analysis result for one image.
#[derive(Clone, Debug, Default)]
pub struct Analysis {
    /// Parallel to `flags` — start VA of each segment row.
    pub seg_start: Vec<u64>,
    /// One flag byte per mapped byte (IDA-style).
    pub flags: Vec<Vec<u8>>,
    /// Sorted by start. Also exposed as [`Analysis::functions`] alias field name.
    pub functions: Vec<Function>,
    /// Sorted by `(to, from, kind)`.
    pub xto: Vec<Xref>,
    /// Sorted by `(from, to)`.
    pub xfrom: Vec<Xref>,
    /// Sorted by addr.
    pub strings: Vec<FoundString>,
    pub data_sizes: HashMap<u64, u8>,
    /// Import slot VA → index in `Binary::imports`.
    pub slot_import: HashMap<u64, u32>,
    /// Thunk function start → import index.
    pub thunk_import: HashMap<u64, u32>,
    pub tables: BTreeMap<u64, JumpTable>,
    pub noret_calls: HashSet<u64>,
    pub insn_count: u64,
}

impl Analysis {
    pub fn flags_at(&self, a: u64) -> u8 {
        match self.seg_index(a) {
            Some(i) => {
                let off = (a - self.seg_start[i]) as usize;
                self.flags[i][off]
            }
            None => 0,
        }
    }

    pub fn add_flags(&mut self, a: u64, f: u8) {
        if let Some(i) = self.seg_index(a) {
            let off = (a - self.seg_start[i]) as usize;
            self.flags[i][off] |= f;
        }
    }

    pub fn clear_flags(&mut self, a: u64, f: u8) {
        if let Some(i) = self.seg_index(a) {
            let off = (a - self.seg_start[i]) as usize;
            self.flags[i][off] &= !f;
        }
    }

    pub fn mapped(&self, a: u64) -> bool {
        self.seg_index(a).is_some()
    }

    pub fn seg_index(&self, a: u64) -> Option<usize> {
        if self.seg_start.is_empty() {
            return None;
        }
        let i = match self.seg_start.binary_search(&a) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let off = a - self.seg_start[i];
        if off >= self.flags[i].len() as u64 {
            None
        } else {
            Some(i)
        }
    }

    pub fn item_size(&self, a: u64) -> u32 {
        let Some(i) = self.seg_index(a) else {
            return 1;
        };
        let f = &self.flags[i];
        let off = (a - self.seg_start[i]) as usize;
        let mut n = 1usize;
        while off + n < f.len() && is_tail_only(f[off + n]) && n < 0x10000 {
            n += 1;
        }
        n as u32
    }

    pub fn item_head(&self, a: u64) -> u64 {
        let mut h = a;
        for _ in 0..0x10000 {
            if !is_tail_only(self.flags_at(h)) || h == 0 {
                break;
            }
            h -= 1;
        }
        if is_tail_only(self.flags_at(h)) {
            a
        } else {
            h
        }
    }

    pub fn func_at(&self, start: u64) -> Option<&Function> {
        self.functions
            .binary_search_by_key(&start, |f| f.start)
            .ok()
            .map(|i| &self.functions[i])
    }

    pub fn func_containing(&self, a: u64) -> Option<&Function> {
        let i = match self.functions.binary_search_by_key(&a, |f| f.start) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        // A function with a chunk after another one can still contain `a`; look back a bit.
        let start = i.saturating_sub(31);
        for f in self.functions[start..=i].iter().rev() {
            if a >= f.start && a < f.end {
                return Some(f);
            }
        }
        None
    }

    pub fn refs_to(&self, a: u64) -> &[Xref] {
        let start = self.xto.partition_point(|x| x.to < a);
        let end = start + self.xto[start..].partition_point(|x| x.to == a);
        &self.xto[start..end]
    }

    pub fn refs_from(&self, a: u64) -> &[Xref] {
        let start = self.xfrom.partition_point(|x| x.from < a);
        let end = start + self.xfrom[start..].partition_point(|x| x.from == a);
        &self.xfrom[start..end]
    }

    pub fn string_at(&self, a: u64) -> Option<&FoundString> {
        self.strings
            .binary_search_by_key(&a, |s| s.addr)
            .ok()
            .map(|i| &self.strings[i])
    }
}

fn is_tail_only(f: u8) -> bool {
    (f & FL_TAIL) != 0 && (f & (FL_CODE | FL_STR | FL_DATA)) == 0
}

/// Runs the full analysis pass. Returns `false` if cancelled via `progress`.
pub fn analyze(bin: &Binary, progress: Option<&AnalysisProgress>) -> Option<Analysis> {
    worker::run(bin, progress)
}

/// Convenience: always succeeds (empty analysis on cancel / unsupported arch).
pub fn run(bin: &Binary) -> Analysis {
    analyze(bin, None).unwrap_or_default()
}

// --- CFG (thin) ------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeKind {
    Next,
    Taken,
    NotTaken,
    Jump,
    Table,
}

impl EdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Next => "next",
            EdgeKind::Taken => "taken",
            EdgeKind::NotTaken => "not_taken",
            EdgeKind::Jump => "jump",
            EdgeKind::Table => "table",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CfgEdge {
    pub to: u32,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug)]
pub struct CfgBlock {
    pub start: u64,
    pub end: u64,
    pub insn_addrs: Vec<u64>,
    pub succ: Vec<CfgEdge>,
}

#[derive(Clone, Debug, Default)]
pub struct Cfg {
    pub blocks: Vec<CfgBlock>,
    pub truncated: bool,
}

/// Build a thin CFG for the function containing `start`.
pub fn build_cfg(bin: &Binary, an: &Analysis, start: u64) -> Option<Cfg> {
    use ceasta_disasm::{decode_at, Flow};

    let f = an.func_containing(start)?;
    let mut leaders = vec![f.start];
    let mut addr = f.start;
    let mut n = 0usize;
    while addr < f.end && n < 512 {
        let Ok(insn) = decode_at(bin, addr) else {
            break;
        };
        let next = insn.next();
        match insn.flow {
            Flow::Cond => {
                if let Some(t) = insn.target {
                    if t >= f.start && t < f.end {
                        leaders.push(t);
                    }
                }
                if next < f.end {
                    leaders.push(next);
                }
            }
            Flow::Jump => {
                if let Some(t) = insn.target {
                    if t >= f.start && t < f.end {
                        leaders.push(t);
                    }
                }
            }
            _ => {}
        }
        addr = next;
        n += 1;
    }
    leaders.sort_unstable();
    leaders.dedup();
    let truncated = n >= 512;

    let mut blocks: Vec<CfgBlock> = leaders
        .iter()
        .enumerate()
        .map(|(i, &s)| {
            let end = leaders.get(i + 1).copied().unwrap_or(f.end);
            CfgBlock {
                start: s,
                end,
                insn_addrs: Vec::new(),
                succ: Vec::new(),
            }
        })
        .collect();

    for blk in &mut blocks {
        let mut a = blk.start;
        while a < blk.end {
            let Ok(insn) = decode_at(bin, a) else {
                break;
            };
            blk.insn_addrs.push(a);
            match insn.flow {
                Flow::Cond | Flow::Jump | Flow::Ret | Flow::Stop => break,
                _ if insn.next() >= blk.end => break,
                _ => a = insn.next(),
            }
        }
        if blk.insn_addrs.is_empty() {
            blk.end = blk.start;
        } else if let Ok(last) = decode_at(bin, *blk.insn_addrs.last().unwrap()) {
            blk.end = last.next();
        }
    }

    let starts: Vec<u64> = blocks.iter().map(|b| b.start).collect();
    let find = |t: u64| -> Option<u32> {
        starts.iter().position(|&s| s == t).map(|i| i as u32)
    };

    for i in 0..blocks.len() {
        let Some(&last_addr) = blocks[i].insn_addrs.last() else {
            continue;
        };
        let Ok(insn) = decode_at(bin, last_addr) else {
            continue;
        };
        let fall = insn.next();
        match insn.flow {
            Flow::Cond => {
                if let Some(t) = insn.target {
                    if let Some(ti) = find(t) {
                        blocks[i].succ.push(CfgEdge {
                            to: ti,
                            kind: EdgeKind::Taken,
                        });
                    }
                }
                if let Some(ti) = find(fall) {
                    blocks[i].succ.push(CfgEdge {
                        to: ti,
                        kind: EdgeKind::NotTaken,
                    });
                }
            }
            Flow::Jump => {
                if let Some(t) = insn.target {
                    if let Some(ti) = find(t) {
                        blocks[i].succ.push(CfgEdge {
                            to: ti,
                            kind: EdgeKind::Jump,
                        });
                    }
                }
            }
            Flow::Ret | Flow::Stop => {}
            _ => {
                if let Some(ti) = find(fall) {
                    blocks[i].succ.push(CfgEdge {
                        to: ti,
                        kind: EdgeKind::Next,
                    });
                }
            }
        }
    }

    Some(Cfg { blocks, truncated })
}

// --- byte search -----------------------------------------------------------

/// Byte-pattern search. Pattern like `"48 8b ?? 05"` (`??` / `?` wildcards).
pub fn find_bytes(bin: &Binary, pattern: &str, max: usize) -> Result<Vec<u64>, String> {
    let needles = parse_pattern(pattern)?;
    if needles.is_empty() {
        return Err("empty pattern".into());
    }
    let mut hits = Vec::new();
    for seg in &bin.segments {
        let data = &seg.data;
        if data.len() < needles.len() {
            continue;
        }
        for i in 0..=data.len() - needles.len() {
            if pattern_matches(&data[i..], &needles) {
                hits.push(seg.start + i as u64);
                if hits.len() >= max {
                    return Ok(hits);
                }
            }
        }
    }
    Ok(hits)
}

fn parse_pattern(pattern: &str) -> Result<Vec<Option<u8>>, String> {
    let mut out = Vec::new();
    for tok in pattern.split_whitespace() {
        if tok == "?" || tok == "??" {
            out.push(None);
            continue;
        }
        if tok.len() != 2 {
            return Err(format!("bad pattern byte: {tok}"));
        }
        let v = u8::from_str_radix(tok, 16).map_err(|_| format!("bad pattern byte: {tok}"))?;
        out.push(Some(v));
    }
    Ok(out)
}

fn pattern_matches(data: &[u8], pat: &[Option<u8>]) -> bool {
    pat.iter()
        .enumerate()
        .all(|(i, b)| b.map(|x| data[i] == x).unwrap_or(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceasta_binary::{Arch, Format, ImportEntry, Segment, PERM_R, PERM_X};

    fn toy_call_chain() -> Binary {
        // 1000: e8 05 00 00 00   call 100A
        // 1005: c3               ret
        // 1006: 90 90 90 90      nops (padding)
        // 100A: 48 83 ec 28      sub rsp, 0x28   (prologue-ish)
        // 100E: c3               ret
        let bytes = vec![
            0xe8, 0x05, 0x00, 0x00, 0x00, // call +5 -> 0x100A
            0xc3, // ret
            0x90, 0x90, 0x90, 0x90, // pad
            0x48, 0x83, 0xec, 0x28, // sub rsp, 28h
            0xc3, // ret
        ];
        let mut bin = Binary::empty("toy.bin", Format::Raw, Arch::X64);
        bin.base = 0x1000;
        bin.entry = 0x1000;
        bin.has_entry = true;
        bin.segments.push(Segment {
            name: ".text".into(),
            start: 0x1000,
            end: 0x1000 + bytes.len() as u64,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: bytes.len() as u64,
            data: bytes,
        });
        bin
    }

    #[test]
    fn discovers_callee_via_call_xref() {
        let bin = toy_call_chain();
        let a = run(&bin);
        assert!(a.func_at(0x1000).is_some());
        assert!(a.func_at(0x100A).is_some());
        let refs = a.refs_from(0x1000);
        assert!(refs.iter().any(|x| x.to == 0x100A && x.kind == XrefKind::Call));
        assert!((a.flags_at(0x1000) & FL_CODE) != 0);
        assert!((a.flags_at(0x1000) & FL_FUNC) != 0);
    }

    #[test]
    fn scans_ascii_and_utf16_strings() {
        // Unreferenced strings need len >= 5 (C++ parity).
        let mut data = b"\0\0\0\0hello\0".to_vec();
        data.extend_from_slice(&[b'w', 0, b'o', 0, b'r', 0, b'l', 0, b'd', 0, 0, 0]);
        let mut bin = Binary::empty("str.bin", Format::Raw, Arch::X64);
        bin.base = 0x2000;
        bin.segments.push(Segment {
            name: ".rdata".into(),
            start: 0x2000,
            end: 0x2000 + data.len() as u64,
            perms: PERM_R,
            file_off: 0,
            file_size: data.len() as u64,
            data,
        });
        // Need an executable seed so analysis initializes; empty exec segment + entry.
        bin.segments.insert(
            0,
            Segment {
                name: ".text".into(),
                start: 0x1000,
                end: 0x1001,
                perms: PERM_R | PERM_X,
                file_off: 0,
                file_size: 1,
                data: vec![0xc3],
            },
        );
        bin.entry = 0x1000;
        bin.has_entry = true;

        let a = run(&bin);
        let found: Vec<_> = a
            .strings
            .iter()
            .map(|s| format!("{}:{:?}", if s.wide { "w" } else { "a" }, s.text))
            .collect();
        assert!(
            a.strings.iter().any(|s| !s.wide && s.text == "hello"),
            "missing ascii hello in {found:?}"
        );
        assert!(
            a.strings.iter().any(|s| s.wide && s.text == "world"),
            "missing utf16 world in {found:?}"
        );
    }

    #[test]
    fn thunk_to_import_slot() {
        // jmp [rip+0] then 8-byte slot filled with a placeholder
        // ff 25 00 00 00 00   jmp qword ptr [rip]
        // <8 bytes slot at 1006>
        let mut bytes = vec![0xff, 0x25, 0x00, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(&0u64.to_le_bytes());
        let mut bin = Binary::empty("thunk.bin", Format::Pe, Arch::X64);
        bin.base = 0x1000;
        bin.entry = 0x1000;
        bin.has_entry = true;
        bin.imports.push(ImportEntry {
            lib: "k".into(),
            name: "ExitProcess".into(),
            slot: 0x1006,
            delay: false,
        });
        bin.segments.push(Segment {
            name: ".text".into(),
            start: 0x1000,
            end: 0x1000 + bytes.len() as u64,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: bytes.len() as u64,
            data: bytes,
        });
        let a = run(&bin);
        let f = a.func_at(0x1000).expect("thunk func");
        assert!(f.thunk);
        assert_eq!(f.thunk_target, 0x1006);
        assert!(a.thunk_import.contains_key(&0x1000));
        assert!(a.slot_import.contains_key(&0x1006));
    }

    #[test]
    fn seeds_tls_and_exports() {
        let mut bin = Binary::empty("tls.bin", Format::Pe, Arch::X64);
        bin.base = 0x1000;
        bin.has_entry = true;
        bin.entry = 0x1000;
        // entry ret; tls callback at 1010: ret; export at 1020: ret
        let mut data = vec![0xc3];
        data.resize(0x20, 0x90);
        data[0x10] = 0xc3;
        data[0x20 - 1] = 0xc3; // won't use
        // make sure 0x1010 and 0x1020 exist
        data.resize(0x21, 0x90);
        data[0x10] = 0xc3;
        data[0x20] = 0xc3;
        bin.segments.push(Segment {
            name: ".text".into(),
            start: 0x1000,
            end: 0x1000 + data.len() as u64,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: data.len() as u64,
            data,
        });
        bin.tls_callbacks.push(0x1010);
        bin.func_hints.push(0x1010);
        bin.exports.push(ceasta_binary::ExportEntry {
            name: "Exp".into(),
            ordinal: 1,
            addr: 0x1020,
            forward: String::new(),
        });
        let a = run(&bin);
        assert!(a.func_at(0x1000).is_some());
        assert!(a.func_at(0x1010).is_some());
        assert!(a.func_at(0x1020).is_some());
        assert_eq!(a.func_at(0x1020).unwrap().name, "Exp");
    }
}
