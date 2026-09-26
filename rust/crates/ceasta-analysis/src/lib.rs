//! Static analysis over a `Binary` (functions, strings — growing toward C++ parity).

use ceasta_binary::Binary;
use ceasta_disasm::{decode_at, Flow};

#[derive(Clone, Debug)]
pub struct Function {
    pub start: u64,
    pub end: u64,
    pub name: String,
    pub thunk: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Analysis {
    pub functions: Vec<Function>,
    pub strings: Vec<FoundString>,
}

#[derive(Clone, Debug)]
pub struct FoundString {
    pub addr: u64,
    pub text: String,
    pub wide: bool,
}

/// Best-effort pass: seed functions from hints + entry, walk a little code, scan ASCII strings.
pub fn run(bin: &Binary) -> Analysis {
    let mut a = Analysis::default();

    let mut starts: Vec<u64> = bin.func_hints.clone();
    if bin.has_entry {
        starts.push(bin.entry);
    }
    starts.sort_unstable();
    starts.dedup();

    for &start in &starts {
        let end = walk_end(bin, start);
        let name = bin
            .symbols
            .iter()
            .find(|s| s.addr == start)
            .map(|s| s.name.clone())
            .unwrap_or_else(|| format!("sub_{start:X}"));
        a.functions.push(Function {
            start,
            end,
            name,
            thunk: false,
        });
    }

    a.strings = scan_ascii(bin, 4);
    a
}

fn walk_end(bin: &Binary, start: u64) -> u64 {
    let mut addr = start;
    for _ in 0..256 {
        let Ok(insn) = decode_at(bin, addr) else {
            break;
        };
        addr += u64::from(insn.size);
        if matches!(insn.flow, Flow::Ret | Flow::Stop) {
            break;
        }
        if insn.flow == Flow::Jump {
            break;
        }
    }
    if addr == start {
        start + 1
    } else {
        addr
    }
}

fn scan_ascii(bin: &Binary, min_len: usize) -> Vec<FoundString> {
    let mut out = Vec::new();
    for seg in &bin.segments {
        let data = &seg.data;
        let mut i = 0;
        while i < data.len() {
            if data[i].is_ascii_graphic() || data[i] == b' ' || data[i] == b'\t' {
                let begin = i;
                while i < data.len()
                    && (data[i].is_ascii_graphic() || data[i] == b' ' || data[i] == b'\t')
                {
                    i += 1;
                }
                if i - begin >= min_len && i < data.len() && data[i] == 0 {
                    let text = String::from_utf8_lossy(&data[begin..i]).into_owned();
                    out.push(FoundString {
                        addr: seg.start + begin as u64,
                        text,
                        wide: false,
                    });
                }
            }
            i += 1;
        }
        if out.len() > 10_000 {
            break;
        }
    }
    out
}
