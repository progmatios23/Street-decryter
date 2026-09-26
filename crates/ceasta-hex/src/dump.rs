//! Hex dump formatting.

use crate::style::{ascii_glyph, classify_byte, ByteClass};

#[derive(Clone, Debug)]
pub struct HexDumpOptions {
    pub width: usize,
    pub group: usize,
    pub show_ascii: bool,
    pub uppercase: bool,
    pub max_bytes: usize,
    pub addr_width: usize,
}

impl Default for HexDumpOptions {
    fn default() -> Self {
        Self {
            width: 16,
            group: 8,
            show_ascii: true,
            uppercase: true,
            max_bytes: 4096,
            addr_width: 8,
        }
    }
}

impl HexDumpOptions {
    pub fn compact() -> Self {
        Self {
            width: 8,
            group: 4,
            show_ascii: true,
            uppercase: false,
            max_bytes: 1024,
            addr_width: 8,
        }
    }

    pub fn wide() -> Self {
        Self {
            width: 32,
            group: 8,
            show_ascii: true,
            uppercase: true,
            max_bytes: 8192,
            addr_width: 16,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HexRow {
    pub addr: u64,
    pub bytes: Vec<Option<u8>>,
    pub ascii: String,
}

#[derive(Clone, Debug)]
pub struct HexLine {
    pub addr: u64,
    pub text: String,
    pub classes: Vec<ByteClass>,
}

pub fn format_byte(b: u8, uppercase: bool) -> String {
    if uppercase {
        format!("{b:02X}")
    } else {
        format!("{b:02x}")
    }
}

pub fn format_row(addr: u64, data: &[u8], opts: &HexDumpOptions) -> String {
    let mut line = format!("{:0width$X}  ", addr, width = opts.addr_width);
    let mut ascii = String::new();
    for i in 0..opts.width {
        if i > 0 && opts.group > 0 && i % opts.group == 0 {
            line.push(' ');
        }
        if i < data.len() {
            line.push_str(&format_byte(data[i], opts.uppercase));
            line.push(' ');
            ascii.push(ascii_glyph(data[i]));
        } else {
            line.push_str("   ");
            ascii.push(' ');
        }
    }
    if opts.show_ascii {
        line.push_str(" |");
        line.push_str(&ascii);
        line.push('|');
    }
    line
}

pub fn dump_bytes(base: u64, data: &[u8], opts: &HexDumpOptions) -> String {
    dump_lines(base, data, opts)
        .into_iter()
        .map(|l| l.text)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn dump_lines(base: u64, data: &[u8], opts: &HexDumpOptions) -> Vec<HexLine> {
    let width = opts.width.max(1);
    let mut lines = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        let end = (off + width).min(data.len());
        let slice = &data[off..end];
        let addr = base + off as u64;
        let mut classes = Vec::with_capacity(width);
        for i in 0..width {
            if i < slice.len() {
                classes.push(classify_byte(slice[i]));
            } else {
                classes.push(ByteClass::Empty);
            }
        }
        lines.push(HexLine {
            addr,
            text: format_row(addr, slice, opts),
            classes,
        });
        off = end;
    }
    lines
}

pub fn dump_window(base: u64, data: &[u8], start: usize, rows: usize, opts: &HexDumpOptions) -> Vec<HexLine> {
    let width = opts.width.max(1);
    let byte_start = start * width;
    if byte_start >= data.len() {
        return Vec::new();
    }
    let byte_end = (byte_start + rows * width).min(data.len());
    dump_lines(base + byte_start as u64, &data[byte_start..byte_end], opts)
}

/// Build HexRow structures (for UI painting).
pub fn rows_of(base: u64, data: &[u8], opts: &HexDumpOptions) -> Vec<HexRow> {
    let width = opts.width.max(1);
    let mut rows = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        let end = (off + width).min(data.len());
        let mut bytes = Vec::with_capacity(width);
        let mut ascii = String::new();
        for i in 0..width {
            if off + i < end {
                let b = data[off + i];
                bytes.push(Some(b));
                ascii.push(ascii_glyph(b));
            } else {
                bytes.push(None);
                ascii.push(' ');
            }
        }
        rows.push(HexRow {
            addr: base + off as u64,
            bytes,
            ascii,
        });
        off = end;
    }
    rows
}


/// Format a single address column.
pub fn format_addr(addr: u64, width: usize, uppercase: bool) -> String {
    if uppercase {
        format!("{addr:0width$X}", width = width)
    } else {
        format!("{addr:0width$x}", width = width)
    }
}

/// Split a dump string back into addresses (best-effort).
pub fn parse_dump_addrs(text: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for line in text.lines() {
        let tok = line.split_whitespace().next().unwrap_or("");
        if let Ok(a) = u64::from_str_radix(tok, 16) {
            out.push(a);
        }
    }
    out
}

/// Count differences between two equal-length buffers.
pub fn count_diffs(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).filter(|(x, y)| x != y).count()
}

/// Produce a side-by-side diff dump for two buffers.
pub fn diff_dump(base: u64, a: &[u8], b: &[u8], opts: &HexDumpOptions) -> String {
    let n = a.len().min(b.len());
    let mut out = String::new();
    let width = opts.width.max(1);
    let mut off = 0usize;
    while off < n {
        let end = (off + width).min(n);
        let aa = &a[off..end];
        let bb = &b[off..end];
        if aa != bb {
            out.push_str(&format!("A {}\n", format_row(base + off as u64, aa, opts)));
            out.push_str(&format!("B {}\n", format_row(base + off as u64, bb, opts)));
        }
        off = end;
    }
    out
}

/// Hex encode without spaces.
pub fn to_hex_string(data: &[u8], uppercase: bool) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push_str(&format_byte(b, uppercase));
    }
    s
}

/// Decode a continuous hex string (no spaces).
pub fn from_hex_string(text: &str) -> Result<Vec<u8>, String> {
    let t = text.trim();
    if t.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let slice = std::str::from_utf8(&bytes[i..i + 2]).map_err(|e| e.to_string())?;
        out.push(u8::from_str_radix(slice, 16).map_err(|e| e.to_string())?);
        i += 2;
    }
    Ok(out)
}

// --- generated width helpers ---

pub fn dump_width_1(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 1,
        group: 1,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_2(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 2,
        group: 1,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_3(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 3,
        group: 1,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_4(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 4,
        group: 2,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_5(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 5,
        group: 2,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_6(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 6,
        group: 3,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_7(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 7,
        group: 3,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_8(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 8,
        group: 4,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_9(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 9,
        group: 4,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_10(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 10,
        group: 5,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_11(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 11,
        group: 5,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_12(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 12,
        group: 6,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_13(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 13,
        group: 6,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_14(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 14,
        group: 7,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_15(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 15,
        group: 7,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_16(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 16,
        group: 8,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_17(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 17,
        group: 8,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_18(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 18,
        group: 9,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_19(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 19,
        group: 9,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_20(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 20,
        group: 10,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_21(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 21,
        group: 10,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_22(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 22,
        group: 11,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_23(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 23,
        group: 11,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_24(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 24,
        group: 12,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_25(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 25,
        group: 12,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_26(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 26,
        group: 13,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_27(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 27,
        group: 13,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_28(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 28,
        group: 14,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_29(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 29,
        group: 14,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_30(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 30,
        group: 15,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_31(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 31,
        group: 15,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_32(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 32,
        group: 16,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_33(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 33,
        group: 16,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_34(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 34,
        group: 17,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_35(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 35,
        group: 17,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_36(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 36,
        group: 18,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_37(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 37,
        group: 18,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_38(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 38,
        group: 19,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_39(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 39,
        group: 19,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_40(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 40,
        group: 20,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_41(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 41,
        group: 20,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_42(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 42,
        group: 21,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_43(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 43,
        group: 21,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_44(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 44,
        group: 22,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_45(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 45,
        group: 22,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_46(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 46,
        group: 23,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_47(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 47,
        group: 23,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_48(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 48,
        group: 24,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_49(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 49,
        group: 24,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_50(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 50,
        group: 25,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_51(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 51,
        group: 25,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_52(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 52,
        group: 26,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_53(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 53,
        group: 26,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_54(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 54,
        group: 27,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_55(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 55,
        group: 27,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_56(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 56,
        group: 28,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_57(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 57,
        group: 28,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_58(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 58,
        group: 29,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_59(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 59,
        group: 29,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_60(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 60,
        group: 30,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_61(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 61,
        group: 30,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_62(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 62,
        group: 31,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_63(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 63,
        group: 31,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}

pub fn dump_width_64(base: u64, data: &[u8], uppercase: bool) -> String {
    let opts = HexDumpOptions {
        width: 64,
        group: 32,
        show_ascii: true,
        uppercase,
        max_bytes: 4096,
        addr_width: 8,
    };
    dump_bytes(base, data, &opts)
}
