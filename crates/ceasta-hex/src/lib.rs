//! Hex dump and view helpers for listing / hex panes.
//!
//! Pure formatting and windowing over byte slices or a [`ceasta_binary::Binary`].
//! No UI dependency — `ceasta-ui` can call these later.

mod dump;
mod edit;
mod find;
mod nav;
mod style;

pub use dump::{
    dump_bytes, dump_lines, dump_window, format_byte, format_row, HexDumpOptions, HexLine, HexRow,
};
pub use edit::{apply_patch, parse_hex_edit, HexPatch, PatchError};
pub use find::{find_hex_pattern, parse_hex_nibbles, HexNeedle};
pub use nav::{addr_of_offset, column_at, offset_of_addr, HexCaret, HexViewState};
pub use style::{ascii_glyph, classify_byte, ByteClass, HexPalette};

use ceasta_binary::Binary;

/// Read up to `len` bytes at `addr` from the image and hex-dump them.
pub fn dump_at(bin: &Binary, addr: u64, len: usize, opts: &HexDumpOptions) -> String {
    let len = len.min(opts.max_bytes);
    let mut buf = vec![0u8; len];
    let n = bin.read(addr, &mut buf);
    buf.truncate(n);
    dump_bytes(addr, &buf, opts)
}

/// Lines for a hex view page.
pub fn view_page(bin: &Binary, state: &HexViewState, opts: &HexDumpOptions) -> Vec<HexLine> {
    let mut buf = vec![0u8; state.page_bytes()];
    let n = bin.read(state.top_addr, &mut buf);
    buf.truncate(n);
    dump_lines(state.top_addr, &buf, opts)
}

/// Summarize a region: size, entropy, printable ratio.
#[derive(Clone, Debug)]
pub struct RegionStats {
    pub addr: u64,
    pub len: usize,
    pub entropy: f64,
    pub printable: f64,
    pub zeros: f64,
    pub ff: f64,
}

pub fn region_stats(bin: &Binary, addr: u64, len: usize) -> RegionStats {
    let len = len.min(1 << 20);
    let mut buf = vec![0u8; len];
    let n = bin.read(addr, &mut buf);
    buf.truncate(n);
    stats_of(&buf, addr)
}

pub fn stats_of(data: &[u8], addr: u64) -> RegionStats {
    let n = data.len().max(1) as f64;
    let mut freq = [0u64; 256];
    let mut printable = 0usize;
    let mut zeros = 0usize;
    let mut ff = 0usize;
    for &b in data {
        freq[b as usize] += 1;
        if (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r' {
            printable += 1;
        }
        if b == 0 {
            zeros += 1;
        }
        if b == 0xff {
            ff += 1;
        }
    }
    let mut entropy = 0.0;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / n;
            entropy -= p * p.log2();
        }
    }
    RegionStats {
        addr,
        len: data.len(),
        entropy,
        printable: printable as f64 / n,
        zeros: zeros as f64 / n,
        ff: ff as f64 / n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceasta_binary::{Arch, Format, Segment, PERM_R};

    #[test]
    fn dumps_toy_bytes() {
        let mut bin = Binary::empty("h.bin", Format::Raw, Arch::X64);
        bin.base = 0x1000;
        bin.segments.push(Segment {
            name: ".data".into(),
            start: 0x1000,
            end: 0x1020,
            perms: PERM_R,
            file_off: 0,
            file_size: 0x20,
            data: (0u8..0x20).collect(),
        });
        let opts = HexDumpOptions::default();
        let s = dump_at(&bin, 0x1000, 32, &opts);
        assert!(s.contains("1000"));
        assert!(s.contains("00 01 02 03"));
        let st = region_stats(&bin, 0x1000, 32);
        assert_eq!(st.len, 32);
        assert!(st.entropy > 3.0);
    }
}
