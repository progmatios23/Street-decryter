//! Hex edit / patch helpers.

use std::fmt;

#[derive(Clone, Debug)]
pub struct HexPatch {
    pub addr: u64,
    pub old: Vec<u8>,
    pub new: Vec<u8>,
}

impl HexPatch {
    pub fn len(&self) -> usize {
        self.new.len()
    }

    pub fn is_empty(&self) -> bool {
        self.new.is_empty()
    }
}

#[derive(Debug)]
pub enum PatchError {
    Msg(String),
    LengthMismatch,
    Unmapped,
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatchError::Msg(s) => write!(f, "{s}"),
            PatchError::LengthMismatch => write!(f, "patch length mismatch"),
            PatchError::Unmapped => write!(f, "unmapped address"),
        }
    }
}

impl std::error::Error for PatchError {}

/// Parse a string like `"90 90 ?? CC"` into concrete bytes (wildcards become 0 with mask).
pub fn parse_hex_edit(text: &str) -> Result<(Vec<u8>, Vec<bool>), String> {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    for tok in text.split_whitespace() {
        if tok == "?" || tok == "??" {
            bytes.push(0);
            mask.push(false);
            continue;
        }
        if tok.len() != 2 {
            return Err(format!("bad hex: {tok}"));
        }
        let v = u8::from_str_radix(tok, 16).map_err(|_| format!("bad hex: {tok}"))?;
        bytes.push(v);
        mask.push(true);
    }
    Ok((bytes, mask))
}

/// Apply a patch into a mutable buffer that starts at `base`.
pub fn apply_patch(buf: &mut [u8], base: u64, patch: &HexPatch) -> Result<(), PatchError> {
    if patch.addr < base {
        return Err(PatchError::Unmapped);
    }
    let off = (patch.addr - base) as usize;
    if off + patch.new.len() > buf.len() {
        return Err(PatchError::Unmapped);
    }
    if !patch.old.is_empty() && patch.old.len() == patch.new.len() {
        if buf[off..off + patch.old.len()] != patch.old[..] {
            return Err(PatchError::Msg("bytes changed under patch".into()));
        }
    }
    buf[off..off + patch.new.len()].copy_from_slice(&patch.new);
    Ok(())
}

/// Build a patch from current bytes and an edit string.
pub fn patch_from_edit(addr: u64, current: &[u8], edit: &str) -> Result<HexPatch, String> {
    let (new, mask) = parse_hex_edit(edit)?;
    if new.len() > current.len() {
        return Err("edit longer than current window".into());
    }
    let mut out = current[..new.len()].to_vec();
    for (i, m) in mask.iter().enumerate() {
        if *m {
            out[i] = new[i];
        }
    }
    Ok(HexPatch {
        addr,
        old: current[..new.len()].to_vec(),
        new: out,
    })
}

/// Invert a patch for undo.
pub fn invert_patch(p: &HexPatch) -> HexPatch {
    HexPatch {
        addr: p.addr,
        old: p.new.clone(),
        new: p.old.clone(),
    }
}

/// Format patch as a unified-ish hex hunk.
pub fn format_patch(p: &HexPatch) -> String {
    let mut s = format!("@@ {:X} @@\n", p.addr);
    s.push_str("- ");
    for (i, b) in p.old.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s.push_str("\n+ ");
    for (i, b) in p.new.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s.push('\n');
    s
}
