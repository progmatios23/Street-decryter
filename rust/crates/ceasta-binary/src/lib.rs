//! Image model and format loaders (PE, ELF, Mach-O, raw).

mod elf;
mod error;
mod macho;
mod pe;
mod raw;

pub use error::{Error, Result};

use std::path::Path;

/// Address size / ISA the image was built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86,
    X64,
    Arm64,
}

impl Arch {
    pub fn bits(self) -> u32 {
        match self {
            Arch::X86 => 32,
            Arch::X64 | Arch::Arm64 => 64,
        }
    }

    pub fn ptr_size(self) -> usize {
        (self.bits() / 8) as usize
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X64 => "x64",
            Arch::Arm64 => "arm64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Pe,
    Elf,
    MachO,
    Raw,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Pe => "pe",
            Format::Elf => "elf",
            Format::MachO => "mach-o",
            Format::Raw => "raw",
        }
    }
}

pub const PERM_R: u32 = 1;
pub const PERM_W: u32 = 2;
pub const PERM_X: u32 = 4;

#[derive(Clone, Debug)]
pub struct Segment {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub perms: u32,
    pub file_off: u64,
    pub file_size: u64,
    pub data: Vec<u8>,
}

impl Segment {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    pub fn exec(&self) -> bool {
        self.perms & PERM_X != 0
    }
}

#[derive(Clone, Debug, Default)]
pub struct ImportEntry {
    pub lib: String,
    pub name: String,
    pub slot: u64,
    pub delay: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ExportEntry {
    pub name: String,
    pub ordinal: u32,
    pub addr: u64,
    pub forward: String,
}

#[derive(Clone, Debug, Default)]
pub struct SymbolEntry {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub func: bool,
}

/// One loaded file — format-independent, filled by the loaders.
#[derive(Clone, Debug)]
pub struct Binary {
    pub path: String,
    pub name: String,
    pub format: Format,
    pub arch: Arch,
    pub base: u64,
    pub entry: u64,
    pub has_entry: bool,
    pub kind: String,
    pub notes: Vec<String>,
    pub libs: Vec<String>,
    pub segments: Vec<Segment>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
    pub symbols: Vec<SymbolEntry>,
    /// Extra function starts (pdata, TLS callbacks, init arrays, …).
    pub func_hints: Vec<u64>,
    /// PE TLS callbacks — run before the entry point.
    pub tls_callbacks: Vec<u64>,
    pub ptr_locs: Vec<u64>,
    pub file: Vec<u8>,
}

impl Binary {
    pub fn empty(path: impl Into<String>, format: Format, arch: Arch) -> Self {
        let path = path.into();
        let name = Path::new(&path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());
        Self {
            path,
            name,
            format,
            arch,
            base: 0,
            entry: 0,
            has_entry: false,
            kind: String::new(),
            notes: Vec::new(),
            libs: Vec::new(),
            segments: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            func_hints: Vec::new(),
            tls_callbacks: Vec::new(),
            ptr_locs: Vec::new(),
            file: Vec::new(),
        }
    }

    pub fn is64(&self) -> bool {
        self.arch != Arch::X86
    }

    pub fn is_x86_family(&self) -> bool {
        matches!(self.arch, Arch::X86 | Arch::X64)
    }

    pub fn seg_at(&self, addr: u64) -> Option<&Segment> {
        self.segments.iter().find(|s| s.contains(addr))
    }

    pub fn is_code(&self, addr: u64) -> bool {
        self.seg_at(addr).is_some_and(|s| s.exec())
    }

    pub fn is_mapped(&self, addr: u64) -> bool {
        self.seg_at(addr).is_some()
    }

    pub fn read(&self, addr: u64, out: &mut [u8]) -> usize {
        let Some(seg) = self.seg_at(addr) else {
            return 0;
        };
        let off = (addr - seg.start) as usize;
        if off >= seg.data.len() {
            return 0;
        }
        let n = out.len().min(seg.data.len() - off);
        out[..n].copy_from_slice(&seg.data[off..off + n]);
        n
    }

    pub fn read_u8(&self, addr: u64) -> Option<u8> {
        let mut b = [0u8; 1];
        (self.read(addr, &mut b) == 1).then_some(b[0])
    }

    pub fn read_u16(&self, addr: u64) -> Option<u16> {
        let mut b = [0u8; 2];
        (self.read(addr, &mut b) == 2).then_some(u16::from_le_bytes(b))
    }

    pub fn read_u32(&self, addr: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        (self.read(addr, &mut b) == 4).then_some(u32::from_le_bytes(b))
    }

    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        (self.read(addr, &mut b) == 8).then_some(u64::from_le_bytes(b))
    }

    pub fn read_ptr(&self, addr: u64) -> Option<u64> {
        if self.is64() {
            self.read_u64(addr)
        } else {
            self.read_u32(addr).map(u64::from)
        }
    }
}

/// Detect format and load from a path.
pub fn open(path: impl AsRef<Path>) -> Result<Binary> {
    let path = path.as_ref();
    let bytes = std::fs::read(path).map_err(|e| Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    from_bytes(bytes, path.display().to_string())
}

pub fn from_bytes(bytes: Vec<u8>, path: impl Into<String>) -> Result<Binary> {
    let path = path.into();
    if bytes.len() >= 2 && bytes[0] == 0x4d && bytes[1] == 0x5a {
        return pe::load(bytes, path);
    }
    if bytes.len() >= 4 && bytes[0] == 0x7f && &bytes[1..4] == b"ELF" {
        return elf::load(bytes, path);
    }
    if macho::is_macho(&bytes) {
        return macho::load(bytes, path);
    }
    Ok(raw::load(bytes, path, 0, Arch::X64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_roundtrip_read() {
        let mut b = Binary::empty("blob.bin", Format::Raw, Arch::X64);
        b.base = 0x1000;
        b.segments.push(Segment {
            name: ".text".into(),
            start: 0x1000,
            end: 0x1010,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: 16,
            data: (0..16).collect(),
        });
        assert_eq!(b.read_u8(0x1004), Some(4));
        assert!(b.is_code(0x1000));
    }
}
