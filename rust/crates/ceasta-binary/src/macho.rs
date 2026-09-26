use crate::{Arch, Binary, Format, Result, Segment, PERM_R, PERM_W, PERM_X};
use goblin::mach::MachO;

pub fn is_macho(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    matches!(
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        0xfeedface | 0xcefaedfe | 0xfeedfacf | 0xcffaedfe | 0xcafebabe | 0xbebafeca
    )
}

fn is_fat(bytes: &[u8]) -> bool {
    matches!(
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        0xcafebabe | 0xbebafeca
    )
}

pub fn load(bytes: Vec<u8>, path: String) -> Result<Binary> {
    if is_fat(&bytes) {
        let (start, size) = {
            let multi = goblin::mach::MultiArch::new(&bytes)
                .map_err(|e| crate::Error::Format(e.to_string()))?;
            let mut chosen: Option<(usize, usize)> = None;
            for arch in multi.iter_arches() {
                let arch = arch.map_err(|e| crate::Error::Format(e.to_string()))?;
                let off = arch.offset as usize;
                let size = arch.size as usize;
                if arch.cputype() == goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
                    chosen = Some((off, size));
                    break;
                }
                if chosen.is_none() {
                    chosen = Some((off, size));
                }
            }
            chosen.unwrap_or((0, bytes.len()))
        };
        let end = start.saturating_add(size);
        if end > bytes.len() {
            return Err(crate::Error::Format("fat mach-o slice out of range".into()));
        }
        return load_thin(bytes[start..end].to_vec(), path);
    }
    load_thin(bytes, path)
}

fn load_thin(bytes: Vec<u8>, path: String) -> Result<Binary> {
    let m = MachO::parse(&bytes, 0)?;
    let arch = match m.header.cputype() {
        goblin::mach::constants::cputype::CPU_TYPE_X86 => Arch::X86,
        goblin::mach::constants::cputype::CPU_TYPE_X86_64 => Arch::X64,
        goblin::mach::constants::cputype::CPU_TYPE_ARM64 => Arch::Arm64,
        other => {
            return Err(crate::Error::Format(format!(
                "unsupported mach-o cputype {other}"
            )))
        }
    };

    let mut b = Binary::empty(path, Format::MachO, arch);
    b.kind = match m.header.filetype {
        6 | 7 => "mach-o dylib".into(), // MH_DYLIB / MH_BUNDLE-ish
        _ => "mach-o".into(),
    };

    let mut base = u64::MAX;
    let mut segs = Vec::new();
    for seg in &m.segments {
        let name = seg.name().unwrap_or("").to_string();
        let start = seg.vmaddr;
        let end = start + seg.vmsize;
        base = base.min(start);
        let mut perms = PERM_R;
        let prot = seg.initprot as u32;
        if prot & 2 != 0 {
            perms |= PERM_W;
        }
        if prot & 4 != 0 {
            perms |= PERM_X;
        }
        segs.push((
            name,
            start,
            end,
            perms,
            seg.fileoff,
            seg.filesize,
            seg.vmsize as usize,
        ));
    }
    let entry = m.entry;
    drop(m);

    for (name, start, end, perms, fileoff, filesize, vmsize) in segs {
        let mut data = vec![0u8; vmsize];
        let off = fileoff as usize;
        let fsz = filesize as usize;
        if off < bytes.len() && fsz > 0 {
            let avail = (bytes.len() - off).min(fsz).min(data.len());
            data[..avail].copy_from_slice(&bytes[off..off + avail]);
        }
        b.segments.push(Segment {
            name,
            start,
            end,
            perms,
            file_off: fileoff,
            file_size: filesize,
            data,
        });
    }
    if base == u64::MAX {
        base = 0;
    }
    b.base = base;
    b.segments.sort_by_key(|s| s.start);

    if entry != 0 {
        b.entry = entry;
        b.has_entry = true;
        b.func_hints.push(b.entry);
    }

    b.file = bytes;
    Ok(b)
}
