//! PE loader — goblin for the image, hand-rolled TLS directory for callbacks.

use crate::{
    Arch, Binary, Error, ExportEntry, Format, ImportEntry, Result, Segment, SymbolEntry, PERM_R,
    PERM_W, PERM_X,
};
use goblin::pe::characteristic::{IMAGE_FILE_DLL, IMAGE_FILE_EXECUTABLE_IMAGE};
use goblin::pe::data_directories::DataDirectory;
use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
use goblin::pe::PE;

pub fn load(bytes: Vec<u8>, path: String) -> Result<Binary> {
    let pe = PE::parse(&bytes)?;
    let arch = match pe.header.coff_header.machine {
        0x014c => Arch::X86,
        0x8664 => Arch::X64,
        0xaa64 => Arch::Arm64,
        other => {
            return Err(Error::Format(format!(
                "unsupported PE machine 0x{other:x}"
            )))
        }
    };

    let mut b = Binary::empty(path, Format::Pe, arch);
    b.base = pe.image_base as u64;
    b.entry = pe.image_base as u64 + pe.entry as u64;
    b.has_entry = pe.entry != 0;

    let chars = pe.header.coff_header.characteristics;
    b.kind = if chars & IMAGE_FILE_DLL != 0 {
        "dll".into()
    } else if chars & IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
        "exe".into()
    } else {
        "pe".into()
    };

    for sec in &pe.sections {
        let name = sec
            .name()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| String::new());
        let start = b.base + sec.virtual_address as u64;
        let vsize = sec.virtual_size.max(sec.size_of_raw_data) as u64;
        let end = start + vsize;
        let mut perms = 0;
        if sec.characteristics & IMAGE_SCN_MEM_READ != 0 {
            perms |= PERM_R;
        }
        if sec.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            perms |= PERM_W;
        }
        if sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            perms |= PERM_X;
        }
        let mut data = vec![0u8; vsize as usize];
        let raw_off = sec.pointer_to_raw_data as usize;
        let raw_sz = sec.size_of_raw_data as usize;
        if raw_off < bytes.len() && raw_sz > 0 {
            let avail = (bytes.len() - raw_off).min(raw_sz).min(data.len());
            data[..avail].copy_from_slice(&bytes[raw_off..raw_off + avail]);
        }
        b.segments.push(Segment {
            name,
            start,
            end,
            perms,
            file_off: sec.pointer_to_raw_data as u64,
            file_size: sec.size_of_raw_data as u64,
            data,
        });
    }
    b.segments.sort_by_key(|s| s.start);

    for import in &pe.imports {
        b.imports.push(ImportEntry {
            lib: import.dll.to_string(),
            name: import.name.to_string(),
            slot: b.base + import.rva as u64,
            delay: false,
        });
        if !b.libs.iter().any(|l| l.eq_ignore_ascii_case(import.dll)) {
            b.libs.push(import.dll.to_string());
        }
    }

    for export in &pe.exports {
        let name = export.name.unwrap_or("").to_string();
        let addr = if export.rva != 0 {
            b.base + export.rva as u64
        } else {
            0
        };
        b.exports.push(ExportEntry {
            name: name.clone(),
            ordinal: 0,
            addr,
            forward: String::new(),
        });
        if addr != 0 && !name.is_empty() {
            b.symbols.push(SymbolEntry {
                name,
                addr,
                size: 0,
                func: true,
            });
            b.func_hints.push(addr);
        }
    }

    // TLS directory is data directory index 9 — goblin 0.8 does not expose callbacks.
    if let Some(opt) = pe.header.optional_header.as_ref() {
        if let Some(dir) = opt.data_directories.get_tls_table() {
            parse_tls(&mut b, &bytes, dir, &pe)?;
        }
    }

    if b.has_entry {
        b.func_hints.push(b.entry);
    }

    b.file = bytes;
    Ok(b)
}

fn parse_tls(b: &mut Binary, file: &[u8], dir: &DataDirectory, pe: &PE<'_>) -> Result<()> {
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(());
    }
    let off = rva_to_off(pe, dir.virtual_address as usize).ok_or_else(|| {
        Error::Format(format!(
            "tls directory rva {:#x} not in a section",
            dir.virtual_address
        ))
    })?;
    let list_va = if b.is64() {
        if off + 32 > file.len() {
            return Ok(());
        }
        u64::from_le_bytes(file[off + 24..off + 32].try_into().unwrap())
    } else {
        if off + 16 > file.len() {
            return Ok(());
        }
        u32::from_le_bytes(file[off + 12..off + 16].try_into().unwrap()) as u64
    };
    if list_va == 0 {
        return Ok(());
    }

    let ptr = b.arch.ptr_size();
    for k in 0..64u64 {
        let slot_va = list_va + k * ptr as u64;
        let Some(slot_off) = va_to_off(pe, b.base, slot_va) else {
            break;
        };
        if slot_off + ptr > file.len() {
            break;
        }
        let cb = if b.is64() {
            u64::from_le_bytes(file[slot_off..slot_off + 8].try_into().unwrap())
        } else {
            u32::from_le_bytes(file[slot_off..slot_off + 4].try_into().unwrap()) as u64
        };
        if cb == 0 {
            break;
        }
        let va = if cb < b.base { b.base + cb } else { cb };
        b.tls_callbacks.push(va);
        b.func_hints.push(va);
        b.symbols.push(SymbolEntry {
            name: format!("tls_callback_{k}"),
            addr: va,
            size: 0,
            func: true,
        });
    }
    if !b.tls_callbacks.is_empty() {
        let n = b.tls_callbacks.len();
        b.notes.push(format!(
            "{n} tls callback{} (run before the entry point)",
            if n == 1 { "" } else { "s" }
        ));
    }
    Ok(())
}

fn rva_to_off(pe: &PE<'_>, rva: usize) -> Option<usize> {
    for sec in &pe.sections {
        let start = sec.virtual_address as usize;
        let size = sec.virtual_size.max(sec.size_of_raw_data) as usize;
        if rva >= start && rva < start + size {
            return Some(sec.pointer_to_raw_data as usize + (rva - start));
        }
    }
    None
}

fn va_to_off(pe: &PE<'_>, image_base: u64, va: u64) -> Option<usize> {
    if va < image_base {
        return None;
    }
    rva_to_off(pe, (va - image_base) as usize)
}
