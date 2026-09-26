use crate::{Arch, Binary, Format, Result, Segment, PERM_R, PERM_W, PERM_X};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use goblin::elf::Elf;

pub fn load(bytes: Vec<u8>, path: String) -> Result<Binary> {
    let elf = Elf::parse(&bytes)?;
    let arch = match elf.header.e_machine {
        3 => Arch::X86,
        62 => Arch::X64,
        183 => Arch::Arm64,
        other => {
            return Err(crate::Error::Format(format!(
                "unsupported ELF machine {other}"
            )))
        }
    };

    let mut b = Binary::empty(path, Format::Elf, arch);
    b.base = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .map(|ph| ph.p_vaddr)
        .min()
        .unwrap_or(0);
    b.entry = elf.entry;
    b.has_entry = elf.entry != 0;
    b.kind = if elf.is_lib {
        "elf shared".into()
    } else {
        "elf".into()
    };

    for ph in elf.program_headers.iter().filter(|ph| ph.p_type == PT_LOAD) {
        let mut perms = 0;
        if ph.p_flags & PF_R != 0 {
            perms |= PERM_R;
        }
        if ph.p_flags & PF_W != 0 {
            perms |= PERM_W;
        }
        if ph.p_flags & PF_X != 0 {
            perms |= PERM_X;
        }
        let mut data = vec![0u8; ph.p_memsz as usize];
        let file_off = ph.p_offset as usize;
        let file_sz = ph.p_filesz as usize;
        if file_off < bytes.len() && file_sz > 0 {
            let avail = (bytes.len() - file_off).min(file_sz).min(data.len());
            data[..avail].copy_from_slice(&bytes[file_off..file_off + avail]);
        }
        b.segments.push(Segment {
            name: format!("load_{:x}", ph.p_vaddr),
            start: ph.p_vaddr,
            end: ph.p_vaddr + ph.p_memsz,
            perms,
            file_off: ph.p_offset,
            file_size: ph.p_filesz,
            data,
        });
    }
    b.segments.sort_by_key(|s| s.start);

    for lib in &elf.libraries {
        b.libs.push((*lib).to_string());
    }

    if b.has_entry {
        b.func_hints.push(b.entry);
    }

    b.file = bytes;
    Ok(b)
}
