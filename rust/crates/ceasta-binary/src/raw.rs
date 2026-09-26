use crate::{Arch, Binary, Format, Segment, PERM_R, PERM_X};

pub fn load(bytes: Vec<u8>, path: String, base: u64, arch: Arch) -> Binary {
    let len = bytes.len() as u64;
    let mut b = Binary::empty(path, Format::Raw, arch);
    b.base = base;
    b.entry = base;
    b.has_entry = !bytes.is_empty();
    b.kind = "raw".into();
    b.segments.push(Segment {
        name: ".text".into(),
        start: base,
        end: base + len,
        perms: PERM_R | PERM_X,
        file_off: 0,
        file_size: len,
        data: bytes.clone(),
    });
    b.file = bytes;
    if b.has_entry {
        b.func_hints.push(base);
    }
    b
}
