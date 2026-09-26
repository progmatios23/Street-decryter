//! Port of `src/core/fileinfo.cpp` — headers, hashes, section entropy, warnings.

use ceasta_binary::{Arch, Binary, Format, PERM_X};
use md5::{Digest as _, Md5};
use sha2::Sha256;

#[derive(Clone, Debug, Default)]
pub struct FileInfo {
    pub header: Vec<(String, String)>,
    pub warnings: Vec<String>,
    pub sections: Vec<SectionInfo>,
}

#[derive(Clone, Debug)]
pub struct SectionInfo {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub entropy: f64,
    pub perms: String,
}

pub fn collect(bin: &Binary) -> FileInfo {
    let mut out = FileInfo::default();
    out.header.push(("file".into(), bin.name.clone()));
    out.header.push(("format".into(), bin.format.as_str().into()));
    out.header.push(("arch".into(), bin.arch.as_str().into()));
    out.header.push(("kind".into(), bin.kind.clone()));
    out.header.push(("base".into(), format!("{:X}", bin.base)));
    if bin.has_entry {
        out.header
            .push(("entry".into(), format!("{:X}", bin.entry)));
    }

    let md5 = Md5::digest(&bin.file);
    let sha = Sha256::digest(&bin.file);
    out.header
        .push(("md5".into(), hex::encode(md5)));
    out.header
        .push(("sha256".into(), hex::encode(sha)));
    out.header
        .push(("size".into(), format!("{} bytes", bin.file.len())));

    match bin.format {
        Format::Pe => pe_extras(bin, &mut out),
        Format::Elf => elf_extras(bin, &mut out),
        Format::MachO => {
            out.header.push(("runtime".into(), "mach-o".into()));
        }
        Format::Raw => {
            out.warnings
                .push("raw blob: no headers, treated as code at the given base".into());
        }
    }

    if !bin.tls_callbacks.is_empty() {
        let n = bin.tls_callbacks.len();
        out.header
            .push(("tls callbacks".into(), n.to_string()));
        for (i, a) in bin.tls_callbacks.iter().enumerate() {
            out.header
                .push((format!("  tls_callback_{i}"), format!("{a:X}")));
        }
        out.warnings.push(format!(
            "{n} tls callback{}: code that runs before the entry point",
            if n == 1 { "" } else { "s" }
        ));
    }

    for note in &bin.notes {
        out.warnings.push(note.clone());
    }

    for seg in &bin.segments {
        let ent = entropy(&seg.data);
        out.sections.push(SectionInfo {
            name: seg.name.clone(),
            addr: seg.start,
            size: seg.size(),
            entropy: ent,
            perms: perms_str(seg.perms),
        });
        if ent > 7.2 && seg.size() > 0x1000 {
            out.warnings.push(format!(
                "section {} looks packed (entropy {ent:.2})",
                seg.name
            ));
        }
    }

    if bin.has_entry {
        if let Some(seg) = bin.seg_at(bin.entry) {
            if !seg.exec() {
                out.warnings.push(
                    "entry point is not in an executable section".into(),
                );
            }
        }
    }

    let _ = bin.arch; // silence on unused in match arms helpers
    out
}

fn perms_str(p: u32) -> String {
    format!(
        "{}{}{}",
        if p & 1 != 0 { "r" } else { "-" },
        if p & 2 != 0 { "w" } else { "-" },
        if p & PERM_X != 0 { "x" } else { "-" }
    )
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut e = 0.0;
    for c in counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        e -= p * p.log2();
    }
    e
}

fn pe_extras(bin: &Binary, out: &mut FileInfo) {
    out.header.push(("image".into(), "PE".into()));
    let s = &bin.security;
    out.header.push((
        "aslr".into(),
        if s.aslr { "yes" } else { "no" }.into(),
    ));
    out.header.push((
        "nx/dep".into(),
        if s.nx { "yes" } else { "no" }.into(),
    ));
    out.header.push((
        "cfg".into(),
        if s.cfg { "yes" } else { "no" }.into(),
    ));
    out.header.push((
        "high entropy va".into(),
        if s.high_entropy_va { "yes" } else { "no" }.into(),
    ));
    if !s.aslr {
        out.warnings.push("ASLR is off".into());
    }
    if !s.nx {
        out.warnings.push("NX/DEP is off".into());
    }
    if bin.arch == Arch::Arm64 {
        out.warnings
            .push("arm64 PE: listing works; decompiler/debugger still x86/x64-focused".into());
    }
}

fn elf_extras(bin: &Binary, out: &mut FileInfo) {
    out.header.push(("image".into(), "ELF".into()));
    if bin.kind.contains("shared") {
        out.header.push(("pie/so".into(), "yes".into()));
    }
}
