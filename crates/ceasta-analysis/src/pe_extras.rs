//! PE-oriented analysis hints that sit on top of [`ceasta_binary::Binary`].
//!
//! Extracts triage notes for TLS callbacks, delay-load imports, security flags,
//! section layout, export forwarders, and common packer/compiler fingerprints.
//! Does not replace the PE loader — it only annotates what is already loaded.

use ceasta_binary::{Binary, Format, ImportEntry, PERM_R, PERM_W, PERM_X};
use std::collections::{BTreeMap, BTreeSet};

/// One actionable hint for the UI / scripts.
#[derive(Clone, Debug)]
pub struct PeHint {
    pub kind: PeHintKind,
    pub addr: Option<u64>,
    pub title: String,
    pub detail: String,
    pub severity: Severity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeHintKind {
    TlsCallback,
    DelayImport,
    Security,
    Section,
    Export,
    Import,
    Entry,
    Packer,
    Debug,
    Exception,
    Reloc,
    Resource,
    Other,
}

impl PeHintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PeHintKind::TlsCallback => "tls",
            PeHintKind::DelayImport => "delay_import",
            PeHintKind::Security => "security",
            PeHintKind::Section => "section",
            PeHintKind::Export => "export",
            PeHintKind::Import => "import",
            PeHintKind::Entry => "entry",
            PeHintKind::Packer => "packer",
            PeHintKind::Debug => "debug",
            PeHintKind::Exception => "exception",
            PeHintKind::Reloc => "reloc",
            PeHintKind::Resource => "resource",
            PeHintKind::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Note,
    Warn,
    Alert,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Note => "note",
            Severity::Warn => "warn",
            Severity::Alert => "alert",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PeExtras {
    pub hints: Vec<PeHint>,
    pub tls_callbacks: Vec<u64>,
    pub delay_imports: Vec<ImportEntry>,
    pub section_summary: Vec<SectionSummary>,
    pub security_summary: String,
    pub suspected_packer: Option<String>,
    pub entry_section: Option<String>,
    pub export_forwarders: Vec<(String, String)>,
    pub odd_section_perms: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SectionSummary {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub perms: u32,
    pub exec: bool,
    pub write: bool,
    pub read: bool,
    pub entropy: f64,
    pub zero_ratio: f64,
}

/// Gather PE extras; for non-PE images returns mostly empty with a note.
pub fn analyze_pe_extras(bin: &Binary) -> PeExtras {
    let mut out = PeExtras::default();
    if bin.format != Format::Pe {
        out.hints.push(PeHint {
            kind: PeHintKind::Other,
            addr: None,
            title: "not PE".into(),
            detail: format!("format is {}", bin.format.as_str()),
            severity: Severity::Info,
        });
        // still compute section summaries — useful for ELF/Mach-O too
        out.section_summary = summarize_sections(bin);
        return out;
    }

    out.tls_callbacks = bin.tls_callbacks.clone();
    for (i, &cb) in bin.tls_callbacks.iter().enumerate() {
        out.hints.push(PeHint {
            kind: PeHintKind::TlsCallback,
            addr: Some(cb),
            title: format!("TLS callback #{i}"),
            detail: "runs before the entry point (and on thread attach)".into(),
            severity: Severity::Warn,
        });
    }

    out.delay_imports = bin
        .imports
        .iter()
        .filter(|i| i.delay)
        .cloned()
        .collect();
    for d in &out.delay_imports {
        out.hints.push(PeHint {
            kind: PeHintKind::DelayImport,
            addr: Some(d.slot),
            title: format!("delay import {}!{}", d.lib, d.name),
            detail: "resolved on first use".into(),
            severity: Severity::Note,
        });
    }

    out.security_summary = format_security(bin);
    push_security_hints(bin, &mut out);

    out.section_summary = summarize_sections(bin);
    for s in &out.section_summary {
        if s.exec && s.write {
            out.odd_section_perms.push(s.name.clone());
            out.hints.push(PeHint {
                kind: PeHintKind::Section,
                addr: Some(s.start),
                title: format!("RWX section {}", s.name),
                detail: format!("perms={:#x} size={:#x}", s.perms, s.size),
                severity: Severity::Alert,
            });
        }
        if s.entropy > 7.0 && s.size > 0x400 {
            out.hints.push(PeHint {
                kind: PeHintKind::Packer,
                addr: Some(s.start),
                title: format!("high entropy section {}", s.name),
                detail: format!("entropy={:.2}", s.entropy),
                severity: Severity::Warn,
            });
        }
    }

    out.entry_section = bin
        .seg_at(bin.entry)
        .map(|s| s.name.clone())
        .filter(|_| bin.has_entry);
    if let Some(name) = &out.entry_section {
        out.hints.push(PeHint {
            kind: PeHintKind::Entry,
            addr: Some(bin.entry),
            title: format!("entry in {name}"),
            detail: format!("{:X}", bin.entry),
            severity: Severity::Info,
        });
        if looks_like_packer_section(name) {
            out.suspected_packer = Some(name.clone());
            out.hints.push(PeHint {
                kind: PeHintKind::Packer,
                addr: Some(bin.entry),
                title: format!("entry section looks packed ({name})"),
                detail: "common packer section name".into(),
                severity: Severity::Warn,
            });
        }
    }

    for e in &bin.exports {
        if !e.forward.is_empty() {
            out.export_forwarders
                .push((e.name.clone(), e.forward.clone()));
            out.hints.push(PeHint {
                kind: PeHintKind::Export,
                addr: Some(e.addr),
                title: format!("forwarded export {}", e.name),
                detail: e.forward.clone(),
                severity: Severity::Note,
            });
        }
    }

    // import library fingerprints
    for lib in interesting_import_libs(bin) {
        out.hints.push(PeHint {
            kind: PeHintKind::Import,
            addr: None,
            title: format!("imports {lib}"),
            detail: import_lib_note(&lib).to_string(),
            severity: Severity::Note,
        });
    }

    // compiler / linker notes from binary.notes
    for n in &bin.notes {
        out.hints.push(PeHint {
            kind: PeHintKind::Debug,
            addr: None,
            title: "note".into(),
            detail: n.clone(),
            severity: Severity::Info,
        });
    }

    // func hints that look like pdata / exception unwind starts
    if bin.func_hints.len() > bin.exports.len() + bin.tls_callbacks.len() + 4 {
        out.hints.push(PeHint {
            kind: PeHintKind::Exception,
            addr: None,
            title: "many function hints".into(),
            detail: format!(
                "{} hints (pdata / init arrays / TLS / exports)",
                bin.func_hints.len()
            ),
            severity: Severity::Info,
        });
    }

    out.hints.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.kind.as_str().cmp(b.kind.as_str()))
            .then_with(|| a.addr.cmp(&b.addr))
    });
    out
}

fn format_security(bin: &Binary) -> String {
    let s = &bin.security;
    format!(
        "ASLR={} NX={} CFG={} HEVA={} dynamic_base={} force_integrity={} raw={:#06x}",
        s.aslr, s.nx, s.cfg, s.high_entropy_va, s.dynamic_base, s.force_integrity, s.raw
    )
}

fn push_security_hints(bin: &Binary, out: &mut PeExtras) {
    let s = &bin.security;
    if !s.aslr && !s.dynamic_base {
        out.hints.push(PeHint {
            kind: PeHintKind::Security,
            addr: None,
            title: "ASLR disabled".into(),
            detail: "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE not set".into(),
            severity: Severity::Warn,
        });
    }
    if !s.nx {
        out.hints.push(PeHint {
            kind: PeHintKind::Security,
            addr: None,
            title: "NX / DEP disabled".into(),
            detail: "IMAGE_DLLCHARACTERISTICS_NX_COMPAT not set".into(),
            severity: Severity::Warn,
        });
    }
    if s.cfg {
        out.hints.push(PeHint {
            kind: PeHintKind::Security,
            addr: None,
            title: "Control Flow Guard".into(),
            detail: "CFG bit set".into(),
            severity: Severity::Info,
        });
    }
    if s.high_entropy_va {
        out.hints.push(PeHint {
            kind: PeHintKind::Security,
            addr: None,
            title: "High-entropy VA".into(),
            detail: "64-bit ASLR with high entropy".into(),
            severity: Severity::Info,
        });
    }
    if s.force_integrity {
        out.hints.push(PeHint {
            kind: PeHintKind::Security,
            addr: None,
            title: "Force integrity".into(),
            detail: "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY".into(),
            severity: Severity::Note,
        });
    }
}

fn summarize_sections(bin: &Binary) -> Vec<SectionSummary> {
    bin.segments
        .iter()
        .map(|s| {
            let entropy = section_entropy(&s.data);
            let zero = if s.data.is_empty() {
                0.0
            } else {
                s.data.iter().filter(|&&b| b == 0).count() as f64 / s.data.len() as f64
            };
            SectionSummary {
                name: s.name.clone(),
                start: s.start,
                end: s.end,
                size: s.size(),
                perms: s.perms,
                exec: s.perms & PERM_X != 0,
                write: s.perms & PERM_W != 0,
                read: s.perms & PERM_R != 0,
                entropy,
                zero_ratio: zero,
            }
        })
        .collect()
}

fn section_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    // sample up to 64KiB for speed
    let take = data.len().min(65536);
    let slice = &data[..take];
    let mut freq = [0u64; 256];
    for &b in slice {
        freq[b as usize] += 1;
    }
    let n = slice.len() as f64;
    let mut h = 0.0;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

fn looks_like_packer_section(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const NAMES: &[&str] = &[
        "upx0", "upx1", "upx2", ".upx", "themida", ".themida", "vmp0", "vmp1",
        ".vmp", "aspack", ".aspack", "pec2", "petite", ".nsp", "mew", ".mpress",
        "kkrunchy", ".packed", "stub",
    ];
    NAMES.iter().any(|p| n.contains(p))
}

fn interesting_import_libs(bin: &Binary) -> Vec<String> {
    let mut out = Vec::new();
    for lib in &bin.libs {
        let l = lib.to_ascii_lowercase();
        if INTERESTING_LIBS.iter().any(|k| l.contains(k)) {
            out.push(lib.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

const INTERESTING_LIBS: &[&str] = &[
    "wininet", "winhttp", "ws2_32", "crypt32", "bcrypt", "ncrypt", "advapi32",
    "ntdll", "urlmon", "ole32", "oleaut32", "shell32", "user32", "gdi32",
    "kernel32", "psapi", "dbghelp", "imagehlp", "wintrust", "secur32",
    "netapi32", "wtsapi32", "wevtapi", "virtdisk", "pcap", "wpcap",
];

fn import_lib_note(lib: &str) -> &'static str {
    let l = lib.to_ascii_lowercase();
    if l.contains("wininet") || l.contains("winhttp") || l.contains("urlmon") {
        "network / HTTP APIs"
    } else if l.contains("crypt") || l.contains("bcrypt") || l.contains("ncrypt") {
        "crypto APIs"
    } else if l.contains("ntdll") {
        "native API"
    } else if l.contains("ws2_32") {
        "Winsock"
    } else if l.contains("advapi32") {
        "registry / services / security"
    } else if l.contains("dbghelp") || l.contains("imagehlp") {
        "debug / image helpers"
    } else {
        "notable import library"
    }
}

/// Format a human-readable extras report.
pub fn format_pe_extras(ex: &PeExtras) -> String {
    let mut out = String::new();
    out.push_str(&format!("security: {}\n", ex.security_summary));
    if let Some(p) = &ex.suspected_packer {
        out.push_str(&format!("suspected packer section: {p}\n"));
    }
    if let Some(e) = &ex.entry_section {
        out.push_str(&format!("entry section: {e}\n"));
    }
    out.push_str(&format!("tls callbacks: {}\n", ex.tls_callbacks.len()));
    for (i, a) in ex.tls_callbacks.iter().enumerate() {
        out.push_str(&format!("  [{i}] {a:X}\n"));
    }
    out.push_str(&format!("delay imports: {}\n", ex.delay_imports.len()));
    out.push_str(&format!("sections: {}\n", ex.section_summary.len()));
    for s in &ex.section_summary {
        out.push_str(&format!(
            "  {:<10} {:X}-{:X} ent={:.2} zero={:.0}% {}\n",
            s.name,
            s.start,
            s.end,
            s.entropy,
            s.zero_ratio * 100.0,
            perms_str(s.perms)
        ));
    }
    out.push_str(&format!("hints: {}\n", ex.hints.len()));
    for h in &ex.hints {
        let a = h
            .addr
            .map(|x| format!("{x:X}"))
            .unwrap_or_else(|| "-".into());
        out.push_str(&format!(
            "  [{}/{}] {} @ {} — {}\n",
            h.severity.as_str(),
            h.kind.as_str(),
            h.title,
            a,
            h.detail
        ));
    }
    out
}

fn perms_str(p: u32) -> String {
    let mut s = String::new();
    if p & PERM_R != 0 {
        s.push('R');
    } else {
        s.push('-');
    }
    if p & PERM_W != 0 {
        s.push('W');
    } else {
        s.push('-');
    }
    if p & PERM_X != 0 {
        s.push('X');
    } else {
        s.push('-');
    }
    s
}

/// Suggested comments to apply for TLS callbacks.
pub fn tls_comment_suggestions(bin: &Binary) -> Vec<(u64, String)> {
    bin.tls_callbacks
        .iter()
        .enumerate()
        .map(|(i, &a)| {
            (
                a,
                format!("tls callback #{i}: runs before the entry point"),
            )
        })
        .collect()
}

/// Suggested function names for TLS callbacks.
pub fn tls_name_suggestions(bin: &Binary) -> Vec<(u64, String)> {
    bin.tls_callbacks
        .iter()
        .enumerate()
        .map(|(i, &a)| (a, format!("TlsCallback_{i}")))
        .collect()
}

/// Map import slot → "lib!name".
pub fn import_label_map(bin: &Binary) -> BTreeMap<u64, String> {
    bin.imports
        .iter()
        .map(|i| (i.slot, format!("{}!{}", i.lib, i.name)))
        .collect()
}

/// Map export addr → name.
pub fn export_name_map(bin: &Binary) -> BTreeMap<u64, String> {
    let mut m = BTreeMap::new();
    for e in &bin.exports {
        if !e.name.is_empty() {
            m.insert(e.addr, e.name.clone());
        }
    }
    m
}

/// Addresses that analysis should treat as function seeds beyond entry.
pub fn extra_func_seeds(bin: &Binary) -> BTreeSet<u64> {
    let mut s = BTreeSet::new();
    s.extend(bin.tls_callbacks.iter().copied());
    s.extend(bin.func_hints.iter().copied());
    s.extend(bin.exports.iter().filter_map(|e| (e.addr != 0).then_some(e.addr)));
    if bin.has_entry {
        s.insert(bin.entry);
    }
    s
}

/// Count imports by DLL.
pub fn imports_by_lib(bin: &Binary) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for i in &bin.imports {
        *m.entry(i.lib.clone()).or_default() += 1;
    }
    m
}

/// Find imports matching a case-insensitive substring.
pub fn find_imports<'a>(bin: &'a Binary, query: &str) -> Vec<&'a ImportEntry> {
    let q = query.to_ascii_lowercase();
    bin.imports
        .iter()
        .filter(|i| {
            i.name.to_ascii_lowercase().contains(&q)
                || i.lib.to_ascii_lowercase().contains(&q)
        })
        .collect()
}

/// Heuristic: image may be packed.
pub fn packing_score(ex: &PeExtras) -> f32 {
    let mut score = 0.0f32;
    if ex.suspected_packer.is_some() {
        score += 0.5;
    }
    for s in &ex.section_summary {
        if s.entropy > 7.2 {
            score += 0.15;
        }
        if s.exec && s.write {
            score += 0.2;
        }
        if s.zero_ratio > 0.7 && s.exec {
            score += 0.1;
        }
    }
    if ex.section_summary.len() <= 3 {
        score += 0.05;
    }
    score.min(1.0)
}

pub fn packer_signature_name_0() -> &'static str { "UPX" }

pub fn section_matches_packer_0(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_0().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_1() -> &'static str { "Themida" }

pub fn section_matches_packer_1(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_1().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_2() -> &'static str { "VMProtect" }

pub fn section_matches_packer_2(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_2().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_3() -> &'static str { "ASPack" }

pub fn section_matches_packer_3(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_3().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_4() -> &'static str { "PECompact" }

pub fn section_matches_packer_4(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_4().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_5() -> &'static str { "Petite" }

pub fn section_matches_packer_5(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_5().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_6() -> &'static str { "NsPack" }

pub fn section_matches_packer_6(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_6().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_7() -> &'static str { "MEW" }

pub fn section_matches_packer_7(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_7().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_8() -> &'static str { "MPRESS" }

pub fn section_matches_packer_8(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_8().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_9() -> &'static str { "kkrunchy" }

pub fn section_matches_packer_9(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_9().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_10() -> &'static str { "Armadillo" }

pub fn section_matches_packer_10(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_10().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_11() -> &'static str { "Enigma" }

pub fn section_matches_packer_11(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_11().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_12() -> &'static str { "Obsidium" }

pub fn section_matches_packer_12(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_12().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_13() -> &'static str { "Safengine" }

pub fn section_matches_packer_13(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_13().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_14() -> &'static str { "PELock" }

pub fn section_matches_packer_14(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_14().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_15() -> &'static str { "Yoda" }

pub fn section_matches_packer_15(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_15().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_16() -> &'static str { "FSG" }

pub fn section_matches_packer_16(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_16().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_17() -> &'static str { "Packman" }

pub fn section_matches_packer_17(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_17().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_18() -> &'static str { "RLPack" }

pub fn section_matches_packer_18(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_18().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_19() -> &'static str { "NeoLite" }

pub fn section_matches_packer_19(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_19().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_20() -> &'static str { "Molebox" }

pub fn section_matches_packer_20(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_20().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_21() -> &'static str { "ExeCryptor" }

pub fn section_matches_packer_21(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_21().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_22() -> &'static str { "tElock" }

pub fn section_matches_packer_22(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_22().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_23() -> &'static str { "Beria" }

pub fn section_matches_packer_23(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_23().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_24() -> &'static str { "ACProtect" }

pub fn section_matches_packer_24(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_24().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_25() -> &'static str { "ASProtect" }

pub fn section_matches_packer_25(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_25().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_26() -> &'static str { "SVKP" }

pub fn section_matches_packer_26(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_26().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_27() -> &'static str { "WinUpack" }

pub fn section_matches_packer_27(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_27().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_28() -> &'static str { "Upack" }

pub fn section_matches_packer_28(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_28().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_29() -> &'static str { "nSquirR" }

pub fn section_matches_packer_29(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_29().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn packer_signature_name_30() -> &'static str { "yodas" }

pub fn section_matches_packer_30(section: &str) -> bool {
    let n = section.to_ascii_lowercase();
    let p = packer_signature_name_30().to_ascii_lowercase();
    n.contains(&p) || n.contains(&p.replace(' ', ""))
}

pub fn all_packer_signature_names() -> Vec<&'static str> {
    vec![
        packer_signature_name_0(),
        packer_signature_name_1(),
        packer_signature_name_2(),
        packer_signature_name_3(),
        packer_signature_name_4(),
        packer_signature_name_5(),
        packer_signature_name_6(),
        packer_signature_name_7(),
        packer_signature_name_8(),
        packer_signature_name_9(),
        packer_signature_name_10(),
        packer_signature_name_11(),
        packer_signature_name_12(),
        packer_signature_name_13(),
        packer_signature_name_14(),
        packer_signature_name_15(),
        packer_signature_name_16(),
        packer_signature_name_17(),
        packer_signature_name_18(),
        packer_signature_name_19(),
        packer_signature_name_20(),
        packer_signature_name_21(),
        packer_signature_name_22(),
        packer_signature_name_23(),
        packer_signature_name_24(),
        packer_signature_name_25(),
        packer_signature_name_26(),
        packer_signature_name_27(),
        packer_signature_name_28(),
        packer_signature_name_29(),
        packer_signature_name_30(),
    ]
}

pub fn detect_packer_by_section_names(bin: &Binary) -> Vec<&'static str> {
    let mut hits = Vec::new();
    for name in all_packer_signature_names() {
        let l = name.to_ascii_lowercase();
        if bin.segments.iter().any(|s| s.name.to_ascii_lowercase().contains(&l)) {
            hits.push(name);
        }
    }
    hits
}

pub fn detect_packer_index(bin: &Binary) -> Option<usize> {
    if bin.segments.iter().any(|s| section_matches_packer_0(&s.name)) {
        return Some(0);
    }
    if bin.segments.iter().any(|s| section_matches_packer_1(&s.name)) {
        return Some(1);
    }
    if bin.segments.iter().any(|s| section_matches_packer_2(&s.name)) {
        return Some(2);
    }
    if bin.segments.iter().any(|s| section_matches_packer_3(&s.name)) {
        return Some(3);
    }
    if bin.segments.iter().any(|s| section_matches_packer_4(&s.name)) {
        return Some(4);
    }
    if bin.segments.iter().any(|s| section_matches_packer_5(&s.name)) {
        return Some(5);
    }
    if bin.segments.iter().any(|s| section_matches_packer_6(&s.name)) {
        return Some(6);
    }
    if bin.segments.iter().any(|s| section_matches_packer_7(&s.name)) {
        return Some(7);
    }
    if bin.segments.iter().any(|s| section_matches_packer_8(&s.name)) {
        return Some(8);
    }
    if bin.segments.iter().any(|s| section_matches_packer_9(&s.name)) {
        return Some(9);
    }
    if bin.segments.iter().any(|s| section_matches_packer_10(&s.name)) {
        return Some(10);
    }
    if bin.segments.iter().any(|s| section_matches_packer_11(&s.name)) {
        return Some(11);
    }
    if bin.segments.iter().any(|s| section_matches_packer_12(&s.name)) {
        return Some(12);
    }
    if bin.segments.iter().any(|s| section_matches_packer_13(&s.name)) {
        return Some(13);
    }
    if bin.segments.iter().any(|s| section_matches_packer_14(&s.name)) {
        return Some(14);
    }
    if bin.segments.iter().any(|s| section_matches_packer_15(&s.name)) {
        return Some(15);
    }
    if bin.segments.iter().any(|s| section_matches_packer_16(&s.name)) {
        return Some(16);
    }
    if bin.segments.iter().any(|s| section_matches_packer_17(&s.name)) {
        return Some(17);
    }
    if bin.segments.iter().any(|s| section_matches_packer_18(&s.name)) {
        return Some(18);
    }
    if bin.segments.iter().any(|s| section_matches_packer_19(&s.name)) {
        return Some(19);
    }
    if bin.segments.iter().any(|s| section_matches_packer_20(&s.name)) {
        return Some(20);
    }
    if bin.segments.iter().any(|s| section_matches_packer_21(&s.name)) {
        return Some(21);
    }
    if bin.segments.iter().any(|s| section_matches_packer_22(&s.name)) {
        return Some(22);
    }
    if bin.segments.iter().any(|s| section_matches_packer_23(&s.name)) {
        return Some(23);
    }
    if bin.segments.iter().any(|s| section_matches_packer_24(&s.name)) {
        return Some(24);
    }
    if bin.segments.iter().any(|s| section_matches_packer_25(&s.name)) {
        return Some(25);
    }
    if bin.segments.iter().any(|s| section_matches_packer_26(&s.name)) {
        return Some(26);
    }
    if bin.segments.iter().any(|s| section_matches_packer_27(&s.name)) {
        return Some(27);
    }
    if bin.segments.iter().any(|s| section_matches_packer_28(&s.name)) {
        return Some(28);
    }
    if bin.segments.iter().any(|s| section_matches_packer_29(&s.name)) {
        return Some(29);
    }
    if bin.segments.iter().any(|s| section_matches_packer_30(&s.name)) {
        return Some(30);
    }
    None
}

/// Compiler / runtime import fingerprints.
pub fn runtime_fingerprint(bin: &Binary) -> Vec<&'static str> {
    let mut tags = Vec::new();
    let names: Vec<String> = bin
        .imports
        .iter()
        .map(|i| i.name.to_ascii_lowercase())
        .collect();
    let joined = names.join(" ");
    if joined.contains("msvcrt") || bin.libs.iter().any(|l| l.to_ascii_lowercase().contains("msvcrt")) {
        tags.push("msvcrt");
    }
    if bin.libs.iter().any(|l| l.to_ascii_lowercase().contains("vcruntime")) {
        tags.push("vcruntime");
    }
    if bin.libs.iter().any(|l| {
        let x = l.to_ascii_lowercase();
        x.contains("ucrtbase") || x.contains("api-ms-win-crt")
    }) {
        tags.push("ucrt");
    }
    if names.iter().any(|n| n.contains("__rust") || n.contains("rust_begin")) {
        tags.push("rustc");
    }
    if names.iter().any(|n| n.contains("go_") || n.contains("runtime.main")) {
        tags.push("golang");
    }
    if names.iter().any(|n| n.contains("py") && n.contains("init")) {
        tags.push("python");
    }
    if bin.libs.iter().any(|l| l.to_ascii_lowercase().contains("libgcc")) {
        tags.push("gcc");
    }
    tags
}

/// Suggest analysis follow-ups as short strings.
pub fn suggested_followups(ex: &PeExtras) -> Vec<String> {
    let mut v = Vec::new();
    if !ex.tls_callbacks.is_empty() {
        v.push(format!(
            "review {} TLS callback(s) before trusting the entry point",
            ex.tls_callbacks.len()
        ));
    }
    if packing_score(ex) >= 0.5 {
        v.push("image may be packed — consider unpacking before deep analysis".into());
    }
    if ex.odd_section_perms.iter().any(|_| true) {
        v.push("RWX sections present — check for self-modifying code / unpacker stubs".into());
    }
    if ex.delay_imports.len() > 0 {
        v.push(format!(
            "{} delay-load import(s) — APIs appear on first call",
            ex.delay_imports.len()
        ));
    }
    for h in ex.hints.iter().filter(|h| h.severity == Severity::Alert).take(5) {
        v.push(format!("alert: {}", h.title));
    }
    v
}

/// Compact JSONL without serde.
pub fn pe_extras_jsonl(ex: &PeExtras) -> String {
    let mut out = String::new();
    for h in &ex.hints {
        let addr = h.addr.map(|a| format!("{a:X}")).unwrap_or_default();
        let title = h.title.replace('"', "'");
        let detail = h.detail.replace('"', "'");
        out.push_str("{\"kind\":\"");
        out.push_str(h.kind.as_str());
        out.push_str("\",\"sev\":\"");
        out.push_str(h.severity.as_str());
        out.push_str("\",\"addr\":\"");
        out.push_str(&addr);
        out.push_str("\",\"title\":\"");
        out.push_str(&title);
        out.push_str("\",\"detail\":\"");
        out.push_str(&detail);
        out.push_str("\"}\n");
    }
    out
}

/// Filter hints by kind.
pub fn hints_of_kind(ex: &PeExtras, kind: PeHintKind) -> Vec<&PeHint> {
    ex.hints.iter().filter(|h| h.kind == kind).collect()
}

/// Filter hints by minimum severity.
pub fn hints_at_least(ex: &PeExtras, sev: Severity) -> Vec<&PeHint> {
    ex.hints.iter().filter(|h| h.severity >= sev).collect()
}

/// Section containing address, if any.
pub fn section_name_at(ex: &PeExtras, addr: u64) -> Option<&str> {
    ex.section_summary
        .iter()
        .find(|s| addr >= s.start && addr < s.end)
        .map(|s| s.name.as_str())
}

/// Total executable bytes.
pub fn exec_image_size(ex: &PeExtras) -> u64 {
    ex.section_summary
        .iter()
        .filter(|s| s.exec)
        .map(|s| s.size)
        .sum()
}

/// Mean section entropy weighted by size.
pub fn weighted_entropy(ex: &PeExtras) -> f64 {
    let mut num = 0.0;
    let mut den = 0.0;
    for s in &ex.section_summary {
        num += s.entropy * s.size as f64;
        den += s.size as f64;
    }
    if den == 0.0 {
        0.0
    } else {
        num / den
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceasta_binary::{Arch, Segment};

    fn toy_pe() -> Binary {
        let mut bin = Binary::empty("t.exe", Format::Pe, Arch::X64);
        bin.base = 0x140000000;
        bin.entry = 0x140001000;
        bin.has_entry = true;
        bin.security.aslr = true;
        bin.security.nx = true;
        bin.security.cfg = true;
        bin.tls_callbacks.push(0x140002000);
        bin.libs.push("WININET.dll".into());
        bin.imports.push(ImportEntry {
            lib: "WININET.dll".into(),
            name: "InternetOpenA".into(),
            slot: 0x140003000,
            delay: false,
        });
        bin.segments.push(Segment {
            name: ".text".into(),
            start: 0x140001000,
            end: 0x140001100,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: 0x100,
            data: vec![0x90; 0x100],
        });
        bin.segments.push(Segment {
            name: "UPX0".into(),
            start: 0x140004000,
            end: 0x140005000,
            perms: PERM_R | PERM_W | PERM_X,
            file_off: 0,
            file_size: 0x1000,
            data: {
                // high entropy-ish
                let mut v = Vec::with_capacity(0x1000);
                for i in 0..0x1000 {
                    v.push((i * 17 + 3) as u8);
                }
                v
            },
        });
        bin
    }

    #[test]
    fn detects_tls_and_packer_section() {
        let bin = toy_pe();
        let ex = analyze_pe_extras(&bin);
        assert_eq!(ex.tls_callbacks.len(), 1);
        assert!(ex.suspected_packer.is_some() || detect_packer_by_section_names(&bin).len() > 0);
        assert!(!ex.hints.is_empty());
        let rep = format_pe_extras(&ex);
        assert!(rep.contains("tls"));
        assert!(packing_score(&ex) > 0.3);
    }

    #[test]
    fn import_maps_and_seeds() {
        let bin = toy_pe();
        let m = import_label_map(&bin);
        assert!(m.values().any(|v| v.contains("InternetOpenA")));
        let seeds = extra_func_seeds(&bin);
        assert!(seeds.contains(&0x140002000));
        assert!(seeds.contains(&bin.entry));
    }

    #[test]
    fn non_pe_still_summarizes_sections() {
        let mut bin = Binary::empty("t.bin", Format::Raw, Arch::X64);
        bin.segments.push(Segment {
            name: ".text".into(),
            start: 0x1000,
            end: 0x1100,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: 0x100,
            data: vec![0; 0x100],
        });
        let ex = analyze_pe_extras(&bin);
        assert_eq!(ex.section_summary.len(), 1);
    }
}
