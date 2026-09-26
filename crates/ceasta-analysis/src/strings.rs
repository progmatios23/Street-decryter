//! String classification — port of the heuristics in `plugins/strings_report.lua`,
//! plus extra buckets useful for triage (crypto, network, errors, GUIDs, …).

use crate::FoundString;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Coarse kind for an “interesting” string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StringKind {
    Url,
    UncPath,
    Path,
    Registry,
    Format,
    Command,
    Crypto,
    Network,
    Error,
    Guid,
    Email,
    IpAddress,
    UserAgent,
    Mime,
    Sql,
    XmlHtml,
    Base64ish,
    HexBlob,
    Debug,
    Version,
    Other,
}

impl StringKind {
    pub fn as_str(self) -> &'static str {
        match self {
            StringKind::Url => "url",
            StringKind::UncPath => "unc path",
            StringKind::Path => "path",
            StringKind::Registry => "registry",
            StringKind::Format => "format",
            StringKind::Command => "command",
            StringKind::Crypto => "crypto",
            StringKind::Network => "network",
            StringKind::Error => "error",
            StringKind::Guid => "guid",
            StringKind::Email => "email",
            StringKind::IpAddress => "ip",
            StringKind::UserAgent => "user-agent",
            StringKind::Mime => "mime",
            StringKind::Sql => "sql",
            StringKind::XmlHtml => "xml/html",
            StringKind::Base64ish => "base64",
            StringKind::HexBlob => "hex",
            StringKind::Debug => "debug",
            StringKind::Version => "version",
            StringKind::Other => "other",
        }
    }

    pub fn from_str_lossy(s: &str) -> Option<Self> {
        let k = s.trim().to_ascii_lowercase();
        Some(match k.as_str() {
            "url" => StringKind::Url,
            "unc path" | "unc" => StringKind::UncPath,
            "path" => StringKind::Path,
            "registry" | "reg" => StringKind::Registry,
            "format" | "fmt" => StringKind::Format,
            "command" | "cmd" => StringKind::Command,
            "crypto" => StringKind::Crypto,
            "network" | "net" => StringKind::Network,
            "error" | "err" => StringKind::Error,
            "guid" | "uuid" => StringKind::Guid,
            "email" => StringKind::Email,
            "ip" | "ip address" => StringKind::IpAddress,
            "user-agent" | "ua" => StringKind::UserAgent,
            "mime" => StringKind::Mime,
            "sql" => StringKind::Sql,
            "xml/html" | "xml" | "html" => StringKind::XmlHtml,
            "base64" | "b64" => StringKind::Base64ish,
            "hex" => StringKind::HexBlob,
            "debug" => StringKind::Debug,
            "version" | "ver" => StringKind::Version,
            "other" => StringKind::Other,
            _ => return None,
        })
    }

    pub fn all() -> &'static [StringKind] {
        &KIND_ALL
    }
}

const KIND_ALL: [StringKind; 21] = [
    StringKind::Url,
    StringKind::UncPath,
    StringKind::Path,
    StringKind::Registry,
    StringKind::Format,
    StringKind::Command,
    StringKind::Crypto,
    StringKind::Network,
    StringKind::Error,
    StringKind::Guid,
    StringKind::Email,
    StringKind::IpAddress,
    StringKind::UserAgent,
    StringKind::Mime,
    StringKind::Sql,
    StringKind::XmlHtml,
    StringKind::Base64ish,
    StringKind::HexBlob,
    StringKind::Debug,
    StringKind::Version,
    StringKind::Other,
];

#[derive(Clone, Debug)]
pub struct ClassifiedString {
    pub addr: u64,
    pub text: String,
    pub wide: bool,
    pub kind: StringKind,
    pub score: f32,
    pub matched_rule: &'static str,
}

#[derive(Clone, Debug, Default)]
pub struct StringReport {
    pub items: Vec<ClassifiedString>,
    pub by_kind: BTreeMap<StringKind, usize>,
}

impl StringReport {
    pub fn interesting_addrs(&self) -> Vec<u64> {
        self.items.iter().map(|i| i.addr).collect()
    }

    pub fn kinds_summary(&self) -> String {
        let mut keys: Vec<_> = self.by_kind.keys().copied().collect();
        keys.sort();
        let mut s = String::new();
        for k in keys {
            s.push_str(&format!("{:<12} {}\n", k.as_str(), self.by_kind[&k]));
        }
        s
    }

    pub fn format_listing(&self, max_text: usize) -> String {
        let mut out = self.kinds_summary();
        out.push_str("---\n");
        for it in &self.items {
            let t = truncate_display(&it.text, max_text);
            out.push_str(&format!(
                "{:X}  [{}] {}\n",
                it.addr,
                it.kind.as_str(),
                t
            ));
        }
        out.push_str(&format!("{} interesting string(s)\n", self.items.len()));
        out
    }
}

#[derive(Clone, Copy, Debug)]
struct Rule {
    kind: StringKind,
    name: &'static str,
    score: f32,
    /// Returns true if the text matches.
    test: fn(&str) -> bool,
}

fn rule_url(t: &str) -> bool {
    // scheme://
    let bytes = t.as_bytes();
    if bytes.len() < 4 {
        return false;
    }
    // find ://
    for i in 1..bytes.len().saturating_sub(2) {
        if bytes[i] == b':' && bytes[i + 1] == b'/' && bytes[i + 2] == b'/' {
            let scheme = &t[..i];
            return scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        }
    }
    false
}

fn rule_unc(t: &str) -> bool {
    t.starts_with("\\\\") || t.starts_with("//")
}

fn rule_win_path(t: &str) -> bool {
    let b = t.as_bytes();
    if b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/')
    {
        return true;
    }
    // also catch mid-string Windows paths
    for i in 0..b.len().saturating_sub(3) {
        if b[i].is_ascii_alphabetic() && b[i + 1] == b':' && b[i + 2] == b'\\' {
            return true;
        }
    }
    false
}

fn rule_unix_path(t: &str) -> bool {
    if !t.starts_with('/') {
        return false;
    }
    let rest = &t[1..];
    let first = rest.split('/').next().unwrap_or("");
    !first.is_empty()
        && first.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        && t.matches('/').count() >= 2
}

fn rule_registry(t: &str) -> bool {
    let u = t.to_ascii_uppercase();
    u.starts_with("HKEY_")
        || u.starts_with("HKLM\\")
        || u.starts_with("HKCU\\")
        || u.starts_with("HKCR\\")
        || u.starts_with("HKU\\")
        || u.starts_with("SOFTWARE\\")
        || u.starts_with("SYSTEM\\")
        || u.starts_with("SOFTWARE/")
}

fn rule_format(t: &str) -> bool {
    // printf-like %%...conversion
    let b = t.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            i += 1;
            if i < b.len() && b[i] == b'%' {
                i += 1;
                continue;
            }
            while i < b.len() && matches!(b[i], b'-' | b'+' | b' ' | b'#' | b'0') {
                i += 1;
            }
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i < b.len() && b[i] == b'.' {
                i += 1;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
            }
            if i < b.len() && matches!(
                b[i],
                b'd' | b'i' | b'o' | b'u' | b'x' | b'X' | b'e' | b'E' | b'f' | b'g' | b'G' | b's'
                    | b'c' | b'p' | b'n'
            ) {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

fn rule_command(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    l.contains("cmd.exe")
        || l.contains("powershell")
        || l.contains("/bin/sh")
        || l.contains("/bin/bash")
        || l.contains("wscript")
        || l.contains("cscript")
        || l.contains("mshta")
        || l.contains("rundll32")
        || l.contains("regsvr32")
}

fn rule_crypto(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    const KEYS: &[&str] = &[
        "aes", "rsa", "sha1", "sha256", "sha512", "md5", "hmac", "chacha", "salsa", "blowfish",
        "twofish", "rc4", "rc2", "des-", "3des", "pbkdf", "bcrypt", "scrypt", "argon2", "x509",
        "certificate", "private key", "public key", "cryptencrypt", "bcryptencrypt", "nonce",
        "iv_len", "gcm", "cbc", "ctr mode",
    ];
    KEYS.iter().any(|k| l.contains(k))
}

fn rule_network(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    const KEYS: &[&str] = &[
        "http", "https", "tcp", "udp", "websocket", "socks", "dns", "smtp", "imap", "ftp://",
        "wininet", "winhttp", "user-agent", "content-type", "application/json", "keep-alive",
    ];
    KEYS.iter().any(|k| l.contains(k))
}

fn rule_error(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    l.contains("error")
        || l.contains("failed")
        || l.contains("exception")
        || l.contains("fatal")
        || l.contains("access denied")
        || l.contains("not found")
}

fn rule_guid(t: &str) -> bool {
    // {8-4-4-4-12} or bare
    let s = t.trim().trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<_> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let lens = [8, 4, 4, 4, 12];
    parts.iter().zip(lens).all(|(p, n)| p.len() == n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn rule_email(t: &str) -> bool {
    let Some(at) = t.find('@') else {
        return false;
    };
    if at == 0 || at + 1 >= t.len() {
        return false;
    }
    let (user, domain) = t.split_at(at);
    let domain = &domain[1..];
    !user.is_empty()
        && domain.contains('.')
        && domain.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
}

fn rule_ip(t: &str) -> bool {
    // crude IPv4
    let parts: Vec<_> = t.split('.').collect();
    if parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u32>().map(|n| n <= 255).unwrap_or(false)
        })
    {
        return true;
    }
    // IPv6-ish
    t.contains(':')
        && t.chars().filter(|c| *c == ':').count() >= 2
        && t.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

fn rule_ua(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    l.contains("mozilla/") || l.contains("user-agent") || l.contains("applewebkit")
}

fn rule_mime(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    l.starts_with("text/")
        || l.starts_with("image/")
        || l.starts_with("audio/")
        || l.starts_with("video/")
        || l.starts_with("application/")
        || l.starts_with("multipart/")
}

fn rule_sql(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    l.contains("select ")
        || l.contains("insert into")
        || l.contains("update ")
        || l.contains("delete from")
        || l.contains("create table")
        || l.contains("drop table")
        || l.contains("union select")
}

fn rule_xml_html(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    l.contains("<?xml")
        || l.contains("<!doctype")
        || l.contains("<html")
        || l.contains("</")
        || l.contains("xmlns=")
}

fn rule_base64(t: &str) -> bool {
    if t.len() < 16 || t.len() % 4 != 0 {
        return false;
    }
    let ok = t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if !ok {
        return false;
    }
    let pad = t.chars().rev().take_while(|c| *c == '=').count();
    pad <= 2 && t.chars().filter(|c| c.is_ascii_uppercase()).count() > 2
}

fn rule_hex_blob(t: &str) -> bool {
    let s = t.trim();
    if s.len() < 16 || s.len() % 2 != 0 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_hexdigit())
}

fn rule_debug(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    l.contains("assert")
        || l.contains("debug")
        || l.contains("todo:")
        || l.contains("fixme")
        || l.contains("__file__")
        || l.contains("stack trace")
}

fn rule_version(t: &str) -> bool {
    // v1.2.3 or 1.2.3.4
    let mut nums = 0;
    let mut cur = false;
    for c in t.chars() {
        if c.is_ascii_digit() {
            if !cur {
                nums += 1;
                cur = true;
            }
        } else if c == '.' {
            cur = false;
        } else if nums > 0 {
            break;
        }
    }
    nums >= 3 && t.contains('.')
}

const RULES: &[Rule] = &[
    Rule { kind: StringKind::Url, name: "url_scheme", score: 1.0, test: rule_url },
    Rule { kind: StringKind::UncPath, name: "unc", score: 0.95, test: rule_unc },
    Rule { kind: StringKind::Path, name: "win_path", score: 0.9, test: rule_win_path },
    Rule { kind: StringKind::Path, name: "unix_path", score: 0.85, test: rule_unix_path },
    Rule { kind: StringKind::Registry, name: "registry", score: 0.95, test: rule_registry },
    Rule { kind: StringKind::Format, name: "printf", score: 0.7, test: rule_format },
    Rule { kind: StringKind::Command, name: "command", score: 0.9, test: rule_command },
    Rule { kind: StringKind::Crypto, name: "crypto", score: 0.75, test: rule_crypto },
    Rule { kind: StringKind::Network, name: "network", score: 0.7, test: rule_network },
    Rule { kind: StringKind::Error, name: "error", score: 0.55, test: rule_error },
    Rule { kind: StringKind::Guid, name: "guid", score: 0.9, test: rule_guid },
    Rule { kind: StringKind::Email, name: "email", score: 0.85, test: rule_email },
    Rule { kind: StringKind::IpAddress, name: "ip", score: 0.8, test: rule_ip },
    Rule { kind: StringKind::UserAgent, name: "ua", score: 0.85, test: rule_ua },
    Rule { kind: StringKind::Mime, name: "mime", score: 0.8, test: rule_mime },
    Rule { kind: StringKind::Sql, name: "sql", score: 0.85, test: rule_sql },
    Rule { kind: StringKind::XmlHtml, name: "xml_html", score: 0.75, test: rule_xml_html },
    Rule { kind: StringKind::Base64ish, name: "base64", score: 0.6, test: rule_base64 },
    Rule { kind: StringKind::HexBlob, name: "hex", score: 0.55, test: rule_hex_blob },
    Rule { kind: StringKind::Debug, name: "debug", score: 0.5, test: rule_debug },
    Rule { kind: StringKind::Version, name: "version", score: 0.5, test: rule_version },
];

/// Classify a single string; returns the first matching rule (lua-compatible order for the core set).
pub fn classify_text(text: &str) -> Option<(StringKind, &'static str, f32)> {
    for r in RULES {
        if (r.test)(text) {
            return Some((r.kind, r.name, r.score));
        }
    }
    None
}

/// Like [`classify_text`] but returns every matching kind.
pub fn classify_text_all(text: &str) -> Vec<(StringKind, &'static str, f32)> {
    RULES
        .iter()
        .filter(|r| (r.test)(text))
        .map(|r| (r.kind, r.name, r.score))
        .collect()
}

/// Classify analysed strings (skips empty / tiny).
pub fn classify_strings(strings: &[FoundString]) -> StringReport {
    let mut report = StringReport::default();
    for s in strings {
        if s.text.len() < 4 {
            continue;
        }
        if let Some((kind, rule, score)) = classify_text(&s.text) {
            *report.by_kind.entry(kind).or_default() += 1;
            report.items.push(ClassifiedString {
                addr: s.addr,
                text: s.text.clone(),
                wide: s.wide,
                kind,
                score,
                matched_rule: rule,
            });
        }
    }
    report.items.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.addr.cmp(&b.addr))
    });
    report
}

/// Filter a report to one kind.
pub fn filter_kind(report: &StringReport, kind: StringKind) -> Vec<&ClassifiedString> {
    report.items.iter().filter(|i| i.kind == kind).collect()
}

/// Minimum score filter.
pub fn filter_score(report: &StringReport, min: f32) -> Vec<&ClassifiedString> {
    report.items.iter().filter(|i| i.score >= min).collect()
}

fn truncate_display(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i >= max {
            out.push('…');
            break;
        }
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Shannon entropy of bytes (0..8).
pub fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for b in text.bytes() {
        freq[b as usize] += 1;
    }
    let n = text.len() as f64;
    let mut h = 0.0;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// High-entropy printable strings often indicate keys / encoded blobs.
pub fn high_entropy_strings(strings: &[FoundString], min_len: usize, min_h: f64) -> Vec<(u64, f64, String)> {
    let mut out = Vec::new();
    for s in strings {
        if s.text.len() < min_len {
            continue;
        }
        let h = shannon_entropy(&s.text);
        if h >= min_h {
            out.push((s.addr, h, s.text.clone()));
        }
    }
    out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    out
}

/// Group strings by kind → addresses.
pub fn group_addrs_by_kind(report: &StringReport) -> BTreeMap<StringKind, Vec<u64>> {
    let mut m: BTreeMap<StringKind, Vec<u64>> = BTreeMap::new();
    for it in &report.items {
        m.entry(it.kind).or_default().push(it.addr);
    }
    m
}

/// Deduplicate by text (keep lowest address).
pub fn dedupe_by_text(items: &[ClassifiedString]) -> Vec<ClassifiedString> {
    let mut best: HashMap<&str, &ClassifiedString> = HashMap::new();
    for it in items {
        best.entry(it.text.as_str())
            .and_modify(|e| {
                if it.addr < e.addr {
                    *e = it;
                }
            })
            .or_insert(it);
    }
    let mut out: Vec<_> = best.values().map(|x| (*x).clone()).collect();
    out.sort_by_key(|i| i.addr);
    out
}

/// Lua-compatible classify: returns kind name or None.
pub fn classify_lua_style(text: &str) -> Option<&'static str> {
    classify_text(text).map(|(k, _, _)| k.as_str())
}

/// Build report and return kind counts as string keys (plugin parity).
pub fn kind_counts_string_keys(report: &StringReport) -> BTreeMap<String, usize> {
    report
        .by_kind
        .iter()
        .map(|(k, n)| (k.as_str().to_string(), *n))
        .collect()
}

pub fn crypto_keyword_0() -> &'static str { "AES128" }

pub fn crypto_keyword_1() -> &'static str { "AES192" }

pub fn crypto_keyword_2() -> &'static str { "AES256" }

pub fn crypto_keyword_3() -> &'static str { "AES-GCM" }

pub fn crypto_keyword_4() -> &'static str { "AES-CBC" }

pub fn crypto_keyword_5() -> &'static str { "AES-CTR" }

pub fn crypto_keyword_6() -> &'static str { "AES-ECB" }

pub fn crypto_keyword_7() -> &'static str { "RSA1024" }

pub fn crypto_keyword_8() -> &'static str { "RSA2048" }

pub fn crypto_keyword_9() -> &'static str { "RSA4096" }

pub fn crypto_keyword_10() -> &'static str { "SHA-1" }

pub fn crypto_keyword_11() -> &'static str { "SHA-256" }

pub fn crypto_keyword_12() -> &'static str { "SHA-384" }

pub fn crypto_keyword_13() -> &'static str { "SHA-512" }

pub fn crypto_keyword_14() -> &'static str { "MD4" }

pub fn crypto_keyword_15() -> &'static str { "MD5" }

pub fn crypto_keyword_16() -> &'static str { "HMAC-SHA1" }

pub fn crypto_keyword_17() -> &'static str { "HMAC-SHA256" }

pub fn crypto_keyword_18() -> &'static str { "ChaCha20" }

pub fn crypto_keyword_19() -> &'static str { "Poly1305" }

pub fn crypto_keyword_20() -> &'static str { "Curve25519" }

pub fn crypto_keyword_21() -> &'static str { "Ed25519" }

pub fn crypto_keyword_22() -> &'static str { "secp256k1" }

pub fn crypto_keyword_23() -> &'static str { "secp256r1" }

pub fn crypto_keyword_24() -> &'static str { "X25519" }

pub fn crypto_keyword_25() -> &'static str { "HKDF" }

pub fn crypto_keyword_26() -> &'static str { "PBKDF2" }

pub fn crypto_keyword_27() -> &'static str { "scrypt" }

pub fn crypto_keyword_28() -> &'static str { "Argon2i" }

pub fn crypto_keyword_29() -> &'static str { "Argon2id" }

pub fn crypto_keyword_30() -> &'static str { "bcrypt" }

pub fn crypto_keyword_31() -> &'static str { "Nettle" }

pub fn crypto_keyword_32() -> &'static str { "OpenSSL" }

pub fn crypto_keyword_33() -> &'static str { "LibreSSL" }

pub fn crypto_keyword_34() -> &'static str { "BoringSSL" }

pub fn crypto_keyword_35() -> &'static str { "CryptoAPI" }

pub fn crypto_keyword_36() -> &'static str { "CNG" }

pub fn crypto_keyword_37() -> &'static str { "BCryptOpenAlgorithmProvider" }

pub fn crypto_keyword_38() -> &'static str { "CryptAcquireContext" }

pub fn crypto_keyword_39() -> &'static str { "NCrypt" }

pub fn crypto_keyword_40() -> &'static str { "DPAPI" }

pub fn crypto_keyword_41() -> &'static str { "CryptProtectData" }

pub fn crypto_keyword_42() -> &'static str { "CryptUnprotectData" }

pub fn crypto_keyword_43() -> &'static str { "CertOpenStore" }

pub fn crypto_keyword_44() -> &'static str { "PKCS7" }

pub fn crypto_keyword_45() -> &'static str { "PKCS8" }

pub fn crypto_keyword_46() -> &'static str { "PKCS12" }

pub fn crypto_keyword_47() -> &'static str { "PEM" }

pub fn crypto_keyword_48() -> &'static str { "DER" }

pub fn crypto_keyword_49() -> &'static str { "ASN.1" }

pub fn crypto_keyword_50() -> &'static str { "X.509" }

pub fn crypto_keyword_51() -> &'static str { "TLS1.2" }

pub fn crypto_keyword_52() -> &'static str { "TLS1.3" }

pub fn crypto_keyword_53() -> &'static str { "SSL3" }

pub fn crypto_keyword_54() -> &'static str { "DTLS" }

pub fn crypto_keyword_55() -> &'static str { "QUIC" }

pub fn crypto_keyword_56() -> &'static str { "Noise_XX" }

pub fn crypto_keyword_57() -> &'static str { "WireGuard" }

pub fn crypto_keyword_58() -> &'static str { "Signal Protocol" }

pub fn crypto_keyword_list() -> Vec<&'static str> {
    vec![
        crypto_keyword_0(),
        crypto_keyword_1(),
        crypto_keyword_2(),
        crypto_keyword_3(),
        crypto_keyword_4(),
        crypto_keyword_5(),
        crypto_keyword_6(),
        crypto_keyword_7(),
        crypto_keyword_8(),
        crypto_keyword_9(),
        crypto_keyword_10(),
        crypto_keyword_11(),
        crypto_keyword_12(),
        crypto_keyword_13(),
        crypto_keyword_14(),
        crypto_keyword_15(),
        crypto_keyword_16(),
        crypto_keyword_17(),
        crypto_keyword_18(),
        crypto_keyword_19(),
        crypto_keyword_20(),
        crypto_keyword_21(),
        crypto_keyword_22(),
        crypto_keyword_23(),
        crypto_keyword_24(),
        crypto_keyword_25(),
        crypto_keyword_26(),
        crypto_keyword_27(),
        crypto_keyword_28(),
        crypto_keyword_29(),
        crypto_keyword_30(),
        crypto_keyword_31(),
        crypto_keyword_32(),
        crypto_keyword_33(),
        crypto_keyword_34(),
        crypto_keyword_35(),
        crypto_keyword_36(),
        crypto_keyword_37(),
        crypto_keyword_38(),
        crypto_keyword_39(),
        crypto_keyword_40(),
        crypto_keyword_41(),
        crypto_keyword_42(),
        crypto_keyword_43(),
        crypto_keyword_44(),
        crypto_keyword_45(),
        crypto_keyword_46(),
        crypto_keyword_47(),
        crypto_keyword_48(),
        crypto_keyword_49(),
        crypto_keyword_50(),
        crypto_keyword_51(),
        crypto_keyword_52(),
        crypto_keyword_53(),
        crypto_keyword_54(),
        crypto_keyword_55(),
        crypto_keyword_56(),
        crypto_keyword_57(),
        crypto_keyword_58(),
    ]
}

pub fn text_has_crypto_keyword(text: &str) -> Option<&'static str> {
    let l = text.to_ascii_lowercase();
    for k in crypto_keyword_list() {
        if l.contains(&k.to_ascii_lowercase()) {
            return Some(k);
        }
    }
    None
}

pub fn network_keyword_0() -> &'static str { "GET " }

pub fn network_keyword_1() -> &'static str { "POST " }

pub fn network_keyword_2() -> &'static str { "PUT " }

pub fn network_keyword_3() -> &'static str { "DELETE " }

pub fn network_keyword_4() -> &'static str { "PATCH " }

pub fn network_keyword_5() -> &'static str { "HEAD " }

pub fn network_keyword_6() -> &'static str { "OPTIONS " }

pub fn network_keyword_7() -> &'static str { "HTTP/1.0" }

pub fn network_keyword_8() -> &'static str { "HTTP/1.1" }

pub fn network_keyword_9() -> &'static str { "HTTP/2" }

pub fn network_keyword_10() -> &'static str { "Host:" }

pub fn network_keyword_11() -> &'static str { "Cookie:" }

pub fn network_keyword_12() -> &'static str { "Set-Cookie" }

pub fn network_keyword_13() -> &'static str { "Authorization:" }

pub fn network_keyword_14() -> &'static str { "Bearer " }

pub fn network_keyword_15() -> &'static str { "Proxy-Connection" }

pub fn network_keyword_16() -> &'static str { "Keep-Alive" }

pub fn network_keyword_17() -> &'static str { "Content-Length" }

pub fn network_keyword_18() -> &'static str { "Transfer-Encoding" }

pub fn network_keyword_19() -> &'static str { "gzip" }

pub fn network_keyword_20() -> &'static str { "deflate" }

pub fn network_keyword_21() -> &'static str { "br" }

pub fn network_keyword_22() -> &'static str { "websocket" }

pub fn network_keyword_23() -> &'static str { "Sec-WebSocket" }

pub fn network_keyword_24() -> &'static str { "Upgrade:" }

pub fn network_keyword_25() -> &'static str { "CONNECT " }

pub fn network_keyword_26() -> &'static str { "SOCKS5" }

pub fn network_keyword_27() -> &'static str { "DNS query" }

pub fn network_keyword_28() -> &'static str { "A record" }

pub fn network_keyword_29() -> &'static str { "AAAA" }

pub fn network_keyword_30() -> &'static str { "CNAME" }

pub fn network_keyword_31() -> &'static str { "MX record" }

pub fn network_keyword_32() -> &'static str { "TXT record" }

pub fn network_keyword_33() -> &'static str { "WinHttpOpen" }

pub fn network_keyword_34() -> &'static str { "WinHttpConnect" }

pub fn network_keyword_35() -> &'static str { "InternetOpen" }

pub fn network_keyword_36() -> &'static str { "InternetConnect" }

pub fn network_keyword_37() -> &'static str { "URLDownloadToFile" }

pub fn network_keyword_38() -> &'static str { "curl " }

pub fn network_keyword_39() -> &'static str { "wget " }

pub fn network_keyword_40() -> &'static str { "libcurl" }

pub fn network_keyword_41() -> &'static str { "reqwest" }

pub fn network_keyword_list() -> Vec<&'static str> {
    vec![
        network_keyword_0(),
        network_keyword_1(),
        network_keyword_2(),
        network_keyword_3(),
        network_keyword_4(),
        network_keyword_5(),
        network_keyword_6(),
        network_keyword_7(),
        network_keyword_8(),
        network_keyword_9(),
        network_keyword_10(),
        network_keyword_11(),
        network_keyword_12(),
        network_keyword_13(),
        network_keyword_14(),
        network_keyword_15(),
        network_keyword_16(),
        network_keyword_17(),
        network_keyword_18(),
        network_keyword_19(),
        network_keyword_20(),
        network_keyword_21(),
        network_keyword_22(),
        network_keyword_23(),
        network_keyword_24(),
        network_keyword_25(),
        network_keyword_26(),
        network_keyword_27(),
        network_keyword_28(),
        network_keyword_29(),
        network_keyword_30(),
        network_keyword_31(),
        network_keyword_32(),
        network_keyword_33(),
        network_keyword_34(),
        network_keyword_35(),
        network_keyword_36(),
        network_keyword_37(),
        network_keyword_38(),
        network_keyword_39(),
        network_keyword_40(),
        network_keyword_41(),
    ]
}

pub fn text_has_network_keyword(text: &str) -> Option<&'static str> {
    let l = text.to_ascii_lowercase();
    for k in network_keyword_list() {
        if l.contains(&k.to_ascii_lowercase()) {
            return Some(k);
        }
    }
    None
}

/// Extended classify that also consults keyword lists for score boosts.
pub fn classify_with_boosts(text: &str) -> Option<(StringKind, &'static str, f32)> {
    let mut base = classify_text(text);
    if let Some(k) = text_has_crypto_keyword(text) {
        match &mut base {
            Some((kind, rule, score)) if *kind == StringKind::Crypto => {
                *score = (*score + 0.15).min(1.0);
                let _ = (k, rule);
            }
            None => base = Some((StringKind::Crypto, "crypto_kw", 0.8)),
            _ => {}
        }
    }
    if let Some(k) = text_has_network_keyword(text) {
        match &mut base {
            Some((kind, rule, score)) if *kind == StringKind::Network => {
                *score = (*score + 0.15).min(1.0);
                let _ = (k, rule);
            }
            None => base = Some((StringKind::Network, "network_kw", 0.75)),
            _ => {}
        }
    }
    base
}

/// Score how "interesting" a string is even without a hard rule match.
pub fn interestingness_heuristic(text: &str) -> f32 {
    let mut s = 0.0f32;
    if text.len() >= 8 {
        s += 0.1;
    }
    if text.chars().any(|c| c == '/' || c == '\\') {
        s += 0.1;
    }
    if text.contains('.') {
        s += 0.05;
    }
    let h = shannon_entropy(text) as f32;
    if h > 4.0 {
        s += 0.2;
    }
    if text.chars().any(|c| c.is_ascii_uppercase()) && text.chars().any(|c| c.is_ascii_lowercase()) {
        s += 0.05;
    }
    if classify_text(text).is_some() {
        s += 0.5;
    }
    s.min(1.0)
}

/// Batch classify with boosts.
pub fn classify_strings_boosted(strings: &[FoundString]) -> StringReport {
    let mut report = StringReport::default();
    for s in strings {
        if s.text.len() < 4 {
            continue;
        }
        if let Some((kind, rule, score)) = classify_with_boosts(&s.text) {
            *report.by_kind.entry(kind).or_default() += 1;
            report.items.push(ClassifiedString {
                addr: s.addr,
                text: s.text.clone(),
                wide: s.wide,
                kind,
                score,
                matched_rule: rule,
            });
        }
    }
    report.items.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.addr.cmp(&b.addr))
    });
    report
}

/// Collect unique texts for a kind.
pub fn unique_texts(report: &StringReport, kind: StringKind) -> BTreeSet<String> {
    report
        .items
        .iter()
        .filter(|i| i.kind == kind)
        .map(|i| i.text.clone())
        .collect()
}

/// JSON-ish lines for tooling (no serde dep in analysis).
/// JSON-ish lines for tooling (no serde dep in analysis).
pub fn report_as_jsonl(report: &StringReport) -> String {
    let mut out = String::new();
    for it in &report.items {
        let esc = it.text.replace('\\', "\\\\").replace('"', "\\\"");
        out.push_str("{\"addr\":\"");
        out.push_str(&format!("{:X}", it.addr));
        out.push_str("\",\"kind\":\"");
        out.push_str(it.kind.as_str());
        out.push_str("\",\"score\":");
        out.push_str(&format!("{:.3}", it.score));
        out.push_str(",\"rule\":\"");
        out.push_str(&it.matched_rule);
        out.push_str("\",\"wide\":");
        out.push_str(if it.wide { "true" } else { "false" });
        out.push_str(",\"text\":\"");
        out.push_str(&esc);
        out.push_str("\"}\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FoundString;

    fn fs(addr: u64, text: &str) -> FoundString {
        FoundString {
            addr,
            len: text.len() as u32 + 1,
            wide: false,
            text: text.to_string(),
        }
    }

    #[test]
    fn classifies_common_patterns() {
        assert_eq!(classify_lua_style("https://example.com/a"), Some("url"));
        assert_eq!(classify_lua_style("C:\\\\Windows\\\\System32"), Some("path"));
        assert_eq!(classify_lua_style("HKEY_LOCAL_MACHINE\\\\Software"), Some("registry"));
        assert_eq!(classify_lua_style("value=%d"), Some("format"));
        assert_eq!(classify_lua_style("SOFTWARE\\\\Foo\\\\Bar"), Some("registry"));
    }

    #[test]
    fn report_groups() {
        let strs = vec![
            fs(0x100, "https://x.test/"),
            fs(0x200, "aes-gcm key"),
            fs(0x300, "boring"),
            fs(0x400, "SELECT * FROM t"),
        ];
        let r = classify_strings(&strs);
        assert!(r.by_kind.contains_key(&StringKind::Url));
        assert!(r.by_kind.contains_key(&StringKind::Crypto));
        assert!(r.by_kind.contains_key(&StringKind::Sql));
        assert!(!r.items.iter().any(|i| i.text == "boring"));
        let listing = r.format_listing(40);
        assert!(listing.contains("interesting string"));
    }

    #[test]
    fn entropy_and_guid() {
        assert!(rule_guid("550e8400-e29b-41d4-a716-446655440000"));
        let h = shannon_entropy("AAAABBBBCCCCDDDD");
        assert!(h > 1.0);
        assert!(text_has_crypto_keyword("use AES256 please").is_some());
    }

    #[test]
    fn boosts_and_dedupe() {
        let strs = vec![fs(1, "https://a"), fs(2, "https://a")];
        let r = classify_strings_boosted(&strs);
        let d = dedupe_by_text(&r.items);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].addr, 1);
    }
}
