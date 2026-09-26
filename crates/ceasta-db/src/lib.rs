//! User annotations on top of a loaded `Binary` + `Analysis`.

mod bookmarks;
mod recent;
mod undo;

pub use bookmarks::{Bookmark, Bookmarks};
pub use recent::{
    load_recent_files, save_recent_files, RecentAddrs, RecentFiles, RecentState,
};
pub use undo::{AnnotationSnapshot, BatchGuard, Edit, UndoStack};

use ceasta_analysis::{self, Analysis, Function};
use ceasta_binary::Binary;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProjectFile {
    pub names: BTreeMap<String, String>,
    pub comments: BTreeMap<String, String>,
    pub breakpoints: Vec<String>,
    #[serde(default)]
    pub bookmarks: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Database {
    pub bin: Binary,
    pub analysis: Analysis,
    pub names: BTreeMap<u64, String>,
    pub comments: BTreeMap<u64, String>,
    pub breakpoints: BTreeSet<u64>,
    pub bookmarks: Bookmarks,
    pub recent: RecentState,
    pub undo: UndoStack,
    /// Cursor for Lua `here` / UI (also mirrored in script host).
    pub here: u64,
    pub dirty: bool,
}

impl Database {
    pub fn new(bin: Binary, analysis: Analysis) -> Self {
        let mut names = BTreeMap::new();
        for s in &bin.symbols {
            if !s.name.is_empty() {
                names.insert(s.addr, s.name.clone());
            }
        }
        for f in &analysis.functions {
            names.entry(f.start).or_insert_with(|| f.name.clone());
        }
        let here = if bin.has_entry { bin.entry } else { bin.base };
        Self {
            bin,
            analysis,
            names,
            comments: BTreeMap::new(),
            breakpoints: BTreeSet::new(),
            bookmarks: Bookmarks::default(),
            recent: RecentState::default(),
            undo: UndoStack::default(),
            here,
            dirty: false,
        }
    }

    pub fn set_name(&mut self, addr: u64, name: impl Into<String>) {
        let new = Some(name.into()).filter(|s| !s.is_empty());
        let old = undo::apply_name(&mut self.names, addr, new.clone());
        if old != new {
            self.undo.push_name(addr, old, new);
            self.dirty = true;
        }
    }

    pub fn set_comment(&mut self, addr: u64, text: impl Into<String>) {
        let new = Some(text.into()).filter(|s| !s.is_empty());
        let old = undo::apply_comment(&mut self.comments, addr, new.clone());
        if old != new {
            self.undo.push_comment(addr, old, new);
            self.dirty = true;
        }
    }

    pub fn toggle_bookmark(&mut self, addr: u64) -> bool {
        let on = self.bookmarks.toggle(addr);
        self.undo.push(Edit::ToggleBookmark { addr, added: on });
        self.dirty = true;
        on
    }

    pub fn bookmarks_list(&self) -> Vec<u64> {
        self.bookmarks.list()
    }

    pub fn push_recent(&mut self, path: impl Into<PathBuf>) {
        self.recent.push_file(path);
    }

    pub fn push_recent_addr(&mut self, addr: u64) {
        self.recent.push_addr(addr);
    }

    pub fn set_here(&mut self, addr: u64) {
        self.here = addr;
        self.push_recent_addr(addr);
    }

    pub fn comment_at(&self, addr: u64) -> String {
        self.comments.get(&addr).cloned().unwrap_or_default()
    }

    pub fn can_undo(&self) -> bool {
        self.undo.can_undo()
    }

    pub fn can_redo(&self) -> bool {
        self.undo.can_redo()
    }

    /// Undo the last annotation edit.
    pub fn undo(&mut self) -> bool {
        self.undo_edit()
    }

    /// Redo the last undone annotation edit.
    pub fn redo(&mut self) -> bool {
        self.redo_edit()
    }

    pub fn undo_edit(&mut self) -> bool {
        self.undo.flush_coalesce();
        let Some(e) = self.undo.pop_undo() else {
            return false;
        };
        self.undo.muted = true;
        undo::apply_edit_undo(
            &mut self.names,
            &mut self.comments,
            &mut self.bookmarks,
            &e,
        );
        self.undo.muted = false;
        self.undo.push_redo(e);
        self.dirty = true;
        true
    }

    pub fn redo_edit(&mut self) -> bool {
        let Some(e) = self.undo.pop_redo() else {
            return false;
        };
        self.undo.muted = true;
        undo::apply_edit_forward(
            &mut self.names,
            &mut self.comments,
            &mut self.bookmarks,
            &e,
        );
        self.undo.muted = false;
        self.undo.push_undo_silent(e);
        self.dirty = true;
        true
    }

    pub fn fmt_addr(&self, addr: u64) -> String {
        if self.bin.is64() {
            format!("{addr:016X}")
        } else {
            format!("{addr:08X}")
        }
    }

    pub fn name_at(&self, addr: u64) -> String {
        self.names.get(&addr).cloned().unwrap_or_default()
    }

    pub fn location(&self, addr: u64) -> String {
        if let Some(n) = self.names.get(&addr) {
            return n.clone();
        }
        for f in &self.analysis.functions {
            if addr >= f.start && addr < f.end {
                if addr == f.start {
                    return f.name.clone();
                }
                return format!("{}+{:X}", f.name, addr - f.start);
            }
        }
        format!("{addr:X}")
    }

    /// Hex address or any known name (`sub_401000`, `start`, symbol, …).
    pub fn resolve(&self, s: &str) -> Option<u64> {
        let t = s.trim();
        if t.is_empty() {
            return None;
        }
        if t.eq_ignore_ascii_case("entry") || t.eq_ignore_ascii_case("start") {
            return self.bin.has_entry.then_some(self.bin.entry);
        }
        if let Some(&a) = self
            .names
            .iter()
            .find(|(_, n)| n.eq_ignore_ascii_case(t))
            .map(|(a, _)| a)
        {
            return Some(a);
        }
        if let Some(f) = self
            .analysis
            .functions
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(t))
        {
            return Some(f.start);
        }
        let hex = t.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(hex, 16).ok()
    }

    pub fn project_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.ceasta", self.bin.path))
    }

    pub fn to_project(&self) -> ProjectFile {
        ProjectFile {
            names: self
                .names
                .iter()
                .map(|(a, n)| (format!("{a:X}"), n.clone()))
                .collect(),
            comments: self
                .comments
                .iter()
                .map(|(a, c)| (format!("{a:X}"), c.clone()))
                .collect(),
            breakpoints: self.breakpoints.iter().map(|a| format!("{a:X}")).collect(),
            bookmarks: self.bookmarks.list().iter().map(|a| format!("{a:X}")).collect(),
        }
    }

    pub fn apply_project(&mut self, p: &ProjectFile) {
        for (k, v) in &p.names {
            if let Ok(a) = u64::from_str_radix(k.trim_start_matches("0x"), 16) {
                self.names.insert(a, v.clone());
            }
        }
        for (k, v) in &p.comments {
            if let Ok(a) = u64::from_str_radix(k.trim_start_matches("0x"), 16) {
                self.comments.insert(a, v.clone());
            }
        }
        for k in &p.breakpoints {
            if let Ok(a) = u64::from_str_radix(k.trim_start_matches("0x"), 16) {
                self.breakpoints.insert(a);
            }
        }
        for k in &p.bookmarks {
            if let Ok(a) = u64::from_str_radix(k.trim_start_matches("0x"), 16) {
                self.bookmarks.add(a);
            }
        }
        self.dirty = true;
    }

    pub fn save_project(&self) -> Result<PathBuf> {
        let path = self.project_path();
        self.save_project_to(&path)?;
        Ok(path)
    }

    pub fn save_project_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.to_project())?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_project_file(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let text = std::fs::read_to_string(path)?;
        let p: ProjectFile = serde_json::from_str(&text)?;
        self.apply_project(&p);
        Ok(())
    }

    pub fn find_bytes(&self, pattern: &str, max: usize) -> std::result::Result<Vec<u64>, String> {
        ceasta_analysis::find_bytes(&self.bin, pattern, max)
    }

    pub fn func_at(&self, addr: u64) -> Option<&Function> {
        self.analysis.func_containing(addr)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HitKind {
    Address,
    Function,
    Name,
    Import,
    Export,
    String,
    Comment,
    Segment,
}

impl HitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HitKind::Address => "address",
            HitKind::Function => "function",
            HitKind::Name => "name",
            HitKind::Import => "import",
            HitKind::Export => "export",
            HitKind::String => "string",
            HitKind::Comment => "comment",
            HitKind::Segment => "segment",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SearchHit {
    pub kind: HitKind,
    pub addr: u64,
    pub text: String,
    pub extra: String,
}

/// Case-insensitive substring search across names, imports, exports, strings, comments, segments.
pub fn search_everything(
    db: &Database,
    query: &str,
    max_per_kind: usize,
) -> (Vec<SearchHit>, bool) {
    let q = query.to_ascii_lowercase();
    let mut hits = Vec::new();
    let mut cut = false;

    let mut push = |kind: HitKind, addr: u64, text: String, extra: String, count: &mut usize| {
        if *count >= max_per_kind {
            cut = true;
            return;
        }
        hits.push(SearchHit {
            kind,
            addr,
            text,
            extra,
        });
        *count += 1;
    };

    // hex address
    if let Some(a) = db.resolve(query) {
        if db.bin.is_mapped(a) {
            let mut c = 0;
            push(
                HitKind::Address,
                a,
                db.fmt_addr(a),
                db.location(a),
                &mut c,
            );
        }
    }

    let mut c = 0;
    for f in &db.analysis.functions {
        if f.name.to_ascii_lowercase().contains(&q) {
            push(
                HitKind::Function,
                f.start,
                f.name.clone(),
                db.fmt_addr(f.start),
                &mut c,
            );
        }
    }

    c = 0;
    for (&a, n) in &db.names {
        if n.to_ascii_lowercase().contains(&q)
            && !db
                .analysis
                .functions
                .iter()
                .any(|f| f.start == a && f.name == *n)
        {
            push(HitKind::Name, a, n.clone(), db.fmt_addr(a), &mut c);
        }
    }

    c = 0;
    for e in &db.bin.imports {
        let label = format!("{}!{}", e.lib, e.name);
        if label.to_ascii_lowercase().contains(&q) {
            push(
                HitKind::Import,
                e.slot,
                label,
                e.lib.clone(),
                &mut c,
            );
        }
    }

    c = 0;
    for e in &db.bin.exports {
        if e.name.to_ascii_lowercase().contains(&q) {
            push(
                HitKind::Export,
                e.addr,
                e.name.clone(),
                if e.forward.is_empty() {
                    String::new()
                } else {
                    format!("-> {}", e.forward)
                },
                &mut c,
            );
        }
    }

    c = 0;
    for s in &db.analysis.strings {
        if s.text.to_ascii_lowercase().contains(&q) {
            push(
                HitKind::String,
                s.addr,
                format!("\"{}\"", escape_short(&s.text, 80)),
                String::new(),
                &mut c,
            );
        }
    }

    c = 0;
    for (&a, text) in &db.comments {
        if text.to_ascii_lowercase().contains(&q) {
            push(
                HitKind::Comment,
                a,
                text.clone(),
                db.location(a),
                &mut c,
            );
        }
    }

    c = 0;
    for s in &db.bin.segments {
        if s.name.to_ascii_lowercase().contains(&q) {
            push(
                HitKind::Segment,
                s.start,
                s.name.clone(),
                format!("{} - {}", db.fmt_addr(s.start), db.fmt_addr(s.end)),
                &mut c,
            );
        }
    }

    (hits, cut)
}

fn escape_short(s: &str, max: usize) -> String {
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
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Default)]
pub struct ImportResult {
    pub names: usize,
    pub comments: usize,
    pub error: Option<String>,
}

impl ImportResult {
    pub fn summary(&self) -> String {
        format!(
            "imported {} name{}, {} comment{}",
            self.names,
            if self.names == 1 { "" } else { "s" },
            self.comments,
            if self.comments == 1 { "" } else { "s" }
        )
    }
}

/// Import names from a `.ceasta` / ida/ghidra JSON (`{"names":{"401000":"main"},...}`).
pub fn import_names(db: &mut Database, path: impl AsRef<Path>) -> ImportResult {
    let path = path.as_ref();
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            return ImportResult {
                error: Some(format!("can't read {}: {e}", path.display())),
                ..Default::default()
            };
        }
    };
    // try project JSON first
    if let Ok(p) = serde_json::from_str::<ProjectFile>(&text) {
        let before_n = db.names.len();
        let before_c = db.comments.len();
        db.apply_project(&p);
        return ImportResult {
            names: db.names.len().saturating_sub(before_n).max(p.names.len()),
            comments: db
                .comments
                .len()
                .saturating_sub(before_c)
                .max(p.comments.len()),
            error: None,
        };
    }
    // map file: "addr name" hex lines
    if path.extension().and_then(|e| e.to_str()) == Some("map")
        || text.lines().take(3).any(|l| l.contains(' '))
    {
        let mut n = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(a) = parts.next() else { continue };
            let Some(name) = parts.next() else { continue };
            let a = a.trim_start_matches("0x").trim_start_matches("0X");
            if let Ok(addr) = u64::from_str_radix(a, 16) {
                db.set_name(addr, name);
                n += 1;
            }
        }
        if n > 0 {
            return ImportResult {
                names: n,
                comments: 0,
                error: None,
            };
        }
    }
    ImportResult {
        error: Some(
            "unrecognized names file (want .ceasta / names JSON, or a simple ADDR NAME .map)"
                .into(),
        ),
        ..Default::default()
    }
}

/// Thin IDA Python export of user names + comments.
pub fn export_ida(db: &Database) -> String {
    let mut out = String::from("# ceasta -> ida names/comments\nimport idc\n\n");
    for (&a, n) in &db.names {
        out.push_str(&format!(
            "idc.set_name(0x{a:X}, \"{}\")\n",
            n.replace('\"', "\\\"")
        ));
    }
    for (&a, c) in &db.comments {
        out.push_str(&format!(
            "idc.set_cmt(0x{a:X}, \"{}\", 0)\n",
            c.replace('\"', "\\\"")
        ));
    }
    out
}

pub fn export_ghidra(db: &Database) -> String {
    let mut out = String::from("// ceasta -> ghidra names/comments\n");
    out.push_str("@category Analysis\n\n");
    for (&a, n) in &db.names {
        out.push_str(&format!(
            "createLabel(toAddr(0x{a:X}), \"{}\", true)\n",
            n.replace('\"', "\\\"")
        ));
    }
    for (&a, c) in &db.comments {
        out.push_str(&format!(
            "setPreComment(toAddr(0x{a:X}), \"{}\")\n",
            c.replace('\"', "\\\"")
        ));
    }
    out
}

pub fn export_x64dbg(db: &Database) -> String {
    // minimal dd64-ish JSON
    let labels: Vec<_> = db
        .names
        .iter()
        .map(|(a, n)| serde_json::json!({"module": db.bin.name, "address": format!("{a:X}"), "text": n}))
        .collect();
    let comments: Vec<_> = db
        .comments
        .iter()
        .map(|(a, c)| serde_json::json!({"module": db.bin.name, "address": format!("{a:X}"), "text": c}))
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "labels": labels,
        "comments": comments,
    }))
    .unwrap_or_else(|_| "{}".into())
}

// --- thin signatures -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Signature {
    pub name: String,
    pub length: u32,
    pub hash: u64,
}

#[derive(Clone, Debug)]
pub struct SigMatch {
    pub addr: u64,
    pub name: String,
}

pub fn make_signatures(db: &Database) -> Vec<Signature> {
    let mut out = Vec::new();
    for f in &db.analysis.functions {
        let name = db.name_at(f.start);
        if name.is_empty() || name.starts_with("sub_") {
            continue;
        }
        let len = (f.end - f.start) as u32;
        let hash = func_hash(db, f);
        out.push(Signature {
            name,
            length: len,
            hash,
        });
    }
    out
}

pub fn signatures_to_text(sigs: &[Signature]) -> String {
    let mut s = String::new();
    for sig in sigs {
        s.push_str(&format!("{:016x} {} {}\n", sig.hash, sig.length, sig.name));
    }
    s
}

pub fn signatures_from_text(text: &str) -> Vec<Signature> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, ' ');
        let (Some(h), Some(l), Some(n)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let Ok(hash) = u64::from_str_radix(h, 16) else {
            continue;
        };
        let Ok(length) = l.parse() else {
            continue;
        };
        out.push(Signature {
            name: n.to_string(),
            length,
            hash,
        });
    }
    out
}

pub fn match_signatures(db: &mut Database, sigs: &[Signature], apply: bool) -> Vec<SigMatch> {
    let mut by_key: BTreeMap<(u32, u64), &Signature> = BTreeMap::new();
    for s in sigs {
        // unique keys only
        let key = (s.length, s.hash);
        if by_key.contains_key(&key) {
            by_key.remove(&key);
        } else {
            by_key.insert(key, s);
        }
    }
    // rebuild uniqueness properly: count first
    let mut counts: BTreeMap<(u32, u64), usize> = BTreeMap::new();
    for s in sigs {
        *counts.entry((s.length, s.hash)).or_default() += 1;
    }
    by_key.clear();
    for s in sigs {
        if counts.get(&(s.length, s.hash)) == Some(&1) {
            by_key.insert((s.length, s.hash), s);
        }
    }

    let mut matches = Vec::new();
    for f in &db.analysis.functions {
        let cur = db.name_at(f.start);
        if !cur.is_empty() && !cur.starts_with("sub_") {
            continue;
        }
        let len = (f.end - f.start) as u32;
        let hash = func_hash(db, f);
        if let Some(sig) = by_key.get(&(len, hash)) {
            matches.push(SigMatch {
                addr: f.start,
                name: sig.name.clone(),
            });
        }
    }
    if apply {
        for m in &matches {
            db.set_name(m.addr, m.name.clone());
        }
    }
    matches
}

fn func_hash(db: &Database, f: &Function) -> u64 {
    // FNV-1a over up to 256 bytes, wildcards for relative call/jump not applied yet (thin)
    let mut h: u64 = 0xcbf29ce484222325;
    let mut buf = [0u8; 256];
    let n = db.bin.read(f.start, &mut buf);
    let take = n.min((f.end - f.start) as usize).min(256);
    for &b in &buf[..take] {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^= u64::from(take as u32);
    h
}

// --- thin diff -------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DiffPair {
    pub a: u64,
    pub b: u64,
    pub name: String,
    pub similarity: f64,
}

#[derive(Clone, Debug, Default)]
pub struct DiffResult {
    pub identical: Vec<DiffPair>,
    pub changed: Vec<DiffPair>,
    pub removed: Vec<u64>,
    pub added: Vec<u64>,
    pub funcs_a: usize,
    pub funcs_b: usize,
}

pub fn diff_databases(a: &Database, b: &Database) -> DiffResult {
    let mut out = DiffResult {
        funcs_a: a.analysis.functions.len(),
        funcs_b: b.analysis.functions.len(),
        ..Default::default()
    };
    let mut used_b = BTreeSet::new();
    for fa in &a.analysis.functions {
        let name_a = a.name_at(fa.start);
        let key_a = if !name_a.is_empty() {
            name_a.clone()
        } else {
            format!("size:{}", fa.end - fa.start)
        };
        let mut best: Option<(usize, f64)> = None;
        for (i, fb) in b.analysis.functions.iter().enumerate() {
            if used_b.contains(&i) {
                continue;
            }
            let name_b = b.name_at(fb.start);
            let by_name = !name_a.is_empty()
                && !name_a.starts_with("sub_")
                && name_a == name_b;
            let size_ok = (fa.end - fa.start) == (fb.end - fb.start);
            if !by_name && !(size_ok && name_a.starts_with("sub_") && name_b.starts_with("sub_")) {
                if !by_name {
                    // try hash match
                    if func_hash(a, fa) != func_hash(b, fb) && !size_ok {
                        continue;
                    }
                    if !size_ok {
                        continue;
                    }
                }
            }
            let sim = if func_hash(a, fa) == func_hash(b, fb) {
                1.0
            } else if size_ok {
                0.7
            } else {
                0.4
            };
            if by_name || sim >= 0.7 {
                if best.map(|(_, s)| sim > s).unwrap_or(true) {
                    best = Some((i, sim));
                }
            }
            let _ = key_a;
        }
        if let Some((i, sim)) = best {
            used_b.insert(i);
            let fb = &b.analysis.functions[i];
            let pair = DiffPair {
                a: fa.start,
                b: fb.start,
                name: if !name_a.is_empty() {
                    name_a
                } else {
                    a.location(fa.start)
                },
                similarity: sim,
            };
            if (sim - 1.0).abs() < f64::EPSILON {
                out.identical.push(pair);
            } else {
                out.changed.push(pair);
            }
        } else {
            out.removed.push(fa.start);
        }
    }
    for (i, fb) in b.analysis.functions.iter().enumerate() {
        if !used_b.contains(&i) {
            out.added.push(fb.start);
        }
    }
    out.changed.sort_by(|x, y| {
        y.similarity
            .partial_cmp(&x.similarity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}
