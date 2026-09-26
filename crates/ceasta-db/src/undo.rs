//! Undo / redo stacks for names and comments (and bookmark toggles).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single reversible edit against annotation maps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Edit {
    SetName {
        addr: u64,
        old: Option<String>,
        new: Option<String>,
    },
    SetComment {
        addr: u64,
        old: Option<String>,
        new: Option<String>,
    },
    ToggleBookmark {
        addr: u64,
        /// true if the bookmark was added by this edit; false if removed.
        added: bool,
    },
    /// Batch of edits applied as one undo step.
    Batch {
        label: String,
        edits: Vec<Edit>,
    },
}

impl Edit {
    pub fn label(&self) -> String {
        match self {
            Edit::SetName { addr, new, .. } => match new {
                Some(n) => format!("name {addr:X} -> {n}"),
                None => format!("clear name {addr:X}"),
            },
            Edit::SetComment { addr, new, .. } => match new {
                Some(_) => format!("comment {addr:X}"),
                None => format!("clear comment {addr:X}"),
            },
            Edit::ToggleBookmark { addr, added } => {
                if *added {
                    format!("bookmark +{addr:X}")
                } else {
                    format!("bookmark -{addr:X}")
                }
            }
            Edit::Batch { label, edits } => format!("{label} ({} edits)", edits.len()),
        }
    }

    pub fn invert(self) -> Edit {
        match self {
            Edit::SetName { addr, old, new } => Edit::SetName {
                addr,
                old: new,
                new: old,
            },
            Edit::SetComment { addr, old, new } => Edit::SetComment {
                addr,
                old: new,
                new: old,
            },
            Edit::ToggleBookmark { addr, added } => Edit::ToggleBookmark {
                addr,
                added: !added,
            },
            Edit::Batch { label, edits } => Edit::Batch {
                label,
                edits: edits.into_iter().rev().map(Edit::invert).collect(),
            },
        }
    }

    pub fn addrs(&self) -> Vec<u64> {
        match self {
            Edit::SetName { addr, .. }
            | Edit::SetComment { addr, .. }
            | Edit::ToggleBookmark { addr, .. } => vec![*addr],
            Edit::Batch { edits, .. } => edits.iter().flat_map(|e| e.addrs()).collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct UndoStack {
    undo: Vec<Edit>,
    redo: Vec<Edit>,
    /// When true, applying an edit does not push (used while undoing/redoing).
    pub muted: bool,
    pub max_depth: usize,
    /// Coalesce consecutive name/comment edits on the same address within this window.
    coalesce: Option<PendingCoalesce>,
}

#[derive(Clone, Debug)]
struct PendingCoalesce {
    edit: Edit,
    /// wall-ish counter; caller bumps via touch.
    gen: u64,
}

impl Default for UndoStack {
    fn default() -> Self {
        Self {
            undo: Vec::new(),
            redo: Vec::new(),
            muted: false,
            max_depth: 2048,
            coalesce: None,
        }
    }
}

impl UndoStack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_depth(max_depth: usize) -> Self {
        Self {
            max_depth: max_depth.max(1),
            ..Self::default()
        }
    }

    pub fn len(&self) -> usize {
        self.undo.len()
    }

    pub fn redo_len(&self) -> usize {
        self.redo.len()
    }

    pub fn is_empty(&self) -> bool {
        self.undo.is_empty()
    }

    pub fn clear(&mut self) {
        self.undo.clear();
        self.redo.clear();
        self.coalesce = None;
    }

    pub fn push(&mut self, e: Edit) {
        if self.muted {
            return;
        }
        self.flush_coalesce();
        self.undo.push(e);
        self.redo.clear();
        self.trim();
    }

    /// Push a name change, coalescing with the previous name edit on the same addr.
    pub fn push_name(&mut self, addr: u64, old: Option<String>, new: Option<String>) {
        if self.muted {
            return;
        }
        let edit = Edit::SetName { addr, old, new };
        self.push_coalesced(edit);
    }

    pub fn push_comment(&mut self, addr: u64, old: Option<String>, new: Option<String>) {
        if self.muted {
            return;
        }
        let edit = Edit::SetComment { addr, old, new };
        self.push_coalesced(edit);
    }

    fn push_coalesced(&mut self, edit: Edit) {
        let same = match (&self.coalesce, &edit) {
            (
                Some(PendingCoalesce {
                    edit: Edit::SetName { addr: a, .. },
                    ..
                }),
                Edit::SetName { addr: b, .. },
            ) if a == b => true,
            (
                Some(PendingCoalesce {
                    edit: Edit::SetComment { addr: a, .. },
                    ..
                }),
                Edit::SetComment { addr: b, .. },
            ) if a == b => true,
            _ => false,
        };
        if same {
            if let Some(pending) = self.coalesce.as_mut() {
                match (&mut pending.edit, edit) {
                    (
                        Edit::SetName { old, new, .. },
                        Edit::SetName {
                            old: _mid,
                            new: newest,
                            ..
                        },
                    ) => {
                        *new = newest;
                        let _ = old;
                    }
                    (
                        Edit::SetComment { old, new, .. },
                        Edit::SetComment {
                            old: _mid,
                            new: newest,
                            ..
                        },
                    ) => {
                        *new = newest;
                        let _ = old;
                    }
                    _ => unreachable!(),
                }
                pending.gen = pending.gen.wrapping_add(1);
                return;
            }
        }
        self.flush_coalesce();
        self.coalesce = Some(PendingCoalesce { edit, gen: 0 });
        self.redo.clear();
    }

    pub fn flush_coalesce(&mut self) {
        if let Some(PendingCoalesce { edit, .. }) = self.coalesce.take() {
            // Avoid no-op coalesced edits.
            let noop = match &edit {
                Edit::SetName { old, new, .. } => old == new,
                Edit::SetComment { old, new, .. } => old == new,
                _ => false,
            };
            if !noop {
                self.undo.push(edit);
                self.trim();
            }
        }
    }

    fn trim(&mut self) {
        if self.undo.len() > self.max_depth {
            let drop = self.undo.len() - self.max_depth;
            self.undo.drain(0..drop);
        }
    }

    pub fn can_undo(&self) -> bool {
        !self.undo.is_empty() || self.coalesce.is_some()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo.is_empty()
    }

    pub fn peek_undo(&self) -> Option<&Edit> {
        if let Some(p) = &self.coalesce {
            return Some(&p.edit);
        }
        self.undo.last()
    }

    pub fn peek_redo(&self) -> Option<&Edit> {
        self.redo.last()
    }

    pub fn undo_labels(&self, max: usize) -> Vec<String> {
        self.flush_coalesce_labels();
        self.undo
            .iter()
            .rev()
            .take(max)
            .map(|e| e.label())
            .collect()
    }

    fn flush_coalesce_labels(&self) {
        // peek-only path — labels include pending via peek_undo
    }

    pub fn pop_undo(&mut self) -> Option<Edit> {
        self.flush_coalesce();
        self.undo.pop()
    }

    pub fn pop_redo(&mut self) -> Option<Edit> {
        self.redo.pop()
    }

    pub fn push_redo(&mut self, e: Edit) {
        self.redo.push(e);
    }

    pub fn push_undo_silent(&mut self, e: Edit) {
        self.undo.push(e);
        self.trim();
    }

    /// Begin a named batch; finish with [`UndoStack::end_batch`].
    pub fn begin_batch(&mut self, label: impl Into<String>) -> BatchGuard {
        BatchGuard {
            label: label.into(),
            edits: Vec::new(),
        }
    }

    pub fn end_batch(&mut self, guard: BatchGuard) {
        if guard.edits.is_empty() {
            return;
        }
        if guard.edits.len() == 1 {
            self.push(guard.edits.into_iter().next().unwrap());
        } else {
            self.push(Edit::Batch {
                label: guard.label,
                edits: guard.edits,
            });
        }
    }

    pub fn describe(&self) -> String {
        format!(
            "undo={} redo={} muted={} max={}",
            self.undo.len() + usize::from(self.coalesce.is_some()),
            self.redo.len(),
            self.muted,
            self.max_depth
        )
    }
}

#[derive(Clone, Debug)]
pub struct BatchGuard {
    pub label: String,
    pub edits: Vec<Edit>,
}

impl BatchGuard {
    pub fn push(&mut self, e: Edit) {
        self.edits.push(e);
    }
}

pub fn apply_name(
    names: &mut BTreeMap<u64, String>,
    addr: u64,
    new: Option<String>,
) -> Option<String> {
    let old = names.remove(&addr);
    if let Some(n) = new {
        if !n.is_empty() {
            names.insert(addr, n);
        }
    }
    old
}

pub fn apply_comment(
    comments: &mut BTreeMap<u64, String>,
    addr: u64,
    new: Option<String>,
) -> Option<String> {
    let old = comments.remove(&addr);
    if let Some(n) = new {
        if !n.is_empty() {
            comments.insert(addr, n);
        }
    }
    old
}

/// Apply an edit forward (the `new` side).
pub fn apply_edit_forward(
    names: &mut BTreeMap<u64, String>,
    comments: &mut BTreeMap<u64, String>,
    bookmarks: &mut crate::bookmarks::Bookmarks,
    edit: &Edit,
) {
    match edit {
        Edit::SetName { addr, new, .. } => {
            apply_name(names, *addr, new.clone());
        }
        Edit::SetComment { addr, new, .. } => {
            apply_comment(comments, *addr, new.clone());
        }
        Edit::ToggleBookmark { addr, added } => {
            if *added {
                bookmarks.addrs.insert(*addr);
            } else {
                bookmarks.addrs.remove(addr);
            }
        }
        Edit::Batch { edits, .. } => {
            for e in edits {
                apply_edit_forward(names, comments, bookmarks, e);
            }
        }
    }
}

/// Apply the inverse of an edit (restore `old`).
pub fn apply_edit_undo(
    names: &mut BTreeMap<u64, String>,
    comments: &mut BTreeMap<u64, String>,
    bookmarks: &mut crate::bookmarks::Bookmarks,
    edit: &Edit,
) {
    let inv = edit.clone().invert();
    apply_edit_forward(names, comments, bookmarks, &inv);
}

/// Snapshot of annotation maps for tests / export.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AnnotationSnapshot {
    pub names: BTreeMap<u64, String>,
    pub comments: BTreeMap<u64, String>,
    pub bookmarks: Vec<u64>,
}

impl AnnotationSnapshot {
    pub fn capture(
        names: &BTreeMap<u64, String>,
        comments: &BTreeMap<u64, String>,
        bookmarks: &crate::bookmarks::Bookmarks,
    ) -> Self {
        Self {
            names: names.clone(),
            comments: comments.clone(),
            bookmarks: bookmarks.list(),
        }
    }
}

/// Diff two snapshots into a batch edit (best-effort).
pub fn diff_snapshots(before: &AnnotationSnapshot, after: &AnnotationSnapshot) -> Edit {
    let mut edits = Vec::new();
    let mut addrs: BTreeMap<u64, ()> = BTreeMap::new();
    for a in before.names.keys().chain(after.names.keys()) {
        addrs.insert(*a, ());
    }
    for a in addrs.keys() {
        let o = before.names.get(a).cloned();
        let n = after.names.get(a).cloned();
        if o != n {
            edits.push(Edit::SetName {
                addr: *a,
                old: o,
                new: n,
            });
        }
    }
    addrs.clear();
    for a in before.comments.keys().chain(after.comments.keys()) {
        addrs.insert(*a, ());
    }
    for a in addrs.keys() {
        let o = before.comments.get(a).cloned();
        let n = after.comments.get(a).cloned();
        if o != n {
            edits.push(Edit::SetComment {
                addr: *a,
                old: o,
                new: n,
            });
        }
    }
    let before_bm: std::collections::BTreeSet<u64> = before.bookmarks.iter().copied().collect();
    let after_bm: std::collections::BTreeSet<u64> = after.bookmarks.iter().copied().collect();
    for a in after_bm.difference(&before_bm) {
        edits.push(Edit::ToggleBookmark {
            addr: *a,
            added: true,
        });
    }
    for a in before_bm.difference(&after_bm) {
        edits.push(Edit::ToggleBookmark {
            addr: *a,
            added: false,
        });
    }
    Edit::Batch {
        label: "snapshot diff".into(),
        edits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bookmarks::Bookmarks;

    #[test]
    fn undo_redo_name() {
        let mut names = BTreeMap::new();
        let mut comments = BTreeMap::new();
        let mut bm = Bookmarks::default();
        let mut stack = UndoStack::new();
        let old = apply_name(&mut names, 0x100, Some("foo".into()));
        stack.push_name(0x100, old, Some("foo".into()));
        stack.flush_coalesce();
        assert_eq!(names.get(&0x100).map(|s| s.as_str()), Some("foo"));
        assert!(stack.can_undo());
        let e = stack.pop_undo().unwrap();
        apply_edit_undo(&mut names, &mut comments, &mut bm, &e);
        stack.push_redo(e);
        assert!(names.get(&0x100).is_none());
        let e = stack.pop_redo().unwrap();
        apply_edit_forward(&mut names, &mut comments, &mut bm, &e);
        assert_eq!(names.get(&0x100).map(|s| s.as_str()), Some("foo"));
    }

    #[test]
    fn coalesce_same_addr() {
        let mut stack = UndoStack::new();
        stack.push_name(1, None, Some("a".into()));
        stack.push_name(1, Some("a".into()), Some("ab".into()));
        stack.push_name(1, Some("ab".into()), Some("abc".into()));
        stack.flush_coalesce();
        assert_eq!(stack.len(), 1);
        match stack.peek_undo() {
            Some(Edit::SetName { old, new, .. }) => {
                assert!(old.is_none());
                assert_eq!(new.as_deref(), Some("abc"));
            }
            _ => panic!("expected name edit"),
        }
    }

    #[test]
    fn batch_invert() {
        let e = Edit::Batch {
            label: "t".into(),
            edits: vec![
                Edit::SetName {
                    addr: 1,
                    old: None,
                    new: Some("x".into()),
                },
                Edit::SetComment {
                    addr: 2,
                    old: None,
                    new: Some("c".into()),
                },
            ],
        };
        let inv = e.invert();
        match inv {
            Edit::Batch { edits, .. } => {
                assert_eq!(edits.len(), 2);
                // inverted order
                match &edits[0] {
                    Edit::SetComment { new, .. } => assert!(new.is_none()),
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
    }
}
