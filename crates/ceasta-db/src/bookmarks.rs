//! Address bookmarks for the listing UI / Lua API.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Bookmark {
    pub addr: u64,
    pub label: String,
    pub color: Option<u32>,
    pub created_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Bookmarks {
    pub addrs: BTreeSet<u64>,
    /// Optional metadata keyed by address.
    pub meta: BTreeMap<u64, Bookmark>,
}

impl Bookmarks {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    pub fn clear(&mut self) {
        self.addrs.clear();
        self.meta.clear();
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.addrs.contains(&addr)
    }

    pub fn list(&self) -> Vec<u64> {
        self.addrs.iter().copied().collect()
    }

    pub fn list_meta(&self) -> Vec<Bookmark> {
        self.addrs
            .iter()
            .map(|&a| {
                self.meta.get(&a).cloned().unwrap_or(Bookmark {
                    addr: a,
                    label: String::new(),
                    color: None,
                    created_ms: 0,
                })
            })
            .collect()
    }

    /// Insert; returns true if newly added.
    pub fn add(&mut self, addr: u64) -> bool {
        let inserted = self.addrs.insert(addr);
        if inserted {
            self.meta.entry(addr).or_insert(Bookmark {
                addr,
                label: String::new(),
                color: None,
                created_ms: 0,
            });
        }
        inserted
    }

    pub fn add_with_label(&mut self, addr: u64, label: impl Into<String>) -> bool {
        let inserted = self.add(addr);
        if let Some(m) = self.meta.get_mut(&addr) {
            m.label = label.into();
        }
        inserted
    }

    pub fn remove(&mut self, addr: u64) -> bool {
        let removed = self.addrs.remove(&addr);
        self.meta.remove(&addr);
        removed
    }

    /// Toggle membership; returns true if bookmarked after the call.
    pub fn toggle(&mut self, addr: u64) -> bool {
        if self.addrs.contains(&addr) {
            self.remove(addr);
            false
        } else {
            self.add(addr);
            true
        }
    }

    pub fn set_label(&mut self, addr: u64, label: impl Into<String>) -> bool {
        if !self.addrs.contains(&addr) {
            return false;
        }
        self.meta.entry(addr).or_insert(Bookmark {
            addr,
            label: String::new(),
            color: None,
            created_ms: 0,
        }).label = label.into();
        true
    }

    pub fn set_color(&mut self, addr: u64, color: Option<u32>) -> bool {
        if !self.addrs.contains(&addr) {
            return false;
        }
        self.meta.entry(addr).or_insert(Bookmark {
            addr,
            label: String::new(),
            color: None,
            created_ms: 0,
        }).color = color;
        true
    }

    pub fn label(&self, addr: u64) -> Option<&str> {
        self.meta.get(&addr).map(|m| m.label.as_str())
    }

    pub fn next_after(&self, addr: u64) -> Option<u64> {
        self.addrs.range((addr + 1)..).next().copied()
            .or_else(|| self.addrs.iter().next().copied())
    }

    pub fn prev_before(&self, addr: u64) -> Option<u64> {
        self.addrs.range(..addr).next_back().copied()
            .or_else(|| self.addrs.iter().next_back().copied())
    }

    pub fn merge(&mut self, other: &Bookmarks) {
        for &a in &other.addrs {
            self.add(a);
            if let Some(m) = other.meta.get(&a) {
                self.meta.insert(a, m.clone());
            }
        }
    }

    pub fn retain_mapped(&mut self, is_mapped: impl Fn(u64) -> bool) {
        let dead: Vec<u64> = self.addrs.iter().copied().filter(|&a| !is_mapped(a)).collect();
        for a in dead {
            self.remove(a);
        }
    }

    pub fn format_list(&self, fmt_addr: impl Fn(u64) -> String) -> String {
        let mut out = String::new();
        for b in self.list_meta() {
            let lab = if b.label.is_empty() {
                String::new()
            } else {
                format!("  {}", b.label)
            };
            out.push_str(&format!("{}{}\n", fmt_addr(b.addr), lab));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_and_nav() {
        let mut b = Bookmarks::new();
        assert!(b.toggle(0x100));
        assert!(b.toggle(0x200));
        assert!(!b.toggle(0x100));
        assert!(!b.contains(0x100));
        assert!(b.contains(0x200));
        b.add(0x100);
        b.add(0x300);
        assert_eq!(b.next_after(0x100), Some(0x200));
        assert_eq!(b.prev_before(0x200), Some(0x100));
        b.set_label(0x200, "mid");
        assert_eq!(b.label(0x200), Some("mid"));
    }
}
