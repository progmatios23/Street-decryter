//! Recently opened files and recently visited addresses.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DEFAULT_MAX_FILES: usize = 16;
const DEFAULT_MAX_ADDRS: usize = 64;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RecentFiles {
    pub paths: Vec<PathBuf>,
    #[serde(default = "default_max_files")]
    pub max: usize,
}

fn default_max_files() -> usize {
    DEFAULT_MAX_FILES
}

impl RecentFiles {
    pub fn new() -> Self {
        Self {
            paths: Vec::new(),
            max: DEFAULT_MAX_FILES,
        }
    }

    pub fn with_max(max: usize) -> Self {
        Self {
            paths: Vec::new(),
            max: max.max(1),
        }
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn clear(&mut self) {
        self.paths.clear();
    }

    pub fn push(&mut self, path: impl Into<PathBuf>) {
        let path = path.into();
        self.paths.retain(|p| p != &path);
        self.paths.insert(0, path);
        if self.paths.len() > self.max {
            self.paths.truncate(self.max);
        }
    }

    pub fn remove(&mut self, path: &Path) -> bool {
        let before = self.paths.len();
        self.paths.retain(|p| p != path);
        before != self.paths.len()
    }

    pub fn list(&self) -> &[PathBuf] {
        &self.paths
    }

    pub fn iter(&self) -> impl Iterator<Item = &PathBuf> {
        self.paths.iter()
    }

    pub fn contains(&self, path: &Path) -> bool {
        self.paths.iter().any(|p| p == path)
    }

    /// Drop entries whose files no longer exist.
    pub fn prune_missing(&mut self) {
        self.paths.retain(|p| p.exists());
    }

    pub fn format_menu(&self) -> Vec<String> {
        self.paths
            .iter()
            .enumerate()
            .map(|(i, p)| format!("{}. {}", i + 1, p.display()))
            .collect()
    }
}

/// Recently visited / jumped-to addresses inside the current database.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RecentAddrs {
    pub addrs: Vec<u64>,
    #[serde(default = "default_max_addrs")]
    pub max: usize,
}

fn default_max_addrs() -> usize {
    DEFAULT_MAX_ADDRS
}

impl RecentAddrs {
    pub fn new() -> Self {
        Self {
            addrs: Vec::new(),
            max: DEFAULT_MAX_ADDRS,
        }
    }

    pub fn with_max(max: usize) -> Self {
        Self {
            addrs: Vec::new(),
            max: max.max(1),
        }
    }

    pub fn push(&mut self, addr: u64) {
        self.addrs.retain(|&a| a != addr);
        self.addrs.insert(0, addr);
        if self.addrs.len() > self.max {
            self.addrs.truncate(self.max);
        }
    }

    pub fn list(&self) -> &[u64] {
        &self.addrs
    }

    pub fn clear(&mut self) {
        self.addrs.clear();
    }

    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }
}

/// Combined recent state persisted with the UI session (not the .ceasta project).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RecentState {
    pub files: RecentFiles,
    pub addrs: RecentAddrs,
}

impl RecentState {
    pub fn push_file(&mut self, path: impl Into<PathBuf>) {
        self.files.push(path);
    }

    pub fn push_addr(&mut self, addr: u64) {
        self.addrs.push(addr);
    }

    pub fn clear_all(&mut self) {
        self.files.clear();
        self.addrs.clear();
    }

    pub fn summarize(&self) -> String {
        format!(
            "{} recent file(s), {} recent addr(s)",
            self.files.len(),
            self.addrs.len()
        )
    }
}

/// Load recent files from a JSON path (best-effort).
pub fn load_recent_files(path: impl AsRef<Path>) -> RecentFiles {
    let path = path.as_ref();
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => RecentFiles::new(),
    }
}

/// Save recent files to a JSON path.
pub fn save_recent_files(path: impl AsRef<Path>, recent: &RecentFiles) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(recent)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mru_order() {
        let mut r = RecentFiles::with_max(3);
        r.push("/a");
        r.push("/b");
        r.push("/c");
        r.push("/a"); // move to front
        assert_eq!(
            r.list(),
            &[
                PathBuf::from("/a"),
                PathBuf::from("/c"),
                PathBuf::from("/b")
            ]
        );
        r.push("/d");
        assert_eq!(r.len(), 3);
        assert_eq!(r.list()[0], PathBuf::from("/d"));
    }

    #[test]
    fn recent_addrs() {
        let mut a = RecentAddrs::with_max(2);
        a.push(1);
        a.push(2);
        a.push(1);
        assert_eq!(a.list(), &[1, 2]);
    }
}
