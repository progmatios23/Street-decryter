//! User annotations on top of a loaded `Binary` + `Analysis`.

use ceasta_analysis::Analysis;
use ceasta_binary::Binary;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProjectFile {
    pub names: BTreeMap<String, String>,
    pub comments: BTreeMap<String, String>,
    pub breakpoints: Vec<String>,
}

#[derive(Debug)]
pub struct Database {
    pub bin: Binary,
    pub analysis: Analysis,
    pub names: BTreeMap<u64, String>,
    pub comments: BTreeMap<u64, String>,
    pub breakpoints: BTreeSet<u64>,
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
        Self {
            bin,
            analysis,
            names,
            comments: BTreeMap::new(),
            breakpoints: BTreeSet::new(),
            dirty: false,
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

    pub fn set_name(&mut self, addr: u64, name: impl Into<String>) {
        self.names.insert(addr, name.into());
        self.dirty = true;
    }

    pub fn set_comment(&mut self, addr: u64, text: impl Into<String>) {
        let text = text.into();
        if text.is_empty() {
            self.comments.remove(&addr);
        } else {
            self.comments.insert(addr, text);
        }
        self.dirty = true;
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
        }
    }

    pub fn save_project(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.to_project())?;
        std::fs::write(path, json)?;
        Ok(())
    }
}
