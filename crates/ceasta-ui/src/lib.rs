//! GUI library — application state shared by `ceasta-app` and future egui panels.

use anyhow::{Context, Result};
use ceasta_analysis::run as analyze;
use ceasta_binary::{open_with, LoadOptions};
use ceasta_db::Database;
use ceasta_debugger::{create as create_debugger, Debugger};
use std::path::Path;

pub struct AppState {
    pub db: Option<Database>,
    pub dbg: Box<dyn Debugger>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            db: None,
            dbg: create_debugger(),
        }
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("db", &self.db.as_ref().map(|d| d.bin.path.as_str()))
            .field("dbg_state", &self.dbg.state())
            .finish()
    }
}

impl AppState {
    pub fn load_file(&mut self, path: &Path) -> Result<()> {
        self.load_file_with(path, &LoadOptions::default())
    }

    pub fn load_file_with(&mut self, path: &Path, opts: &LoadOptions) -> Result<()> {
        let bin = open_with(path, opts).with_context(|| format!("open {}", path.display()))?;
        let analysis = analyze(&bin);
        self.db = Some(Database::new(bin, analysis));
        Ok(())
    }

    pub fn summary(&self) -> String {
        match &self.db {
            Some(db) => format!(
                "{} — {} {}, {} functions, {} tls callbacks",
                db.bin.name,
                db.bin.format.as_str(),
                db.bin.arch.as_str(),
                db.analysis.functions.len(),
                db.bin.tls_callbacks.len()
            ),
            None => "no file loaded".into(),
        }
    }
}
