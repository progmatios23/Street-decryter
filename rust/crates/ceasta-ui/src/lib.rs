//! GUI scaffold — egui panels will mirror `src/ui/*`.

use ceasta_db::Database;
use ceasta_debugger::StubDebugger;

#[derive(Debug)]
pub struct AppState {
    pub db: Option<Database>,
    pub dbg: StubDebugger,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            db: None,
            dbg: StubDebugger::default(),
        }
    }
}

impl AppState {
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
