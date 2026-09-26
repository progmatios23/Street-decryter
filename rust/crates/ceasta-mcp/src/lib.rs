//! MCP tool surface scaffold — stdio/HTTP transport comes next.

use ceasta_db::Database;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct McpServer<'a> {
    pub db: &'a Database,
    pub allow_debug: bool,
}

impl<'a> McpServer<'a> {
    pub fn tool_list(&self) -> Value {
        let mut tools = vec![
            "get_file_info",
            "list_functions",
            "disassemble",
            "decompile",
            "list_tls_callbacks",
        ];
        if self.allow_debug {
            tools.extend_from_slice(&["debug_start", "debug_status"]);
        }
        json!(tools)
    }

    pub fn file_info(&self) -> Value {
        let b = &self.db.bin;
        json!({
            "name": b.name,
            "format": b.format.as_str(),
            "arch": b.arch.as_str(),
            "entry": format!("{:X}", b.entry),
            "tls_callbacks": b.tls_callbacks.iter().map(|a| format!("{a:X}")).collect::<Vec<_>>(),
            "functions": self.db.analysis.functions.len(),
        })
    }
}
