//! MCP tool surface — JSON-RPC stdio + localhost HTTP.

mod http;

pub use http::{parse_bind_addr, router, serve_http, serve_http_blocking, HttpState};

use ceasta_analysis::{build_cfg, find_bytes};
use ceasta_db::Database;
use ceasta_debugger::Debugger;
use ceasta_decompiler::decompile_function;
use ceasta_disasm::decode_at;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct McpOptions {
    pub allow_debug: bool,
    pub allow_lua: bool,
}

impl Default for McpOptions {
    fn default() -> Self {
        Self {
            allow_debug: false,
            allow_lua: false,
        }
    }
}

pub struct McpServer<'a> {
    pub db: &'a Database,
    pub allow_debug: bool,
    pub allow_lua: bool,
    /// Shared debugger used by HTTP control API and MCP debug tools.
    pub debugger: Option<&'a Mutex<Box<dyn Debugger>>>,
}

impl<'a> McpServer<'a> {
    pub fn new(db: &'a Database, opts: &McpOptions) -> Self {
        Self {
            db,
            allow_debug: opts.allow_debug,
            allow_lua: opts.allow_lua,
            debugger: None,
        }
    }

    pub fn with_debugger(mut self, dbg: &'a Mutex<Box<dyn Debugger>>) -> Self {
        self.debugger = Some(dbg);
        self
    }

    pub fn tool_names(&self) -> Vec<&'static str> {
        let mut tools = vec![
            "get_file_info",
            "get_binary_info",
            "list_functions",
            "list_strings",
            "list_imports",
            "list_exports",
            "list_tls_callbacks",
            "disassemble",
            "disassemble_function",
            "decompile",
            "decompile_function",
            "get_xrefs_to",
            "get_xrefs_from",
            "get_basic_blocks",
            "search_bytes",
            "lookup",
            "read_bytes",
        ];
        if self.allow_debug {
            tools.extend_from_slice(&[
                "debug_start",
                "debug_status",
                "debug_continue",
                "debug_step_into",
                "debug_kill",
            ]);
        }
        if self.allow_lua {
            tools.push("run_lua");
        }
        tools
    }

    pub fn tool_list(&self) -> Value {
        json!(self.tool_names())
    }

    pub fn tools_schema(&self) -> Value {
        let tools: Vec<Value> = self
            .tool_names()
            .into_iter()
            .map(|name| {
                json!({
                    "name": name,
                    "description": tool_desc(name),
                    "inputSchema": { "type": "object", "properties": {} },
                })
            })
            .collect();
        json!(tools)
    }

    pub fn file_info(&self) -> Value {
        let b = &self.db.bin;
        json!({
            "name": b.name,
            "path": b.path,
            "format": b.format.as_str(),
            "arch": b.arch.as_str(),
            "kind": b.kind,
            "base": format!("{:X}", b.base),
            "entry": if b.has_entry { format!("{:X}", b.entry) } else { "none".into() },
            "tls_callbacks": b.tls_callbacks.iter().map(|a| format!("{a:X}")).collect::<Vec<_>>(),
            "functions": self.db.analysis.functions.len(),
            "imports": b.imports.len(),
            "exports": b.exports.len(),
            "strings": self.db.analysis.strings.len(),
            "segments": b.segments.iter().map(|s| json!({
                "name": s.name,
                "start": format!("{:X}", s.start),
                "end": format!("{:X}", s.end),
            })).collect::<Vec<_>>(),
        })
    }

    pub fn call_tool(&self, name: &str, args: &Value) -> Result<Value> {
        match name {
            "get_file_info" | "get_binary_info" => Ok(self.file_info()),
            "list_functions" => {
                let filter = args
                    .get("filter")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let funcs: Vec<_> = self
                    .db
                    .analysis
                    .functions
                    .iter()
                    .filter(|f| filter.is_empty() || f.name.to_ascii_lowercase().contains(&filter))
                    .take(500)
                    .map(|f| {
                        json!({
                            "addr": format!("{:X}", f.start),
                            "size": f.end - f.start,
                            "name": self.db.name_at(f.start).if_empty(&f.name),
                        })
                    })
                    .collect();
                Ok(json!(funcs))
            }
            "list_strings" => {
                let strings: Vec<_> = self
                    .db
                    .analysis
                    .strings
                    .iter()
                    .take(500)
                    .map(|s| {
                        json!({
                            "addr": format!("{:X}", s.addr),
                            "wide": s.wide,
                            "text": s.text,
                        })
                    })
                    .collect();
                Ok(json!(strings))
            }
            "list_imports" => {
                let imports: Vec<_> = self
                    .db
                    .bin
                    .imports
                    .iter()
                    .map(|e| {
                        json!({
                            "slot": format!("{:X}", e.slot),
                            "lib": e.lib,
                            "name": e.name,
                        })
                    })
                    .collect();
                Ok(json!(imports))
            }
            "list_exports" => {
                let exports: Vec<_> = self
                    .db
                    .bin
                    .exports
                    .iter()
                    .map(|e| {
                        json!({
                            "addr": format!("{:X}", e.addr),
                            "ordinal": e.ordinal,
                            "name": e.name,
                            "forward": e.forward,
                        })
                    })
                    .collect();
                Ok(json!(exports))
            }
            "list_tls_callbacks" => Ok(json!(self
                .db
                .bin
                .tls_callbacks
                .iter()
                .enumerate()
                .map(|(i, a)| json!({ "index": i, "addr": format!("{a:X}") }))
                .collect::<Vec<_>>())),
            "disassemble" => {
                let addr = resolve_arg(self.db, args, "address")
                    .or_else(|| resolve_arg(self.db, args, "where"))
                    .ok_or_else(|| Error::Msg("address required".into()))?;
                let n = args.get("count").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
                Ok(json!(disasm_lines(self.db, addr, n)))
            }
            "disassemble_function" | "decompile" | "decompile_function" => {
                let addr = resolve_arg(self.db, args, "address")
                    .or_else(|| resolve_arg(self.db, args, "where"))
                    .ok_or_else(|| Error::Msg("address required".into()))?;
                let f = self
                    .db
                    .func_at(addr)
                    .ok_or_else(|| Error::Msg(format!("no function at {addr:X}")))?;
                if name.starts_with("decompile") {
                    Ok(json!({ "code": decompile_function(&self.db.bin, f) }))
                } else {
                    let n = ((f.end - f.start) as usize).min(200);
                    Ok(json!(disasm_lines(self.db, f.start, n)))
                }
            }
            "get_xrefs_to" => {
                let addr = resolve_arg(self.db, args, "address")
                    .ok_or_else(|| Error::Msg("address required".into()))?;
                let refs: Vec<_> = self
                    .db
                    .analysis
                    .refs_to(addr)
                    .iter()
                    .map(|x| {
                        json!({
                            "from": format!("{:X}", x.from),
                            "kind": x.kind.as_str(),
                            "location": self.db.location(x.from),
                        })
                    })
                    .collect();
                Ok(json!(refs))
            }
            "get_xrefs_from" => {
                let addr = resolve_arg(self.db, args, "address")
                    .ok_or_else(|| Error::Msg("address required".into()))?;
                let refs: Vec<_> = self
                    .db
                    .analysis
                    .refs_from(addr)
                    .iter()
                    .map(|x| {
                        json!({
                            "to": format!("{:X}", x.to),
                            "kind": x.kind.as_str(),
                        })
                    })
                    .collect();
                Ok(json!(refs))
            }
            "get_basic_blocks" => {
                let addr = resolve_arg(self.db, args, "address")
                    .ok_or_else(|| Error::Msg("address required".into()))?;
                let g = build_cfg(&self.db.bin, &self.db.analysis, addr)
                    .ok_or_else(|| Error::Msg(format!("no function at {addr:X}")))?;
                Ok(json!({
                    "truncated": g.truncated,
                    "blocks": g.blocks.iter().enumerate().map(|(i, b)| json!({
                        "id": i,
                        "start": format!("{:X}", b.start),
                        "end": format!("{:X}", b.end),
                        "insns": b.insn_addrs.len(),
                        "succ": b.succ.iter().map(|e| json!({
                            "to": e.to,
                            "kind": e.kind.as_str(),
                        })).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                }))
            }
            "search_bytes" => {
                let pat = args
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::Msg("pattern required".into()))?;
                let hits = find_bytes(&self.db.bin, pat, 100).map_err(Error::Msg)?;
                Ok(json!(hits
                    .iter()
                    .map(|a| json!({
                        "addr": format!("{a:X}"),
                        "location": self.db.location(*a),
                    }))
                    .collect::<Vec<_>>()))
            }
            "lookup" => {
                let addr = resolve_arg(self.db, args, "address")
                    .ok_or_else(|| Error::Msg("address required".into()))?;
                Ok(json!({
                    "addr": format!("{addr:X}"),
                    "location": self.db.location(addr),
                    "name": self.db.name_at(addr),
                    "mapped": self.db.bin.is_mapped(addr),
                    "code": self.db.bin.is_code(addr),
                }))
            }
            "read_bytes" => {
                let addr = resolve_arg(self.db, args, "address")
                    .ok_or_else(|| Error::Msg("address required".into()))?;
                let n = args.get("size").and_then(|v| v.as_u64()).unwrap_or(16) as usize;
                let n = n.min(4096);
                let mut buf = vec![0u8; n];
                let got = self.db.bin.read(addr, &mut buf);
                buf.truncate(got);
                Ok(json!({
                    "addr": format!("{addr:X}"),
                    "hex": buf.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
                }))
            }
            "debug_start" | "debug_status" | "debug_continue" | "debug_step_into" | "debug_kill" => {
                self.call_debug_tool(name, args)
            }
            "run_lua" => {
                if !self.allow_lua {
                    return Err(Error::Msg("run_lua disabled (pass --allow-lua)".into()));
                }
                Err(Error::Msg("lua host not yet ported".into()))
            }
            other => Err(Error::Msg(format!("unknown tool: {other}"))),
        }
    }

    fn call_debug_tool(&self, name: &str, args: &Value) -> Result<Value> {
        if !self.allow_debug {
            return Err(Error::Msg(
                "debug tools disabled (pass --allow-debug)".into(),
            ));
        }
        let slot = self
            .debugger
            .ok_or_else(|| Error::Msg("debugger not available on this transport".into()))?;
        let mut dbg = slot
            .lock()
            .map_err(|_| Error::Msg("debugger lock poisoned".into()))?;
        match name {
            "debug_start" => {
                let exe = args
                    .get("exe")
                    .or_else(|| args.get("path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(self.db.bin.path.as_str());
                let arg_str = args
                    .get("args")
                    .map(|v| match v {
                        Value::String(s) => s.clone(),
                        Value::Array(a) => a
                            .iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(" "),
                        other => other.to_string(),
                    })
                    .unwrap_or_default();
                dbg.start(Path::new(exe), &arg_str)
                    .map_err(|e| Error::Msg(e.to_string()))?;
                let _ = wait_dbg_stop(&mut **dbg, 15_000);
                Ok(debug_snapshot(&**dbg))
            }
            "debug_status" => Ok(debug_snapshot(&**dbg)),
            "debug_continue" => {
                dbg.cont().map_err(|e| Error::Msg(e.to_string()))?;
                Ok(debug_snapshot(&**dbg))
            }
            "debug_step_into" => {
                dbg.step_into().map_err(|e| Error::Msg(e.to_string()))?;
                let _ = wait_dbg_stop(&mut **dbg, 5_000);
                Ok(debug_snapshot(&**dbg))
            }
            "debug_kill" => {
                dbg.kill();
                Ok(debug_snapshot(&**dbg))
            }
            _ => Err(Error::Msg(format!("unknown debug tool: {name}"))),
        }
    }

    /// Handle one JSON-RPC request. Returns `None` for notifications (no response).
    pub fn handle_rpc(&self, req: &Value) -> Option<Value> {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(json!({}));
        if matches!(method, "notifications/initialized" | "initialized") {
            return None;
        }
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "ceasta", "version": env!("CARGO_PKG_VERSION") },
            })),
            "tools/list" => Ok(json!({ "tools": self.tools_schema() })),
            "tools/call" => {
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                match self.call_tool(name, &args) {
                    Ok(v) => Ok(json!({
                        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default() }]
                    })),
                    Err(e) => Ok(json!({
                        "isError": true,
                        "content": [{ "type": "text", "text": e.to_string() }]
                    })),
                }
            }
            "ping" => Ok(json!({})),
            "" => Err(Error::Msg("missing method".into())),
            other => Err(Error::Msg(format!("method not found: {other}"))),
        };
        Some(match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err(e) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": e.to_string() }
            }),
        })
    }

    /// Minimal MCP JSON-RPC loop over stdin/stdout (initialize + tools/list + tools/call).
    pub fn serve_stdio(&self) -> Result<()> {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        for line in stdin.lock().lines() {
            let line = line.map_err(|e| Error::Msg(e.to_string()))?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let req: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(e) => {
                    let err = json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": { "code": -32700, "message": format!("parse error: {e}") }
                    });
                    writeln!(stdout, "{err}").map_err(|e| Error::Msg(e.to_string()))?;
                    continue;
                }
            };
            if let Some(resp) = self.handle_rpc(&req) {
                writeln!(stdout, "{resp}").map_err(|e| Error::Msg(e.to_string()))?;
                let _ = stdout.flush();
            }
        }
        Ok(())
    }
}

fn tool_desc(name: &str) -> &'static str {
    match name {
        "get_file_info" | "get_binary_info" => "format, arch, entry, segments, counts",
        "list_functions" => "list discovered functions",
        "list_strings" => "list analyzed strings",
        "list_imports" => "list imports",
        "list_exports" => "list exports",
        "list_tls_callbacks" => "PE TLS callbacks",
        "disassemble" => "disassemble n instructions from an address",
        "disassemble_function" => "disassemble one function",
        "decompile" | "decompile_function" => "F5-style pseudocode for a function",
        "get_xrefs_to" => "references to an address",
        "get_xrefs_from" => "references from an address",
        "get_basic_blocks" => "CFG blocks of a function",
        "search_bytes" => "byte pattern search",
        "lookup" => "what's at an address",
        "read_bytes" => "read raw bytes",
        "debug_start" => "start the target under the debugger",
        "debug_status" => "debugger state, pc, registers",
        "debug_continue" => "continue the debuggee",
        "debug_step_into" => "single-step into",
        "debug_kill" => "kill the debuggee",
        "run_lua" => "run lua (not yet ported)",
        _ => "",
    }
}

pub(crate) fn resolve_arg(db: &Database, args: &Value, key: &str) -> Option<u64> {
    let v = args.get(key)?;
    if let Some(s) = v.as_str() {
        return db.resolve(s);
    }
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    None
}

pub(crate) fn disasm_lines(db: &Database, mut addr: u64, n: usize) -> Vec<Value> {
    let mut out = Vec::new();
    for _ in 0..n {
        match decode_at(&db.bin, addr) {
            Ok(insn) => {
                out.push(json!({
                    "addr": format!("{addr:X}"),
                    "text": insn.text,
                    "size": insn.size,
                }));
                addr = insn.next();
            }
            Err(_) => break,
        }
    }
    out
}

fn wait_dbg_stop(dbg: &mut dyn Debugger, timeout_ms: u32) -> bool {
    let start = Instant::now();
    let limit = Duration::from_millis(timeout_ms as u64);
    while start.elapsed() < limit {
        if dbg.state() != ceasta_debugger::State::Running {
            return true;
        }
        dbg.poll(50);
    }
    dbg.state() != ceasta_debugger::State::Running
}

fn debug_snapshot(dbg: &dyn Debugger) -> Value {
    let regs: Vec<_> = dbg
        .registers()
        .unwrap_or_default()
        .into_iter()
        .map(|r| json!({ "name": r.name, "value": format!("{:X}", r.value) }))
        .collect();
    json!({
        "state": format!("{:?}", dbg.state()).to_ascii_lowercase(),
        "pc": dbg.pc().ok().map(|p| format!("{p:X}")),
        "regs": regs,
        "reason": dbg.stop_reason(),
        "pid": dbg.pid(),
    })
}

trait IfEmpty {
    fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str;
}

impl IfEmpty for str {
    fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str {
        if self.is_empty() {
            fallback
        } else {
            self
        }
    }
}

impl IfEmpty for String {
    fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str {
        self.as_str().if_empty(fallback)
    }
}
