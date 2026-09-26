//! Lua plugin host — embeds Lua 5.4 via `mlua` and exposes `ceasta.*`.

mod api_ext;
mod dbg;

pub use dbg::{DebuggerBinding, DynDebugger, NullDebugger};

use ceasta_analysis::find_bytes;
use ceasta_db::Database;
use ceasta_disasm::decode_at;
use mlua::{Lua, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
    #[error(transparent)]
    Lua(#[from] mlua::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

struct Command {
    name: String,
    #[allow(dead_code)]
    help: String,
    func: mlua::RegistryKey,
}

type CmdBuf = Arc<Mutex<Vec<(String, String, mlua::RegistryKey)>>>;
type EventMap = Arc<Mutex<HashMap<String, Vec<mlua::RegistryKey>>>>;

/// Holds a Lua VM bound to one loaded database.
pub struct LuaHost {
    lua: Lua,
    db: Arc<Mutex<Database>>,
    commands: Vec<Command>,
    pending: CmdBuf,
    cursor: Arc<Mutex<u64>>,
    events: EventMap,
    debugger: Option<DynDebugger>,
}

impl LuaHost {
    pub fn new(db: Database) -> Result<Self> {
        let entry = if db.bin.has_entry { db.bin.entry } else { db.bin.base };
        let lua = Lua::new();
        let db = Arc::new(Mutex::new(db));
        let pending: CmdBuf = Arc::new(Mutex::new(Vec::new()));
        let cursor = Arc::new(Mutex::new(entry));
        let events: EventMap = Arc::new(Mutex::new(HashMap::new()));
        let mut host = Self {
            lua,
            db,
            commands: Vec::new(),
            pending,
            cursor,
            events,
            debugger: None,
        };
        host.install_api()?;
        Ok(host)
    }

    /// Replace stub `ceasta.dbg.*` with a live debugger binding.
    pub fn bind_debugger(&mut self, binding: DynDebugger) -> Result<()> {
        self.debugger = Some(binding.clone());
        let globals = self.lua.globals();
        let ceasta: mlua::Table = globals.get("ceasta")?;
        crate::dbg::install_bound_dbg(&self.lua, &ceasta, binding)?;
        Ok(())
    }

    fn harvest(&mut self) -> Result<()> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| Error::Msg("cmd lock".into()))?;
        for (name, help, key) in pending.drain(..) {
            self.commands.push(Command { name, help, func: key });
        }
        Ok(())
    }

    fn install_api(&mut self) -> Result<()> {
        let db = self.db.clone();
        let ceasta = self.lua.create_table()?;
        ceasta.set("version", "ceasta lua api 1 (Lua 5.4)")?;

        {
            let f = self.lua.create_function(|_, args: mlua::Variadic<Value>| {
                let mut line = String::new();
                for (i, v) in args.iter().enumerate() {
                    if i > 0 {
                        line.push('\t');
                    }
                    line.push_str(&value_to_string(v));
                }
                println!("{line}");
                Ok(())
            })?;
            ceasta.set("log", f.clone())?;
            self.lua.globals().set("print", f)?;
        }

        ceasta.set(
            "warn",
            self.lua.create_function(|_, msg: String| {
                eprintln!("warning: {msg}");
                Ok(())
            })?,
        )?;

        {
            let db = db.clone();
            let file_fn = self.lua.create_function(move |lua, ()| {
                let db = db.lock().map_err(|_| mlua::Error::external("db lock"))?;
                let t = lua.create_table()?;
                t.set("name", db.bin.name.clone())?;
                t.set("path", db.bin.path.clone())?;
                t.set("format", db.bin.format.as_str())?;
                t.set("arch", db.bin.arch.as_str())?;
                t.set("kind", db.bin.kind.clone())?;
                t.set("entry", db.bin.entry)?;
                t.set("base", db.bin.base)?;
                t.set("has_entry", db.bin.has_entry)?;
                t.set("bits", db.bin.arch.bits())?;
                Ok(t)
            })?;
            ceasta.set("file", file_fn.clone())?;
            ceasta.set("info", file_fn)?;
        }

        {
            let db = db.clone();
            ceasta.set(
                "functions",
                self.lua.create_function(move |lua, ()| {
                    let db = db.lock().map_err(|_| mlua::Error::external("db lock"))?;
                    let arr = lua.create_table()?;
                    for (i, f) in db.analysis.functions.iter().enumerate() {
                        let t = lua.create_table()?;
                        t.set("addr", f.start)?;
                        t.set("start", f.start)?;
                        t.set("end", f.end)?;
                        t.set("size", f.end.saturating_sub(f.start))?;
                        t.set("name", f.name.clone())?;
                        arr.set(i + 1, t)?;
                    }
                    Ok(arr)
                })?,
            )?;
        }

        {
            let db = db.clone();
            ceasta.set(
                "imports",
                self.lua.create_function(move |lua, ()| {
                    let db = db.lock().map_err(|_| mlua::Error::external("db lock"))?;
                    let arr = lua.create_table()?;
                    for (i, e) in db.bin.imports.iter().enumerate() {
                        let t = lua.create_table()?;
                        t.set("addr", e.slot)?;
                        t.set("slot", e.slot)?;
                        t.set("name", e.name.clone())?;
                        t.set("lib", e.lib.clone())?;
                        arr.set(i + 1, t)?;
                    }
                    Ok(arr)
                })?,
            )?;
        }

        {
            let db = db.clone();
            ceasta.set(
                "strings",
                self.lua.create_function(move |lua, ()| {
                    let db = db.lock().map_err(|_| mlua::Error::external("db lock"))?;
                    let arr = lua.create_table()?;
                    for (i, s) in db.analysis.strings.iter().enumerate() {
                        let t = lua.create_table()?;
                        t.set("addr", s.addr)?;
                        t.set("text", s.text.clone())?;
                        t.set("wide", s.wide)?;
                        arr.set(i + 1, t)?;
                    }
                    Ok(arr)
                })?,
            )?;
        }

        {
            let db = db.clone();
            let name_fn = self.lua.create_function(move |_, addr: u64| {
                let db = db.lock().map_err(|_| mlua::Error::external("db lock"))?;
                Ok(db.name_at(addr))
            })?;
            ceasta.set("name", name_fn.clone())?;
            ceasta.set("name_at", name_fn)?;
        }

        {
            let db = db.clone();
            ceasta.set(
                "location",
                self.lua.create_function(move |_, addr: u64| {
                    let db = db.lock().map_err(|_| mlua::Error::external("db lock"))?;
                    Ok(db.location(addr))
                })?,
            )?;
        }

        {
            let db = db.clone();
            ceasta.set(
                "xrefs_to",
                self.lua.create_function(move |lua, addr: u64| {
                    let db = db.lock().map_err(|_| mlua::Error::external("db lock"))?;
                    let arr = lua.create_table()?;
                    for (i, x) in db.analysis.refs_to(addr).iter().enumerate() {
                        let t = lua.create_table()?;
                        t.set("from", x.from)?;
                        t.set("to", x.to)?;
                        t.set("type", x.kind.as_str())?;
                        t.set("kind", x.kind.as_str())?;
                        arr.set(i + 1, t)?;
                    }
                    Ok(arr)
                })?,
            )?;
        }

        {
            let db = db.clone();
            ceasta.set(
                "read_cstr",
                self.lua.create_function(move |_, (addr, max): (u64, Option<usize>)| {
                    let db = db.lock().map_err(|_| mlua::Error::external("db lock"))?;
                    let max = max.unwrap_or(256).min(4096);
                    let mut buf = vec![0u8; max];
                    let n = db.bin.read(addr, &mut buf);
                    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
                    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
                })?,
            )?;
        }

        {
            let db = db.clone();
            ceasta.set(
                "disasm",
                self.lua.create_function(move |lua, (addr, n): (u64, Option<usize>)| {
                    let db = db.lock().map_err(|_| mlua::Error::external("db lock"))?;
                    let n = n.unwrap_or(16).min(256);
                    let arr = lua.create_table()?;
                    let mut a = addr;
                    for i in 0..n {
                        match decode_at(&db.bin, a) {
                            Ok(insn) => {
                                let t = lua.create_table()?;
                                t.set("addr", insn.addr)?;
                                t.set("text", insn.text.clone())?;
                                t.set("size", insn.size)?;
                                arr.set(i + 1, t)?;
                                a = insn.next();
                            }
                            Err(_) => break,
                        }
                    }
                    Ok(arr)
                })?,
            )?;
        }

        {
            let db = db.clone();
            ceasta.set(
                "find",
                self.lua.create_function(move |lua, pattern: String| {
                    let db = db.lock().map_err(|_| mlua::Error::external("db lock"))?;
                    let hits =
                        find_bytes(&db.bin, &pattern, 200).map_err(mlua::Error::external)?;
                    let arr = lua.create_table()?;
                    for (i, a) in hits.iter().enumerate() {
                        arr.set(i + 1, *a)?;
                    }
                    Ok(arr)
                })?,
            )?;
        }

        {
            let db = db.clone();
            ceasta.set(
                "set_comment",
                self.lua.create_function(move |_, (addr, text): (u64, String)| {
                    let mut db = db.lock().map_err(|_| mlua::Error::external("db lock"))?;
                    db.set_comment(addr, text);
                    Ok(())
                })?,
            )?;
        }

        {
            let db = db.clone();
            ceasta.set(
                "set_name",
                self.lua.create_function(move |_, (addr, name): (u64, String)| {
                    let mut db = db.lock().map_err(|_| mlua::Error::external("db lock"))?;
                    db.set_name(addr, name);
                    Ok(())
                })?,
            )?;
        }

        ceasta.set(
            "goto_addr",
            self.lua.create_function(|_, _addr: u64| Ok(()))?,
        )?;

        {
            let pending = self.pending.clone();
            ceasta.set(
                "register_command",
                self.lua.create_function(
                    move |lua, (name, func, help): (String, mlua::Function, Option<String>)| {
                        let key = lua.create_registry_value(func)?;
                        pending
                            .lock()
                            .map_err(|_| mlua::Error::external("cmd lock"))?
                            .push((name, help.unwrap_or_default(), key));
                        Ok(())
                    },
                )?,
            )?;
        }

        api_ext::install_extended(
            &self.lua,
            &ceasta,
            self.db.clone(),
            self.cursor.clone(),
            self.events.clone(),
        )?;
        self.lua.globals().set("ceasta", ceasta)?;
        Ok(())
    }

    pub fn exec_file(&mut self, path: &Path) -> Result<()> {
        let src = std::fs::read_to_string(path)
            .map_err(|e| Error::Msg(format!("read {}: {e}", path.display())))?;
        self.lua
            .load(&src)
            .set_name(path.display().to_string())
            .exec()?;
        self.harvest()?;
        Ok(())
    }

    /// Alias for [`Self::exec_file`].
    pub fn load_file(&mut self, path: &Path) -> Result<()> {
        self.exec_file(path)
    }

    pub fn load_plugins(&mut self, dirs: &[PathBuf]) -> Result<usize> {
        let mut n = 0;
        for dir in dirs {
            let Ok(rd) = std::fs::read_dir(dir) else {
                continue;
            };
            let mut files: Vec<_> = rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("lua"))
                .collect();
            files.sort();
            for f in files {
                self.exec_file(&f)?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Run every command registered so far (CLI `run` behaviour).
    pub fn run_registered(&self) -> Result<()> {
        for cmd in &self.commands {
            let f: mlua::Function = self.lua.registry_value(&cmd.func)?;
            if let Err(e) = f.call::<()>(()) {
                eprintln!("command {:?}: {e}", cmd.name);
            }
        }
        Ok(())
    }

    pub fn command_names(&self) -> Vec<String> {
        self.commands.iter().map(|c| c.name.clone()).collect()
    }

    pub fn fire(&mut self, event: &str, arg: i64) {
        api_ext::fire_events(&self.lua, &self.events, event, arg);
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::Nil => "nil".into(),
        Value::Boolean(b) => b.to_string(),
        Value::Integer(i) => i.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.to_str().map(|x| x.to_string()).unwrap_or_default(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceasta_analysis::run as analyze;
    use ceasta_binary::{Arch, Format, Segment, PERM_R, PERM_X};

    #[test]
    fn hello_registers_and_runs() {
        let mut bin = ceasta_binary::Binary::empty("t.bin", Format::Raw, Arch::X64);
        bin.name = "t.bin".into();
        bin.base = 0x1000;
        bin.has_entry = true;
        bin.entry = 0x1000;
        bin.segments.push(Segment {
            name: ".text".into(),
            start: 0x1000,
            end: 0x1010,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: 16,
            data: vec![0xc3; 16],
        });
        let an = analyze(&bin);
        let db = Database::new(bin, an);
        let mut host = LuaHost::new(db).unwrap();
        let dir = std::env::temp_dir().join("ceasta_lua_test");
        let _ = std::fs::create_dir_all(&dir);
        let script = dir.join("t.lua");
        std::fs::write(
            &script,
            r#"
ceasta.register_command("t", function()
    local f = ceasta.file()
    ceasta.log(f.name)
end, "x")
"#,
        )
        .unwrap();
        host.exec_file(&script).unwrap();
        assert_eq!(host.command_names(), vec!["t".to_string()]);
        host.run_registered().unwrap();
    }
}
