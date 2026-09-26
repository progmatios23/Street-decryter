//! Optional debugger binding for `ceasta.dbg.*`.

use mlua::{Lua, Table, Value};
use std::sync::{Arc, Mutex};

/// Minimal debugger surface the Lua host can bind.
///
/// Real backends (ptrace / Win32) implement this; without a binding, stubs error.
pub trait DebuggerBinding: Send {
    fn state(&self) -> &'static str;
    fn pc(&self) -> Option<u64>;
    fn sp(&self) -> Option<u64>;
    fn reg(&self, name: &str) -> Option<u64>;
    fn regs(&self) -> Vec<(String, u64)>;
    fn read_mem(&self, addr: u64, buf: &mut [u8]) -> Result<usize, String>;
    fn write_mem(&mut self, addr: u64, data: &[u8]) -> Result<(), String>;
    fn step_into(&mut self) -> Result<bool, String>;
    fn step_over(&mut self) -> Result<bool, String>;
    fn step_out(&mut self) -> Result<bool, String>;
    fn cont(&mut self) -> Result<(), String>;
    fn pause(&mut self) -> Result<(), String>;
    fn wait(&mut self, _ms: Option<u32>) -> Result<&'static str, String>;
    fn add_bp(&mut self, addr: u64) -> Result<(), String>;
    fn del_bp(&mut self, addr: u64) -> bool;
    fn to_static(&self, addr: u64) -> Option<u64> {
        Some(addr)
    }
    fn to_runtime(&self, addr: u64) -> Option<u64> {
        Some(addr)
    }
    fn image_base(&self) -> u64 {
        0
    }
}

pub type DynDebugger = Arc<Mutex<dyn DebuggerBinding>>;

/// Install a live `ceasta.dbg` table backed by `dbg`.
pub fn install_bound_dbg(lua: &Lua, ceasta: &Table, dbg: DynDebugger) -> mlua::Result<()> {
    let table = lua.create_table()?;

    {
        let dbg = dbg.clone();
        table.set(
            "state",
            lua.create_function(move |_, ()| {
                let g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                Ok(g.state().to_string())
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "pc",
            lua.create_function(move |_, ()| {
                let g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                Ok(g.pc().map(|v| Value::Integer(v as i64)).unwrap_or(Value::Nil))
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "sp",
            lua.create_function(move |_, ()| {
                let g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                Ok(g.sp().map(|v| Value::Integer(v as i64)).unwrap_or(Value::Nil))
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "reg",
            lua.create_function(move |_, name: String| {
                let g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                Ok(g.reg(&name)
                    .map(|v| Value::Integer(v as i64))
                    .unwrap_or(Value::Nil))
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "regs",
            lua.create_function(move |lua, ()| {
                let g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                let t = lua.create_table()?;
                for (k, v) in g.regs() {
                    t.set(k, v)?;
                }
                Ok(t)
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "read",
            lua.create_function(move |lua, (addr, n): (u64, usize)| {
                let g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                let n = n.min(65536);
                let mut buf = vec![0u8; n];
                let got = g.read_mem(addr, &mut buf).map_err(mlua::Error::external)?;
                buf.truncate(got);
                lua.create_string(&buf)
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "write",
            lua.create_function(move |_, (addr, bytes): (u64, mlua::String)| {
                let mut g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                let data: Vec<u8> = bytes.as_bytes().to_vec();
                g.write_mem(addr, &data).map_err(mlua::Error::external)?;
                Ok(true)
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "step_into",
            lua.create_function(move |_, ()| {
                let mut g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                g.step_into().map_err(mlua::Error::external)
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "step_over",
            lua.create_function(move |_, ()| {
                let mut g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                g.step_over().map_err(mlua::Error::external)
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "step_out",
            lua.create_function(move |_, ()| {
                let mut g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                g.step_out().map_err(mlua::Error::external)
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "cont",
            lua.create_function(move |_, ()| {
                let mut g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                g.cont().map_err(mlua::Error::external)?;
                Ok(true)
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "pause",
            lua.create_function(move |_, ()| {
                let mut g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                g.pause().map_err(mlua::Error::external)?;
                Ok(true)
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "wait",
            lua.create_function(move |_, ms: Option<u32>| {
                let mut g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                g.wait(ms).map(|s| s.to_string()).map_err(mlua::Error::external)
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "add_bp",
            lua.create_function(move |_, addr: u64| {
                let mut g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                g.add_bp(addr).map_err(mlua::Error::external)?;
                Ok(true)
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "del_bp",
            lua.create_function(move |_, addr: u64| {
                let mut g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                Ok(g.del_bp(addr))
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "to_static",
            lua.create_function(move |_, addr: u64| {
                let g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                Ok(g.to_static(addr))
            })?,
        )?;
    }
    {
        let dbg = dbg.clone();
        table.set(
            "to_runtime",
            lua.create_function(move |_, addr: u64| {
                let g = dbg.lock().map_err(|_| mlua::Error::external("dbg lock"))?;
                Ok(g.to_runtime(addr))
            })?,
        )?;
    }

    ceasta.set("dbg", table)?;
    Ok(())
}

/// A no-op binding that reports state `"none"` (useful in tests).
#[derive(Debug, Default)]
pub struct NullDebugger;

impl DebuggerBinding for NullDebugger {
    fn state(&self) -> &'static str {
        "none"
    }
    fn pc(&self) -> Option<u64> {
        None
    }
    fn sp(&self) -> Option<u64> {
        None
    }
    fn reg(&self, _name: &str) -> Option<u64> {
        None
    }
    fn regs(&self) -> Vec<(String, u64)> {
        Vec::new()
    }
    fn read_mem(&self, _addr: u64, _buf: &mut [u8]) -> Result<usize, String> {
        Err("debugger not attached".into())
    }
    fn write_mem(&mut self, _addr: u64, _data: &[u8]) -> Result<(), String> {
        Err("debugger not attached".into())
    }
    fn step_into(&mut self) -> Result<bool, String> {
        Err("debugger not attached".into())
    }
    fn step_over(&mut self) -> Result<bool, String> {
        Err("debugger not attached".into())
    }
    fn step_out(&mut self) -> Result<bool, String> {
        Err("debugger not attached".into())
    }
    fn cont(&mut self) -> Result<(), String> {
        Err("debugger not attached".into())
    }
    fn pause(&mut self) -> Result<(), String> {
        Err("debugger not attached".into())
    }
    fn wait(&mut self, _ms: Option<u32>) -> Result<&'static str, String> {
        Err("debugger not attached".into())
    }
    fn add_bp(&mut self, _addr: u64) -> Result<(), String> {
        Err("debugger not attached".into())
    }
    fn del_bp(&mut self, _addr: u64) -> bool {
        false
    }
}
