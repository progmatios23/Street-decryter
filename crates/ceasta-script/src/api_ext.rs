//! Extended `ceasta.*` bindings: TLS, events, host protect, memory helpers.

use ceasta_db::Database;
use ceasta_host;
use mlua::{Lua, Table, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type EventMap = Arc<Mutex<HashMap<String, Vec<mlua::RegistryKey>>>>;

pub fn install_extended(
    lua: &Lua,
    ceasta: &Table,
    db: Arc<Mutex<Database>>,
    cursor: Arc<Mutex<u64>>,
    events: EventMap,
) -> mlua::Result<()> {
    ceasta.set("version", env!("CARGO_PKG_VERSION"))?;

    {
        let cursor = cursor.clone();
        ceasta.set(
            "here",
            lua.create_function(move |_, ()| {
                Ok(*cursor.lock().map_err(|_| mlua::Error::external("cursor"))?)
            })?,
        )?;
    }
    {
        let cursor = cursor.clone();
        ceasta.set(
            "goto_addr",
            lua.create_function(move |_, addr: u64| {
                *cursor.lock().map_err(|_| mlua::Error::external("cursor"))? = addr;
                Ok(())
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "comment",
            lua.create_function(move |_, addr: u64| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                Ok(db.comments.get(&addr).cloned().unwrap_or_default())
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "tls_callbacks",
            lua.create_function(move |lua, ()| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                let arr = lua.create_table()?;
                for (i, a) in db.bin.tls_callbacks.iter().enumerate() {
                    let t = lua.create_table()?;
                    t.set("index", i + 1)?;
                    t.set("addr", *a)?;
                    arr.set(i + 1, t)?;
                }
                Ok(arr)
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "resolve",
            lua.create_function(move |_, text: String| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                Ok(db.resolve(&text))
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "read",
            lua.create_function(move |lua, (addr, n): (u64, usize)| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                let n = n.min(65536);
                let mut buf = vec![0u8; n];
                let got = db.bin.read(addr, &mut buf);
                buf.truncate(got);
                lua.create_string(&buf)
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "read_u8",
            lua.create_function(move |_, addr: u64| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                let mut b = [0u8; 1];
                if db.bin.read(addr, &mut b) < 1 {
                    return Ok(Value::Nil);
                }
                Ok(Value::Integer(b[0] as i64))
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "read_u32",
            lua.create_function(move |_, addr: u64| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                let mut b = [0u8; 4];
                if db.bin.read(addr, &mut b) < 4 {
                    return Ok(Value::Nil);
                }
                Ok(Value::Integer(u32::from_le_bytes(b) as i64))
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "read_u64",
            lua.create_function(move |_, addr: u64| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                let mut b = [0u8; 8];
                if db.bin.read(addr, &mut b) < 8 {
                    return Ok(Value::Nil);
                }
                Ok(Value::Integer(u64::from_le_bytes(b) as i64))
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "is_mapped",
            lua.create_function(move |_, addr: u64| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                Ok(db.bin.seg_at(addr).is_some())
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "is_code",
            lua.create_function(move |_, addr: u64| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                Ok(db
                    .bin
                    .seg_at(addr)
                    .map(|s| s.perms & ceasta_binary::PERM_X != 0)
                    .unwrap_or(false))
            })?,
        )?;
    }

    ceasta.set(
        "host_protect_reason",
        lua.create_function(|_, pid: u32| Ok(ceasta_host::protect_reason(pid, None)))?,
    )?;

    {
        let events = events.clone();
        ceasta.set(
            "on",
            lua.create_function(move |lua, (event, func): (String, mlua::Function)| {
                let key = lua.create_registry_value(func)?;
                events
                    .lock()
                    .map_err(|_| mlua::Error::external("events"))?
                    .entry(event)
                    .or_default()
                    .push(key);
                Ok(())
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "xrefs_from",
            lua.create_function(move |lua, addr: u64| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                let arr = lua.create_table()?;
                for (i, x) in db.analysis.refs_from(addr).iter().enumerate() {
                    let t = lua.create_table()?;
                    t.set("from", x.from)?;
                    t.set("to", x.to)?;
                    t.set("kind", x.kind.as_str())?;
                    t.set("type", x.kind.as_str())?;
                    arr.set(i + 1, t)?;
                }
                Ok(arr)
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "bookmark_toggle",
            lua.create_function(move |_, addr: u64| {
                let mut db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                Ok(db.toggle_bookmark(addr))
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "bookmarks",
            lua.create_function(move |lua, ()| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                let arr = lua.create_table()?;
                for (i, a) in db.bookmarks.list().iter().enumerate() {
                    arr.set(i + 1, *a)?;
                }
                Ok(arr)
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "exports",
            lua.create_function(move |lua, ()| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                let arr = lua.create_table()?;
                for (i, e) in db.bin.exports.iter().enumerate() {
                    let t = lua.create_table()?;
                    t.set("name", e.name.clone())?;
                    t.set("addr", e.addr)?;
                    t.set("ordinal", e.ordinal)?;
                    t.set("forward", e.forward.clone())?;
                    arr.set(i + 1, t)?;
                }
                Ok(arr)
            })?,
        )?;
    }

    {
        let cursor = cursor.clone();
        ceasta.set(
            "set_here",
            lua.create_function(move |_, addr: u64| {
                *cursor.lock().map_err(|_| mlua::Error::external("cursor"))? = addr;
                Ok(())
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "read_bytes",
            lua.create_function(move |lua, (addr, n): (u64, usize)| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                let n = n.min(65536);
                let mut buf = vec![0u8; n];
                let got = db.bin.read(addr, &mut buf);
                buf.truncate(got);
                lua.create_string(&buf)
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "read_u16",
            lua.create_function(move |_, addr: u64| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                let mut b = [0u8; 2];
                if db.bin.read(addr, &mut b) < 2 {
                    return Ok(Value::Nil);
                }
                Ok(Value::Integer(u16::from_le_bytes(b) as i64))
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "read_i32",
            lua.create_function(move |_, addr: u64| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                let mut b = [0u8; 4];
                if db.bin.read(addr, &mut b) < 4 {
                    return Ok(Value::Nil);
                }
                Ok(Value::Integer(i32::from_le_bytes(b) as i64))
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "read_ptr",
            lua.create_function(move |_, addr: u64| {
                let db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                let ps = db.bin.arch.ptr_size();
                let mut b = vec![0u8; ps];
                if db.bin.read(addr, &mut b) < ps {
                    return Ok(Value::Nil);
                }
                let v = if ps == 8 {
                    u64::from_le_bytes(b.as_slice().try_into().unwrap())
                } else {
                    u32::from_le_bytes(b.as_slice().try_into().unwrap()) as u64
                };
                Ok(Value::Integer(v as i64))
            })?,
        )?;
    }

    {
        let db = db.clone();
        ceasta.set(
            "undo",
            lua.create_function(move |_, ()| {
                let mut db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                Ok(db.undo())
            })?,
        )?;
    }
    {
        let db = db.clone();
        ceasta.set(
            "redo",
            lua.create_function(move |_, ()| {
                let mut db = db.lock().map_err(|_| mlua::Error::external("db"))?;
                Ok(db.redo())
            })?,
        )?;
    }

    install_dbg_stubs(lua, ceasta)?;

    Ok(())
}

fn dbg_err<T>() -> mlua::Result<T> {
    Err(mlua::Error::external(
        "debugger not bound — start a debug session or call LuaHost::bind_debugger",
    ))
}

fn install_dbg_stubs(lua: &Lua, ceasta: &Table) -> mlua::Result<()> {
    let dbg = lua.create_table()?;
    dbg.set("state", lua.create_function(|_, ()| Ok("none"))?)?;
    dbg.set("pc", lua.create_function(|_, ()| Ok(Value::Nil))?)?;
    dbg.set("sp", lua.create_function(|_, ()| Ok(Value::Nil))?)?;
    dbg.set(
        "reg",
        lua.create_function(|_, _name: String| Ok(Value::Nil))?,
    )?;
    dbg.set(
        "regs",
        lua.create_function(|lua, ()| lua.create_table())?,
    )?;
    dbg.set(
        "read",
        lua.create_function(|_, (_addr, _n): (u64, usize)| dbg_err::<Value>())?,
    )?;
    dbg.set(
        "read_ptr",
        lua.create_function(|_, _addr: u64| dbg_err::<Value>())?,
    )?;
    dbg.set(
        "write",
        lua.create_function(|_, (_addr, _bytes): (u64, String)| dbg_err::<bool>())?,
    )?;
    for name in [
        "step_into",
        "step_over",
        "step_out",
        "step_back",
        "cont",
        "pause",
    ] {
        dbg.set(
            name,
            lua.create_function(|_, ()| dbg_err::<bool>())?,
        )?;
    }
    dbg.set(
        "run_to",
        lua.create_function(|_, _addr: u64| dbg_err::<bool>())?,
    )?;
    dbg.set(
        "wait",
        lua.create_function(|_, _ms: Option<u32>| dbg_err::<String>())?,
    )?;
    dbg.set(
        "add_bp",
        lua.create_function(|_, _addr: u64| dbg_err::<bool>())?,
    )?;
    dbg.set(
        "del_bp",
        lua.create_function(|_, _addr: u64| dbg_err::<bool>())?,
    )?;
    dbg.set(
        "trace",
        lua.create_function(|_, _n: Option<u32>| dbg_err::<i64>())?,
    )?;
    dbg.set(
        "to_static",
        lua.create_function(|_, addr: u64| Ok(addr))?,
    )?;
    dbg.set(
        "to_runtime",
        lua.create_function(|_, addr: u64| Ok(addr))?,
    )?;
    dbg.set(
        "call",
        lua.create_function(|_, (_func,): (Value,)| dbg_err::<Value>())?,
    )?;
    ceasta.set("dbg", dbg)?;
    Ok(())
}



pub fn fire_events(lua: &Lua, events: &EventMap, name: &str, arg: i64) {
    let Ok(g) = events.lock() else {
        return;
    };
    let Some(list) = g.get(name) else {
        return;
    };
    for key in list {
        if let Ok(f) = lua.registry_value::<mlua::Function>(key) {
            let _ = f.call::<()>(arg);
        }
    }
}
