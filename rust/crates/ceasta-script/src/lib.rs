//! Lua plugin host scaffold — will embed `mlua` and the `ceasta.*` API from docs/lua.md.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("lua host not enabled (build with ceasta-script/lua when ready)")]
    Disabled,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Default)]
pub struct LuaHost {
    pub commands: Vec<String>,
}

impl LuaHost {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_plugins(&mut self, _dirs: &[std::path::PathBuf]) -> Result<usize> {
        Err(Error::Disabled)
    }

    pub fn fire(&mut self, _event: &str, _arg: i64) {}
}
