//! Debugger façade — backends land behind `Debugger`; attach always consults `ceasta-host`.

use ceasta_host;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
    #[error("debugging is not implemented yet on this platform (rust scaffold)")]
    Unsupported,
    #[error("refusing to attach to {pid}: {reason} (protect this machine)")]
    Protected { pid: u32, reason: String },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum State {
    #[default]
    None,
    Running,
    Stopped,
}

/// Shared options mirrored from the C++ debugger.
#[derive(Clone, Debug)]
pub struct Options {
    pub break_on_entry: bool,
    pub break_on_tls: bool,
    pub protect_host: bool,
    pub watch_host: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            break_on_entry: true,
            break_on_tls: true,
            protect_host: true,
            watch_host: true,
        }
    }
}

pub trait Debugger: Send {
    fn options_mut(&mut self) -> &mut Options;
    fn state(&self) -> State;
    fn start(&mut self, exe: &Path, args: &str) -> Result<()>;
    fn attach(&mut self, pid: u32) -> Result<()>;
    fn detach(&mut self);
    fn kill(&mut self);
    fn poll(&mut self, timeout_ms: u32);
}

/// Null backend used until win/linux implementations land.
#[derive(Debug, Default)]
pub struct StubDebugger {
    pub options: Options,
    state: State,
}

impl Debugger for StubDebugger {
    fn options_mut(&mut self) -> &mut Options {
        &mut self.options
    }

    fn state(&self) -> State {
        self.state
    }

    fn start(&mut self, _exe: &Path, _args: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn attach(&mut self, pid: u32) -> Result<()> {
        if self.options.protect_host {
            if let Some(reason) = ceasta_host::protect_reason(pid, None) {
                return Err(Error::Protected { pid, reason });
            }
        }
        Err(Error::Unsupported)
    }

    fn detach(&mut self) {
        self.state = State::None;
        ceasta_host::health_reset();
    }

    fn kill(&mut self) {
        self.state = State::None;
        ceasta_host::health_reset();
    }

    fn poll(&mut self, _timeout_ms: u32) {
        if self.options.watch_host && self.state != State::None {
            let _ = ceasta_host::health_check();
        }
    }
}

/// Check attach policy without constructing a backend.
pub fn attach_allowed(pid: u32, protect_host: bool) -> Result<()> {
    if protect_host {
        if let Some(reason) = ceasta_host::protect_reason(pid, None) {
            return Err(Error::Protected { pid, reason });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protect_blocks_self() {
        let err = attach_allowed(std::process::id(), true).unwrap_err();
        assert!(matches!(err, Error::Protected { .. }));
    }
}
