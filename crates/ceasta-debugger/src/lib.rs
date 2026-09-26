//! Debugger façade — backends land behind `Debugger`; attach always consults `ceasta-host`.

mod breakpoints;
mod memory;
mod registers;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux;

pub use breakpoints::{BreakpointStore, INT3};
pub use registers::{RegValue, X64Regs};

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
    /// When true, the backend should break on TLS callbacks once their addresses are known.
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
    fn options(&self) -> &Options;
    fn options_mut(&mut self) -> &mut Options;
    fn state(&self) -> State;
    fn start(&mut self, exe: &Path, args: &str) -> Result<()>;
    fn attach(&mut self, pid: u32) -> Result<()>;
    fn detach(&mut self);
    fn kill(&mut self);
    fn poll(&mut self, timeout_ms: u32);

    fn cont(&mut self) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn step_into(&mut self) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn step_over(&mut self) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn add_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn del_breakpoint(&mut self, _addr: u64) -> bool {
        false
    }
    fn read_memory(&self, _addr: u64, _buf: &mut [u8]) -> Result<usize> {
        Err(Error::Unsupported)
    }
    fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn registers(&self) -> Result<Vec<RegValue>> {
        Err(Error::Unsupported)
    }
    fn pc(&self) -> Result<u64> {
        Err(Error::Unsupported)
    }
    /// Convenience alias used by the CLI.
    fn rip(&self) -> Option<u64> {
        self.pc().ok()
    }
    fn stop_reason(&self) -> &str {
        ""
    }
    fn pid(&self) -> Option<u32> {
        None
    }
    fn image_base(&self) -> u64 {
        0
    }
}

/// Null backend used when the platform has no ptrace / Debug API backend.
#[derive(Debug, Default)]
pub struct StubDebugger {
    pub options: Options,
    state: State,
}

impl Debugger for StubDebugger {
    fn options(&self) -> &Options {
        &self.options
    }

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

/// Platform debugger: Linux ptrace on Linux x86_64, stub elsewhere.
pub fn create() -> Box<dyn Debugger> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Box::new(linux::LinuxDebugger::new())
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        Box::new(StubDebugger::default())
    }
}

/// `create()` wrapped for HTTP / multi-threaded hosts (`axum` handlers share one session).
pub type SharedDebugger = std::sync::Arc<std::sync::Mutex<Box<dyn Debugger>>>;

pub fn create_shared() -> SharedDebugger {
    std::sync::Arc::new(std::sync::Mutex::new(create()))
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

    #[test]
    fn create_returns_debugger() {
        let mut dbg = create();
        assert_eq!(dbg.state(), State::None);
        // options are on by default (host protect)
        assert!(dbg.options_mut().protect_host);
    }

    #[test]
    fn create_shared_mutex() {
        let shared = create_shared();
        let mut dbg = shared.lock().unwrap();
        assert_eq!(dbg.state(), State::None);
        let err = dbg.attach(std::process::id()).unwrap_err();
        assert!(matches!(err, Error::Protected { .. }));
    }
}
