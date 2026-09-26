//! Linux ptrace debugger backend (x86_64).

use crate::breakpoints::{BreakpointStore, INT3};
use crate::memory::{read_bytes, write_bytes};
use crate::registers::{RegValue, X64Regs};
use crate::{Debugger, Error, Options, Result, State};
use nix::errno::Errno;
use nix::sys::ptrace::{self, Options as PtraceOptions};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{execv, fork, ForkResult, Pid};
use nix::libc;
use std::collections::HashMap;
use std::ffi::CString;
use std::path::Path;
use std::time::{Duration, Instant};

const AT_ENTRY: u64 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StepKind {
    None,
    Into,
    /// Single-step over a restored permanent BP, then continue.
    PassBp,
}

pub struct LinuxDebugger {
    options: Options,
    state: State,
    pid: Option<Pid>,
    tid: Option<Pid>,
    attached: bool,
    killing: bool,
    reason: String,
    exit_code: i32,
    entry: u64,
    image_base: u64,
    bps: BreakpointStore,
    stepping: StepKind,
    threads: HashMap<i32, bool>,
    /// break_on_tls is stored in options; remembered so later TLS callbacks can arm traps.
    #[allow(dead_code)]
    tls_armed: bool,
}

impl LinuxDebugger {
    pub fn new() -> Self {
        Self {
            options: Options::default(),
            state: State::None,
            pid: None,
            tid: None,
            attached: false,
            killing: false,
            reason: String::new(),
            exit_code: 0,
            entry: 0,
            image_base: 0,
            bps: BreakpointStore::new(),
            stepping: StepKind::None,
            threads: HashMap::new(),
            tls_armed: false,
        }
    }

    fn ensure_idle(&self) -> Result<()> {
        if self.state != State::None {
            return Err(Error::Msg("a process is already being debugged".into()));
        }
        Ok(())
    }

    fn cur(&self) -> Result<Pid> {
        self.tid
            .or(self.pid)
            .ok_or_else(|| Error::Msg("no process".into()))
    }

    fn peek(&self, addr: u64) -> Result<usize> {
        let tid = self.cur()?;
        let word = ptrace::read(tid, addr as ptrace::AddressType).map_err(nix_err)?;
        Ok(word as usize)
    }

    fn poke(&self, addr: u64, word: usize) -> Result<()> {
        let tid = self.cur()?;
        // nix 0.29 write takes c_long
        ptrace::write(tid, addr as ptrace::AddressType, word as libc::c_long).map_err(nix_err)
    }

    fn get_x64(&self) -> Result<X64Regs> {
        let tid = self.cur()?;
        let r = ptrace::getregs(tid).map_err(nix_err)?;
        Ok(X64Regs {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rbp: r.rbp,
            rsp: r.rsp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            rip: r.rip,
            eflags: r.eflags,
            cs: r.cs,
            ss: r.ss,
            ds: r.ds,
            es: r.es,
            fs: r.fs,
            gs: r.gs,
            fs_base: r.fs_base,
            gs_base: r.gs_base,
            orig_rax: r.orig_rax,
        })
    }

    fn set_x64(&self, regs: &X64Regs) -> Result<()> {
        let tid = self.cur()?;
        let mut r = ptrace::getregs(tid).map_err(nix_err)?;
        r.rax = regs.rax;
        r.rbx = regs.rbx;
        r.rcx = regs.rcx;
        r.rdx = regs.rdx;
        r.rsi = regs.rsi;
        r.rdi = regs.rdi;
        r.rbp = regs.rbp;
        r.rsp = regs.rsp;
        r.r8 = regs.r8;
        r.r9 = regs.r9;
        r.r10 = regs.r10;
        r.r11 = regs.r11;
        r.r12 = regs.r12;
        r.r13 = regs.r13;
        r.r14 = regs.r14;
        r.r15 = regs.r15;
        r.rip = regs.rip;
        r.eflags = regs.eflags;
        ptrace::setregs(tid, r).map_err(nix_err)
    }

    fn write_cc(&self, addr: u64) -> Result<()> {
        write_bytes(addr, &[INT3], |a| self.peek(a), |a, w| self.poke(a, w))
    }

    fn restore_byte(&self, addr: u64, byte: u8) -> Result<()> {
        write_bytes(addr, &[byte], |a| self.peek(a), |a, w| self.poke(a, w))
    }

    fn read_auxv_entry(&self) -> u64 {
        let pid = match self.pid {
            Some(p) => p.as_raw(),
            None => return 0,
        };
        let data = match std::fs::read(format!("/proc/{pid}/auxv")) {
            Ok(d) => d,
            Err(_) => return 0,
        };
        let mut i = 0;
        while i + 16 <= data.len() {
            let key = u64::from_ne_bytes(data[i..i + 8].try_into().unwrap());
            let val = u64::from_ne_bytes(data[i + 8..i + 16].try_into().unwrap());
            if key == 0 {
                break;
            }
            if key == AT_ENTRY {
                return val;
            }
            i += 16;
        }
        0
    }

    fn scan_image_base(&mut self) {
        let pid = match self.pid {
            Some(p) => p.as_raw(),
            None => return,
        };
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        let maps = match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
            Ok(s) => s,
            Err(_) => return,
        };
        let Some(exe) = exe else { return };
        let exe_s = exe.to_string_lossy();
        for line in maps.lines() {
            if !line.contains(exe_s.as_ref()) {
                continue;
            }
            if let Some(dash) = line.find('-') {
                if let Ok(lo) = u64::from_str_radix(&line[..dash], 16) {
                    self.image_base = lo;
                    return;
                }
            }
        }
    }

    fn set_temp_bp(&mut self, addr: u64, reason: &str) -> Result<()> {
        if let Some(orig) = self.bps.original(addr) {
            // already a permanent BP — treat as temp over it
            self.bps.set_temp(addr, orig, reason);
            return Ok(());
        }
        let mut byte = [0u8; 1];
        let n = read_bytes(addr, &mut byte, |a| self.peek(a))?;
        if n != 1 {
            return Err(Error::Msg(format!("can't read memory at {addr:#x}")));
        }
        self.write_cc(addr)?;
        self.bps.set_temp(addr, byte[0], reason);
        Ok(())
    }

    fn remove_temp_bp(&mut self) {
        if let Some((addr, orig, _)) = self.bps.take_temp() {
            if !self.bps.has(addr) {
                let _ = self.restore_byte(addr, orig);
            }
        }
    }

    fn after_exec(&mut self, tid: Pid) -> Result<()> {
        self.tid = Some(tid);
        self.entry = self.read_auxv_entry();
        self.scan_image_base();
        self.tls_armed = self.options.break_on_tls;
        if self.options.break_on_entry && self.entry != 0 && !self.killing {
            if self.set_temp_bp(self.entry, "entry point").is_ok() {
                self.state = State::Running;
                self.reason.clear();
                ptrace::cont(tid, None).map_err(nix_err)?;
                return Ok(());
            }
        }
        self.report_stop("entry", tid);
        Ok(())
    }

    fn report_stop(&mut self, why: &str, tid: Pid) {
        self.tid = Some(tid);
        self.state = State::Stopped;
        self.reason = why.to_string();
        self.stepping = StepKind::None;
        if let Some(running) = self.threads.get_mut(&tid.as_raw()) {
            *running = false;
        }
    }

    fn cleanup(&mut self) {
        self.state = State::None;
        self.pid = None;
        self.tid = None;
        self.attached = false;
        self.killing = false;
        self.reason.clear();
        self.entry = 0;
        self.image_base = 0;
        self.bps = BreakpointStore::new();
        self.stepping = StepKind::None;
        self.threads.clear();
        self.tls_armed = false;
        ceasta_host::health_reset();
    }

    fn handle_status(&mut self, tid: Pid, status: WaitStatus) {
        match status {
            WaitStatus::Exited(_, code) => {
                self.exit_code = code;
                if self.pid.map(|p| p == tid).unwrap_or(false) || self.threads.len() <= 1 {
                    self.cleanup();
                } else {
                    self.threads.remove(&tid.as_raw());
                }
            }
            WaitStatus::Signaled(_, sig, _) => {
                self.exit_code = 128 + sig as i32;
                if self.pid.map(|p| p == tid).unwrap_or(false) || self.threads.len() <= 1 {
                    self.cleanup();
                } else {
                    self.threads.remove(&tid.as_raw());
                }
            }
            WaitStatus::Stopped(tid, sig) => {
                self.threads.insert(tid.as_raw(), false);
                if sig == Signal::SIGTRAP {
                    self.on_trap(tid, None);
                } else if self.killing {
                    let _ = ptrace::cont(tid, Some(sig));
                } else if sig == Signal::SIGSTOP && self.attached {
                    // initial attach stop already consumed; unexpected SIGSTOP → report
                    self.report_stop("signal SIGSTOP", tid);
                } else {
                    // deliver other signals by default when continuing later; stop for now
                    self.report_stop(&format!("signal {sig}"), tid);
                }
            }
            WaitStatus::PtraceEvent(tid, _sig, event) => {
                self.threads.insert(tid.as_raw(), false);
                if event == libc::PTRACE_EVENT_EXEC as i32 {
                    let _ = self.after_exec(tid);
                } else if event == libc::PTRACE_EVENT_CLONE as i32
                    || event == libc::PTRACE_EVENT_FORK as i32
                    || event == libc::PTRACE_EVENT_VFORK as i32
                {
                    if let Ok(new_tid) = ptrace::getevent(tid) {
                        let child = Pid::from_raw(new_tid as i32);
                        self.threads.insert(child.as_raw(), false);
                        let _ = ptrace::cont(child, None);
                    }
                    let _ = ptrace::cont(tid, None);
                    self.state = State::Running;
                } else {
                    let _ = ptrace::cont(tid, None);
                    self.state = State::Running;
                }
            }
            WaitStatus::StillAlive => {}
            _ => {}
        }
    }

    fn on_trap(&mut self, tid: Pid, _event: Option<i32>) {
        self.tid = Some(tid);
        // re-arm a permanent BP we single-stepped past
        if let Some(addr) = self.bps.reinsert.take() {
            if self.bps.original(addr).is_some() {
                let _ = self.write_cc(addr);
            }
        }

        let regs = match self.get_x64() {
            Ok(r) => r,
            Err(_) => {
                self.report_stop("trap", tid);
                return;
            }
        };
        let pc = regs.rip;

        // INT3 leaves RIP one past the breakpoint
        if pc > 0 {
            let bp_addr = pc - 1;
            if let Some(orig) = self.bps.original(bp_addr) {
                let mut r = regs;
                r.rip = bp_addr;
                let _ = self.set_x64(&r);
                let is_temp = self
                    .bps
                    .temp()
                    .map(|(a, _, _)| a == bp_addr)
                    .unwrap_or(false);
                let reason = if is_temp {
                    let why = self
                        .bps
                        .temp()
                        .map(|(_, _, r)| r.to_string())
                        .unwrap_or_else(|| "breakpoint".into());
                    self.remove_temp_bp();
                    why
                } else {
                    // permanent: restore orig, single-step later will reinsert
                    let _ = self.restore_byte(bp_addr, orig);
                    self.bps.reinsert = Some(bp_addr);
                    "breakpoint".to_string()
                };
                self.report_stop(&reason, tid);
                return;
            }
        }

        if self.stepping == StepKind::Into {
            self.report_stop("step", tid);
            return;
        }
        if self.stepping == StepKind::PassBp {
            // permanent BP re-armed above; keep running
            self.stepping = StepKind::None;
            self.state = State::Running;
            self.reason.clear();
            if let Some(running) = self.threads.get_mut(&tid.as_raw()) {
                *running = true;
            }
            let _ = ptrace::cont(tid, None);
            return;
        }

        self.report_stop("trap", tid);
    }

    fn resume(&mut self, step: StepKind) -> Result<()> {
        if self.state != State::Stopped {
            return Err(Error::Msg("the process isn't stopped".into()));
        }
        let tid = self.cur()?;
        // if stopped on a permanent BP with restored byte, single-step then reinsert via reinsert
        self.stepping = step;
        self.state = State::Running;
        self.reason.clear();
        if let Some(running) = self.threads.get_mut(&tid.as_raw()) {
            *running = true;
        }
        match step {
            StepKind::Into => ptrace::step(tid, None).map_err(nix_err)?,
            StepKind::PassBp => ptrace::step(tid, None).map_err(nix_err)?,
            StepKind::None => {
                // if we need to step over a restored permanent BP first
                if self.bps.reinsert.is_some() {
                    self.stepping = StepKind::PassBp;
                    ptrace::step(tid, None).map_err(nix_err)?;
                } else {
                    ptrace::cont(tid, None).map_err(nix_err)?;
                }
            }
        }
        Ok(())
    }

    fn wait_initial_stop(&mut self, child: Pid) -> Result<()> {
        let status = waitpid(child, Some(WaitPidFlag::__WALL)).map_err(nix_err)?;
        match status {
            WaitStatus::Stopped(tid, _) => {
                self.tid = Some(tid);
                Ok(())
            }
            other => Err(Error::Msg(format!(
                "the target did not start under the debugger ({other:?})"
            ))),
        }
    }

    fn host_watch(&mut self) {
        if !self.options.watch_host || self.state == State::None {
            return;
        }
        if let Some(msg) = ceasta_host::health_check() {
            let _ = msg;
            if self.attached {
                self.detach();
            } else {
                self.kill();
            }
        }
    }

    fn protect_pid(&self, pid: u32) -> Result<()> {
        if self.options.protect_host {
            if let Some(reason) = ceasta_host::protect_reason(pid, None) {
                return Err(Error::Protected { pid, reason });
            }
        }
        Ok(())
    }
}

impl Default for LinuxDebugger {
    fn default() -> Self {
        Self::new()
    }
}

impl Debugger for LinuxDebugger {
    fn options(&self) -> &Options {
        &self.options
    }

    fn options_mut(&mut self) -> &mut Options {
        &mut self.options
    }

    fn state(&self) -> State {
        self.state
    }

    fn start(&mut self, exe: &Path, args: &str) -> Result<()> {
        self.ensure_idle()?;
        if !exe.exists() {
            return Err(Error::Msg(format!("no such file: {}", exe.display())));
        }
        let mut argv_owned: Vec<CString> = Vec::new();
        argv_owned.push(CString::new(exe.to_string_lossy().as_bytes()).map_err(|e| {
            Error::Msg(format!("bad exe path: {e}"))
        })?);
        for a in args.split_whitespace() {
            argv_owned.push(CString::new(a).map_err(|e| Error::Msg(format!("bad arg: {e}")))?);
        }
        let argv_refs: Vec<&std::ffi::CStr> = argv_owned.iter().map(|c| c.as_c_str()).collect();

        match unsafe { fork().map_err(nix_err)? } {
            ForkResult::Child => {
                // Collect fds first, then close — never close while ReadDir is live.
                let mut to_close = Vec::new();
                if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
                    for ent in entries.flatten() {
                        if let Ok(n) = ent.file_name().to_string_lossy().parse::<i32>() {
                            if n > 2 {
                                to_close.push(n);
                            }
                        }
                    }
                }
                for n in to_close {
                    let _ = nix::unistd::close(n);
                }
                let _ = ptrace::traceme();
                let _ = execv(&argv_owned[0], &argv_refs);
                // exec failed
                unsafe { libc::_exit(127) };
            }
            ForkResult::Parent { child } => {
                self.wait_initial_stop(child)?;
                // refuse self/critical if protect_host (child is new — usually fine)
                if let Err(e) = self.protect_pid(child.as_raw() as u32) {
                    let _ = kill(child, Signal::SIGKILL);
                    let _ = waitpid(child, Some(WaitPidFlag::__WALL));
                    return Err(e);
                }
                self.pid = Some(child);
                self.tid = Some(child);
                self.threads.insert(child.as_raw(), false);
                self.attached = false;
                let opts = PtraceOptions::PTRACE_O_EXITKILL
                    | PtraceOptions::PTRACE_O_TRACECLONE
                    | PtraceOptions::PTRACE_O_TRACEEXEC
                    | PtraceOptions::PTRACE_O_TRACEFORK
                    | PtraceOptions::PTRACE_O_TRACEVFORK;
                ptrace::setoptions(child, opts).map_err(nix_err)?;
                self.state = State::Running;
                self.after_exec(child)?;
                Ok(())
            }
        }
    }

    fn attach(&mut self, pid: u32) -> Result<()> {
        self.ensure_idle()?;
        self.protect_pid(pid)?;
        let target = Pid::from_raw(pid as i32);
        ptrace::attach(target).map_err(|e| {
            Error::Msg(format!("can't attach to {pid}: {e}"))
        })?;
        let status = waitpid(target, Some(WaitPidFlag::__WALL)).map_err(nix_err)?;
        match status {
            WaitStatus::Stopped(_, _) => {}
            other => {
                let _ = ptrace::detach(target, None);
                return Err(Error::Msg(format!("attach wait failed: {other:?}")));
            }
        }
        self.pid = Some(target);
        self.tid = Some(target);
        self.threads.insert(target.as_raw(), false);
        self.attached = true;
        let opts = PtraceOptions::PTRACE_O_TRACECLONE
            | PtraceOptions::PTRACE_O_TRACEEXEC
            | PtraceOptions::PTRACE_O_TRACEFORK
            | PtraceOptions::PTRACE_O_TRACEVFORK;
        let _ = ptrace::setoptions(target, opts);
        self.entry = self.read_auxv_entry();
        self.scan_image_base();
        self.tls_armed = self.options.break_on_tls;
        self.state = State::Stopped;
        self.reason = "attached".into();
        Ok(())
    }

    fn detach(&mut self) {
        if self.state == State::None {
            return;
        }
        // restore breakpoint bytes
        let restores: Vec<(u64, u8)> = self.bps.iter_permanent().collect();
        for (addr, orig) in restores {
            let _ = self.restore_byte(addr, orig);
        }
        self.remove_temp_bp();
        let tids: Vec<i32> = self.threads.keys().copied().collect();
        for tid in tids {
            let _ = ptrace::detach(Pid::from_raw(tid), None);
        }
        if let Some(pid) = self.pid {
            let _ = ptrace::detach(pid, None);
        }
        self.cleanup();
    }

    fn kill(&mut self) {
        if self.state == State::None {
            return;
        }
        self.killing = true;
        if let Some(pid) = self.pid {
            let _ = kill(pid, Signal::SIGKILL);
            let deadline = Instant::now() + Duration::from_secs(3);
            while self.state != State::None && Instant::now() < deadline {
                self.poll(100);
            }
        }
        if self.state != State::None {
            self.cleanup();
        }
    }

    fn poll(&mut self, timeout_ms: u32) {
        self.host_watch();
        if self.state != State::Running {
            return;
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        for _ in 0..512 {
            if self.state != State::Running {
                break;
            }
            match waitpid(
                Pid::from_raw(-1),
                Some(WaitPidFlag::WNOHANG | WaitPidFlag::__WALL),
            ) {
                Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Ok(status) => {
                    if let Some(tid) = status.pid() {
                        self.handle_status(tid, status);
                    }
                }
                Err(_) => break,
            }
            self.host_watch();
        }
    }

    fn cont(&mut self) -> Result<()> {
        self.resume(StepKind::None)
    }

    fn step_into(&mut self) -> Result<()> {
        self.resume(StepKind::Into)
    }

    fn step_over(&mut self) -> Result<()> {
        // Feasible stub: treat like step_into. A call-aware step-over needs a disassembler.
        self.step_into()
    }

    fn add_breakpoint(&mut self, addr: u64) -> Result<()> {
        if self.pid.is_none() {
            return Err(Error::Msg("no process".into()));
        }
        if self.bps.has(addr) && self.bps.iter_permanent().any(|(a, _)| a == addr) {
            return Ok(());
        }
        if let Some((t, orig, _)) = self.bps.temp() {
            if t == addr {
                self.bps.insert_permanent(addr, orig);
                return Ok(());
            }
        }
        let mut byte = [0u8; 1];
        if read_bytes(addr, &mut byte, |a| self.peek(a))? != 1 {
            return Err(Error::Msg(format!("can't write a breakpoint at {addr:#x}")));
        }
        self.write_cc(addr)?;
        self.bps.insert_permanent(addr, byte[0]);
        Ok(())
    }

    fn del_breakpoint(&mut self, addr: u64) -> bool {
        match self.bps.remove_permanent(addr) {
            Some(orig) => {
                if let Some((t, _, _)) = self.bps.temp() {
                    if t == addr {
                        // temp still owns the site
                        return true;
                    }
                }
                let _ = self.restore_byte(addr, orig);
                true
            }
            None => false,
        }
    }

    fn read_memory(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        let n = read_bytes(addr, buf, |a| self.peek(a))?;
        // hide INT3 bytes at our breakpoints
        for (i, b) in buf.iter_mut().enumerate().take(n) {
            let a = addr + i as u64;
            *b = self.bps.hide_int3(a, *b);
        }
        Ok(n)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        write_bytes(addr, data, |a| self.peek(a), |a, w| self.poke(a, w))
    }

    fn registers(&self) -> Result<Vec<RegValue>> {
        Ok(self.get_x64()?.to_list())
    }

    fn pc(&self) -> Result<u64> {
        Ok(self.get_x64()?.rip)
    }

    fn stop_reason(&self) -> &str {
        &self.reason
    }

    fn pid(&self) -> Option<u32> {
        self.pid.map(|p| p.as_raw() as u32)
    }

    fn image_base(&self) -> u64 {
        self.image_base
    }
}

impl Drop for LinuxDebugger {
    fn drop(&mut self) {
        if self.state != State::None {
            if self.attached {
                self.detach();
            } else {
                self.kill();
            }
        }
    }
}

fn nix_err(e: Errno) -> Error {
    Error::Msg(format!("{e}"))
}
