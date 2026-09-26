//! Never attack the machine we are on: refuse dangerous attaches, watch for BSOD.

use std::sync::Mutex;
use std::time::{Duration, Instant};

static HEALTH: Mutex<HealthState> = Mutex::new(HealthState::new());

#[derive(Debug, Default)]
struct HealthState {
    armed: bool,
    alerted: bool,
    last_check: Option<Instant>,
    last_wall: Option<Instant>,
}

impl HealthState {
    const fn new() -> Self {
        Self {
            armed: false,
            alerted: false,
            last_check: None,
            last_wall: None,
        }
    }
}

/// Why attaching to `pid` would hurt this machine. `None` = ok to attach.
pub fn protect_reason(pid: u32, name: Option<&str>) -> Option<String> {
    platform::protect_reason(pid, name)
}

pub fn health_reset() {
    if let Ok(mut g) = HEALTH.lock() {
        *g = HealthState::new();
    }
}

/// While a debug session is live: empty = host still looks fine.
pub fn health_check() -> Option<String> {
    let mut g = HEALTH.lock().ok()?;
    if g.alerted {
        return None;
    }
    let now = Instant::now();
    if !g.armed {
        g.armed = true;
        g.last_check = Some(now);
        g.last_wall = Some(now);
        return None;
    }

    if let Some(prev) = g.last_wall {
        let gap = now.saturating_duration_since(prev);
        if gap > Duration::from_secs(15) {
            g.alerted = true;
            g.last_check = Some(now);
            g.last_wall = Some(now);
            return Some(format!(
                "host clock jumped {} ms — possible BSOD, hard reboot, or the session was suspended",
                gap.as_millis()
            ));
        }
    }

    if let Some(last) = g.last_check {
        if now.saturating_duration_since(last) < Duration::from_millis(400) {
            g.last_wall = Some(now);
            return None;
        }
    }
    g.last_check = Some(now);
    g.last_wall = Some(now);

    if let Some(msg) = platform::critical_gone() {
        g.alerted = true;
        return Some(msg);
    }
    None
}

#[cfg(windows)]
mod platform {
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    fn lower(s: &str) -> String {
        s.to_ascii_lowercase()
    }

    fn critical_name(name: &str) -> bool {
        matches!(
            lower(name).as_str(),
            "system"
                | "smss.exe"
                | "csrss.exe"
                | "wininit.exe"
                | "services.exe"
                | "lsass.exe"
                | "winlogon.exe"
                | "lsaiso.exe"
                | "registry"
                | "secure system"
                | "memory compression"
                | "fontdrvhost.exe"
        )
    }

    fn process_name(pid: u32) -> Option<String> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return None;
            }
            let mut pe = std::mem::zeroed::<PROCESSENTRY32W>();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut name = None;
            if Process32FirstW(snap, &mut pe) != FALSE {
                loop {
                    if pe.th32ProcessID == pid {
                        name = Some(wchar_to_string(&pe.szExeFile));
                        break;
                    }
                    if Process32NextW(snap, &mut pe) == FALSE {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            name
        }
    }

    fn parent_of(pid: u32) -> u32 {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return 0;
            }
            let mut pe = std::mem::zeroed::<PROCESSENTRY32W>();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut ppid = 0;
            if Process32FirstW(snap, &mut pe) != FALSE {
                loop {
                    if pe.th32ProcessID == pid {
                        ppid = pe.th32ParentProcessID;
                        break;
                    }
                    if Process32NextW(snap, &mut pe) == FALSE {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            ppid
        }
    }

    fn wchar_to_string(w: &[u16]) -> String {
        let len = w.iter().position(|&c| c == 0).unwrap_or(w.len());
        String::from_utf16_lossy(&w[..len])
    }

    fn named_alive(want: &str) -> bool {
        let want = lower(want);
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return false;
            }
            let mut pe = std::mem::zeroed::<PROCESSENTRY32W>();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut found = false;
            if Process32FirstW(snap, &mut pe) != FALSE {
                loop {
                    if lower(&wchar_to_string(&pe.szExeFile)) == want {
                        found = true;
                        break;
                    }
                    if Process32NextW(snap, &mut pe) == FALSE {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            found
        }
    }

    fn process_alive(pid: u32) -> bool {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if h == 0 {
                // access denied still means it exists
                return true;
            }
            CloseHandle(h);
            true
        }
    }

    pub fn protect_reason(pid: u32, name: Option<&str>) -> Option<String> {
        if pid == 0 {
            return Some("pid 0 is the idle / system process".into());
        }
        if pid == 4 {
            return Some("pid 4 is the Windows System process".into());
        }
        let self_pid = unsafe { GetCurrentProcessId() };
        if pid == self_pid {
            return Some("that's ceasta itself".into());
        }
        if pid == parent_of(self_pid) {
            return Some("that's ceasta's parent process".into());
        }
        let n = name.map(|s| s.to_string()).or_else(|| process_name(pid))?;
        if critical_name(&n) {
            return Some(format!(
                "{n} is a critical Windows process — attaching can bluescreen or log you off"
            ));
        }
        None
    }

    pub fn critical_gone() -> Option<String> {
        if !named_alive("csrss.exe") {
            return Some(
                "csrss.exe is gone — the host session is dying (logoff or BSOD)".into(),
            );
        }
        if !process_alive(4) {
            return Some("the Windows System process (pid 4) is gone — host crash".into());
        }
        None
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::path::PathBuf;

    fn critical_name(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "systemd"
                | "init"
                | "kthreadd"
                | "ksoftirqd"
                | "migration"
                | "rcu_sched"
                | "rcu_bh"
                | "watchdog"
                | "systemd-udevd"
                | "systemd-journal"
        )
    }

    fn process_alive(pid: u32) -> bool {
        PathBuf::from(format!("/proc/{pid}")).exists()
    }

    fn process_name(pid: u32) -> Option<String> {
        let s = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        Some(s.trim().to_string())
    }

    fn is_kernel_thread(pid: u32) -> bool {
        if !process_alive(pid) {
            return false;
        }
        fs::read_link(format!("/proc/{pid}/exe")).is_err()
    }

    pub fn protect_reason(pid: u32, name: Option<&str>) -> Option<String> {
        if pid == 0 {
            return Some("pid 0 is the idle process".into());
        }
        if pid == 1 {
            return Some("pid 1 is init/systemd — attaching can take the machine down".into());
        }
        let self_pid = std::process::id();
        if pid == self_pid {
            return Some("that's ceasta itself".into());
        }
        // parent
        if let Ok(stat) = fs::read_to_string(format!("/proc/{self_pid}/stat")) {
            if let Some(ppid) = parse_ppid(&stat) {
                if pid == ppid {
                    return Some("that's ceasta's parent process".into());
                }
            }
        }
        if is_kernel_thread(pid) {
            return Some("that's a kernel thread".into());
        }
        let n = name.map(|s| s.to_string()).or_else(|| process_name(pid))?;
        if critical_name(&n) {
            return Some(format!("{n} is a critical system process"));
        }
        None
    }

    fn parse_ppid(stat: &str) -> Option<u32> {
        // comm can contain spaces/parens: find ") " then fields
        let rest = stat.rsplit_once(')')?.1;
        let mut parts = rest.split_whitespace();
        let _state = parts.next()?;
        parts.next()?.parse().ok()
    }

    pub fn critical_gone() -> Option<String> {
        if !process_alive(1) {
            return Some("pid 1 is gone — the host is going down".into());
        }
        None
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod platform {
    pub fn protect_reason(pid: u32, _name: Option<&str>) -> Option<String> {
        if pid == std::process::id() {
            Some("that's ceasta itself".into())
        } else {
            None
        }
    }

    pub fn critical_gone() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_self() {
        let why = protect_reason(std::process::id(), None);
        assert!(why.is_some(), "should refuse attach to self");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refuses_pid1() {
        let why = protect_reason(1, None);
        assert!(why.unwrap().contains("pid 1"));
    }

    #[test]
    fn health_arms_quietly() {
        health_reset();
        assert!(health_check().is_none());
    }
}
