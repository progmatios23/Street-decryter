#include "core/debugger.h"
#include "core/os.h"
#include "core/util.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#elif defined(__linux__)
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#endif

// host protection and health: keep the debugger from attaching to the machine
// we are on in a way that would take it down, and notice when the host itself
// has gone (bsod / hard reboot) while a session is live.

namespace {

std::string lower_name(std::string s)
{
    for (char& c : s)
        c = (char)std::tolower((unsigned char)c);
    return s;
}

#ifdef _WIN32

// names that own the session. attaching / killing them is how you get a bsod
// or an instant logoff. svchost is left alone: too many ordinary things live there.
bool critical_win_name(const std::string& lower)
{
    static const char* const names[] = {
        "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
        "winlogon.exe", "lsaIso.exe", "lsaiso.exe", "registry", "secure system",
        "memory compression", "fontdrvhost.exe",
    };
    for (const char* n : names)
        if (lower == lower_name(n))
            return true;
    return false;
}

std::string process_name_of(uint32_t pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return {};
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    std::string name;
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        if (pe.th32ProcessID == pid) {
            name = os::narrow(pe.szExeFile);
            break;
        }
    }
    CloseHandle(snap);
    return name;
}

uint32_t parent_of(uint32_t pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    uint32_t ppid = 0;
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        if (pe.th32ProcessID == pid) {
            ppid = pe.th32ParentProcessID;
            break;
        }
    }
    CloseHandle(snap);
    return ppid;
}

bool process_alive(uint32_t pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return GetLastError() == ERROR_ACCESS_DENIED; // exists but locked down
    DWORD code = 0;
    bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
}

bool find_named_alive(const char* want)
{
    std::string w = lower_name(want);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    bool found = false;
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        if (lower_name(os::narrow(pe.szExeFile)) == w) {
            found = true;
            break;
        }
    }
    CloseHandle(snap);
    return found;
}

#elif defined(__linux__)

bool critical_linux_name(const std::string& name)
{
    static const char* const names[] = {
        "systemd", "init", "kthreadd", "ksoftirqd", "migration", "rcu_sched", "rcu_bh",
        "watchdog", "systemd-udevd", "systemd-journal",
    };
    std::string l = lower_name(name);
    for (const char* n : names)
        if (l == n)
            return true;
    return false;
}

std::string process_name_of(uint32_t pid)
{
    std::string err;
    std::vector<uint8_t> bytes;
    if (!os::read_file(util::fmt("/proc/%u/comm", pid), bytes, err) || bytes.empty())
        return {};
    std::string s((const char*)bytes.data(), bytes.size());
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
        s.pop_back();
    return s;
}

bool process_alive(uint32_t pid)
{
    return access(util::fmt("/proc/%u", pid).c_str(), F_OK) == 0;
}

bool is_kernel_thread(uint32_t pid)
{
    if (!process_alive(pid))
        return false;
    // kernel threads have no /proc/<pid>/exe
    char buf[64];
    snprintf(buf, sizeof(buf), "/proc/%u/exe", pid);
    char link[256];
    ssize_t n = readlink(buf, link, sizeof(link) - 1);
    return n < 0;
}

#else

std::string process_name_of(uint32_t) { return {}; }
bool process_alive(uint32_t) { return true; }

#endif

// health check state (process-wide; one ui / one debugger)
struct health_state {
    bool armed = false;
    bool alerted = false;
    uint64_t last_check_ms = 0;
    uint64_t last_wall_ms = 0;
};
health_state g_health;

} // namespace

std::string host_protect_reason(uint32_t pid, const std::string& name)
{
    if (pid == 0)
        return "pid 0 is the idle / system process";
#ifdef _WIN32
    if (pid == 4)
        return "pid 4 is the Windows System process";
    uint32_t self = GetCurrentProcessId();
    if (pid == self)
        return "that's ceasta itself";
    if (pid == parent_of(self))
        return "that's ceasta's parent process";
    std::string n = name.empty() ? process_name_of(pid) : name;
    if (!n.empty() && critical_win_name(lower_name(n)))
        return util::fmt("%s is a critical Windows process — attaching can bluescreen or log you off", n.c_str());
#elif defined(__linux__)
    if (pid == 1)
        return "pid 1 is init/systemd — attaching can take the machine down";
    uint32_t self = (uint32_t)getpid();
    if (pid == self)
        return "that's ceasta itself";
    if (pid == (uint32_t)getppid())
        return "that's ceasta's parent process";
    if (is_kernel_thread(pid))
        return "that's a kernel thread";
    std::string n = name.empty() ? process_name_of(pid) : name;
    if (!n.empty() && critical_linux_name(n))
        return util::fmt("%s is a critical system process", n.c_str());
#else
    (void)name;
    (void)pid;
#endif
    return {};
}

void host_health_reset()
{
    g_health = {};
}

std::string host_health_check()
{
    if (g_health.alerted)
        return {}; // one alert per session is enough
    uint64_t now = os::now_ms();
    if (!g_health.armed) {
        g_health.armed = true;
        g_health.last_check_ms = now;
        g_health.last_wall_ms = now;
        return {};
    }

    uint64_t prev_wall = g_health.last_wall_ms;
    uint64_t gap = now >= prev_wall ? now - prev_wall : 0;

    // a multi-second jump while we were pumping means the machine slept hard or
    // came back from a crash/reboot. 15 s is past a normal ui hitch.
    if (prev_wall && gap > 15000) {
        g_health.alerted = true;
        g_health.last_check_ms = now;
        g_health.last_wall_ms = now;
        return util::fmt("host clock jumped %llu ms — possible BSOD, hard reboot, or the session was suspended",
            (unsigned long long)gap);
    }

    // throttle the process probes
    if (now - g_health.last_check_ms < 400) {
        g_health.last_wall_ms = now;
        return {};
    }
    g_health.last_check_ms = now;
    g_health.last_wall_ms = now;

#ifdef _WIN32
    // csrss owns every win32 session; if it's gone, the machine is gone or logging off
    if (!find_named_alive("csrss.exe")) {
        g_health.alerted = true;
        return "csrss.exe is gone — the host session is dying (logoff or BSOD)";
    }
    if (!process_alive(4)) {
        g_health.alerted = true;
        return "the Windows System process (pid 4) is gone — host crash";
    }
#elif defined(__linux__)
    if (!process_alive(1)) {
        g_health.alerted = true;
        return "pid 1 is gone — the host is going down";
    }
#else
    (void)0;
#endif
    return {};
}
