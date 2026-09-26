-- host_guard.lua - explain host protection, and react when the host looks like
-- it bluescreened / rebooted during a debug session.
-- The C++ side already blocks attach with Debug > Protect this machine; this
-- plugin surfaces the same rules and listens for the host_alert event.

ceasta.on("host_alert", function()
    ceasta.warn("host alert while debugging — the session machine may have crashed (BSOD) or rebooted")
    ceasta.warn("detach / kill the debuggee if it is still listed; do not keep writing memory")
end)

ceasta.register_command("Host protect / explain", function()
    ceasta.log("protect this machine refuses attach to:")
    ceasta.log("  - ceasta itself and its parent")
    ceasta.log("  - windows: System, smss, csrss, wininit, services, lsass, winlogon, ...")
    ceasta.log("  - linux: pid 1, kernel threads, systemd/init, ...")
    ceasta.log("toggle: Debug > Protect this machine")
    ceasta.log("from lua: ceasta.host_protect_reason(pid) -> reason or nil")
    ceasta.log("host crash watch: Debug > Watch for host crash / BSOD (event: host_alert)")
end, "explain how ceasta refuses to attach to the machine we are on")
