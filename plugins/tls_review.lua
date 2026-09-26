-- tls_review.lua - list PE TLS callbacks and comment them in the listing.
-- TLS callbacks run before the entry point (and again when a thread attaches),
-- so malware and packers hide work there. With Debug > Break on tls callbacks
-- on, the debugger stops on each of them before entry.

ceasta.register_command("TLS callbacks / review", function()
    local cbs = ceasta.tls_callbacks()
    if #cbs == 0 then
        return ceasta.log("no tls callbacks in this file (PE only, or none present)")
    end
    ceasta.log(("%d tls callback%s (run before the entry point):"):format(
        #cbs, #cbs == 1 and "" or "s"))
    for _, cb in ipairs(cbs) do
        local where = ceasta.location(cb.addr)
        ceasta.log(("  [%d] %s"):format(cb.index, where))
        local note = ceasta.comment(cb.addr)
        if note == "" then
            ceasta.set_comment(cb.addr, "tls callback: runs before the entry point")
        end
    end
    ceasta.log("tip: Debug > Break on tls callbacks stops on each before entry")
end, "list PE TLS callbacks and comment them in the listing")

ceasta.on("load", function()
    local n = #ceasta.tls_callbacks()
    if n > 0 then
        ceasta.warn(("%d tls callback%s — Plugins > TLS callbacks / review"):format(
            n, n == 1 and "" or "s"))
    end
end)
