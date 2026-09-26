# Rust native architecture

How the C++ monolith maps onto a Rust workspace, and why the boundaries look
like this.

## Goals

1. **One mental model** — same product (listing, F5, debugger, plugins, MCP).
2. **Native Rust** — formats and x86 decode without C++; OS FFI only in debugger backends.
3. **Safe by default** — host protect + health watch stay first-class (`ceasta-host`).
4. **Incremental ship** — CLI first, GUI second; C++ remains until parity.

## Layered structure

### 1. `ceasta-binary` — image truth

Owns `Binary`, `Segment`, imports/exports/symbols, `tls_callbacks`, raw bytes.

| Module | Responsibility |
|--------|----------------|
| `pe` | PE32/PE32+, TLS directory, relocs, exports |
| `elf` | ELF32/64, notes, init arrays |
| `macho` | thin + fat, bind/chained fixups later |
| `raw` | blob + base + arch |

Replaces: `src/core/binary.*`, `pe.cpp`, `elf.cpp`, `macho.cpp`.

### 2. `ceasta-disasm` — one instruction at a time

Trait `Decoder` + `iced-x86` for x86/x64. ARM64 behind a feature when a pure-Rust
decoder is chosen (or a thin capstone feature as escape hatch only).

Replaces: `src/core/disasm.*`.

### 3. `ceasta-analysis` — graph over the image

Function starts, xrefs, strings, switch tables, thunks. Reads only `&Binary` +
decoder; writes into an `Analysis` struct (no UI types).

Replaces: `src/core/analysis.*`, pieces of `search.*`, `signatures.*`, `diff.*`.

### 4. `ceasta-decompiler` — F5

Consumes analysis + disasm; returns text / structured AST for the UI and MCP.
No debugger dependency.

Replaces: `src/core/decompiler.*`, `protos.*` (API prototypes table).

### 5. `ceasta-debugger` — live process

```rust
pub trait Debugger: Send {
    fn start(&mut self, exe: &Path, args: &str) -> Result<()>;
    fn attach(&mut self, pid: u32) -> Result<()>;
    // poll, step, bp, registers, memory…
}
```

Backends: `win` (`windows` crate), `linux` (`nix` / ptrace). `attach` always
asks `ceasta-host` first when `protect_host` is on.

Replaces: `debugger.cpp`, `debugger_linux.cpp`, `debugger_steps.cpp`, …

### 6. `ceasta-host` — never attack this machine

| API | Role |
|-----|------|
| `protect_reason(pid)` | why attach is refused |
| `health_check()` | BSOD / reboot / critical process gone |
| `health_reset()` | new session |

Replaces: `host_guard.cpp` (+ menu flags in the app).

### 7. `ceasta-db` — user work

Names, comments, types, breakpoints, bookmarks, undo, `.ceasta` project file.

Replaces: `database.*`, `exchange.*` (import/export adapters as submodules).

### 8. `ceasta-script` — Lua

`mlua` sandbox with the same `ceasta.*` / `ceasta.dbg.*` surface documented in
`docs/lua.md`. Plugins from `plugins/*.lua` load unchanged where possible.

Replaces: `lua_host.*`.

### 9. `ceasta-mcp` — AI bridge

stdio + localhost HTTP; tools mirror the C++ MCP list. Debug tools gated on
`--allow-debug` and host protect.

Replaces: `mcp.*`, `mcp_transport.*`.

### 10. `ceasta-ui` / `ceasta-app` — shell

`egui` panels: functions, listing, graph, pseudocode, debugger, output/Lua.
`ceasta-app` is the binary; `ceasta-ui` is the library.

Replaces: `src/ui/*`, `app.*`, `main*.cpp`.

### 11. `ceasta-cli` — headless

Same commands as today’s `ceasta-cli` (`info`, `disasm`, `dbg`, `mcp`, `run`, …).

## Advantages vs staying on C++

1. **Fearless concurrency** for analysis workers + MCP without corrupting the DB.
2. **Fewer security bugs** in loaders and memory R/W (parse + attach are hostile input).
3. **Faster iteration** — `cargo test -p ceasta-binary` instead of full CMake relinks.
4. **Smaller deploy story** — static musl CLI, single GUI crate; less `third_party` drift.
5. **Host safety as a crate** — protect/BSOD watch testable without spinning the GUI.
6. **Plugin stability** — keep Lua API; rewrite only the host, not every plugin.

## Non-goals (for the port)

- Rewriting plugins in Rust (Lua stays).
- Kernel debugger / KD.
- Bit-identical decompiler output on day one (parity tests drive convergence).

## Cutover checklist

- [ ] `ceasta-cli info/disasm/funcs` match C++ on a corpus
- [ ] Debugger smoke: start, bp, step, detach on win + linux
- [ ] Host protect refuses self + critical pids in CI
- [ ] Lua plugins in `plugins/` run under `mlua`
- [ ] MCP tools used by Cursor/Claude still work
- [ ] GUI opens PE/ELF/Mach-O and F5 works for x64
