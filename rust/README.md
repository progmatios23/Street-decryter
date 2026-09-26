# ceasta — Rust native rewrite

This tree is the **native Rust** port of ceasta (disassembler, decompiler,
debugger, Lua plugins, MCP). The C++ tree at the repo root stays the shipping
product until crates here reach parity; both can live in one repo during the
migration.

## Why Rust (advantages)

| Area | C++ today | Rust native |
|------|-----------|-------------|
| Memory | manual / RAII, UAF risk in debugger & loaders | ownership + borrow checker; safer attach/read paths |
| Threads | UI + analysis + MCP by discipline | `Send`/`Sync` enforced; less “forgot the lock” |
| Formats | hand-rolled PE/ELF/Mach-O | `goblin` + typed structs; less header foot-guns |
| x86 disasm | Capstone (C FFI) | `iced-x86` (pure Rust) — no C disassembler in the hot path |
| Errors | `std::string& err` everywhere | `Result` + `thiserror`; impossible to ignore quietly |
| Packaging | CMake + MSVC + AppImage glue | one `cargo build --release` per target |
| Supply chain | vendored trees in `third_party/` | crates.io + lockfile; optional vendoring |
| Plugins | Lua via vendored VM compiled as C++ | `mlua` (safe wrappers); same plugin API surface |
| UI | Dear ImGui + DX11 / GLFW | `egui`/`eframe` (pure Rust) or keep imgui-rs as a bridge |
| Host protect | `host_guard.cpp` | `ceasta-host` — same rules, safer process enumeration |

**Native** here means: no C++ core, prefer pure-Rust crates for formats and
x86, platform crates (`windows`, `nix`) only at the debugger OS boundary.

## Crate map (rewritten structure)

```text
rust/
  Cargo.toml                 workspace
  crates/
    ceasta-binary            loaders: PE / ELF / Mach-O / raw  → Binary
    ceasta-disasm            iced-x86 (+ arm64 later)
    ceasta-analysis          functions, xrefs, strings, switches
    ceasta-decompiler        F5-style pseudocode
    ceasta-debugger          start / attach / step (win + linux)
    ceasta-db                names, comments, bps, .ceasta projects
    ceasta-script            Lua plugins (ceasta.* API)
    ceasta-mcp               MCP stdio / http
    ceasta-host              protect this machine + BSOD / host watch
    ceasta-ui                egui shell (panels, listing, graph)
    ceasta-cli               `ceasta-cli` binary
    ceasta-app               `ceasta` GUI binary
```

### Dependency direction (no cycles)

```text
ceasta-cli / ceasta-app
        │
        ▼
   ceasta-ui ──────────────────────────┐
        │                              │
        ▼                              ▼
   ceasta-mcp ◄── ceasta-script ◄── ceasta-db
        │                │               │
        └───────► ceasta-debugger ◄──────┤
                        │                │
                        ▼                ▼
                  ceasta-host     ceasta-analysis
                        │                │
                        └──────► ceasta-disasm
                                      │
                                      ▼
                               ceasta-binary
```

## Migration phases

1. **Foundation (this scaffold)** — workspace, `Binary` + PE TLS, `ceasta-host`, CLI `info`/`funcs` stubs.
2. **Analysis parity** — functions, xrefs, strings, signatures, diff.
3. **Debugger** — Windows Debug API + Linux ptrace behind one trait; host protect on by default.
4. **Decompiler + plugins** — port F5; `mlua` with the existing `docs/lua.md` API.
5. **UI** — egui listing/graph/pseudo; feature-flag C++ GUI until cutover.
6. **Cutover** — ship Rust CLI/AppImage/dmg; archive or thin-wrap C++.

## Build

```bash
cd rust
cargo build -p ceasta-cli --release
./target/release/ceasta-cli info /path/to/file.exe
```

## Status

Scaffold + working PE/ELF/Mach-O open via `goblin`, TLS callback extraction for
PE, host-protect helpers, and a CLI entrypoint. Analysis, debugger, decompiler,
UI, MCP, and Lua are crate stubs with clear module boundaries ready to fill.
