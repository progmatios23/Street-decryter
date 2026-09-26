# ceasta — Rust native

The product is **full Rust** at the repo root (`Cargo.toml` + `crates/`).
C++ lives only under [`legacy/`](../../legacy/) as a behavioural reference.

## Why Rust

| Area | Legacy C++ | Rust native |
|------|------------|-------------|
| Memory | manual / RAII | ownership + borrow checker |
| Threads | discipline | `Send`/`Sync` enforced |
| Formats | hand-rolled PE/ELF/Mach-O | `goblin` |
| x86 disasm | Capstone (C FFI) | `iced-x86` (pure Rust) |
| Errors | `string& err` | `Result` + `thiserror` |
| Packaging | CMake + MSVC | `cargo build --release` |
| Plugins | vendored Lua C | `mlua` |
| Host protect | `host_guard.cpp` | `ceasta-host` |

## Crate map

```text
Cargo.toml                 workspace
crates/
  ceasta-binary            PE / ELF / Mach-O / raw
  ceasta-disasm            iced-x86
  ceasta-analysis          functions, xrefs, strings, switches
  ceasta-fileinfo          hashes, entropy, security flags
  ceasta-decompiler        F5-style pseudocode
  ceasta-debugger          start / attach / step (win + linux)
  ceasta-db                names, comments, bps, .ceasta projects
  ceasta-script            Lua plugins (ceasta.* API)
  ceasta-mcp               MCP stdio
  ceasta-host              protect this machine + BSOD watch
  ceasta-ui                GUI state
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

## Build

```bash
cargo build -p ceasta-cli --release
./target/release/ceasta-cli info /path/to/file
./target/release/ceasta-cli protect 1
```

See also [`ARCHITECTURE.md`](ARCHITECTURE.md).
