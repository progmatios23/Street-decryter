# ceasta

**Full Rust.** Disassembler, decompiler, debugger, Lua plugins, MCP.

```bash
cargo build -p ceasta-cli --release
./target/release/ceasta-cli info ./binary
./target/release/ceasta-cli protect 1
```

## Crates

| Crate | Role |
|-------|------|
| `ceasta-binary` | PE / ELF / Mach-O / raw loaders |
| `ceasta-disasm` | x86/x64 decode (`iced-x86`) |
| `ceasta-analysis` | functions, xrefs, strings, flags |
| `ceasta-fileinfo` | hashes, entropy, security flags |
| `ceasta-decompiler` | F5 pseudocode |
| `ceasta-debugger` | start / attach / step |
| `ceasta-host` | never attach to this machine + BSOD watch |
| `ceasta-db` | names, comments, projects |
| `ceasta-script` | Lua plugins |
| `ceasta-mcp` | MCP for AI clients |
| `ceasta-ui` / `ceasta-app` | GUI |
| `ceasta-cli` | headless CLI |

Architecture: [`docs/rust/ARCHITECTURE.md`](docs/rust/ARCHITECTURE.md).

The old C++ tree is under [`legacy/`](legacy/) (reference only — not built by CI).
