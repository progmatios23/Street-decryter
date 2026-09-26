# contributing to ceasta

thanks for looking. issues and pull requests are welcome.

## license

ceasta is [GPLv3](../LICENSE). anything you contribute is shipped under the same
license.

## building

```bash
cargo build -p ceasta-cli --release
cargo test --workspace
```

rustc 1.75+ (CI uses stable). the C++ tree under `legacy/` is reference-only
and is not built by the root workspace or CI.

## where things live

| path | role |
|------|------|
| `crates/ceasta-binary` | PE / ELF / Mach-O / raw loaders |
| `crates/ceasta-analysis` | functions, xrefs, strings |
| `crates/ceasta-disasm` | iced-x86 decode |
| `crates/ceasta-decompiler` | F5 pseudocode |
| `crates/ceasta-debugger` | start / attach / step |
| `crates/ceasta-host` | never attack this machine |
| `crates/ceasta-db` | names, comments, projects |
| `crates/ceasta-script` | Lua (`mlua`) |
| `crates/ceasta-mcp` | MCP |
| `crates/ceasta-cli` | headless CLI |
| `crates/ceasta-ui` / `ceasta-app` | GUI |
| `plugins/` | Lua plugins |
| `legacy/` | archived C++ (not the product) |

architecture notes: [`docs/rust/ARCHITECTURE.md`](../docs/rust/ARCHITECTURE.md).

## pull requests

- keep a change focused on one thing
- match the code around it: rustfmt, short comments where non-obvious
- it has to build with `cargo test --workspace` on linux and windows — ci checks both
- say what you changed and how you checked it

## bugs

use the bug report template. the most useful thing is the kind of file
(e.g. "64-bit pe exe", "elf x86 pie") and, if you can share it, the file itself
or where to get it.

## plugins

plugins are plain lua, see the [lua guide](../docs/lua.md). a good general plugin
can go in `plugins/` through a pull request.
