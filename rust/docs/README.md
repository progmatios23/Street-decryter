# ceasta — Rust rewrite notes

See the full design in this folder:

- [README.md](./README.md) — advantages + crate map + phases
- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) — layered structure vs C++

Quick start:

```bash
cd rust && cargo build -p ceasta-cli --release
./target/release/ceasta-cli info /path/to/binary
./target/release/ceasta-cli protect $$
```
