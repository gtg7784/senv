# senv

> Encrypted `.env` replacement with first-class TUI — written in Rust.

**Status**: 🚧 Alpha / scaffolding. TUI shell works, encryption/storage layers are stubs.

## Why senv?

Existing tools split into four camps that don't compose:

- **loaders** (`dotenvy`) — convenient, plaintext on disk
- **vaults** (`envy`, `keynest`) — secure, but no `.env` ergonomics
- **git filters** (`git-agecrypt`) — encrypted at rest, opaque at runtime
- **crypto substrates** (`rage`, `age-plugin-yubikey`) — building blocks only

senv combines all four into a single Rust binary with a first-class TUI — a gap that `dotenvx`, `dotenvage`, `envy`, and `murk` each fill only partially.

## Design

| Layer | Responsibility | Sources of inspiration |
|---|---|---|
| `tui/` | ratatui interactive interface (the differentiator) | — first of its kind |
| `cli/` | clap subcommands + `senv -- <cmd>` exec wrapper | dotenvx, doppler |
| `core/` | discovery, ops, schema, shared+scoped merge | murk |
| `crypto/` | age x25519/ssh/plugin, BLAKE3 keyed MAC, identity unlock | murk + envy |
| `storage/` | atomic file I/O, OS keyring backends, symlink rejection | dotenvage + murk |
| `inject/` | `Command::env_clear` + spawn, `eval $(senv export)`, PTY | dotenvage + envchain |

## Build

```bash
cargo build --release
./target/release/senv
```

Release binary is ~1.6MB after LTO + strip.

## Try the TUI

```bash
cargo run
# or
cargo run -- tui
```

| Key | Action |
|---|---|
| `↑↓` / `j` / `k` | Navigate rows |
| `t` / `T` | Cycle env tab |
| `space` | Reveal/mask current value |
| `e` / `a` / `d` | Edit / Add / Delete (modal) |
| `o` | Toggle personal override (murk-style scoped) |
| `s` | Edit schema (description / example / tags) |
| `r` | Manage recipients |
| `i` | Import `.env` wizard |
| `D` | Diff against `.env.example` |
| `L` / `U` | Lock now / Unlock |
| `?` / `F1` | Help overlay |
| `q` / `Ctrl+C` | Quit |

## Roadmap

- [x] CLI dispatch, TUI shell, layer scaffolding
- [ ] `storage/vault_file.rs` — `.env.age` JSON with atomic write + flock + symlink reject + BLAKE3 MAC
- [ ] `crypto/identity.rs` — age x25519, keyring-core backend, TouchID unlock
- [ ] `core/ops.rs` — set / get / list / import / diff
- [ ] `inject/exec.rs` — `senv -- cargo run` end-to-end
- [ ] Schema editor modal
- [ ] Recipients management (incl. `github:username` SSH-key fetch)
- [ ] `.env` ↔ `.env.age` bidirectional sync

## License

MIT OR Apache-2.0
