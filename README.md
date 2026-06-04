# senv

> Encrypted `.env` replacement with first-class TUI — written in Rust.

**Status**: 🚀 Alpha / functional. All six TUI modals, the CLI exec wrapper, age encryption, OS keyring identity, and multi-recipient sharing are wired end-to-end. 24 unit tests pass.

## Why senv?

Existing tools split into four camps that don't compose:

- **loaders** (`dotenvy`) — convenient, plaintext on disk
- **vaults** (`envy`, `keynest`) — secure, but no `.env` ergonomics
- **git filters** (`git-agecrypt`) — encrypted at rest, opaque at runtime
- **crypto substrates** (`rage`, `age-plugin-yubikey`) — building blocks only

senv combines all four into a single Rust binary with a first-class TUI — a gap that `dotenvx`, `dotenvage`, `envy`, and `murk` each fill only partially.

## Architecture

```mermaid
flowchart TB
    subgraph user[" User "]
        CLI["senv ⟨cmd⟩"]
        TUI["senv (TUI)"]
    end

    subgraph senv[" senv binary "]
        direction TB
        cli["cli/<br/>clap dispatch"]
        tui_layer["tui/<br/>ratatui modals"]
        core["core/<br/>discovery · ops · schema"]
        crypto["crypto/<br/>age identity + lock"]
        storage["storage/<br/>vault_file + BLAKE3 MAC"]
        inject["inject/<br/>exec wrapper · export"]

        cli --> core
        tui_layer --> core
        core --> crypto
        core --> storage
        core --> inject
        crypto --> storage
        inject --> crypto
        inject --> storage
    end

    subgraph os[" OS / Filesystem "]
        keyring[("🔐 OS Keyring<br/>Keychain · Secret Service · CredMgr")]
        envage[("📄 .env.age<br/>JSON · mode 0600")]
        envfile[("📄 .env<br/>fallback")]
    end

    CLI --> cli
    TUI --> tui_layer
    crypto --> keyring
    storage --> envage
    core -.-> envfile
```

| Layer | Responsibility | Inspired by |
|---|---|---|
| `tui/` | ratatui interactive interface (the differentiator) | — first of its kind |
| `cli/` | clap subcommands + `senv -- <cmd>` exec wrapper | dotenvx, doppler |
| `core/` | discovery, ops, schema, multi-recipient re-encryption | murk |
| `crypto/` | age x25519, OS keyring identity, lock/unlock | murk + envy |
| `storage/` | atomic file I/O, BLAKE3 MAC, symlink rejection | murk |
| `inject/` | `Command::env` spawn, `eval $(senv export)` | dotenvage + envchain |

## Build

```bash
cargo build --release
./target/release/senv
```

Release binary is ~2.5MB after LTO + strip.

## CLI

```bash
senv init                  # mint age identity, store in OS keyring, create .env.age
senv import .env           # encrypt each entry into the vault
senv list                  # masked list of cwd .env keys
senv diff                  # missing / extra vs .env.example
senv export                # eval $(senv export) shell-compatible output
senv -- cargo run          # spawn child with vault env injected
senv tui                   # interactive TUI (default if no subcommand)
```

### Flow: `senv init`

```mermaid
sequenceDiagram
    actor U as User
    participant S as senv
    participant A as age::x25519
    participant K as 🔐 OS Keyring
    participant F as 📄 .env.age

    U->>S: senv init
    S->>A: Identity::generate()
    A-->>S: { private, public }
    S->>K: set_password(service="senv", account="default-identity", key=private)
    K-->>S: ok
    S->>F: write Vault { recipients:[public], secrets:{}, mac }
    Note over F: tempfile → fsync → rename<br/>chmod 0600
    F-->>S: persisted
    S-->>U: ✓ recipient: age1uadkg…
```

### Flow: `senv import .env`

```mermaid
sequenceDiagram
    actor U as User
    participant S as senv
    participant D as dotenvy
    participant K as 🔐 OS Keyring
    participant F as 📄 .env.age
    participant A as age

    U->>S: senv import .env
    S->>D: from_read_iter(.env)
    D-->>S: Vec⟨(key, SecretString)⟩
    S->>K: get_password(default-identity)
    K-->>S: private key
    S->>F: read existing Vault (or new)
    F-->>S: Vault { recipients, secrets, mac }
    loop for each (key, plaintext)
        S->>A: encrypt(plaintext, recipients)
        A-->>S: base64(age ciphertext)
        Note over S: vault.secrets[key] = ciphertext
    end
    S->>S: vault.mac = BLAKE3(keys ‖ ciphertexts ‖ recipients)
    S->>F: atomic write (tempfile + fsync + rename + dir fsync)
    S-->>U: ✓ N entries encrypted
```

### Flow: `senv -- <cmd>`

```mermaid
sequenceDiagram
    actor U as User
    participant S as senv
    participant K as 🔐 OS Keyring
    participant F as 📄 .env.age
    participant A as age
    participant C as Child Process

    U->>S: senv -- cargo run
    S->>K: load private key
    K-->>S: identity (in-memory, zeroized on drop)
    S->>F: read + verify MAC
    alt MAC mismatch
        F-->>S: ⚠ tampered
        S-->>U: error: vault integrity check failed
    else MAC ok
        F-->>S: Vault
        loop for each secret
            S->>A: decrypt(ciphertext, identity)
            A-->>S: plaintext
        end
        S->>C: spawn("cargo", ["run"], env={K:V, ...})
        C-->>S: exit code
        S-->>U: exit with child code
    end
```

## TUI

```bash
cargo run                  # or ./target/release/senv
```

| Key | Action |
|---|---|
| `↑↓` / `j` / `k` | Navigate rows |
| `t` / `T` | Cycle env tab |
| `space` | Reveal/mask current value |
| `e` | Edit value (textarea modal, vault re-encrypt on Enter) |
| `a` | Add secret (KEY=VALUE) |
| `s` | Edit schema description (persisted in vault) |
| `r` | Recipients: list / `a` add age1... / `d` revoke + re-encrypt |
| `i` | Import wizard with `.env` preview |
| `D` | Diff vs `.env.example` (Missing/Extra/Match) |
| `L` / `U` | Lock now / Unlock |
| `?` / `F1` | Help overlay |
| `q` / `Ctrl+C` | Quit |

### Modal state machine

```mermaid
stateDiagram-v2
    [*] --> Normal: launch
    Normal --> EditValue: e
    Normal --> AddSecret: a
    Normal --> SchemaEdit: s
    Normal --> Recipients: r
    Normal --> ImportWizard: i
    Normal --> DiffView: D
    Normal --> Help: ? / F1
    Normal --> [*]: q / Ctrl+C

    EditValue --> Normal: Esc (cancel) / Enter (vault re-encrypt)
    AddSecret --> Normal: Esc (cancel) / Enter (vault re-encrypt)
    SchemaEdit --> Normal: Esc (cancel) / Enter (vault re-encrypt)
    Recipients --> Normal: Esc
    ImportWizard --> Normal: Esc (cancel) / Enter (encrypt + reload)
    DiffView --> Normal: Esc
    Help --> Normal: Esc / ? / q
```

## Security model

### Threat → defense mapping

```mermaid
flowchart LR
    subgraph T[" 🔴 Threat "]
        T1["Leak .env.age<br/>(public repo, backup, USB)"]
        T2["Tamper .env.age<br/>(swap a ciphertext)"]
        T3["Symlink attack<br/>(redirect read/write)"]
        T4["Crash mid-write<br/>(partial vault)"]
        T5["Other user reads file<br/>(shared host)"]
        T6["Memory disclosure<br/>(coredump, swap)"]
        T7["Ex-teammate keeps copy<br/>(after offboarding)"]
        T8["Brute-force decryption"]
    end

    subgraph D[" 🟢 Defense "]
        D1["age x25519<br/>need private key"]
        D2["BLAKE3 MAC<br/>verify on read · refuse unlock"]
        D3["path.is_symlink() reject<br/>read + write"]
        D4["tempfile → fsync → rename<br/>+ directory fsync"]
        D5["chmod 0600<br/>owner-only"]
        D6["secrecy::SecretString<br/>+ Zeroize on drop"]
        D7["Recipients revoke<br/>→ full vault re-encryption<br/>⚠ also rotate the secret value"]
        D8["ChaCha20-Poly1305 AEAD<br/>not a passphrase"]
    end

    T1 --> D1
    T2 --> D2
    T3 --> D3
    T4 --> D4
    T5 --> D5
    T6 --> D6
    T7 --> D7
    T8 --> D8
```

### Key facts

- **At rest**: `.env.age` is JSON wrapping age-encrypted ciphertext per entry, plus a BLAKE3 MAC covering keys + ciphertext + recipient list. Tampering invalidates the MAC and unlock refuses to proceed.
- **At runtime**: private key lives only in the OS keyring (Keychain on macOS, Secret Service on Linux, Credential Manager on Windows). Loaded on unlock, dropped on lock.
- **Atomicity**: every vault write is tempfile → fsync → rename, with the directory also fsynced on Unix. Vault paths are checked for symlinks and refused before reading or writing.
- **Permissions**: written vaults are chmod 0600 on Unix.
- **No plaintext on disk** once you have moved off `.env` (the loader still falls back to `.env` when no vault is present so the wrapper works pre-init).

### Scenarios

| Situation | Outcome |
|---|---|
| `.env.age` pushed to a public repo | 🟢 OK — needs the private key to decrypt |
| Laptop stolen, keyring locked | 🟢 OK — keyring locked, key inaccessible |
| Laptop stolen, screen unlocked | 🔴 Risk — attacker runs `senv`, secrets exposed → auto-lock recommended |
| Vault tampered in transit | 🟢 OK — MAC verify fails, unlock refuses |
| Teammate offboarded (revoked) | 🟡 New commits safe, but old git history still decryptable by their key — **rotate the secret values too** |
| `.env` accidentally committed | ⚫ senv can't prevent this — keep `.env` in `.gitignore` + pre-commit hook |

## Workflow examples

### Adopt senv in a new project

```bash
cd my-rust-app
senv init                       # generate identity + empty vault
senv import .env                # encrypt existing .env into the vault
rm .env                         # plaintext no longer needed
git add .env.age .gitignore
git commit -m "switch to encrypted env"

senv -- cargo run               # daily use
```

### Add a teammate

```bash
# 🧑‍💻 Them (on their machine)
git clone repo && cd repo
senv init                       # they generate their own age key
# share their public recipient via Slack:
# "my recipient is age1ttttgkfg…"

# 🧑‍💻 You
senv                            # TUI → r (Recipients) → a → paste age1ttttgkfg… → Enter
# → vault automatically re-encrypted for both keys
git add .env.age && git commit -m "share with @them" && git push

# 🧑‍💻 Them
git pull && senv                # auto-unlock, secrets visible
```

### Revoke a teammate (and really revoke)

```bash
senv                            # TUI → r → j/k pick → d → vault re-encrypted without them
git add .env.age && git commit -m "revoke @them" && git push

# 🚨 Don't stop there: their old clone can still decrypt past commits.
# Rotate the underlying secret values too (DB passwords, API keys, ...)
# Then edit the new values in senv: TUI → e
```

## Roadmap

Implemented:

- [x] CLI dispatch, TUI shell, layer scaffolding
- [x] `storage/vault_file.rs` — `.env.age` JSON with atomic write + symlink reject + BLAKE3 MAC
- [x] `crypto/identity.rs` — age x25519, keyring-core backend, lock/unlock
- [x] `core/ops.rs` — init / import / list / diff / export
- [x] `inject/exec.rs` — `senv -- cargo run` end-to-end
- [x] EditValue / AddSecret modals
- [x] DiffView modal (.env.example comparison)
- [x] ImportWizard modal
- [x] SchemaEdit modal (description per key, persisted in vault)
- [x] Recipients modal: add by age pubkey + revoke + full vault re-encryption
- [x] Multi-recipient ciphertext (any listed recipient can decrypt)
- [x] Unit tests (24 passing across storage / vault / ops)

Next:

- [ ] `github:user` SSH-key fetch in Recipients add wizard
- [ ] SchemaEdit example + tags fields (currently description only)
- [ ] Personal override (`o` key) writes to vault.scoped
- [ ] CI mode: `SENV_PASSPHRASE` / `SENV_IDENTITY` env var fallback when keyring is unavailable
- [ ] TouchID prompt on first unlock per session
- [ ] Integration tests under `tests/` driving the binary end-to-end
- [ ] `senv set KEY=VAL [--personal]` CLI write
- [ ] `senv vault list` reading the encrypted store directly

## License

MIT OR Apache-2.0
