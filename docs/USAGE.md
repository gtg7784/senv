# senv user manual

> An encrypted `.env` replacement — written in Rust, as ergonomic as plain `.env`.

---

## 5-minute quickstart

```bash
# 1. Build (until Homebrew is published)
cd senv
cargo build --release
sudo cp target/release/senv /usr/local/bin/   # or any directory on your PATH

# 2. Go to a project and initialize
cd my-project
senv init                       # generate age identity + OS keyring + empty .env.age

# 3. Migrate an existing .env in one line
senv import .env
rm .env                          # plaintext is no longer needed

# 4. Daily use — just prefix any command with `senv --`
senv -- cargo run
senv -- npm run dev
senv -- pytest

# 5. Edit interactively in the TUI
senv                             # launches TUI
# → arrows / j / k to navigate
# → e to edit, a to add, q to quit
```

That's it. Details below.

---

## Install

### Option A: build from source (today)

```bash
git clone https://github.com/gtg7784/senv.git
cd senv
cargo build --release
# Binary at target/release/senv (~2.5MB)
```

### Option B: Homebrew (after first release)

```bash
brew tap gtg7784/senv
brew install senv
```

---

## Core concepts

| Term | Meaning |
|---|---|
| **identity** | age x25519 keypair. Private key lives in OS keyring; public (`age1...`) goes into the vault |
| **recipient** | A public key that can decrypt the vault. Multiple recipients = a team |
| **vault** | The `.env.age` file. JSON + per-entry age ciphertext + BLAKE3 MAC |
| **keyring** | OS-native secret store: macOS Keychain, Linux Secret Service, Windows Credential Manager |

Core rule: **no plaintext `.env` on disk.** Only `.env.age` is committed. To unlock anywhere, your private key must be in that machine's keyring.

---

## CLI reference

```bash
senv init                        # mint first identity + create empty vault
senv import <file>               # encrypt a plaintext .env into the vault
senv list                        # masked cwd .env keys (byte sizes only)
senv diff                        # missing / extra vs .env.example
senv export                      # eval $(senv export) to inject into current shell
senv -- <command>                # spawn child process with vault env injected
senv                             # no args = TUI
senv tui                         # explicit TUI
senv --help
senv --version
```

### `senv -- <cmd>` is the workhorse

Daily command. Prefix any tool with `senv --` and every secret in the vault is exported into the child process.

```bash
senv -- cargo run
senv -- npm test
senv -- python manage.py runserver
senv -- docker compose up
senv -- gh issue create
```

The child inherits the parent (`senv`) environment, with vault entries layered on top. The exit code propagates (CI-friendly).

---

## TUI

```bash
senv          # or senv tui
```

### Layout

```
┌─ Header ────────────────────────────────────────────────┐
│  senv │ project: my-app │ origin/main │ 🔓 unlocked     │
├─Envs──┬─Secrets─────────────────────────┬─Recipients────┤
│ ▶dev  │  KEY              VALUE   SOURCE│ ★ alan (you) │
│  stg  │ ▶DATABASE_URL    ●●●●●●●  shared│  · jisoo     │
│  prd  │  STRIPE_KEY      ●●●●●●●  shared├─Activity──────┤
│       │  GITHUB_PAT      ●●●●●●●  yours │ 14:22 unlock │
├───────┴─────────────────────────────────┴───────────────┤
│ [↑↓/jk] nav · space reveal · e edit · a add · ...      │
└─────────────────────────────────────────────────────────┘
```

### Keymap

| Key | Action |
|---|---|
| `↑↓` / `j` / `k` | Move between rows |
| `t` / `T` | Cycle env tab (dev/staging/prod) |
| `space` | Reveal/mask the selected value |
| `e` | Edit value — modal opens, `Enter` to save, `Esc` to cancel |
| `a` | Add new secret — type `KEY=VALUE`, press `Enter` |
| `d` | Delete (with confirmation) |
| `s` | Edit schema description — persisted in the vault |
| `r` | Manage recipients (add/revoke teammates) |
| `i` | `.env` import wizard — preview keys before encrypting |
| `D` | Diff vs `.env.example` (Missing/Extra/OK) |
| `L` / `U` | Lock now / Unlock |
| `?` / `F1` | Help overlay |
| `q` / `Ctrl+C` | Quit |

### Empty screen on first launch

If the vault has zero secrets, you'll see a placeholder message. In this state `j/k` has nothing to move through (works as designed). Use `i` (import) or `a` (add) to populate first.

---

## Team workflow

### Add a teammate

**Teammate (on their machine)**
```bash
git clone <repo> && cd <repo>
senv init                                 # generate their own age key
# Output includes their public key:
#   recipient: age1ttttgkfg...
# Send this line to you via Slack
```

**You (vault owner)**
```bash
senv                                       # launch TUI
# → r (Recipients)
# → a (input mode)
# → paste "age1ttttgkfg..."
# → Enter

# All secrets are immediately re-encrypted for both keys
git add .env.age
git commit -m "share secrets with @them"
git push
```

**Teammate (back on their machine)**
```bash
git pull
senv                                       # auto-unlock, all secrets visible
```

### Revoke a teammate

```bash
senv                                       # TUI
# → r → j/k pick the leaving teammate → d (revoke)
# → vault re-encrypted for the remaining recipients only
git add .env.age && git commit -m "revoke @them" && git push
```

> ⚠️ **Important**: Revoke only protects the *new* vault. The leaving teammate's past git clones can still decrypt earlier commits with their key. **For real revocation, also rotate the secret values themselves** (change DB passwords, re-issue API keys, etc.). Then edit the new values in senv via `e`.

---

## Why this is secure (summary)

1. **age asymmetric encryption** — locked with the public key, opened with the private key. Mathematical, not a passphrase. Brute-force infeasible.
2. **Private key only in OS keyring** — no plaintext key file on disk. Locks together with the OS.
3. **`.env.age` is safe to commit** — only listed recipients can decrypt. Even a public repo is fine for the vault.
4. **BLAKE3 MAC** — detects tampering immediately. Unlock refuses on mismatch.
5. **Atomic write + 0600 permissions** — crash-safe + other users can't read.
6. **Symlink rejection** — attackers can't redirect the vault path.
7. **Memory zeroize** — secrets are wiped from memory after use (protects against coredump/swap).

Full threat model: see the [Security model section in README](../README.md#security-model).

---

## Troubleshooting

### Vault is empty after `senv init`, and the TUI shows nothing

→ Expected. The vault holds zero secrets. Use `a` (add) or `senv import .env`.

### `j/k` doesn't work

→ There are no rows to scroll through. Add data first (`a` or `i`). `q`/`?` are mode keys and work even with an empty vault.

### Row highlight isn't visible

→ It's cyan background + black text + bold + `▶ ` symbol. If your terminal renders cyan as invisible, open an issue and we'll add a theme switch.

### `senv -- cargo run` triggered a keyring prompt

→ First-time unlock on macOS asks for Keychain access. Choose **Always Allow** to skip the prompt next time.

### Moved to a new machine, vault won't open

→ The private key lives in the OS keyring and doesn't follow you automatically. Two options:
1. **On the new machine, `senv init` → add the new public key to the vault from the old machine** (`r` → `a`)
2. **Export/import the existing key** — not yet implemented; planned for v2.

### No keyring in CI / containerized environments

→ Not yet wired. Planned: `SENV_IDENTITY` env var for injecting the private key.

### What if someone gets `.env.age`?

→ They see ciphertext. Without a private key on the recipients list, they can't read anything. **However the key *names* (e.g. `DATABASE_URL`) are visible.** If even names should stay private, keep the vault in a private repo only.

### `q` doesn't quit

→ Try `Ctrl+C`. If still stuck, you're inside a modal — `Esc` first, then `q`.

---

## FAQ

**Q. How does this differ from `dotenvx` or `1Password CLI`?**

A. Three differences:
1. **TUI** — others ship only a CLI. senv's TUI is first-class, with visual editing for schema/recipients/diff.
2. **Single Rust binary** — no Node/Python runtime. 2.5MB.
3. **OS keyring + age** — dotenvx keeps the private key in plaintext `.env.keys`. senv only stores it in the keyring (clean it up any time with `security delete-generic-password`).

**Q. Does it work on Linux/Windows?**

A. Linux works (`linux-keyutils` backend). Windows code is in place but no release binary yet. Coming in the next milestone.

**Q. How do I back up `.env.age` safely?**

A. Commit it to git — it's already encrypted. Public backups are fine. Back up the private key separately:
```bash
# Export the senv identity from macOS Keychain
security find-generic-password -s senv -a default-identity -w
# → AGE-SECRET-KEY-1... — store somewhere safe (paper, 1Password)
```

**Q. Do all projects on the same machine share one keyring entry?**

A. Yes, currently (`service=senv`, `account=default-identity`). One master key unlocks every project vault on that machine. Per-project separation (`account=<project-fingerprint>`) is planned for v2.

---

## Next

- Deeper architecture + threat model: [README.md](../README.md)
- Source: [src/](../src/)
- Issues / feature requests: <https://github.com/gtg7784/senv/issues>

Bug reports and PRs welcome.
