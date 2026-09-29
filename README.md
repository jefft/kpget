# kpget

Fetch passwords from a running [KeepassXC](https://keepassxc.org) database
from the command line, with every fetch gated by a physical Yubikey touch.

Intended for scripts — backups, deploys, restore procedures — that previously
had to prompt the user to copy-paste a password. `kpget URL` prints the
password to stdout:

```sh
PASSPHRASE=$(kpget https://my-backup-passphrase)
```

## Requirements

- KeepassXC with Browser Integration enabled
- A Yubikey programmed for HMAC-SHA1 challenge-response on slot 1, touch required
- [uv](https://docs.astral.sh/uv/) (manages the virtualenv and Python version)

## Setup

```sh
# 1. Program the Yubikey (skip if already done)
ykman otp chalresp --touch --generate 1

# 2. Enable Browser Integration in KeepassXC:
#    Settings → Browser Integration → Enable browser integration

# 3. Install dependencies
uv sync

# 4. Associate kpget with the open database.
#    KeepassXC will show a dialog — name the connection 'kpget-cli'.
uv run kpget register
```

The repo-root `kpget` script is a thin `uv run` launcher, so `./kpget URL`
works from any directory without manually activating the virtualenv.

By default kpget invokes `sudo ykman`; set `KPGET_YKMAN=ykman` if your udev
rules already grant your user direct Yubikey access.

## Usage

```
kpget URL               # print the password for URL to stdout
kpget register [LABEL]  # associate with the currently focused database
kpget list              # show stored associations (rowid / name / database / created)
kpget label ROWID NAME  # rename a stored association
kpget rm ROWID          # forget an association
kpget unlock            # trigger KeepassXC's unlock dialog
```

`kpget URL` is shorthand for `kpget get URL`. The URL is matched against the
**URL field** of KeepassXC entries; invent one for secrets that aren't web
logins, e.g. `https://my-backup-passphrase`.

**Multiple databases:** unlock each database and run `kpget register` once per
database. `kpget URL` detects which database is active and only tries
associations that belong to it.

## Security model

The threat kpget defends against is an adversary who can read files on disk —
a stolen machine, a leaked backup, a snapshot of the home directory. In that
scenario `keepassclient.db` is useless: it contains only ciphertext, and the
key to unseal it never exists on disk at all.

The sealing key is derived on demand from the output of a Yubikey HMAC-SHA1
challenge-response (`ykman otp calculate`). The Yubikey computes the HMAC
internally using a secret that never leaves the device; the result is only
produced when the device is physically touched. No process — including one
running as root — can mint the key while the user is away from the keyboard.

The fixed challenge is intentional. HMAC with a secret key is a secure PRF
regardless of whether the input is public; a fixed challenge simply means the
output is stable (same key, same response, same sealing key). The threat model
does not include an adversary who already holds the HMAC output — at that
point they already have the sealing key, and challenge rotation would not help.

Authenticated encryption (XSalsa20-Poly1305) means a tampered or corrupt row
fails closed rather than decrypting to garbage. No secret is ever passed as a
process argument, which would be world-readable via `/proc/*/cmdline`.
`keepassclient.db` is tightened to mode `600` on every open.

**What this does not defend against:** an attacker who can execute arbitrary
code as your user while the Yubikey is physically present (they could invoke
`ykman` themselves); a compromised KeepassXC process; or an adversary with
both your disk image and physical possession of the Yubikey.

**Manual fallback:** whenever KeepassXC can't supply the password — no
Yubikey, no registered connection, KeepassXC unreachable, no matching entry —
`kpget URL` prints the reason and the entry location, then prompts for the
password on stdin (hidden prompt on a TTY, raw line on piped stdin), then
re-emits it on stdout — so callers work identically either way. The SecretSpec
endpoint instead reports `interaction_required`.

## SecretSpec integration

`kpget` implements the [SecretSpec](https://secretspec.dev) Secret Provider
Protocol v1, so declared secrets resolve live out of KeepassXC with every
fetch requiring a Yubikey touch. Nothing caches the sealing key across
requests.

**Register the provider** (idempotent; re-run after every `uv sync`, because
uv rebuilds `.venv` with your umask and reintroduces group-write bits that
SecretSpec's loader rejects):

```sh
uv sync                           # builds .venv/bin/kpget-secretspec-provider
uv run kpget-secretspec-register  # writes ~/.config/secretspec/providers.d/kpget.secretspec.json
```

**Declare secrets** in your `secretspec.toml`:

```toml
[providers]
kpget = "kpget://"

[profiles.default]
MY_KEY = { providers = ["kpget"],
           refs = { kpget = { item = "https://example.com/login", field = "password" } } }
```

`field` is `password` (default), `username`, or `totp`. Then:

```sh
secretspec get MY_KEY --reason "restoring backup"
secretspec run -- ./deploy.sh
```

Each resolution requires one Yubikey touch. `secretspec get` may resolve a
secret more than once (value + cache refresh), so expect a touch per
resolution. Declarations that omit `refs` use the key name as the search item.
The provider is read-only (`resolve_address`, `get`, `get_many`, `exists`).
Wire-level conformance is validated against the upstream
`secretspec-ipc-conformance` runner (transport-only profile).

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `KPGET_DB` | `<repo>/keepassclient.db` | Path to the association database |
| `KPGET_YKMAN` | `sudo ykman` | ykman invocation (e.g. `ykman` with udev rules) |
