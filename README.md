# ctf

Fast CTF workspace management for **Linux + Bash**. Ordinary directories,
permanent IDs, Unicode-friendly search, and preserved attachment originals.
No solving tools, telemetry, database, or background service.

## Install

Download a [GitHub Release](https://github.com/jacek4yang/ctf/releases/latest).
Binaries support x86-64 and ARM64 GNU/Linux with glibc 2.35+ (Ubuntu 22.04+).
No Rust toolchain or clipboard/archive helper programs are required.

```bash
(
  set -eu
  version=1.0.0
  arch=$(uname -m)             # x86_64 or aarch64
  case "$arch" in x86_64|aarch64) ;; *) echo 'Unsupported architecture' >&2; exit 1;; esac
  asset="ctf-v$version-$arch-unknown-linux-gnu.tar.gz"
  base="https://github.com/jacek4yang/ctf/releases/download/v$version"
  curl -fLO "$base/$asset"
  curl -fLO "$base/SHA256SUMS"
  sha256sum --check --ignore-missing SHA256SUMS
  tar xf "$asset"
  sudo install -m755 ctf /usr/local/bin/ctf
)
eval "$(ctf init bash)"
```

Run the download block in an empty directory. Add this line once to `~/.bashrc`:

```bash
eval "$(ctf init bash)"
```

Alternatively, with stable Rust 1.93+:

```bash
cargo install --git https://github.com/jacek4yang/ctf --locked
```

Ensure the installed binary is on `PATH` (source installs use `~/.cargo/bin`).

## Quick start

```bash
ctf contest new BUUCTF
ctf use BUUCTF
ctf new easyRSA
ctf import ~/Downloads/challenge.zip
ctf extract
ctf target 'nc example.com 1337'
ctf info
```

The default workspace is `~/CTF`. Override it with an absolute path, for example
`export CTF_HOME=/data/CTF`. Bash integration lets `use`, `new`, and `go` change
your current shell's directory, and provides dynamic name completion.
Without integration, navigation prints the destination instead.

## Main commands

```bash
ctf contest new '研究生网络安全创新大赛'
ctf contest list 研究生
ctf use 1                       # permanent contest ID or exact/unique query
ctf new '签到题'
ctf new '[极客大挑战 2019]EasySQL'
ctf list rsa easy               # every term must match
ctf list --limit 50             # default 20; also CTF_LIMIT
ctf list --all
ctf go 2                       # permanent challenge ID, never a result row
ctf go 极客
ctf rename 2 'easy RSA'         # keeps ID and contents
ctf contest rename BUUCTF 'BUU CTF'
ctf adopt existing-directory   # direct child of the current contest
ctf contest adopt existing-contest  # direct child of CTF_HOME
ctf import 'https://example.org/attachment.zip'
ctf paste                      # native X11 clipboard text
ctf extract challenge.tar.xz
ctf doctor                     # read-only integrity check
ctf doctor --fix               # conservative internal residue cleanup
```

Exact names, prefixes, substrings, and ordered fuzzy matches work with Chinese,
ASCII, mixed names, and case differences. Ambiguity always shows IDs instead of
guessing. Numeric input always means a permanent ID. Quote shell metacharacters;
use `--` before names beginning with `-`. Names cannot be empty, `.`, `..`, `.ctf`,
or contain slashes/control characters. Adoption never moves a directory and
refuses existing `.ctf` metadata. Renaming the current directory refreshes Bash's
path with integration enabled.

The current directory determines the contest; outside one, the last `ctf use`
selection applies. `list --all` means all matches in that contest. Attachment,
clipboard, target, and extraction commands must run inside a challenge.

## Workspace and originals

```text
~/CTF/
├── .ctf/                         # permanent IDs and current selection
└── BUUCTF/
    ├── .ctf/
    └── easyRSA/
        ├── .ctf/archive/         # independent read-only attachment originals
        ├── attachment.zip       # editable working copy
        └── extracted-…/         # successful extraction output
```

Imports never silently overwrite files: collisions get `-2`, `-3`, etc.
Metadata records source, filename, timestamp, size, and SHA-256. `paste` preserves
UTF-8 bytes exactly, including empty text and line endings. It requires X11 and
`$DISPLAY`; no `xclip`, `xsel`, or `wl-clipboard` is needed. Legacy X11 `STRING`
accepts ASCII only. Target strings are stored literally and never executed.

Extraction uses isolated staging and publishes output only on success. Paths,
links, special files, conflicts, and `.ctf` entries are checked. Supported formats:
ZIP, TAR, TAR.GZ/TGZ, TAR.BZ2/TBZ2, TAR.XZ/TXZ, GZIP, BZIP2, XZ, and unencrypted
7z with Copy/LZMA/LZMA2/BZIP2/Deflate. Nested archives are never unpacked automatically.

## Doctor, backups, and upgrades

Doctor checks metadata, IDs, registered/unregistered directories, original hashes
and sizes, missing copies, unsafe paths, and interrupted operations. Its records
use `OK`, `WARN`, `ERROR`, `FIXABLE`, and `FIXED`; unresolved issues return exit 1.
CLI usage errors return 2; other command failures return 1. Diagnostics go to
stderr; normal results go to stdout.

`--fix` removes only unambiguous internal residue, clears invalid current selection,
and finishes cleanup of committed operations. It never reassigns IDs, auto-adopts
directories, or reconstructs corrupt metadata. See [recovery guidance](https://github.com/jacek4yang/ctf/blob/main/docs/recovery.md)
before manual repairs. Completed extraction directories are user data, not residue.

Back up the **entire workspace**, including all `.ctf` directories. Before upgrading,
stop active operations, back up, run doctor, and replace the binary using the same
verified installation steps. Existing v0.1 workspaces remain readable without
automatic migration. IDs are never reused, even after failures or manual deletion.

## Deliberate limits

Linux + Bash + X11 only. Use a local filesystem with reliable locks and atomic
rename. Originals resist accidental edits, not deliberate changes by their owner.
Ambiguous damage requires manual recovery or backup restoration.

Attachment/archive input and expanded output: 1 GiB; extracted entries: 10,000.
Clipboard: five seconds; HTTP and 7z: 120 seconds. XZ dictionaries: 256 MiB;
7z decoder address space: 1 GiB. RAR, encrypted archives, other 7z codecs, and
encoding conversion are unsupported.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo build --release
bash tests/smoke.bash
# With Xvfb and xauth installed (CI runs this):
xvfb-run -a cargo test --test cli -- --ignored --test-threads=1
```

Official releases are built by GitHub Actions from version-matching `vX.Y.Z` tags
on merged `main`, using locked dependencies and a pinned stable compiler. Release
PRs dry-run both architectures and clean-container installation before publication.

MIT licensed.
