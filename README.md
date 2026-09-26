# ctf

Fast CTF workspace management for **Linux and Bash**. Contests and challenges
are ordinary directories, with permanent numeric IDs and Unicode-friendly search.

## Install

Requires stable Rust (1.89+) and Bash.

```bash
cargo install --git https://github.com/jacek4yang/ctf --locked
eval "$(ctf init bash)"
```

Recommended `~/.bashrc` setup:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
# Optional: export CTF_HOME=/absolute/path/to/workspace
eval "$(ctf init bash)"
```

The default workspace is `~/CTF`. Bash integration provides dynamic completion
and makes `ctf use`, `ctf new`, and `ctf go` change your current shell's directory.
Without it, these commands print the destination instead.

## Use

```bash
ctf contest new "BUUCTF"
ctf contest new "研究生网络安全创新大赛"
ctf contest list
ctf contest list 研究生
ctf use 1                       # or: ctf use BUUCTF

ctf new "签到题"
ctf new "easyRSA"
ctf new "[极客大挑战 2019]EasySQL"
ctf new "RSA签到"
ctf list
ctf list rsa easy               # all terms must match
ctf list 极客 sql
ctf list --limit 50             # default: 20; also configurable with CTF_LIMIT
ctf list --all
ctf go 2                       # permanent ID, never a result row number
ctf go 极客                     # exact name or unique fuzzy match

ctf import ~/Downloads/challenge.zip
ctf import 'https://example.org/attachment.zip'
ctf paste
ctf extract                    # or: ctf extract challenge.zip
ctf target "nc 1.2.3.4 2333"
ctf info
```

Search normalizes Unicode and case, ranking exact matches, prefixes, substrings,
then ordered subsequences. Chinese and mixed names work without transliteration.
Ambiguous queries show candidates with their permanent IDs and fail safely.
Numeric input always selects an ID. `use` and `go` without arguments offer a
compact terminal prompt. Quote shell metacharacters; use `--` before a name
beginning with `-`. Names cannot contain slashes or control characters, or be
empty, `.` / `..`, or `.ctf`.

The current directory determines the contest. Outside a contest, the last
`ctf use` selection applies. Imports, clipboard, extraction, and target commands
must run inside a challenge. `--all` lists all matches in the current contest.

## Source material

Imports keep an independent read-only original under `.ctf/archive/` and an
editable working copy in the challenge root. Collisions get `-2`, `-3`, etc.
Metadata records source, filename, timestamp, size, and SHA-256. `ctf paste` has
built-in native X11 clipboard reading: an X11 session with `$DISPLAY` is required,
but no clipboard helper programs are needed. Wayland is not implemented yet.
UTF-8 text is saved byte-for-byte, including empty text and line endings. Legacy
`STRING` is accepted only for ASCII; other encodings fail without conversion.
Clipboard transfers have a five-second deadline and the same 1 GiB attachment
limit. Targets are stored as raw text. Neither command executes or decodes input.

Extraction supports ZIP, TAR, TAR.GZ/TGZ, TAR.BZ2/TBZ2, GZIP, and BZIP2. It creates
a new `extracted-*` directory inside the challenge, rejecting traversal, absolute
paths, links, special files, conflicting entries, and `.ctf` paths. It never
recursively unpacks nested archives. Imports and expanded archives are limited
to 1 GiB; archives to 10,000 entries. RAR, 7z, XZ, and encrypted archives are not
supported. HTTP downloads have a 120-second timeout.

Back up the entire workspace, including `.ctf` directories. IDs are never reused;
manually deleting a challenge leaves its reserved record. Renaming/adopting
existing directories is not supported. Originals are protected against accidental
editing, not deliberate changes by their owner. Interrupted operations can leave
an unregistered directory or unreferenced original. Use a local filesystem with
reliable file locks and atomic rename.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo build --release
bash tests/smoke.bash
# Optional locally; CI runs these with Xvfb and xauth installed:
xvfb-run -a cargo test --test cli -- --ignored --test-threads=1
```

MIT licensed.
