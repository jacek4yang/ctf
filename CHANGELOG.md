# v1.0.0

First stable release of the focused Linux + Bash CTF workspace manager.

- Permanent contest and challenge IDs, Unicode-friendly fuzzy search, bounded lists,
  dynamic completion, and fast Bash directory switching.
- Explicit rename and adoption commands preserve identity without guessing ownership.
- `ctf doctor` diagnoses damaged metadata, missing files, unsafe paths, and interrupted
  operations. `--fix` removes only unambiguous internal residue.
- Local/HTTP attachment imports preserve archived originals with SHA-256 metadata.
  Native X11 clipboard reading supports UTF-8 and incremental transfers without helpers.
- Safe staged extraction of ZIP, TAR, gzip, bzip2, XZ, and unencrypted 7z, with
  traversal/link rejection and bounded sizes, entries, and 7z resources.
- Atomic metadata, durable writes, operation journals, and scoped locks improve recovery
  while preserving compatibility with existing version-1 workspaces.
- Official x86-64 and ARM64 Linux archives and SHA256SUMS are built and installation-tested
  by GitHub Actions. Binaries require glibc 2.35 or newer; no Rust toolchain is needed.

Back up the entire workspace, including hidden `.ctf` directories, before upgrading.
No metadata migration is required. Stop active `ctf` operations, replace the binary,
then run `ctf doctor`. Ambiguous damage requires explicit manual recovery; see
[recovery guidance](https://github.com/jacek4yang/ctf/blob/main/docs/recovery.md).
