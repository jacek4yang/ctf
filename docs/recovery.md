# Recovery

Back up the entire workspace, including every `.ctf` directory, before manual
recovery. Stop other `ctf` commands while inspecting damage. Run `ctf doctor`
first: it never initializes metadata or rewrites files.

`ctf doctor --fix` removes only disposable internal residue and completed or
unapplied operation journals. It does not reassign IDs, adopt directories, restore
working copies, or reconstruct corrupt metadata. Warnings and unresolved errors
return exit 1. Fixed records say `FIXED`; repeating the command is safe.

| Report | Action |
| --- | --- |
| Missing/corrupt index, invalid IDs | Restore `.ctf/index.json` from a workspace backup. Never reset the index: its counters reserve permanent IDs. |
| Missing registered directory | Restore its recorded path from backup. Its ID remains reserved. |
| Unregistered directory | Explicitly adopt it if it has no `.ctf`, or preserve/move it outside the workspace. Doctor never infers ownership. |
| Missing working copy | Copy the matching archived original to its recorded working filename, without overwriting existing data. |
| Original hash/size mismatch | Restore the original from backup; do not update the recorded hash to conceal damage. Working copies may be edited freely. |
| Unsafe symlink/hardlink | Preserve the linked data; replace managed metadata/paths with independent regular files/directories after inspection. |

## Interrupted operations

`.ctf/pending.json` in the workspace records the requested operation, permanent
ID, parent contest, and old/new names. Normal commands stop while it exists.

- Rename: if the directory moved but the index still names the old path, move it
  back to that old path **only if the destination is absent**. Then run doctor
  with `--fix` and retry the rename. If both paths exist, preserve both and inspect
  them; do not overwrite either. A committed rename needs only `doctor --fix`.
- Creation/adoption: preserve an unregistered partial directory outside the
  workspace, then run `doctor --fix`. Inspect its contents before reintroducing
  it through explicit adoption. Adoption refuses existing `.ctf` metadata; remove
  such metadata only after backing it up and confirming it belongs to the failed
  operation. Reserved ID gaps are expected and are never reused.
- Import/paste: the challenge's `.ctf/import.json` records intent before the
  working copy is published. A completed import needs only `doctor --fix`. If
  metadata did not commit, preserve the journal and both copies in a backup,
  inspect them, then remove that journal and explicitly re-import the preserved
  source. Doctor can subsequently remove its now-unreferenced archive copy.

Unfinished extraction lives under the challenge's `.ctf/staging/`, not beside
completed output. Doctor can remove abandoned staging under the challenge lock.
Completed `extracted-*` directories and arbitrary user files are never cleanup
targets. Legacy working-directory `.tmp*` files are reported for manual inspection.

Use a local filesystem with reliable locking, atomic rename, and directory fsync.
These protections handle ordinary failures and interrupted operations; they are
not a security boundary against another process running as your user and changing
the workspace concurrently outside `ctf`.
