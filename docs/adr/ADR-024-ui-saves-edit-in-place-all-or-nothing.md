# ADR-024: UI saves edit the file in place, all or nothing

- **Status**: Decided in design, recorded here, 2026-10-25. In-place save: design D3 (MIK-8842). All or nothing across file and keychain: lead ruling 2026-10-25. The keychain sequence below refines how that ruling is met, after review.
- **Ticket**: MIK-8839 (lead's addition); binding on U8 (MIK-8860, API8.5 to API8.9) and U21 (MIK-8873, API21.5 and API21.6)
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

| # | Fact | Where |
|---|---|---|
| F1 | A config write runs in one of two modes: `Rewrite` re-serialises the whole file, dropping comments; `Refuse` writes nothing and says what would be lost. | `src/config_persistence.rs:174-181` |
| F2 | Only `Refuse` refuses, and no public caller asks for it today. | `src/config_reload/write.rs:90` |
| F3 | A proven in-place splice exists for backends: it edits only the changed keys and keeps every other byte. | `src/config_persistence_splice.rs`, `src/config_persistence_splice_tests.rs` |
| F4 | File writes are atomic and locked. | `src/config_persistence_atomic.rs`, `src/config_persistence_lock.rs` |
| F5 | Secrets are kept in the OS keychain, not in `gateway.yaml`; the file names the entry as a `{keychain.name}` placeholder. | `docs/ARCHITECTURE.md:120`, `:144`; design D3; frame 41c |

An operator's hand-commented `gateway.yaml` is theirs, and one UI save that drops its comments, or leaves the file pointing at a secret that no longer exists, costs the trust of every Settings tab.

## Decision

- **In place.** Every UI save edits only the changed keys in the file's own text, extending the splice (F3) from backends to every setting the UI writes, and to `capabilities/*.yaml` for the capability editor (MIK-8902).
- **Never `Rewrite` from the UI.** When the splice cannot be proven safe (an anchor or alias on the edited key, a structure it does not handle), the save uses `Refuse` (F1): nothing is written, and the change comes back as a patch the operator can paste (frame 41t). The patch loads under the strict key check.
- **Two proofs per splice.** Meaning: the edited text parses to the old document plus exactly the changed keys, and the check fails if replaced text held an alias or anchor the new text drops. Bytes: every untouched line, comment and line ending is unchanged.
- **Stale diff.** A save carries the hash of the file its diff was made from; if the file changed since, nothing is written and the diff is regenerated.
- **Secrets never overwrite in place.** A changed secret is written to a new keychain entry with a fresh name; the file edit then points at that name and commits atomically (F4). The old entry is not deleted: other settings, or another gateway sharing the keychain, may still name it, and replacing one reference does not prove it unused. A crash before the commit leaves the old file and old secret working, plus an unreferenced new entry; a crash after it leaves the new file and new secret working.
- **No automatic cleanup.** Gateway › Settings lists keychain entries under the gateway's prefix that no loaded config names, with when each was written, for an admin to delete one at a time. Nothing deletes a keychain entry on its own.
- **Partial keychain failure.** If writing any new entry fails, the entries this save created are deleted (nothing else can name them yet) and nothing else changes.

## Consequences

- No UI save ever drops a comment; a save that cannot keep them is a patch, not a loss.
- At every instant the file names secrets that exist, so a killed save never leaves a dangling reference.
- Keychain entry names change on every secret change; the file is the only place that says which is current, and unused entries accumulate until an admin removes them.
- Saves that touch unusual YAML (anchors, merge keys) fall back to the patch more often; that is the intended cost.
- History (U21) keeps exact bytes, so restore is byte for byte and comments come back; restoring a version whose secret entry an admin has since deleted asks for the secret again.
