# ADR-024: UI saves edit the file in place, all or nothing

- **Status**: Decided in design, recorded here, 2026-10-25. In-place save: design D3 (MIK-8842). All or nothing across file and keychain: lead ruling 2026-10-25. Not reopened by this ADR.
- **Ticket**: MIK-8839 (lead's addition); binding on U8 (MIK-8860, API8.5 to API8.9) and U21 (MIK-8873, API21.5 and API21.6)
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

| # | Fact | Where |
|---|---|---|
| F1 | A config write runs in one of two modes: `Rewrite` re-serialises the whole file, dropping comments; `Refuse` writes nothing and says what would be lost. | `src/config_persistence.rs:174-181` |
| F2 | Only `Refuse` refuses, and no public caller asks for it today. | `src/config_reload/write.rs:90` |
| F3 | A proven in-place splice exists for backends: it edits only the changed keys and keeps every other byte. | `src/config_persistence_splice.rs`, `src/config_persistence_splice_tests.rs` |
| F4 | Writes are atomic and locked. | `src/config_persistence_atomic.rs`, `src/config_persistence_lock.rs` |
| F5 | Secrets are kept in the OS keychain, not in `gateway.yaml`. | design D3; frame 41c |

An operator's hand-commented `gateway.yaml` is theirs, and one UI save that drops its comments, or leaves a new secret in the keychain after the file write failed, costs the trust of every Settings tab.

## Decision

- **In place.** Every UI save edits only the changed keys in the file's own text, extending the splice (F3) from backends to every setting the UI writes, and to `capabilities/*.yaml` for the capability editor (MIK-8902).
- **Never `Rewrite` from the UI.** When the splice cannot be proven safe (an anchor or alias on the edited key, a structure it does not handle), the save uses `Refuse` (F1): nothing is written, and the change comes back as a patch the operator can paste (frame 41t). The patch loads under the strict key check.
- **Two proofs per splice.** Meaning: the edited text parses to the old document plus exactly the changed keys, and the check fails if replaced text held an alias or anchor the new text drops. Bytes: every untouched line, comment and line ending is unchanged.
- **Stale diff.** A save carries the hash of the file its diff was made from; if the file changed since, nothing is written and the diff is regenerated.
- **All or nothing across file and keychain.** 1. prove the file edit; 2. write keychain entries; 3. write the file atomically (F4); 4. if step 3 fails, restore the previous keychain values. A refused or failed save leaves no new secret in the keychain and no file change. A secret-only change is its own save with an empty file part.

## Consequences

- No UI save ever drops a comment; a save that cannot keep them is a patch, not a loss.
- Saves that touch unusual YAML (anchors, merge keys) fall back to the patch more often; that is the intended cost.
- History (U21) keeps exact bytes, so restore is byte for byte and comments come back.
