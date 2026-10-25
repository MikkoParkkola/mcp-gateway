# ADR-022: Rotating a key with a grace period

- **Status**: Proposed, 2026-10-25
- **Ticket**: MIK-8839 (ADR.6); unblocks U9 (MIK-8862, key lifecycle with rotation grace and last-used) and UI8 (MIK-8882); lands on top of U19 (MIK-8861, API19.6)
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

Access › Actions › Rotate (frame 29c) offers two reasons: Routine, where the old secret keeps working 15 minutes so the agent can be updated without a gap, and It leaked, where the old secret stops now.

| # | Fact | Where |
|---|---|---|
| F1 | A configured key has one digest, `key_sha256`. | `src/config/features/api_key.rs:71-74` |
| F2 | Names are unique across `api_keys` and refused at load when duplicated; the name is the key's identity-grant subject `api_key:<name>`. | `src/config/features/api_key.rs:78-80`; `src/config/features/auth_api_key_name_tests.rs:35` |
| F3 | A key's principal is the first 48 bits of its digest. It is persisted as the key of sessions, grants, journals and task owners, and two credentials sharing one principal are refused. | `src/gateway/auth.rs:72-79`, `:85-102` (MIK-7973) |
| F4 | Besides the shared-principal check, six places tie a configured key to its principal through its current digest: the client built after a match, the dashboard-link key lookup, the operational event source's standing check, the two client lookups behind event watches (which compare the digest's first 6 bytes inline), and live-event admission. | `src/gateway/auth_resolved.rs:231`, `:255`, `:270`; `src/gateway/ui/session.rs:146`; `src/events/operational_source.rs:57`; `src/events/services.rs:147` |
| F5 | Matching hashes the presented key once and compares it with every key's digest in constant time, so neither a match nor its position shows in the timing; expiry is checked after the match. | `src/gateway/auth_resolved.rs` (`validate_token_with_origin`) |
| F6 | `auth.api_keys` is restart-only today. | `src/config_reload/diff.rs`; `src/config/features/auth.rs:151-157` |

F3 and F4 decide most of this ADR. A rotation that simply replaces the digest gives the key a new principal, and every place in F4 then stops recognising what the key owns.

## Options

1. **Replace the digest; accept a new principal.** Every rotation orphans the key's sessions, tasks and journal entries (F3), and a routine rotation interrupts running work.
2. **Keep the principal across rotations.** At the first rotation the key records the principal it already has as an explicit field, and every later digest maps to it. During the grace period two digests map to it.
3. **Rewrite owned records to the new principal** at rotation. Touches sessions, grants, journals and task stores at once, with no atomic way to do it.

## Decision

Option 2.

- **Config.** A key gains optional fields: `principal` (the 12 hex digits it has always had, written at its first rotation), and `previous_key_sha256` with `previous_expires_at`. Load refuses `previous_key_sha256` without `previous_expires_at`, so a retired secret can never stay valid by omission. A key without `principal` derives it from its digest exactly as today.
- **One derivation.** Every place that turns a configured key into a principal or compares one against it (F3's check, the six in F4, and any new one) calls one function that reads `principal` when present and derives it from `key_sha256` otherwise. Inline prefix comparisons (`digest[..6]`) are replaced by that call; a behavioural test per site rotates a key and checks the site still resolves it.
- **Matching.** The fold over every key (F5) also compares the presented digest with each key's previous digest, using a fixed dummy digest when a key has none, and combines the results with constant-time operations rather than a short-circuit; a match against the dummy is masked off after the compare, so it can never authenticate a key with no previous secret. Only after the fold does it check `previous_expires_at`. Both digests resolve to the key's principal. A match on the previous digest is recorded, so Activity can show "still using the old secret".
- **Routine.** Sets `previous_expires_at` to now plus 15 minutes. Sessions, watches and tasks carry on. A second rotation replaces any earlier previous digest, ending that grace at once; the dialog says so when one is running.
- **It leaked.** Sets no previous digest, and ends the key's live sessions and event watches on the next reload. The principal, its grants, task ownership and journal entries are kept, so the agent resumes its work once it has the new secret.
- **Invariants.** Every credential digest is unique on its own, independently of principals: load refuses any two equal digests among all keys' current and previous digests and the configured bearer's. It also keeps refusing shared principals (F3) with the explicit `principal` counted. An explicit `principal` never lets two different secrets authenticate as the same key unless both are that key's current and previous digest. Names stay unique (F2), so the grant subject `api_key:<name>` is untouched.
- **Hot apply.** U19 (MIK-8861, API19.6) makes `auth.api_keys` and these fields apply on reload. Until it ships, the UI's "Key changes take effect on the next call" is not true and must not ship.

## Consequences

- A key keeps its identity and what it owns across any number of rotations; a leak ends what was running under the old secret without losing durable state.
- The hot path compares two digests per configured key instead of one, all in constant time; for the tens of keys a gateway holds this is microseconds.
- Expired `previous_*` fields are pruned at the next save.
- This is an auth change and gets the security review the ticket asks for, with tests: an expired previous digest is refused; a previous digest without an expiry is refused at load; It leaked refuses the old secret and ends its sessions; a second rotation ends the first grace; no code path derives a configured key's principal outside the one function; `client_for_key` and `client_for_key_at` keep a rotated key's watches (they build the client inline today, so the test is behavioural, not a ban on one call); two keys cannot share a principal through `principal`; two keys cannot share a digest.
