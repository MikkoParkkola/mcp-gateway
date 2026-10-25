# ADR-022: Rotating a key with a grace period

- **Status**: Proposed, 2026-10-25
- **Ticket**: MIK-8839 (ADR.6); unblocks U9 (MIK-8862, key lifecycle with rotation grace and last-used) and UI8 (MIK-8882)
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

Access › Actions › Rotate (frame 29c) offers two reasons: Routine, where the old secret keeps working 15 minutes so the agent can be updated without a gap, and It leaked, where the old secret stops now.

| # | Fact | Where |
|---|---|---|
| F1 | A configured key has one digest, `key_sha256`. | `src/config/features/api_key.rs:73` |
| F2 | Names are unique across `api_keys` and refused at load when duplicated; the name is the key's identity-grant subject `api_key:<name>`. | `src/config/features/api_key.rs:78-80`; `auth_api_key_name_tests.rs:35` |
| F3 | A key's principal is the first 48 bits of its digest. It is persisted as the key of sessions, grants, journals and task owners, and two credentials sharing one principal are refused. | `src/gateway/auth.rs:72-79`, `:85-96` (MIK-7973) |
| F4 | `auth.api_keys` is restart-only today: a reload marks it outstanding until a restart. | `src/config_reload/diff.rs` (`auth` tracked, only `dashboard_session` excluded, `src/config/features/auth.rs:151-157`) |
| F5 | Matching hashes the presented key once and compares it with every key's digest in constant time, so neither a match nor its position shows in the timing; expiry is checked after the match. | `src/gateway/auth_resolved.rs` (`validate_token_with_origin`) |

F3 decides most of this ADR. A rotation that simply replaces the digest gives the key a new principal: its sessions end, its task ownership and journal entries point at a principal nothing holds any more.

## Options

1. **Replace the digest; accept a new principal.** Simple. Every rotation orphans what the key owns (F3), and a routine rotation interrupts running tasks.
2. **Keep the principal across rotations.** At the first rotation the key records the principal it already has as an explicit field, and every later digest maps to that principal. During the grace period two digests map to it.
3. **Rewrite owned records to the new principal** at rotation. Touches sessions, grants, journals and task stores at once, with no atomic way to do it.

## Decision

Option 2.

- **Config.** A key gains two optional fields: `principal` (the 12 hex digits it has always had, written at its first rotation) and `previous_key_sha256` with `previous_expires_at`. A key without `principal` derives it from its digest exactly as today, so existing configs are unchanged.
- **Matching.** The fold over every key (F5) also compares the presented digest with each key's `previous_key_sha256`, in constant time and for every key whether or not its grace is still running, so the timing stays flat. Only after the fold does it check `previous_expires_at`, the way expiry is checked today. Both digests resolve to the key's principal. A match on the previous digest is recorded as such, so Activity can show "still using the old secret".
- **Reasons.** Routine sets `previous_expires_at` to now plus 15 minutes. It leaked sets no previous digest: the old secret stops at once.
- **Invariants.** Load refuses a `previous_key_sha256` equal to any other key's current or previous digest, and keeps refusing shared principals (F3) with the explicit `principal` counted. Names stay unique (F2), so the grant subject `api_key:<name>` is untouched.
- **Hot apply.** Rotation is useless if it waits for a restart (F4). U19 (MIK-8861, API19.1 and API19.2) already makes `auth.api_keys` apply on reload with an atomic key-table swap; this change lands on top of it. Until U19 ships, the UI's "Key changes take effect on the next call" is not true and must not ship.

## Consequences

- A key keeps its sessions, grants, journals and tasks across any number of rotations.
- The hot path compares two digests per configured key instead of one, all in constant time; for the tens of keys a gateway holds this is microseconds.
- `previous_*` fields are pruned at the next save after they expire.
- This is an auth change and gets the security review the ticket asks for, with tests: an expired previous digest is refused; It leaked refuses the old secret immediately; two keys cannot share a principal through `principal`.
