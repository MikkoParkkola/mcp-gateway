# ADR-018: How To do's decisions write

- **Status**: Proposed, 2026-10-25
- **Ticket**: MIK-8839 (ADR.2); unblocks U15 (MIK-8868, typed To do queue with working accept paths) and U9 (MIK-8862) for grants
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

To do (frames 44, 44b, 44c, 44d) asks a person to accept a changed capability, allow an access request, or adopt an unmanaged server. Two of the three cannot be completed by any route today.

| # | Fact | Where |
|---|---|---|
| F1 | Control-plane grant and policy writes authorize the caller, then refuse with 409 before any write, "because dispatch never reads this store". | `src/gateway/ui/control_plane/mutations.rs:301-325` |
| F2 | Enforced grants live in the identity-grants file; the CLI changes them only by rewriting that file (upsert, revoke). | `src/commands/identity.rs:134`, `:190`; `docs/design/2026-09-28-grant-change-journal.md` P1 |
| F3 | The CLI journals each grant change beside the file; the gateway turns journal and file into governance records exactly once, every record with actor `unknown`. | `src/config_reload/grant_audit.rs:3-13` |
| F4 | A running gateway applies a grant-file change on its next reload, under a grants reload lock. | design P3; `src/config_reload/env_poll.rs:244` |
| F5 | A capability pin is a hash written into the file; the previous definition is not kept, so no diff can be shown. | `src/capability/hash.rs` (`rewrite_with_pin`); api-gaps.md F11 |
| F6 | Adding a backend already has a route. | `POST /ui/api/backends` |

## Options

1. **Make dispatch read the control-plane store.** Grants and policies move into the store and F1's refusal goes away. A core-path change on every call (E2 in `mutations.rs`), and two sources of truth until the file is retired.
2. **Write the files the gateway already enforces, through the CLI's own code.** The UI's accept calls the same upsert and revoke functions as `mcp-gateway identity grants`, which write the file and its journal; the existing ingestion (F3) records it. The journal entry gains the signed-in admin as actor.
3. **Leave To do read-only** and tell the operator which CLI command to run. Honest, and the opposite of what the frames promise.

## Decision

Option 2.

- **Access request (44c).** Allow writes one grant through the CLI's upsert path (F2), with the chosen tools and expiry; the gateway applies it on reload (F4), so the request's result line (44r) appears after the reload, not before.
- **Actor.** The journal entry carries the admin who allowed it. The record keeps `unknown` for CLI and hand edits, as F3 rules today; a UI write is the only source with an authenticated actor. This is an additive, optional field in the journal record.
- **Changed capability (44b).** Accept re-pins the file through the U8 save path (MIK-8860.API8.9) under the accepting admin. The diff shown before accepting comes from configuration history (MIK-8873.API21.6), which keeps every version's bytes; history starts when U21 ships, so a change to a file never seen before has no diff, and 44b says so.
- **Adopt (44d).** Uses the existing add route (F6) with the tools ticked in the decision.
- **The control-plane store.** F1's refusal stays; this ADR does not make dispatch read the store.

## Consequences

- No change to dispatch or to how grants are enforced; one path writes grants, whoever starts the change.
- A UI accept takes effect after the next grants reload, as a CLI change does; the result is shown when it applies.
- The journal schema gains an optional actor field; older journals still parse.
- Option 1 stays open for a later release and would supersede this ADR.
