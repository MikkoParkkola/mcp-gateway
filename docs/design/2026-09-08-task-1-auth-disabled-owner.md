# Design correction — TASK.1.20 task owner resolution

Replaces the approved r3 entry that made a strong verified identity an
unconditional requirement for task ownership, with a single refusal row for
callers without one. That row was written for a gateway that has identities;
applied unconditionally it removes tasks from every auth-disabled deployment,
where the approved scope intentionally shares anonymous task ownership.

Corrected rule (one owner, resolved once per request at the router):

| verified identity | auth.enabled | owner |
| --- | --- | --- |
| present | any | `stable_actor_id()` (`oidc:` prefixed) |
| absent | false | `local:auth-disabled:tasks:v1` (internal constant) |
| absent | true | `task_principal(None, session_owner_key(client))`; empty -> refused, creation refused |

The auth-disabled tag is a gateway configuration constant, never request data,
and cannot collide with `oidc:` or `credential:` owners. No `VerifiedIdentity`
is synthesised, so the destructive-confirmation strong-identity requirement is
unchanged. The resolved string is reused for create, get, update, cancel,
replay and subscription ownership — one rendering only.

Basis: test-plan 140 ruling 2026-09-07; final parent ruling 2026-09-08.
