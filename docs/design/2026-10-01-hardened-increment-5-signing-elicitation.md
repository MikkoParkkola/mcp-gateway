# HARDEN increment 5: signing and elicitation (design delta + test plan)

Parent: `docs/design/2026-09-28-hardened-posture.md` §2 items 2 and 6, test rows 6, 7, 10,
11, §9 increment 5. This delta re-anchors those items on current source (base 48a4d2768) and
settles what the parent left open. Out of scope: 4c `private_backends` and T14, which needs
4c's loopback-allowing pinned policy (operator decision 8); forced `require_nonce` (M6);
direct-route destructive backend tools (M3).

## 1. Current source (what exists, what does not)

| Item | Today | Gap |
|---|---|---|
| Posture resolve order | `posture::resolve` runs before `message_signing.resolve_with_env` (`src/config/mod.rs:588-590`) | `resolve` (`src/security/posture.rs:76-109`) never sets `message_signing.enabled` |
| Missing secret | `resolve_with_env` returns early when signing is off (`src/config/features/security.rs:229`); when on, `resolve_key` refuses fewer than 32 bytes or all-zero (`:308-334`) | none once `enabled` is forced |
| Meta signing context | `SigningInvocationContext::capture` (`src/gateway/meta_mcp/signing.rs:41-64`) makes a context only for an external `gateway_invoke`; nonce from `params.arguments.nonce` | other `tools/call` results are unsigned |
| Meta nonce admission | `prepare_signing_invocation` (`signing.rs:178-220`) at `src/gateway/router/handlers.rs:1632`, after the destructive gate (`:1472`, `Answer` exit at `:1514`) | non-invoke calls have no admission |
| Meta finalisation | `response_security.rs:225-250` signs when `delivery()` is `GatewayInvoke` | |
| Stored replay | `complete_delivery` strips `_signature` only when `owns_signature()` (`admission.rs:72-76`) | |
| Direct route | `finish_direct` at `backend_handlers.rs:1101`, `:1173`; idempotency cache exit at `:1045-1048` returns without it; no MAC at all | |
| Legacy session mint | era decided from `MCP-Protocol-Version` before the body (`handlers.rs:589-597`); a legacy POST calls `get_or_create_session_scoped` (`:609`); GET calls it at `:269` | HTTP keeps no handshake capabilities; any legacy request mints |
| Elicitation parse | `Declared::from_handshake` (`src/protocol/meta.rs:464`) | |
| Direct-route era | reads `mcp-protocol-version` (`backend_handlers.rs:653`), never classifies | |
| Legacy confirmation | `for_legacy()` chosen at `handlers.rs:1523-1527` (only production caller) | |
| Runtime posture | `state.live_config.running().security.posture` (`src/gateway/router/hardened_identity.rs:32`) | |

## 2. Behaviour under `hardened` (standard unchanged)

**Row 6.** `posture::resolve` sets `message_signing.enabled = true`. Because it runs before
`resolve_with_env`, an env-only secret is resolved, and an absent or short one refuses start
through the existing `resolve_key` error. No new check.

**Row 7.** Every successful `tools/call` result on both routes carries the v2 `_signature`
(`sign_json_rpc_response_at`).
- *Nonce source.* `params._meta["io.mcp-gateway/nonce"]` (M1), taken off the request at
  capture, before sanitisation, like the chain nonce. Same validity rule as today's
  `gateway_invoke` nonce (non-empty string, at most 256 bytes; else `-32602 "Invalid signing
  nonce"`). `gateway_invoke` keeps `arguments.nonce`; a `gateway_invoke` carrying both is
  refused `-32602 "two signing nonces"` so one call never has two replay identities.
- *Admission before dispatch.* For a non-invoke call, `prepare_signing_invocation` skips
  `check_invocation_policy` (it needs `server`/`tool`, which only `gateway_invoke` has) and
  runs the nonce-store admission and `require_nonce` exactly as for `gateway_invoke`, keyed on
  the same quota principal. `prepared_target` stays `None`, as it is today for these calls.
- *Sign only what was admitted.* A response is signed only when its context passed admission.
  The destructive gate's `Answer` (a modern challenge or a refusal) exits before admission and
  is delivered unsigned. Consuming the nonce there would refuse the client's own follow-up,
  which resends the request, as a replay.
- *Stored results.* `owns_signature()` becomes "this context signs", so a stored result is kept
  without `_signature` and a replay is signed fresh against the replaying request's nonce.
- *Direct route.* `tools/call` takes the same `_meta` nonce off the params (and refuses a
  malformed one with `-32602`), admits it through `state.meta_mcp` before dispatch, and signs
  the success at both `finish_direct` sites and at the idempotency `CachedResult` exit.
- Under `standard`, nothing changes: contexts are still made only for `gateway_invoke`.

**Row 10 (meta route).** Sessions are in memory and posture is restart-only, so it suffices
that under `hardened` only an elicitation-declaring `initialize` can create a legacy session:
- legacy POST `initialize`: `Declared::from_handshake(params.capabilities)` must declare
  `elicitation`, else 403 + `-32600 "client must declare elicitation
  (security.posture=hardened)"` before `get_or_create_session_scoped`; nothing is minted;
- any other legacy POST, and GET: resume the caller's own live session (new
  `resume_session_scoped`, the get half of `get_or_create_session_for` with no create); no
  such session is the same refusal, and nothing is minted;
- the identity check (row 8) still runs first, before the body.

**Row 10 (direct route).** No handshake state is added. A request whose
`MCP-Protocol-Version` does not declare the modern era (`declares_modern_era`, as `/mcp`) is
refused with the same 403 + `-32600`, unless it is an `initialize` declaring elicitation.
Notifications from such a client are refused too (403 with `{}`, as the identity refusal).

**Row 11.** At `handlers.rs:1523-1527` the policy is `for_modern()` when the request is modern
*or* the posture is `hardened`, so an unconfirmable legacy destructive call is refused
(`-32001`) instead of proceeding on a WARN.

## 3. Test plan (red-first; production constructors; each row names the mutant that must redden it)

Harness: the production router built by `test_router_app_state_with_auth_and_config` as in
`src/gateway/router/hardened_identity_tests.rs` (callers use a `kind: personal` key to pass
row 8). Row 7 needs the signer installed from config by the production wiring, never set by
hand.

| Row | Test | Asserts | Mutant |
|---|---|---|---|
| 6 | `hardened_resolves_env_secret_before_signing_check` | hardened config, `shared_secret: ${VAR}` only in env, `enabled` unset: load succeeds, signing on, secret resolved | force `enabled` after `resolve_with_env` |
| 6 | `hardened_without_signing_secret_refuses` | hardened, no secret: load fails naming `message_signing.shared_secret` | drop the forcing |
| 7 | `hardened_signs_tools_call_on_both_routes` | a non-invoke meta `tools/call` and a direct `tools/call`, each with a `_meta` nonce: `_signature` verifies with the v2 MAC and binds the nonce | keep the `gateway_invoke`-only capture |
| 7 | `hardened_tool_call_nonce_replay_refused` | same nonce twice, each route: second refused before dispatch, backend saw one call | admit after dispatch / skip admission on the direct route |
| 7 | `hardened_direct_cached_result_is_signed` | idempotent replay on the direct route is signed against the replaying nonce | leave the `CachedResult` exit unsigned |
| 7 | `destructive_challenge_does_not_consume_nonce` | a challenged call answered unsigned; the follow-up with the same nonce is admitted and signed | admit before the destructive gate |
| 7 | `gateway_invoke_with_two_nonces_refused` | `-32602`, nothing dispatched | accept either nonce |
| 10 | `hardened_refuses_legacy_without_elicitation_no_session` | legacy `initialize` without elicitation: 403, the text, no `mcp-session-id`, session count unchanged | check after the mint |
| 10 | `hardened_refuses_legacy_without_elicitation_get` | GET with no live session: refused, nothing minted | skip GET |
| 10 | `hardened_legacy_request_without_session_refused` | legacy `tools/list` with no session: refused, nothing minted; after an elicitation-declaring `initialize` the same request is served | mint on non-initialize |
| 10 | `hardened_direct_legacy_refused` | direct legacy `tools/call` refused with backend at 0 calls; elicitation `initialize` and a modern-header request pass | skip the direct route |
| 11 | `hardened_legacy_confirmation_policy_refuses` | legacy session, unconfirmable destructive call: `-32001` under hardened, WARN-and-proceed under standard | keep `for_legacy()` under hardened |
| 16 | `standard_posture_applies_no_override` (extended) | standard: signing not forced, non-invoke results unsigned, legacy without elicitation served | apply any override under standard |

## 4. Upgrade guide and ledger

UPGRADING-4.0 item 111 (110 reserved for #2538): adopting `hardened` now needs a signing
secret; `tools/call` results carry `_signature`; legacy clients must declare elicitation, and
on the direct route legacy clients are refused. The HARDEN.1 ledger note records increment 5
and that T14 waits on 4c (decision 8).
