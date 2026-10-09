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
through the existing `resolve_key` error. No new check. An operator-set `enabled: false` is
overridden silently, like the other forced controls (`ssrf_protection`, the preset floor), and
the startup info line names it.

**Row 7.** Every successful `tools/call` result on both routes whose nonce was admitted carries
the v2 `_signature` (`sign_json_rpc_response_at`). An answer given before admission is delivered
unsigned and leaves the nonce unspent; the cases are listed under *Sign only what was admitted*
and *Direct route* below.
- *Nonce source.* `params._meta["io.mcp-gateway/nonce"]` (M1), taken off the request at
  capture, before sanitisation, like the chain nonce. Same validity rule as today's
  `gateway_invoke` nonce (non-empty string, at most 256 bytes; else `-32602 "Invalid signing
  nonce"`). `gateway_invoke` keeps `arguments.nonce`; a `gateway_invoke` carrying both is
  refused `-32602 "two signing nonces"` so one call never has two replay identities.
- *Admission before dispatch.* For a non-invoke call, `prepare_signing_invocation` skips
  `check_invocation_policy` (it needs `server`/`tool`, which only `gateway_invoke` has) and
  runs the nonce-store admission and `require_nonce` exactly as for `gateway_invoke`, keyed on
  the same quota principal. `prepared_target` stays `None`, as it is today for these calls.
- *One nonce, one request.* Admission consumes the nonce. A confirmation follow-up after the
  ordinary gate's in-band challenge (which runs after admission) is a new request and carries a
  new nonce; a follow-up resending the first nonce is a replay by construction and is refused
  `-32001`, as a replayed `gateway_invoke` nonce is today. The task-augmented gate answers before
  admission, so after its challenge the first nonce is still unspent and the follow-up may carry
  it (row 104). Clients already send one nonce per request.
- *A malformed nonce is refused first.* Its format is checked as soon as it is taken off the
  request, before either gate, so it is refused `-32602` even where the task-augmented gate would
  otherwise answer before admission.
- *Sign only what was admitted.* A response is signed only when its context passed admission.
  The task-augmented gate's `Answer` (`handlers.rs:1472-1514`) exits before admission and is
  delivered unsigned; the ordinary gate (`meta_mcp/mod.rs:2205`) runs inside dispatch, after
  admission, so its challenge is signed.
- *Signing failure fails closed* on both routes: the result is replaced by `-32603 "Response
  signing failed"`, as `response_security.rs:245-250` does on the meta route.
- *Stored results.* `owns_signature()` becomes "this context signs", so a stored result is kept
  without `_signature` and a replay is signed fresh against the replaying request's nonce.
- *Direct route.* `tools/call` takes the same `_meta` nonce off the params (and refuses a
  malformed one with `-32602`), admits it through `state.meta_mcp` before dispatch, and signs
  the success at both `finish_direct` sites and at the idempotency `CachedResult` exit.
  Admission runs after the route's own refusals (the direct-route guards, tool policy and the
  undeclared-key check, `backend_handlers.rs`), so a refused call spends no nonce and its answer,
  an `isError` result or an error, is unsigned: no backend ran, and a forged refusal can only
  withhold service, which dropping the response already does. On the meta route the same
  undeclared-key refusal runs inside dispatch, after admission, so it is signed and spends the
  nonce.
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

**Row 10 (direct route).** No handshake state is added. The direct route classifies each
request exactly as `/mcp` does: the duplicate-safe header read (`handlers.rs:589-595`) and
`classify_and_observe` (`handlers.rs:722-741`), refusing `RequestShape::Malformed` with
`-32602` (so a modern header over a legacy body cannot pass as modern), then the `/mcp`
header checks: a revision served in neither era, an unsupported modern revision, the
single-occurrence and header/body mirroring checks (`handlers.rs:808-934`). That block moves
into one function both routes call, unchanged for `/mcp`, so the two cannot drift. A request whose era is
`Legacy` is refused with the same 403 + `-32600`, unless it is an `initialize` declaring
elicitation. This Legacy gate runs only under `hardened`; since MIK-8040 the
`/mcp` request checks above run on the direct route under every posture, before dispatch.
Notifications from such a client are refused too, with the same 403 and body; the gate runs before the notification branch.

**Row 11.** At `handlers.rs:1523-1527` the policy is `for_modern()` when the request is modern
*or* the posture is `hardened`, so an unconfirmable legacy destructive call is refused
(`-32001`) instead of proceeding on a WARN.

## 3. Test plan (red-first; production constructors; each row names the mutant that must redden it)

Harnesses. Rows 6 and 7: the shipped binary from its YAML and env
(`tests/common/signing_gateway.rs`, which installs no `AppState` or signer; the production
constructor wires the signer, nonce store and idempotency cache, `server/mod.rs:1020`). Under
`hardened` an HTTP backend on loopback is refused by the destination policy, so the backend
is a stdio backend, which the policy does not cover. Callers present a `kind: personal` API
key to pass row 8. Rows 10 and 11: the production router as in
`src/gateway/router/hardened_identity_tests.rs`; these rows need no signer.

| Row | Test | Asserts | Mutant |
|---|---|---|---|
| 6 | `hardened_resolves_env_secret_before_signing_check` | hardened config, `shared_secret: ${VAR}` only in env, `enabled` unset: load succeeds, signing on, secret resolved | force `enabled` after `resolve_with_env` |
| 6 | `hardened_without_signing_secret_refuses` | hardened, no secret: load fails naming `message_signing.shared_secret` | drop the forcing |
| 7 | `hardened_signs_tools_call_on_both_routes` | a non-invoke meta `tools/call` and a direct `tools/call`, each with a `_meta` nonce: `_signature` verifies with the v2 MAC and binds the nonce | keep the `gateway_invoke`-only capture |
| 7 | `hardened_tool_call_nonce_replay_refused` | same nonce twice on each route, and once on each route: every second use refused before dispatch, backend saw one call | admit after dispatch / skip admission on the direct route / a per-route store |
| 7 | `hardened_meta_stored_result_is_resigned` | an idempotent meta-route replay is delivered with a fresh `_signature` binding the replaying nonce, and the stored copy has none | keep the `gateway_invoke`-only `owns_signature` |
| 7 | `task_gate_answer_is_unsigned_and_keeps_its_nonce` | a task-augmented destructive call's challenge carries no `_signature`; the follow-up with the same nonce is admitted and signed | admit before the task gate |
| 7 | `malformed_signing_nonce_refused` | an empty or 257-byte `_meta` nonce on each route: `-32602`, nothing dispatched | skip nonce validation |
| 7 | `hardened_direct_cached_result_is_signed` | an idempotent replay on the direct route is served from the cache (backend still at one call) and signed against the replaying nonce | leave the `CachedResult` exit unsigned |
| 7 | `confirmation_follow_up_needs_a_fresh_nonce` | a destructive meta tool's in-band challenge is signed; the follow-up with a new nonce completes signed; with the first nonce it is refused | skip admission for the follow-up |
| 7 | `hardened_direct_signing_failure_fails_closed` | a backend result the v2 primitive rejects (non-object result) is answered `-32603`, never delivered unsigned | deliver unsigned on signing error |
| 7 | `gateway_invoke_with_two_nonces_refused` | `-32602`, nothing dispatched | accept either nonce |
| 10 | `hardened_refuses_legacy_without_elicitation_no_session` | legacy `initialize` without elicitation: 403, the text, no `mcp-session-id`, session count unchanged | check after the mint |
| 10 | `hardened_refuses_legacy_without_elicitation_get` | GET with no live session: refused, nothing minted | skip GET |
| 10 | `hardened_legacy_request_without_session_refused` | legacy `tools/list` with no session: refused, nothing minted; after an elicitation-declaring `initialize` the same request is served | mint on non-initialize |
| 10 | `modern_request_mints_no_session_for_legacy_resume` | a modern request returns no `mcp-session-id`, and a following legacy request without a session is refused | mint on the modern branch |
| 10 | `hardened_direct_legacy_refused` | direct legacy `tools/call` refused with backend at 0 calls; an elicitation `initialize` and a well-formed modern request pass; a modern header over a legacy body, a doubled header, and an unsupported revision and a header/body name mismatch are each refused, otherwise-valid modern metadata, backend still at 0 calls | skip the direct route / trust the header alone / skip the shared header checks |
| 11 | `hardened_legacy_confirmation_policy_refuses` | legacy session, unconfirmable destructive call: `-32001` under hardened, WARN-and-proceed under standard | keep `for_legacy()` under hardened |
| 16 | `standard_posture_applies_no_override` (extended) | standard: signing not forced, legacy without elicitation served on `/mcp` and the direct route | apply any override under standard |
| 16 | `standard_signing_keeps_invoke_only_scope` | standard with signing explicitly enabled: non-invoke meta and direct results unsigned, `gateway_invoke` signed as before | widen capture without the posture check |

As built. Four row 7 tests are unit tests against the production context and signer
(`src/gateway/meta_mcp/signing_scope_tests.rs`), because the shipped binary cannot be driven
into their state: `task_gate_answer_is_unsigned_and_keeps_its_nonce`,
`gateway_invoke_with_two_nonces_refused`, `hardened_direct_signing_failure_fails_closed` (the
inner gateway always answers an object, which the primitive signs), and
`hardened_capture_signs_every_tool_call`, which carries the stored-copy mutant of
`hardened_meta_stored_result_is_resigned`. `confirmation_follow_up_needs_a_fresh_nonce`
drives the shipped binary (MIK-7633): the `gateway_kill_server` challenge is signed over its
nonce, the follow-up resending that nonce is refused and runs nothing, and the follow-up with
a fresh nonce completes signed; both MACs pass the independent oracle.
`hardened_direct_cached_result_is_signed` drives the direct cache exit end to end.

### Existing hardened fixtures

Row 6 makes a signing secret mandatory under `hardened`, on both entry points: `Config::load`
and `Gateway::new`, whose `validate_with_env` reaches `resolve_with_env`
(`config/mod.rs:782`) after `posture::resolve` (`server/mod.rs:583-588`). Every existing
hardened fixture that passes through either one gains a 32-byte `message_signing.shared_secret`
in the same commit as the forcing: `src/security/posture_tests.rs`,
`src/security/firewall/anomaly_posture_tests.rs`, the 4b startup and reload tests
(`src/gateway/server/tests/hardened_destination.rs`, `tests/posture_reload.rs`) and
`tests/hardened_backend_env_proxy.rs`. Router fixtures built with a hand-set posture (rows 8,
10, 11) do not call `posture::resolve` and are unaffected.

## 4. Upgrade guide and ledger

The guide also states: one nonce per request (a confirmation follow-up, and a retry after a
failed dispatch, take a new nonce, because admission consumes it before dispatch); and the
task-augmented gate's challenges and refusals are delivered unsigned.

UPGRADING-4.0 item 112 at time of writing (110 is #2529, 111 is #2538); re-read at merge and take the next free number, with "Reserved: lands with #N" placeholders keeping rows contiguous: adopting `hardened` now needs a signing
secret; `tools/call` results carry `_signature`; legacy clients must declare elicitation, and
on the direct route legacy clients are refused. The HARDEN.1 ledger note records increment 5
and that T14 waits on 4c (decision 8).

## 5. Review dispositions (seat A, design round 1; each verified at source)

- HIGH, ordinary destructive gate runs after nonce admission: ACCEPTED as a semantics
  statement, not a reordering. The gate is inside dispatch (`meta_mcp/mod.rs:2205`); the
  follow-up is a new request with a new nonce, and resending the first nonce is a replay.
  Test `confirmation_follow_up_needs_a_fresh_nonce`.
- HIGH, a modern header alone passes the direct route: ACCEPTED. Direct route uses the `/mcp`
  classifier and refuses `Malformed`; negative tests added.
- MEDIUM, the router fixture installs no signer (`router/tests.rs:553-558`): ACCEPTED. Rows 6
  and 7 drive the shipped binary; stdio backend, since loopback HTTP is refused under hardened.
- MEDIUM, standard with signing on is untested: ACCEPTED. `standard_signing_keeps_invoke_only_scope`.
- Improvements taken: fail-closed direct signing, cross-route replay, cache-hit assertion.

## 6. Review dispositions (seat B, design round 1)

- HIGH, the meta stored-replay change has no test: ACCEPTED, `hardened_meta_stored_result_is_resigned`.
- MEDIUM, a modern-created session resumed by legacy requests: REJECTED. A request whose
  header declares the modern era mints no session (`handlers.rs:597-605` returns an empty id),
  and era is read from that header before the session step, so every live session came from
  the legacy branch, where under hardened only an elicitation-declaring `initialize` mints.
- LOW, nonce validity untested: ACCEPTED, `malformed_signing_nonce_refused`.
- Improvements taken: the `enabled: false` override is stated; row 16 covers both routes; the
  nonce-per-request rule and unsigned task-gate answers go in the guide. Not taken: an
  end-of-load invariant; `resolve_with_env` has the one ordered call on the load path
  (`config/mod.rs:588-590`), and the other call (`:782`, in `validate_with_env`) runs after
  `posture::resolve` on that path, and on the literal (rewrite) path where the posture is
  deliberately not applied.

## 7. Review dispositions (seat A, delta round 2)

- MEDIUM, the direct route lacks `/mcp`'s separate header checks: ACCEPTED. The block at
  `handlers.rs:808-934` becomes one function both routes call; negative tests use otherwise
  valid modern metadata.
- Improvements taken: `task_gate_answer_is_unsigned_and_keeps_its_nonce`,
  `modern_request_mints_no_session_for_legacy_resume`.
- The round raised no unresolved finding against the dispositions in sections 5 and 6.
