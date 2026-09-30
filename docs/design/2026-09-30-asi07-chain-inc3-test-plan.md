# ASI07 chain increment 3: test plan

Binding design: `2026-09-30-asi07-chain-inc3.md` (adopted r3). Red-first: tests plus
signature-only stubs, CI red at assertions, then the implementation. No local cargo; CI only.

Oracles. The client-side verifier in the integration tests is an independent re-implementation. It
uses `ring` Ed25519, `serde_json_canonicalizer` and `sha2` in test code, not the crate's
`verify_chain`, so "the client can verify the full chain" is shown by code that does not share the
implementation under test. A fake upstream (the `BackendFixture`) signs links with test code and
serves tampered, swapped, stale and dropped-hop chains. A real upstream is a second gateway process
(origin role, message signing off), reached through D's direct route.

## End-to-end (tests/signature_chain_hops.rs)

| # | Test | Asserts | Mutant that must redden it |
|---|---|---|---|
| H1 | `two_hop_chain_verifies_at_the_client_invoke` | client -> D(`verify`) -> real U, via `gateway_invoke` with a chain nonce: two links. The oracle verifies both signatures, origin = U, last = D, D.prev = H(U link), D.in = U.out, D.out = H(received), last nonce = client nonce, and U's link is byte-identical to what U signed | no append / drop upstream links / wrong prev |
| H1d | `two_hop_chain_verifies_at_the_client_direct` | the same through D's direct-route `tools/call` | direct route not chained |
| H2 | `require_refuses_a_tampered_upstream_signature` | fake U, one flipped byte in `sig`, D `require`: -32001 naming `BadSignature`; the backend was called once | skip `verify_chain` |
| H3 | `verify_marks_a_tampered_upstream_unverified` | the same under `verify`: delivered, one link by D with `up: unverified`, `prev` null, `in` = H(raw); the oracle refuses it | present an unchecked hop as verified |
| H4 | `require_refuses_a_swapped_nonce` | fake U answers a fixed nonce, not D's: -32001 `Nonce` | skip the nonce check / reuse the client nonce upstream |
| H5 | `require_refuses_a_stale_upstream_link` | fake U `ts` older than the replay window: -32001 `Stale` | skip staleness |
| H6 | `require_refuses_a_dropped_middle_hop` | fake U serves U1's origin plus U3's link whose `prev` names a removed U2: -32001 `Linkage` | skip linkage |
| H7 | `require_refuses_an_absent_chain` | fake U sends no chain: -32001 | treat absent as verified |
| H8 | `emit_always_without_client_nonce_is_not_verifiable` | `emit: always`, no client nonce, both routes: link nonce null; the oracle refuses (`Nonce`) | - (scope pin) |
| H9 | `invoke_nonce_alone_emits_no_chain_on_request` | `emit: on_request` with an invoke nonce only: no chain key | invoke nonce as trigger |

## Integration and unit

| # | Test | Asserts |
|---|---|---|
| N1 | `chained_backend_gets_a_fresh_outbound_nonce_meta` | the `gateway_invoke` dispatch to a `verify` backend carries `_meta` chain-nonce: 32 hex characters, different on two calls, trace `_meta` members kept; an `off` backend's params have no such key |
| N2 | `chained_backend_gets_a_fresh_outbound_nonce_direct` | the same on the direct route; for `off`, no write beyond the existing client-nonce strip |
| C1 | `chain_backend_config_validation` | `verify`/`require` refuse at load without `chain_origins`, without `chain_signer`, with a key missing from `trusted_keys`, or without `security.signature_chain`; `off` needs none |
| P1 | `terminal_purpose_accepts_exactly_max_links` / `forward_purpose_needs_room_to_append` | `ChainPurpose::Terminal` accepts `len == max_links`; `Forward` refuses it |
| P2 | `append_that_would_exceed_the_cap_is_refused` | an upstream chain already at `max_links` links (so D cannot append), D `verify`: -32001, no chain |
| I1 | `require_refuses_an_interim_reply_before_asking` | `require` backend returns `input_required`: -32001; zero client requests, zero upstream retries |
| I2 | `schema_processing_after_receipt_still_verifies` | output-schema enforcement changes the delivered content; the chain verifies; D.in = raw digest != D.out |
| K1 | `require_refuses_task_execution_at_admission` | a task-augmented call to a `require` backend: -32001 at admission; no handle captured, backend not called |
| K2 | `verify_task_result_is_never_chained` | a task result from a `verify` backend carries no chain |
| Z1 | `chained_backend_bypasses_the_response_cache` | cache on: two identical calls reach the backend twice; both chained with distinct upstream nonces |
| Z2 | `chained_replay_carries_no_chain_meta` / `..._direct` | idempotent replay of a chained result: no chain key; backend called once |
| G1 | `gate_substitution_drops_the_upstream_outcome` | context integrity withholds a verified result: no chain delivered (neither upstream links nor D's) |
| S1 | `stored_chain_old_records_replay_as_before` | a pre-change stored record (`Backend`) still replays `src: replay`; `ChainedBackend` maps to `NotEligible` |

## Mutants (CI mutants workflow, throwaway/mutants-* branch)
Run after green on `signature_chain.rs`, the raw-receipt verify site, the direct-route nonce writer
and the stored-chain mapping. Every surviving mutant is killed or recorded with a reason.

## Docs
- UPGRADING: a new item for the per-backend `signature_chain` modes, the refusals and the limits.
- CHANGELOG fragment.
- OWASP ASI07 row (CHAIN.3), rewritten from H1-H7.
- The GH1944.CHAIN.1 ledger note, with the evidence (run IDs) and the accepted limits.

## r2 (round 1: seat 1 DO-NOT-SHIP, seat 2 SHIP-WITH-FIXES; every finding accepted)

Harness. The fake upstream becomes a small dynamic MCP server in the test (not the fixed-result
`BackendFixture`). It records each request it receives (D's outbound `_meta`) and each response it
sends, and it signs with test code according to a per-test mode:

- honest: answers the nonce it received;
- tampered signature;
- fixed wrong nonce;
- replay of its first response;
- stale `ts`;
- wrong origin key;
- wrong last signer;
- changed content;
- dropped middle hop (U1 + U3);
- oversized-after-append;
- no chain;
- `input_required`;
- unsolicited task handle.

The real second gateway stays only in H1/H1d (interop). "Preserved" is asserted as RFC 8785 byte equality between each delivered upstream link and the link the upstream recorded sending. That is the form the signature covers; the JSON transport does not keep raw bytes, so raw-byte equality is not observable.

Changed and added rows:

| # | Change |
|---|---|
| H2-H7 | Parameterized over both routes (`gateway_invoke` and direct `tools/call`). Added modes: wrong origin (`Origin`), wrong last signer (`LastSigner`), changed content (`Content`), a replay window set to 30 s with `ts` 31 s old (`Stale`, so the configured value is what is passed). H4 becomes "replay of the upstream's first response to a second dispatch" (`Nonce`). Each row asserts the refusal names the rule, and the upstream saw exactly one request per call. |
| N1/N2 | Two calls carry the same explicit client nonce, for `verify` and `require`. Each outbound nonce is 32 hex characters, differs from the client nonce, and differs across calls. N2 covers the sanitized and passthrough arms, absent and populated `_meta`, and keeps arbitrary members. `off` makes no write beyond the client-nonce strip. |
| I1b | `verify` + `input_required`: stripped, `NotEligible`, no chain, round proceeds unchained. |
| K3 | Unsolicited task handle returned to a synchronous `require` call: -32001 at raw receipt; zero polls, zero handle captures. |
| K2 | Now "a freshly polled completion from a `verify` backend carries no chain". Also a valid synchronous chained call next to a task call on the same backend: the synchronous call is chained. |
| P2 | Replaced: the upstream chain is well under `max_links` and each link is under 1 KiB, but the total is close enough to 16 KiB that D's appended link crosses it: -32001. A control with a shorter chain fits and verifies. |
| F1 | Positive fallback: signing on, `emit: always`, invoke nonce only. A two-link chain whose last nonce is the invoke nonce; the oracle verifies with that nonce. F1b: both nonces present, the chain nonce wins. |
| R1 | Firewall redaction on a chained result: the delivered text is redacted, the oracle computes H(delivered) independently and it equals D.out, and D.in equals the upstream's recorded `out`. |
| G1 | Adds a unit assertion: `GateEffect::Enforced` clears both `chain_source` and the upstream outcome, and a serialized response contains neither. |
| Z2 | Adds stored-classification cases (verified, unverified, mode-only chained with no outcome), each stored as `ChainedBackend`. Each replay requests a chain with a fresh nonce and asserts a successful response with no chain key. |
| C1 | Adds controls: a valid `verify` config loads; an omitted mode defaults to `off`; empty `chain_origins` is refused; each refusal names its field. |
| X1 | Scope negatives, with the backend opted in to `verify`, each with a chain nonce, none chained: a surfaced (named) tool, Code Mode execute, a playbook step, a capability backend, and a direct-route non-`tools/call` method. |

Mutant rule (binding). An inequivalent surviving mutant on a required rule blocks acceptance; only
an equivalent mutant may be recorded with a reason. The raw-receipt `verify_chain` bypass must be
killed by the tamper, swap and dropped-hop rows on both routes.

## r3 (round 2: both seats SHIP-WITH-FIXES; adopted with these additions, per the review cap)

| # | Addition |
|---|---|
| P2b | Link-count boundary, restored, on both routes. `max_links: 3`: an upstream chain of 3 links means D cannot append, so -32001. A control chain of 2 links is appended to exactly 3 and the oracle verifies it (Terminal, `len == max_links`). |
| H7b | `verify` with an absent upstream chain, both routes: delivered, exactly one link by D with `up: unverified`, `prev` null, `in` = H(raw); the oracle refuses it for `Unverified`. |
| E1 | Enforcement without an emission trigger, both routes: `emit: on_request` and no client nonce. D still sends its fresh upstream challenge. A tampered upstream under `require` gives -32001 `BadSignature`; an honest upstream succeeds with no chain key. |
| H1 | The preservation oracle is RFC 8785 byte equality of each upstream link against the upstream's recorded emission. The design wording is aligned. |

Status: ADOPTED at r3 after two review rounds.
