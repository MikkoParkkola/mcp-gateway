<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# MCP protocol compatibility

The gateway negotiates the MCP revision with each side on its own: once with
the client, and once with every backend. A client and a backend on different
revisions therefore work together through it. This page lists what works for
each pairing, what the gateway translates, and what it refuses. Every row
names the test that pins it.

Code is cited by symbol rather than by line, because line numbers drift.

## Revisions

| Revision | Era | How it is reached | Source |
|---|---|---|---|
| 2026-07-28 | modern | Stated per request (`MCP-Protocol-Version` header and `_meta`); no handshake. On by default; `server.modern_protocol: false` turns it off | `MODERN_VERSIONS` in `src/protocol/meta.rs` |
| 2025-11-25 | legacy | `initialize` handshake; the default | `SUPPORTED_VERSIONS` in `src/protocol/mod.rs` |
| 2025-06-18 | legacy | `initialize` handshake | same |
| 2025-03-26 | legacy | `initialize` handshake | same |
| 2024-11-05 | legacy | `initialize` handshake | same |

The handshake never offers 2026-07-28, because that revision has no handshake
(`protocol::tests::handshake_and_modern_path_keep_separate_version_lists`).
A client that asks for a revision outside the list is answered with
2025-11-25, which the client may accept or refuse.

## How each side is negotiated

**Client side.** `negotiate_version` (`src/protocol/mod.rs`) answers a legacy
client at the revision it asked for. Tests:
`tests/integration.rs::test_version_negotiation`,
`tests/nfr_obs5_flag.rs::a_default_gateway_negotiates_down_to_each_supported_revision`.

**Backend side.** The gateway proposes 2025-11-25 in `initialize` unless the
backend's config pins another revision. If the backend rejects that, in a
JSON-RPC error or with an HTTP 400/426 status, the gateway reads the backend's
list of supported revisions, picks the highest one both sides speak
(`negotiate_best_version`, `src/protocol/negotiate.rs`), and retries once. It
then uses the revision the backend selected for every later request, so each
backend keeps its own revision. Separately, it probes each backend with
`server/discover` to learn its era, and treats anything other than a
recognised modern answer as legacy (`src/protocol/era.rs`). Tests:
`tests/mik_7217_era_probe_acs.rs::discover_4_a_peer_that_rejects_the_probe_is_classified_legacy`,
`tests/gh517_neg_acs.rs::server_selected_version_governs_later_requests`,
`tests/gh517_neg_acs.rs::http_status_rejection_negotiates_a_supported_version`,
`tests/gh517_neg_acs.rs::a_selection_made_on_the_negotiation_retry_governs_later_requests`,
`src/protocol/negotiate.rs::tests::the_body_reported_in_gh_517_negotiates`.

A backend that selects a revision the gateway does not speak fails with a
protocol error that names that revision
(`tests/gh517_neg_acs.rs::unsupported_server_selection_fails_the_backend`).

## Client × backend

| Client | Backend | Ordinary calls | A backend that needs input mid-call | Test |
|---|---|---|---|---|
| legacy | legacy | Work; each side at its own negotiated revision | Not relayed (see limits) | `tests/gh517_neg_acs.rs::server_selected_version_governs_later_requests` |
| legacy | returns 2026-style input requests | Work | **Translated.** The gateway puts each question to the client as an ordinary `elicitation/create`, `sampling/createMessage` or `roots/list` request, collects the answers, and retries the backend with them | `tests/mik_7212_mrtr7_stdio_acs.rs::ac_mrtr_7a_stdio_client_answers_while_serve_loop_reads` (shipped binary over stdio); `src/gateway/meta_mcp/tests.rs::a_legacy_clients_question_is_bridged_from_the_invoke_path` |
| modern | legacy | Work; the client speaks 2026-07-28, the backend its own legacy revision | Only the 2026 input-request shape is carried (row below); a legacy backend's own server-to-client request is not | `tests/r5_stdio_modern_continuation.rs::ac_stdio_modern_retry_with_the_envelope_completes` (backend handshakes at 2025-06-18) |
| modern | returns 2026-style input requests | Work | Passed on as a sealed continuation; the client answers by retrying, and the backend's own state never reaches the client | `tests/r5_stdio_modern_continuation.rs::ac_stdio_modern_caller_receives_a_continuation_not_a_refusal`, `::ac_stdio_modern_retry_with_the_envelope_completes` |
| any | modern (probed) | Sent statelessly: no session header on the backend request | as above | `tests/mik_7214_header_9_acs.rs::a_modern_call_sends_neither_the_minted_nor_the_configured_session` |

## Refused rather than translated

| Case | What the client gets | Test |
|---|---|---|
| A legacy client calls a 2026-only method (`tasks/get`, `tasks/update`, `tasks/cancel`, `subscriptions/listen`) | `-32601` method not found; the tasks extension is not emulated for legacy clients | `tests/mik_7272_owner2_stdio_tasks.rs` (stdio, `tasks/get` → `-32601`); `tests/mik_7272_task_1_acs.rs::ac_task_1_5_tasks_cancel_is_gated_as_a_2026_07_28_method` |
| A backend asks for a request type outside `sampling/createMessage`, `elicitation/create` and `roots/list` | The call fails; nothing is sent to the client | `tests/mik_7212_mrtr7_bridge_acs.rs::ac_mrtr_7a_a_method_outside_the_closed_set_is_refused_unsent` |
| A backend asks a legacy client for something its `initialize` did not declare (for example elicitation) | The call fails; the client is not asked | `tests/mik_7212_mrtr7_stdio_acs.rs::mik_1991_a_handshake_without_elicitation_keeps_the_question_out` |
| A bridged exchange runs past its round, request or time bounds | The call fails | `tests/mik_7212_mrtr7_bridge_acs.rs::ac_mrtr_7b_the_retry_bound_cuts_off_after_three_retries` |

## Limits

- **Translation of mid-call input runs one way.** A backend that uses the
  2026 input-request result reaches a legacy client through the gateway. The
  reverse is not implemented: a legacy backend that asks mid-call by sending
  its own `elicitation/create`, `sampling/createMessage` or `roots/list`
  request is not relayed to any client. Backend connections do not accept
  server-initiated requests. On stdio the request is logged and dropped, on
  HTTP with SSE the call fails, and on WebSocket it is dropped
  (`StdioTransport::handle_response`, `src/transport/http/sse_decoder.rs`,
  `src/transport/websocket.rs`). This is read from the code; no test pins it.
- **Legacy clients over HTTP.** The bridge is tested end to end with a legacy
  client on stdio. A legacy HTTP client receiving the relayed request on its
  SSE stream has no end-to-end test yet.
- **Tasks are 2026-only.** A legacy client gets `-32601` for the tasks
  methods; long-running calls are not turned into tasks for it.
- **Unknown client revisions** are answered with 2025-11-25 rather than
  refused.

See also: [spec-divergences](spec-divergences.md),
[v4.0.0 supported matrix](release/v4.0.0-supported-matrix.md#protocol-revisions).
