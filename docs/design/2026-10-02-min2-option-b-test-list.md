# MIN.2 option B: test list (prepared fallback)

Status: PREPARED, not active. Option C (`2026-10-01-min2-min4-tenant-reads.md`) is the
primary path. Operator ruling in chat, 2026-10-02: if C has no reviewed design plus red tests
by 2026-10-04 12:00 CEST, 4.0 ships B. B judges request/response reads only. Streams,
notifications and server-to-client requests move to 4.0.1, with the written reason recorded in
`RELEASE-4.0.0-operator-decisions.md`.

## Scope of B

In scope: every answer to a request, both result and error. This covers:

- `/mcp` POST answers, JSON and the single POST-SSE answer frame;
- `/mcp/{backend}` answers for every method;
- stdio answers, batch arrays included;
- and, within those answers, cached and idempotent replays, task reads and settlements,
  playbook and composite answers, `resources/read`, `prompts/get`, catalogues and
  `completion/complete`.

Out of scope for 4.0, moved to 4.0.1:

- notifications on any transport;
- the GET session stream;
- `subscriptions/listen`;
- server-to-client sampling and elicitation;
- MIK-7630 event deliveries.

Shared with C: one `ReadHistory` per process keyed on `caller_key`; the `U` rule for unread
parts; commit after the last replacement; `tenant_read` event; the config enum; the corpus.

## Tests (numbers refer to the C test table)

| # | Test | Notes for B |
|---|---|---|
| 2 | concurrent stateless POSTs, two sessions, one `caller_key` | POST only; no GET sessions |
| 2b | `meta_and_direct_share_history` | as in C |
| 2e | `judged_bytes_are_sent_bytes` | POST and stdio answers |
| 2f | `blocked_evidence_survives_replacement` | as in C |
| 2g | `refusal_with_json_id_terminates` | as in C |
| 2j | `stdio_batch_items_judged` | as in C |
| 2l | `event_hash_is_after_slot_http` | as in C |
| 2m | `terminal_audit_failure_terminates` | as in C |
| 2o | `middleware_errors_through_outbound` | answer frames only |
| 3 | `a_then_b_two_events` | POST JSON, POST-SSE answer, stdio, direct |
| 4 | `a_then_b_block_refuses` | answers only: B replaced by the refusal |
| 5 | `request_only_tenant_any_method` | as in C |
| 6 | `error_data_is_a_read` | as in C |
| 7 | `gateway_refusal_charges_nothing` | as in C |
| 8 | `grant_slot_replacement_commits_nothing` | as in C |
| 9 | `finalization_replacement_commits_nothing` | as in C |
| 12 | `direct_every_method_event` | as in C |
| 13 | `playbook_continue_refused_step` | as in C |
| 14 | `cache_hit_restores_pre_transform` | as in C |
| 15 | `task_request_only_tenant` / legacy row | as in C |
| 16 | `uninspected_both_orders` | as in C |
| 17 | `history_bounds_and_ownership` | single-copy tickets only |
| 18 | `hidden_attribution_without_logger` | as in C |
| 20 | `unconfigured_is_noop` / `config_mode` | as in C |
| 21 | `tenant_read_corpus_fp_measurement` | corpus restricted to answers |
| 22 | bench and NFR.WORKLOAD.1 k6 run | default config and with `arg_keys` set |
| B1 | `notification_not_judged_is_documented` | a B notification after A is delivered unjudged; pins the 4.0.1 boundary so it is visible, not silent |

Dropped from C for B: 1, 2a, 2c, 2d, 2i, 2k, 2n (compile-fail on stream types), 2p, 2q, 10,
11, 19 (the stream half). A 4.0.1 ticket carries them.

First red test for B: row 4 on POST JSON. A read of A, then a read of B with
`cross_tenant_reads: block`, must answer the refusal.
