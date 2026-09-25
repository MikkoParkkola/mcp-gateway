<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# NFR.PERF.1 — release-line benchmark, 2026-09-15

Archived so the figures quoted in `docs/internal/release/v4.0.0-burndown-tracker.md` row
`2026-09-15n` can be checked against their source rather than taken on trust.

## Method

- Host: `bench-host`, one session, 3.5.0 collected first on the same box.
- Baseline: `v3.5.0` (`32f135a61fb50c20a044fb4c2347bc1cf8015d89`).
- Subject: `chore/v4-reconcile-main` at `5eb6982e` — the branch 4.0.0 ships from.
  Earlier runs of this criterion measured `origin/main`, which is a different tree.
- Harness: `benches/gateway_benchmarks.rs` via criterion. Raw logs on `bench-host` at
  `<bench-logs>/v4-perf-releaseline/{before-3.5.0,after-releaseline,session}.log`.
- Figures below are criterion's point estimate with its bootstrap confidence interval.

## What this does and does not measure

`NFR.PERF.1` is written in P50 and P99 terms. **This harness produces neither.**
It times in-process component work — no wire, no backend, no queue — so there is
no latency distribution to take a percentile from, and a confidence interval is
not a P99. The comparisons below are therefore an *indicator* against the
criterion's 5% and 10% figures, not a measurement in the criterion's own terms.
That gap is the standing reason the row is PARTIAL rather than MET; it is
recorded in full in `RELEASE-4.0.0-criteria-status.md` under `NFR.PERF.1`.

## All 56 comparisons, worst first

| change | benchmark | interval |
|---:|---|---|
|   12.23% | `cache_key/schema_fingerprint/50` | [+11.968, +12.506] |
|    9.71% | `cache_key/schema_fingerprint/200` | [+9.4855, +9.9225] |
|    7.75% | `cache_key/schema_fingerprint/10` | [+7.4948, +8.0003] |
|    6.72% | `modern_request_path/validate_headers_encoded_name` | [+6.5214, +6.9116] |
|    6.41% | `session_sandbox/check_payload_too_large` | [+3.8326, +8.5763] |
|    5.08% | `budget_enforcer/daily_accumulator_add` | [+4.9018, +5.2081] |
|    4.99% | `simhash/index_find_similar/10` | [+4.7716, +5.2033] |
|    4.94% | `simhash/index_find_similar/500` | [+4.7327, +5.1359] |
|    4.18% | `continuation/mint_envelope/32` | [+4.0921, +4.2925] |
|    4.00% | `tool_registry/get_miss` | [+2.7874, +5.0699] |
|    3.45% | `cache_key/stable_tool_order/200` | [+3.1256, +3.8078] |
|    3.06% | `modern_request_path/validate_headers` | [+2.8659, +3.2363] |
|    3.00% | `simhash/hamming_distance` | [+2.7351, +3.2861] |
|    2.83% | `redactor/scan_and_redact_credential_response` | [+1.1491, +4.3774] |
|    2.83% | `budget_enforcer/check_paid_tool_within_limit` | [+2.6012, +3.0742] |
|    2.75% | `simhash/index_find_similar/100` | [+2.6281, +2.8722] |
|    2.48% | `mcp_frame/parse_request` | [+2.1375, +2.8147] |
|    2.27% | `mcp_frame/parse_response` | [+1.9846, +2.5775] |
|    2.20% | `continuation/mint_envelope/4096` | [+2.1365, +2.2605] |
|    2.17% | `modern_request_path/classify_legacy` | [+1.4357, +2.8863] |
|    1.93% | `cache_key/stable_tool_order/50` | [+1.7651, +2.0793] |
|    1.86% | `continuation/open_envelope/32` | [+1.4229, +2.2625] |
|    1.81% | `cache_key/stable_tool_order/10` | [+1.6017, +2.0194] |
|    1.80% | `session_sandbox/check_unrestricted` | [+1.5294, +2.0437] |
|    1.80% | `continuation/check_bindings` | [+1.7100, +1.8948] |
|    1.72% | `redactor/scan_and_redact_clean_response` | [+0.1133, +3.2998] |
|    1.64% | `semantic_search/query_top10/500` | [+1.4278, +1.8409] |
|    1.56% | `tool_registry/insert_one` | [+1.3535, +1.7654] |
|    1.33% | `cache_key/from_context` | [+0.8596, +1.8305] |
|    1.30% | `mcp_frame/parse_ping` | [+0.2321, +2.3020] |
|    1.22% | `semantic_search/index_tool_insert_into_499_tool_corpus` | [+0.9770, +1.4428] |
|    1.12% | `tool_registry/contains_hit` | [+0.9974, +1.2481] |
|    1.12% | `session_sandbox/check_backend_denied` | [+0.1724, +2.0836] |
|    1.08% | `semantic_search/query_top10/50` | [+0.8748, +1.2809] |
|    0.85% | `session_sandbox/check_all_limits_passing` | [+0.2525, +1.5492] |
|    0.49% | `tool_registry/get_hit/10` | [+0.2551, +0.7095] |
|    0.24% | `budget_enforcer/check_disabled` | [−1.0504, +1.5156] |
|    0.00% | `tool_registry/replace_server_50` | [−83.729, +203.56] |
|    0.00% | `tool_registry/get_hit/1000` | [−5.3890, −5.1054] |
|    0.00% | `tool_registry/get_hit/100` | [−0.3298, −0.0675] |
|    0.00% | `simhash/compute/64` | [−2.4640, −0.8937] |
|    0.00% | `simhash/compute/4` | [−3.0592, −2.4501] |
|    0.00% | `simhash/compute/16` | [−4.7341, −4.0634] |
|    0.00% | `session_sandbox/check_tool_denied` | [−4.0598, −1.4717] |
|    0.00% | `semantic_search/query_top10/200` | [−0.3701, −0.0634] |
|    0.00% | `semantic_search/query_all_matches_500_tools` | [−3.9847, −3.4798] |
|    0.00% | `semantic_search/index_build_500_tools` | [−0.4997, −0.2157] |
|    0.00% | `modern_request_path/classify_modern` | [−1.6355, −1.3388] |
|    0.00% | `mcp_frame/parse_notification` | [−1.0808, −0.5272] |
|    0.00% | `input_scanner/scan_injection_args_5_fields` | [−44.344, −43.950] |
|    0.00% | `input_scanner/scan_clean_args_5_fields` | [−63.613, −63.355] |
|    0.00% | `continuation/open_envelope/4096` | [−0.2154, −0.0201] |
|    0.00% | `cache_key/key_for_slot` | [−2.5715, −1.6028] |
|    0.00% | `cache_key/from_session_and_user` | [−22.636, −13.778] |
|    0.00% | `cache_key/from_header` | [−3.2148, −2.2483] |
|    0.00% | `budget_enforcer/check_free_tool` | [−2.4295, +0.0810] |
