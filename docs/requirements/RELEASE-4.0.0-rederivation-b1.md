<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 rederivation — batch B1 (MET rows, criteria-status.md lines 26-112)

Audit of what is ON RECORD as evidence for each MET row in scope. Not a re-run of the suite —
a check that a citation exists and says what the row claims. HEAD at audit time: `b015f575`.

| criterion ID | verdict | test_name | green_at | red_at | run_count | note |
|---|---|---|---|---|---|---|
| MIK-7213.CACHE.1a | AMBIGUOUS | `ac_cache_1_a_cacheable_result_carries_ttl_and_scope` (tests/mik_7213_acs.rs:257-262) | 98aadc57 | none-on-record | 1 | Row claims ttlMs on all 5 methods; cited test asserts it on `tools/list` only, none of the other 4. |
| MIK-7213.CACHE.1b | AMBIGUOUS | `ac_cache_3_no_response_from_this_gateway_claims_public` (tests/mik_7213_acs.rs:264-283) | 98aadc57 | none-on-record | 1 | Row claims cacheScope on all 5; cited test checks `!=public` on 4/5 (no `resources/read`), not presence on all 5. |
| MIK-7213.CACHE.2 | SUBSTANTIATED | `ac_cache_2_this_gateways_list_is_private` + `ac_cache_3_a_filtered_list_is_never_public` (tests/mik_7213_acs.rs:88-101) | 98aadc57 | none-on-record | 1 | Direct calls to production `scope_for_method`/`for_list`; commit msg describes a pre-commit probe (not a citable revision). |
| MIK-7213.CACHE.3a | SUBSTANTIATED | `ac_cache_3_every_cacheable_method_has_an_assessed_row` (tests/mik_7213_acs.rs:335-360) | cf8c6eca | none-on-record | 2 (probe) | Vacuous-holds claim matches test; commit msg narrates red-then-green probe but that red state was never itself committed. |
| MIK-7213.CACHE.3b | SUBSTANTIATED | `ac_cache_3_every_cacheable_method_has_an_assessed_row` (tests/mik_7213_acs.rs:335-360) | cf8c6eca | none-on-record (documented in cf8c6eca commit msg: red at :350 on deleting prompts/list row) | 2 | Best-evidenced row in scope: commit msg explicitly narrates the falsifier and its restore-to-green. |
