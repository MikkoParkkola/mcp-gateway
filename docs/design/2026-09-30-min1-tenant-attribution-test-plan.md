# MIK-7116.MIN.1: test plan

Design: `2026-09-30-min1-tenant-attribution.md` (v3). Increment 1 = T1-T12, T23-T26; increment 2 = T13-T19, T27; increment 3 = T20-T22. Tests are written
first, committed and pushed as a draft PR, and must fail on the base for the
stated reason before implementation starts. The red commit carries
`pub(crate)` signature stubs only (extractors return an empty set, the new log
methods ignore the attribution), so CI fails on assertions, not on a compile
error that would hide every other test.

Every test configures a real sink (a firewall `audit_log` file, or a
`TransparencyLogger` file) and reads the file back. A test without a sink
would pass without observing anything.

`h(x)` = `security::hash_argument(&json!(x))`, computed in the test from the
public helper, not from the implementation's wrapper.

| # | Level | Setup | Assertion | Red on base because |
|---|---|---|---|---|
| T1 | unit, firewall | `audit_log` file; `tenant_guard { enabled: false, arg_keys: [customer_id] }`; `check_request` with `{"filter": {"customer_id": "cust-1"}}` | allowed; `request` line `tenants == [h("cust-1")]`; raw `cust-1` absent from the line | no field |
| T2 | unit, firewall | as T1, `enabled: true, max: 1`; principal `p1` asks `cust-1` then `cust-2` | second blocked with `CrossTenantReach`; its line `tenants == [h("cust-2")]`; with a transparency log on the `/mcp` route, the #2421 refusal record has `tenants == [h("cust-2")]` and no `data_classes` | refusal line and record never name the tenant |
| T3 | unit, firewall | `audit_log`, default `tenant_guard`; request with `customer_id` | line has no `tenants` key | green guard (schema stability) |
| T4 | unit, tenant_guard | `enabled: true, max: 1`; `response_tenants` and `request_tenants` over values naming `cust-2`, then `check(p1, cust-1)` | `Allowed`: extraction never records | green guard (double-count regression) |
| T5 | unit, tenant_guard | `response_tenants` over text-JSON `{"rows":[{"customer_id":"cust-9"}]}` in `content[0].text`, and over `{"structuredContent":{"customer_id":7}}` | `{"cust-9"}` and `{"7"}` | stub returns empty |
| T6 | unit, tenant_guard | `response_tenants` over a text block > 1 MiB that is valid JSON naming a tenant | empty set (bound honoured) | green guard |
| T7 | integration, meta D1 (`audit_record_tests.rs` harness) | transparency log + firewall `arg_keys: [customer_id]`, `enabled: false`; backend replies with text-JSON naming `cust-9`; `invoke_tool` with `arguments: {"customer_id": "cust-1"}` | the one record: `tenants == sorted[h(cust-1), h(cust-9)]`, `data_classes` is a non-empty array; neither raw id in the file | no field; also proves the task-local reaches `audit_invocation` |
| T8 | integration, meta D1 | as T7, response inspection in action mode, reply text also carries an `AKIA…` key (HIGH) so `apply_response_gates` returns `Err` | outcome ≠ `ok`; `tenants` contains `h(cust-9)`; no `data_classes` | no field; proves extraction precedes the gates |
| T9 | integration, meta D1 | as T7 with no firewall | record has neither `tenants` nor `data_classes` | green guard |
| T10 | integration, meta D1 | as T7 but the call names no tenant | record has neither field (`data_classes` is never empty, so this catches the unconditional-write mistake) | green guard |
| T11 | integration, meta D1 | the T7 log file | `verify_log` succeeds; after changing one character inside `tenants`, it fails | no field |
| T12 | integration, direct D1 (`router/direct_audit_tests.rs` harness) | firewall `arg_keys`, transparency log; direct `tools/call` with `customer_id: cust-1`, backend reply naming `cust-9` | the direct record: `route == "direct"`, `tenants == sorted[h(cust-1), h(cust-9)]`, `data_classes` a non-empty array | no field; also proves the direct scope carries the notes |

| T23 | unit, transparency log | `log_invocation_attributed` with 1025 distinct tenant hashes | record holds exactly 1024 sorted hashes and `tenants_total == 1025`; `verify_log` passes; with 1024 there is no `tenants_total` | no writer |
| T24 | unit, transparency log | `extra` containing `route` (a domain field) and `entry_hash` (a chain field) | both rejected with an error, nothing appended | no writer |
| T25 | integration, meta D1 | as T7 with the response cache on; same call twice | the second (hit) record carries the same `tenants` and `data_classes` as the first | hits skip the gates |
| T26 | integration, direct D1 | as T12, response inspection in action mode with an `AKIA…` key in the reply | outcome ≠ `ok`; `tenants ∋ h(cust-9)`; no `data_classes` | no field |

### MIN.2 observe (design §7)

Sensitive payload in these tests: a text-JSON row carrying an email address,
which the kernel classifies `PersonalData` (checked in T13's own assertion,
so a classifier change fails loudly instead of silently turning the test green).

| # | Level | Setup | Assertion | Red on base because |
|---|---|---|---|---|
| T13 | integration, meta D1 | as T7; API-key caller `ci`; call 1 returns a sensitive row for `cust-A`, call 2 a sensitive row for `cust-B` | record 1: `tenants == [h(cust-A)]`, `data_classes ∋ "personal_data"`, no `cross_tenant`; record 2: `cross_tenant == "would_block"`; call 2's result is `Ok` and its content still carries the backend's `cust-B` row (observe mode withholds nothing; the default kernel is monitor-only, so the row is delivered) | no field |
| T14 | integration, meta D1 | as T13, call 2 for `cust-A` again | record 2 has no `cross_tenant` | green guard (same tenant ≠ cross-tenant) |
| T15 | integration, meta D1 | as T13, call 2 returns a **non-sensitive** row (`{"customer_id":"cust-B","plan":"pro"}`) | no `cross_tenant` on record 2; then call 3, sensitive for `cust-A` → still no `cross_tenant` (non-sensitive reads are not recorded) | green guard |
| T16 | integration, meta D1 | one call whose response holds sensitive rows for `cust-A` and `cust-B` | its record has `cross_tenant == "would_block"` | no field |
| T17 | integration, meta D1 | as T13 but calls 1 and 2 from different API keys | neither record has `cross_tenant` | green guard (per-principal key) |
| T18 | integration, meta D1 | as T13 with an anonymous caller | record has `cross_tenant == "unkeyed"` | no field |
| T27 | integration, mixed routes | shared state (`direct_guards_fixture.rs` harness): sensitive read for `cust-A` via meta `gateway_invoke`, then for `cust-B` via direct `/mcp/{name}`, same API key | the direct record has `cross_tenant == "would_block"` | no field; proves one window across routes |
| T19 | unit, tenant_guard | two sensitive observations for different tenants, the second after `window_secs` has elapsed (`record_at` with a fixed `Instant`) | not would-block | green guard (window honoured) |

### MIN.4 measurement (design §8)

| # | Level | Setup | Assertion | Red on base because |
|---|---|---|---|---|
| T20 | lib test | load `tests/fixtures/mik_7116_min4_corpus.json` via `include_str!`; run each session through the production extractor, `ContextIntegrityKernel::default()` and the §7 observer | confusion counts equal the table in `docs/release/mik-7116-min4-fp-measurement.md` (the test parses that table) | observer stub returns never-flag, so TP = 0 ≠ documented |
| T21 | lib test | the corpus | holds ≥ 3 `flag` and ≥ 8 `clean` sessions; at least one `clean` session is a legitimate cross-tenant incident review, and at least one `clean` session returns a ≥ 9-digit numeric id that the phone pattern (`kernel.rs:34`) misreads as personal data | corpus absent |

The runbook's `jq` count is checked by T22: run it (via `std::process::Command`
only if `jq` is on PATH; otherwise the test is skipped with a printed reason)
over the log T13 wrote, and expect `1`. `ponytail:` a skip-when-absent test is
weak; CI images carry `jq`, and a missing `jq` is visible in the output.

Existing suites that must stay green unchanged: `tests/mik_7116_tenant_acs.rs`,
`firewall/audit.rs` tests, `meta_mcp/audit_record_tests.rs`,
`router/direct_audit_tests.rs`.

Not tested, with reason:
- Upstream task recovery: its note is a documented no-op; request-side tenants
  only.

Local runs: targeted only (`-j 2`, `--lib tenant`, `--lib audit_record`,
`--lib direct_audit`); CI runs the full matrix.
