# PR #473 review — shard `tests-a` (first half of `tests/`)

Pinned range `c3626cf8..60b138bb`, payload built from the SHAs, not the worktree.

## Partition

`git diff --name-only c3626cf8 60b138bb -- tests/ | sort` yields 60 files. This
shard is files 1-30; `pr473-tests-b` takes 31-60.

Whole-shard payload: sha256 `246cb7207ee894a49d7d2ed31026857a77add19eac8d05f8fb955682bded9cc2`,
489,522 bytes, 30 files, 11,563 insertions / 26 deletions.

489 KB exceeds the ~150 KB reviewer ceiling, so the shard was split into four
parts that partition it by file. Per-part byte counts sum to 489,522 exactly.

| part | files | bytes | payload sha256 | digest as ledgered (NUL+payload) | ledger `material_bytes` |
|---|---|---|---|---|---|
| 0 | 18 | 109,419 | `2cee2c32…` | `a94ffc7a94b13078473fa5f2441c3dc9b25483607a25d80b2233232806b54b76` | 109,420 |
| 1 | 4 | 121,811 | `5ab9752b…` | `81d29dcbd46aed913153be2403e6f6cd8a229ddab00a06e3d415277a23d18c9a` | 121,812 |
| 2 | 2 | 125,142 | `d1c72106…` | `8c2fcecd3e6de118db1dd847ce47841630ab8fdc2f7ab10f8df14135843814f0` | 125,143 |
| 3 | 6 | 133,150 | `2120a48e…` | `b1a26bad9126fee505d4e3ee96d27e18fc0937d4e6ca4f6755bf5598b8e5a3d2` | 133,151 |

Files, in partition order:

- part 0: `backend_tests.rs`, `common/mod.rs`, `continuation_expiry_metric_test.rs`,
  `cross_feature_tests.rs`, `firewall_integration.rs`, the four
  `fixtures/mik_7217/initialize_*.json`, `generated_tls_strict.rs`,
  `gh452_session_owner.rs`, `gh462_config_preservation.rs`,
  `gh475_quiet_upgrade_still_warns.rs`,
  `gh475_rl9_429_only_neither_opens_circuit_nor_exhausts_budget.rs`,
  `idem_p1_p3_p6_acs.rs`, `integration.rs`, `kubernetes_manifest_tests.rs`,
  `load/k6_gateway.js`
- part 1: `mik_6704_acs.rs`, `mik_6977_acs.rs`, `mik_7116_tenant_acs.rs`,
  `mik_7212_acs.rs`
- part 2: `mik_7212_mrtr_component_acs.rs`, `mik_7212_mrtr7_bridge_acs.rs`
- part 3: `mik_7212_mrtr7_stdio_acs.rs`, `mik_7213_acs.rs`, `mik_7214_acs.rs`,
  `mik_7214_header_9_acs.rs`, `mik_7214_header5_mirroring.rs`,
  `mik_7214_param_headers.rs`
