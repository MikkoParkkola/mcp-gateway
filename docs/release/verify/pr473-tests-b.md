# PR #473 unreviewed-slice review — shard `tests-b`

Range: `c3626cf8..60b138bb10a869703254eae2fe500f055d96f8d7`, paths under `tests/`.

## Partition

`git diff --name-only c3626cf8 60b138bb -- tests/ | sort` yields 60 paths. This
shard takes entries 31-60; peer shard `pr473-tests-a` takes 1-30.

Files (30):

```
tests/mik_7215_acs.rs
tests/mik_7215_control_2_budget_acs.rs
tests/mik_7215_control4_reap_count_acs.rs
tests/mik_7215_controls_acs.rs
tests/mik_7216_mrtr_10_acs.rs
tests/mik_7217_acs.rs
tests/mik_7217_era_probe_acs.rs
tests/mik_7218_acs.rs
tests/mik_7222_acs.rs
tests/mik_7272_conformance.rs
tests/mik_7272_error_2_resource_not_found.rs
tests/mik_7272_exploit_acs.rs
tests/mik_7272_oauth_acs.rs
tests/mik_7272_result_2.rs
tests/mik_7272_subscriptions_acs.rs
tests/mik_7272_task_1_acs.rs
tests/mik_7312_continuation_state.rs
tests/mrtr7_roots_acs.rs
tests/nfr_compat_2_stdio_client_session.rs
tests/nfr_compat1_revisions.rs
tests/nfr_obs_3_era_observability.rs
tests/nfr_obs_records.rs
tests/nfr_obs5_flag.rs
tests/nfr_perf_4_meta_tool_band.rs
tests/nfr_sec1_controls.rs
tests/public_claims_validation.rs
tests/schema_2020_12_validity.rs
tests/secret_injection_tests.rs
tests/stdio_tests.rs
tests/webui_management_tests.rs
```

## Payload

Whole shard: 443,072 bytes, 30 files, 10,059 insertions / 33 deletions,
`sha256 0c58936eff45a2cd9d1dbe9db50b7df88f01a65a4c64727483016c668e6b5c05`.

The shard exceeds the ~150KB reviewer ceiling, so it was split into four parts
that partition it — byte counts sum exactly to the whole (131,405 + 142,230 +
141,810 + 27,627 = 443,072), and every file appears in exactly one part.

| part | files (sorted-list positions) | bytes | payload sha256 | NUL-prefixed digest |
|---|---|---|---|---|
| p1 | 31-39 | 131,405 | `34a9c2f4…5cc8b1c0` | `fcf9b6ff5e22aca7fae764d769cab4c465e69ed2be3ee00012b4552617580571` |
| p2 | 40-46 | 142,230 | `c035dacc…989c4ac1` | `600b25c7d2db48c625fe9b9e66149a530c851109cafda8dcb2a20eada09dc421` |
| p3 | 47-56 | 141,810 | `6856347c…2e75b5f3` | `463aee15bff454ee83d4062e523ad2ffc01420e32b19e607421e3da8fc2ae4b5` |
| p4 | 57-60 | 27,627 | `b0966aed…7aa29a99` | `131f627013e3bb0b379047342eb8e7370e21d82745fc25a6ac369ca73cb2745c` |

The NUL-prefixed digest is what binds a ledger row to a payload, per the
brief's Correction: `{ printf '\0'; cat part.diff; } | shasum -a 256`, and
`material_bytes` is payload bytes + 1.

## Ledger rows

| part | vendor | ts | verdict | material_sha256 | material_bytes | process_status |
|---|---|---|---|---|---|---|
| p4 | gpt | 2026-09-08T17:10:57Z | SHIP-WITH-FIXES | `131f6270…3cb2745c` | 27,628 | ok |

(remaining rows appended as runs land)
