# MIK-8387 PR-B: red evidence

Test plan v2 (`358a84ba7`), §6 step 2. Every run below is on Spark (`spark-cargo`), with the tests added on top of base `19ca01f07` and no production change.

## Step 0: S7a-0, the positive witnesses: green (2026-10-17)

`spark-cargo test --lib --all-features -- excluded_target`

```
test gateway::router::stored_read_slot_tests::excluded_target::s7a_0_the_two_keys_share_the_owner_and_the_touch_is_observable ... ok
```

S7a is therefore resolvable with this fixture:
- Two scoped API keys carry one verified identity, so they share the task's owner. The excluded key's read of the task does not answer as an unknown task does.
- The included key's call leaves a warm slot.
- The touch is observable through a real idle eviction.

The fixture is the design's §4.0 fallback, a static scoped key plus the `VerifiedIdentity` extension. The auth middleware's API-key branch leaves the extension in place.

## S7a-warm: red for the stated reason

```
test gateway::router::stored_read_slot_tests::excluded_target::s7a_warm_an_excluded_read_does_not_touch_the_targets_slot ... FAILED
panicked at src/gateway/router/stored_read_excluded_target_tests.rs:201:5:
S7a-warm: the excluded target was touched: its aged slot survived the idle eviction; read: {"error":{"code":-32001,"message":"the backend does not list a tool named `read`"},"id":9,"jsonrpc":"2.0"}
test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 12196 filtered out
```

**Reason.** The slot was aged 400 s past a 300 s idle window. It survived a real eviction after the excluded key's read, so that read touched the target's slot. This matches the stated cause: `settle_caller_view` reads the unscoped registry and touches the slot (`task_replay.rs:221`) before any scope check.

**Attribution.** The cause is confirmed when the commit-5 conversion turns this row green. The row's mutant (`settle_caller_view`'s `scoped_get` reverted to `get_for(Unscoped::Visibility)`) must then turn it red again.

**Observed, not part of this row.** The excluded key gets the answer -32001 "the backend does not list a tool named `read`". It is recorded here for the oracle review; S7a asserts only that the output is not served.

## L: red for the stated reason (design §2.8, run B2)

The second pass at base, with the dedicated config, reports 127 `disallowed_methods` errors:
- 126 on `BackendRegistry` methods, in 59 files;
- 1 on `resolve_propagation_credential`, at `propagation.rs:26`.

With `--no-default-features` it reports 114 errors in 53 files.
