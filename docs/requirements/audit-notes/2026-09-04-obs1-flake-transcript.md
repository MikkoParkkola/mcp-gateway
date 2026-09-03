# OBS.1 stdio observation — flake measurement and its close

The `NFR.OBS.1` evidence row rested on `cargo test --lib stdio_observation`, 2 passed
at `4b522687`. That run is module-scoped. Under a full `--lib` run the same test was
intermittently red, and this file is the transcript, because a rate quoted from a log
in somebody's home directory is not evidence anybody else can check.

## Red — the rate before the fix

Command, on Spark, at `2b1f2690`:

```
cargo test --lib -- --nocapture   # 8 consecutive full-suite runs
```

| run | outcome |
|---|---|
| 1 | ok |
| 2 | **FAILED** — `stdio_observation::records_protocol_revision` |
| 3 | ok |
| 4 | ok |
| 5 | ok |
| 6 | **FAILED** — same test |
| 7 | ok |
| 8 | ok |

2 failures in 8 = 25%.

## Diagnosis, not quarantine

`1b13b255` split the assertion so a red says which half broke: an empty capture (the
harness) or records present without `protocol_revision` (the record site). Both
failures reported `0 record(s) captured, keys []` — the capture, never the record
site. That is what turned a suspected product defect into a harness defect and made
the fix findable.

Root cause: `tracing` caches per-callsite interest process-wide. A sibling test
reaching the emit site while no subscriber is installed caches that callsite as
`never`, and every later capture in the same process is skipped. Parallel test order
decides whether that happens, which is exactly the shape of the observed flake.

`b6836a02` keeps the callsite interested for the life of the process, so the cached
answer can no longer be `never`.

## Green — the rate after the fix

Command, on Spark, at `b6836a02`:

```
for i in $(seq 12); do echo "=== run $i ==="; cargo test --lib; done
```

12 runs, 12 `test result: ok. 3898 passed; 0 failed`. Zero failures.

Twelve consecutive greens at the measured 25% failure rate has probability
`0.75^12 = 0.0317`, so the run rejects the pre-fix rate at p < 0.05. It does not
prove the test can never fail; it proves the 25% rate is gone.

## What this row may claim

`NFR.OBS.1` row 1 is a `T` criterion. Its red observation is `2b1f2690` (the
assertion that fired: the capture held no records), its green is `b6836a02` at 12
runs. Both revisions are named because a green alone re-derives nothing.

The assertion was edited at `1b13b255`, between the red and the green. That edit
narrows what the test asserts on failure, not what it asserts on success, and the
pre-fix runs in the table above are the red for the criterion — but the general rule
applies here and is recorded in the readiness board: editing an evidence test
invalidates its recorded red, and a row wanting to stay MET across such an edit owes
a fresh red or a falsifier probe.
