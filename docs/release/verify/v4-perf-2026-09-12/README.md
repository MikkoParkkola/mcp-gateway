# Criterion re-measurement, 2026-09-12

Raw Criterion output for the `NFR.PERF.1` re-measurement, copied off `bench-host` on
2026-09-13 so the evidence outlives one machine. `run.sh` is the script that produced
both logs, verbatim. The logs carry a `.txt` extension because `.gitignore` excludes
`*.log`; an earlier commit added this directory without them and the exclusion dropped
them silently, which is the failure mode a checksum list exists to make visible.

**Read these as what they are.** They are in-process Criterion microbenchmarks. The
criterion asks for P50 and P99 of served requests, and no harness in this repository
produces those, which is why the row stays PARTIAL and why no percentile may be quoted
from these files. They refresh the headroom argument the release owner ruled on
2026-09-05; they do not settle the criterion. Reading: `RELEASE-4.0.0-criteria-status.md`,
row `NFR.PERF.1`.

- before: `v3.5.0` at `32f135a61fb50c20a044fb4c2347bc1cf8015d89`, collected first
- after: `main` at `bd1adbb42fa983a8f93038189707a77e65f83547` — **not** the release line,
  which carries 55 of the 74 cited evidence commits against main's 3
- one clone, one `CARGO_TARGET_DIR`, one Criterion session, so the comparison is against a
  baseline taken on the same box minutes earlier

```
5f4fd9f16e96cd49168524c6f8addf90880536d43f1ea1dcc4b5a483e1fb30c3  after-main.criterion.txt
a10391f84add50b2fa7296fadf94a41fb8e181e2516771db836041476a59d0e3  before-3.5.0.criterion.txt
94e8d96b690ce64c3384a5d93cb65ff52ee58e19a541fb7a6f6fc63e473122c5  run.sh
```
