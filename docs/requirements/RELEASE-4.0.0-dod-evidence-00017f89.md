## v4.0.0 DoD evidence — measured at `00017f89`

CI is green on the pushed tip. This records the measurement, and which rows of
`docs/requirements/RELEASE-4.0.0-dod-check.md` it supersedes. That document is a point-in-time
record taken at `c3083368` and is not edited retroactively.

### Suite

| Metric | Value |
|---|---|
| Test binaries | 96 |
| Passed | 5511 |
| Failed | **0** |
| Ignored | 30 |

Source: the `Tests` job of the CI run on `00017f89`, `cargo test --all-features --no-fail-fast`.

### Gate jobs

All 18 jobs of the CI workflow report success, including every job that was red on the previous
pushed tip `e0f9396b`:

| Job | `e0f9396b` | `00017f89` |
|---|---|---|
| Tests | failure — `--test mik_7272_sub2b_acs` | **success** |
| Clippy (pedantic) | failure — 3 errors in `mik_7272_sub2b_acs` | **success** |
| Secret-leak lint (CWE-532) | failure — 2 findings interpolating a token-shaped value | **success** |
| Release criteria ledger | failure — header/row disagreement | **success** |

Also green: Control-drift probes (NFR.SEC.7), Kani, Format, Windows check, Dependency audit,
Secrets scan, Public claims, Public repo hygiene, First-use usability smoke, Service template
smoke, Helm chart lint + render, Helm OCI package/push/pull, Helm air-gap export/import, Helm
supply chain (cosign + SBOM), K8s kind apply+upgrade+rollback.

### Criteria ledger

`python3 scripts/release/count-release-criteria.py` reports
**149 criteria, 189 rows, 188 met or non-blocking, 1 blocking**, and `--check` exits 0.

### The one remaining gate

`NFR.SEC.7` is the sole blocking criterion, and its open half is a deployment rather than a code
change. The control is unconditional in code — no toggle exists — and the control-drift probe
job passes in CI against this tip. What is unmet is the running process: it is
`3.4.0-f30539af`, built before `5d25f104` added the control, so the guard cannot be observed in
force on the live port until that process is replaced.

### Independent review

The last implementation commit on this branch (`e8c941ca`, clearing the declared log level when a
request declares none) was reviewed by two independent non-Claude reviewers. Both returned SHIP.
Three improvements were raised across them; all three are landed — `b727a7c9` and `00017f89`.

### What this supersedes in the `c3083368` dod-check

- **§4 / D1** — the suite was recorded FAIL with 14 failures at that head. It is green here, and
  the `every_cited_test_exists` failure specifically is repaired: the citation at
  `tests/mik_7272_conformance.rs:150` resolves to a test defined at `tests/mik_7212_acs.rs:449`.
- **§12** — the reviewer-availability note is inverted relative to the current state.
- **The `NFR.SEC.7` row** — superseded by the code/deploy split, and by the correction that the
  origin guard is unconditional rather than enabled by default.

The H1–H11, D1–D30 and §1–13 tables otherwise stand.
