# NFR.WORKLOAD.1 — observed pin values

**This is observed output, not an edit to the contract.** `RELEASE-4.0.0-workload-contract.md`
is frozen; its §11 table still reads `(pinned at freeze)` on every row. The values below were
resolved by machine on 2026-09-13 so that whoever ratifies §11 has them without anyone
having touched a frozen document.

Authority note: the evaluator reads the runner-written `<run>/pins.json`
(`eval_workload.py:134-138`), never this file and never the markdown table. An empty §11
table therefore blocks human ratification, not execution.

## Load generator

| Artefact | Value |
|---|---|
| k6 image (`grafana/k6:0.54.0`) | `sha256:1f40432b1cbe7234e977f96c362c9bc550a2d2b583d014dd8669fe40d3e9e755` |

Resolved from the Docker Hub registry API with no local daemon, then pulled by digest on
Spark. Void condition 9 was observed firing twice before any measurement: an unset digest
and a tag-shaped digest each exit 3.

## Harness artefacts (sha256)

| Artefact | sha256 |
|---|---|
| `docs/requirements/RELEASE-4.0.0-workload-contract.md` | `6bada5f908d5dbb18a6fe0b67b648ba855b651f79e9dc82eb5f0b1c034ec662b` |
| `benchmarks/workload/run_workload.sh` | `a8a28089e68969e9881ae7f168fb8d6bd124a469b7621582bd14e0b930b276ba` |
| `benchmarks/workload/eval_workload.py` | `80d2031be39a86f1cdc385d2268578ee0469cfd813897ca8869b83798f1fa509` |
| `benchmarks/workload/mcp_backend.py` | `41b26fca2c318de3d5927a532a3c76e1896f3c76d8f0fb4792e792af0211adf3` |
| `benchmarks/workload/k6_workload.js` | `9d3844c3144345d7b59ec4a08ac8aa5c1b57868dd1f1696d00b7b19a736d39bc` |
| `benchmarks/workload/gateway.workload.yaml` (template) | `811b7a63557fac6ba4cf5bb66517a02c6ea47e0a8317a18090d0286c56d45727` |
| `benchmarks/workload/gateway.workload.mixed.yaml` (template) | `bc775b8506b0f7cb3cbd4110ee06a6df04e86a8da93ca4358b08e16bd624a324` |

The `eval_workload.py` digest above is the **fixed** evaluator, not the one that
was current when the contract was frozen. Void 4 read a key k6 never emits, which
made every run void before any rep could be graded; the fix is commit `339ac7aa`.
A pin recorded against the pre-fix evaluator would pin a file that cannot grade.

The two rendered-config rows in §11 are marked `(pinned at first rep)` and can only be
filled by an actual run; they are absent here by construction.

## Checkout SHAs

| Cell | Ref | Commit |
|---|---|---|
| A | `v3.5.0` | `32f135a61fb50c20a044fb4c2347bc1cf8015d89` |
| B | `v3.5.1` | `e138680a542b41fa156a94a1ffc9decd9692be77` |
| C / D / E | branch tip | `69ba9e03cc6df0a6a92fdaa813444a61e97cc29e` |

The C/D/E value is the commit the arms were actually built from, read back from each arm's
`.checkout_sha` after the build, not the branch tip at the time the contract was frozen. The
two differ only by documentation commits, but the pin records what was built.

## Feature-set check (void condition 6)

All nine pinned build features — `a2a`, `webui`, `config-export`, `cost-governance`,
`firewall`, `discovery`, `semantic-search`, `tool-profiles`, `metrics` — are declared in
`Cargo.toml` at all three refs. Void 6 cannot trip on a feature missing from an older tag.
