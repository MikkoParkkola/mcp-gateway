# PR #473 review — non-src/tests/docs shard

Range: c3626cf8..60b138bb, paths excluding `src/`, `tests/`, `docs/`.
25 files, 4000 insertions / 63 deletions.

## Payload

Full concatenated diff exceeded the 150KB review limit (269,962 bytes), so it
was split into three payloads by path, each reviewed independently on both
vendors:

| payload | paths | bytes | sha256 |
|---|---|---|---|
| p1-small-config | `.gap-brief.md`, `.github/`, `.gitignore`, `.reviewprompt`, `ARCHITECTURE.md`, `CHANGELOG.md`, `CLAUDE.md`, `Cargo.toml` | 43,719 | `49c0ba485870820103f6960869f0fc97653a0d3b74272346e7e503a4b62b26e` |
| p2-scratch-docs | `.hdr9-material.txt`, `CLAUDE-TO-CODEX-COORDINATION.md` | 135,114 | `d1094e2c589bd16e18d8f456317a2e82354cb60ad38c3e55ffe2c1e14cadb34` |
| p3-lockfile-scripts | `Cargo.lock`, `README.md`, `benches/`, `benchmarks/`, `deploy/`, `examples/`, `llms.txt`, `scripts/` | 91,129 | `53761f930600d6226a33e5e4f4a98ca29cc01012b6ed0dd3896479cbcd8ffb4` |

Note: the review brief's original `sha256sum payload.diff` binding instruction
was superseded mid-session (brief correction, 2026-09-08): the ledger's
`material_sha256` hashes a leading NUL byte plus stdin, not the raw payload.
Matched here via `{ printf '\0'; cat payload.diff; } | sha256sum`.

## Ledger rows (both vendors, all 3 payloads)

All six runs: `process_status: ok`, verdict **SHIP-WITH-FIXES**.

| payload | vendor | ts | head |
|---|---|---|---|
| p1 | codex | 2026-09-08T16:27:04Z | e68082bc |
| p1 | grok | 2026-09-08T16:36:23Z | 4fd0adc3 |
| p2 | codex | 2026-09-08T16:28:15Z | e68082bc |
| p2 | grok | 2026-09-08T16:34:06Z | 0a1af1fe |
| p3 | codex | 2026-09-08T16:29:14Z | e68082bc |
| p3 | grok | 2026-09-08T16:36:51Z | 4fd0adc3 |

**Not covered**: the ledger's `output` field is a short stamp, not the review
body; the full text lives in `gpt-p{1,2,3}.out` / `grok-p{1,2,3}.out` under
this session's scratchpad. Session ran out of context budget before those six
transcripts could be read and each finding individually source-verified per
the brief's CONFIRMED/DEAD/CANNOT-VERIFY protocol. Stated plainly, not
silently dropped — a follow-up pass should extract and verify those findings
before this shard is treated as fully closed.

## Findings verified directly by this shard (not from the reviewer outputs)

### 1. Agent scratch files committed to the repo — CONFIRMED, file hygiene, blocks 4.0.0

`.hdr9-material.txt` (1,106 lines), `CLAUDE-TO-CODEX-COORDINATION.md` (806),
`.reviewprompt` (47), `.gap-brief.md` (46) are inter-agent working material
(review prompts, coordination notes for a design round), not product:

- `.hdr9-material.txt` — a review-round prompt + pasted design/test-plan text
  for MIK-7214.HEADER.9a/9b.
- `CLAUDE-TO-CODEX-COORDINATION.md` — a status note between two agent sessions
  about branch ownership and commit handoffs.
- `.reviewprompt` — a §P2 test-plan review prompt for cluster-G schema
  validity.
- `.gap-brief.md` — instructions for a worktree-spawned gap-closing agent.

`rg` across the tree confirms nothing in `src/`, build scripts, or tests
reads any of the four — the only references are `docs/release/v4.0.0-readiness-plan.md:89-90`
(which itself names this exact cleanup as "Gap 6 — file hygiene", owned by
this shard) and `CODEX-TO-CLAUDE-COORDINATION.md:27` (a sibling scratch file,
also untracked, referencing the fourth by name). Verdict: none of the four
ships in a public 4.0.0 release; delete or gitignore before merge.

The `.gitignore` diff (c3626cf8..60b138bb) adds a narrow pattern for this
exact class of file — `.review-*` — but it neither matches any of the four
already-tracked offenders (`.reviewprompt` has no hyphen after "review"; the
other three don't start with `.review` at all) nor were the four removed from
tracking. The hygiene gap the new `.gitignore` rule was written to close is
still open in the files it was meant to catch.

### 2. Release-claim drift — CONFIRMED, low severity, should block

`README.md`, `CLAUDE.md`, `ARCHITECTURE.md`, and `benchmarks/public_claims.json`
move the meta-tool count from 16→17 consistently (readme_benchmark, the
`with_webhook_status` field removed, "14-16"→"14-17" everywhere, token
figures 1600→1700). **`llms.txt:41` was missed**: "The minimum operational
surface has 14 tools. The README benchmark scenario has **16**." while
`llms.txt:3` and `:5` in the same file already say 17. Confirmed at source:
`git show 60b138bb:llms.txt` lines 3, 5, 41. This is the self-contradicting
drift the brief flagged — llms.txt now disagrees with itself, and
`benchmarks/public_claims.json`'s CI drift check does not cover llms.txt.

### 3. CI/release workflow changes — DEAD (no gate weakened); one drift risk noted

`.github/workflows/{ci,release,docker}.yml`:

- Pins two previously-floating action tags to SHAs (`sigstore/cosign-installer@v3`,
  `anchore/sbom-action/download-syft@v0`) — strictly stronger, removes a
  `ponytail: floating major tag` follow-up comment because the follow-up is
  done.
- Adds a new `release-criteria` job (runs `count-release-criteria.py --check`
  plus its own test) to all three workflows, wired into `needs:` for the
  publish/build jobs — a new blocking gate, not a removed one.
- `continue-on-error: ${{ !startsWith(github.ref, 'refs/tags/v') }}` on the
  ci.yml copy only: report-only on ordinary PRs (ledger edited mid-flight),
  blocking on a tag push. This is a deliberately scoped exception, documented
  inline, not a silent weakening — DEAD as a "weakened gate" finding.
- `pull_request: branches: [main]` → `[main, codex/v4-release-delivery]` —
  widens the trigger, does not narrow it.
- No `continue-on-error` was added to any job that previously ran unconditionally.

No confirmed gate regression in this file set.

## Summary

- CONFIRMED: 2 (scratch-file hygiene, llms.txt drift) — both should block a
  clean 4.0.0 tag, neither is a functional/security defect.
- DEAD: 1 (CI-gate-weakening theory).
- CANNOT-VERIFY: 0 directly checked; 6 reviewer-ledger verdicts (all
  SHIP-WITH-FIXES) not yet individually decomposed into per-finding
  CONFIRMED/DEAD/CANNOT-VERIFY — see "Not covered" above.

**Confirmed finding blocking a clean 4.0.0 release**: the four agent scratch
files should not ship in the public tag; `llms.txt:41` should read 17, not 16.
Neither is a security or correctness defect in the gateway itself.
