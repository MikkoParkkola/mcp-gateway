# Legal review brief — v3.3.0 license flip (PR #349)

**For:** counsel reviewing the license change before merge/release.
**Prepared by:** engineering (Claude Opus 4.8), tri-model analysis (Claude + grok 4.5 + gpt-5.5), adversarial review (gpt-5.6-sol). Not legal advice.

## What changed (one paragraph)
`mcp-gateway` flips its repository license default from **MIT** to **PolyForm
Noncommercial 1.0.0**. Only ~36 explicitly-marked source files (a "MIT core" of
generic, single-user, dependency-closed building blocks) are MIT; every other
file is Noncommercial by default. Commercial use of the Noncommercial code —
which is effectively the whole runnable gateway — requires a commercial license.
The mechanism, files, and enforcement are in `LICENSES.md`, `LICENSE`,
`LICENSE-MIT`, `LICENSE-NONCOMMERCIAL`, `.mit-core-allowlist`, and
`scripts/ci/check-license-headers.sh`. Rationale + decisions: `docs/adr/ADR-011`.

## The three questions we need answered

1. **Is the per-file boundary enforceable as written?**
   The MIT/NC split is per file (SPDX header + allowlist), enforced by a
   bidirectional CI guard. `Cargo.toml` uses `license-file = "LICENSES.md"`
   because the SPDX `license` field cannot express mixed per-file licensing. Is
   this structure sound for asserting, in an enforcement action, that a specific
   file was Noncommercial? Is anything needed beyond the SPDX header + the
   `LICENSES.md` statement (e.g. a per-file copyright/notice line)?

2. **Is the `NOTICE.md` correction wording right?**
   Versions 3.0.0–3.2.1 distributed enterprise features under MIT. We state
   plainly that MIT rights already granted on distributed copies **cannot be
   revoked**, that those versions are deprecated, and that from 3.3.0 the model
   is as above. Does the wording adequately protect us without over-claiming?

3. **Is the withdrawal plan appropriate?**
   `scripts/release/deprecate-leaked-3x.sh` (after 3.3.0 publishes): `cargo yank`
   the old crates.io versions, `npm deprecate` the range, delete old ghcr image
   tags, add a NOTICE banner to old GitHub releases (tags kept), bump the
   Homebrew formula. All are distribution-removal, not license-revocation. Any
   legal risk in yanking/deprecating (e.g. disrupting existing dependents), or
   anything we should add/avoid?

## What we already verified (engineering)
- MIT core is **dependency-closed**: no MIT file imports Noncommercial code.
- The three modules that leaked enterprise logic in the first draft (`ranking`
  = authorization, `registry` = plugin marketplace, `capability/definition` =
  multi-user grant model) are now Noncommercial.
- CI guard is bidirectional (MIT-core must be MIT; nothing outside may be) and
  scans `src` + `crates` + `tests` + `examples` + `benches`.
- `LICENSE-NONCOMMERCIAL` matches the canonical PolyForm-NC 1.0.0 text.
- Docs (README, COMMERCIAL.md, CONTRIBUTING.md, LICENSES.md) state one
  consistent model.

## The business intent (for context)
Noncommercial/personal use of the whole gateway is free. Commercial use of the
runnable gateway requires a license. There is intentionally **no** free-commercial
tier (the single-user and multi-user runtime code are woven together and were
judged not cleanly separable without a refactor we chose not to do now).

## Not asking you to bless
The exact module-by-module boundary (an engineering judgment) or the code. Only
the three questions above, plus anything you flag.
