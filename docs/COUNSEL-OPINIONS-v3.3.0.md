# AI-counsel opinions on the v3.3.0 license flip

**Caveat:** these are AI models role-playing software-licensing counsel, at the
operator's request, to front-load obvious fixes. **Not legal advice; not a
substitute for a bar-admitted attorney.** The human legal review still governs.

## Engagement
Both models were asked to advise Mikko Parkkola (sole licensor) in his interest:
monetize commercial use + contain the 3.0.0–3.2.1 MIT leak. Four questions:
enforceability of the per-file split, the leak exposure + NOTICE wording, the
withdrawal plan's legal risk, and go/no-go.

## grok 4.5 — **COUNSEL: FIX FIRST**
Complete opinion. Verdict: aggressive intent is reasonable; execution has holes.
Key points:
- **Per-file split is insufficient as drafted.** "Absence = Noncommercial" is
  fragile: an extracted file loses the governing context. No copyright notices,
  no explicit marker on NC files, no contributor CLA/DCO.
- **The 3.0.0–3.2.1 leak is real and broad** — recipients may use/fork/sell/
  sublicense/distribute those exact artifacts forever. NOTICE wording is "mostly
  safe" (correctly disclaims revocation) but should be tightened.
- **Withdrawal:** sequencing is right (ship 3.3.0, then withdraw). yank/deprecate/
  banner are low-risk; **deleting container images is the risky one** — prefer
  deprecate/unlist.
- **Real remaining levers vs the past leak:** trademark on the name/marks,
  later-granted patents (only under commercial terms), and support/security-update
  starvation.

### grok's ranked MUST-FIX
1. **Per-file headers** — copyright notice on every file + an explicit license
   marker on NC files (`LicenseRef-PolyForm-Noncommercial-1.0.0`), not mere
   absence. *(Largest enforceability gap.)*
2. **Contributor CLA/DCO** binding contributors to the per-file model.
3. **NOTICE tightening** — scope to exact artifacts, address code-mixing, AS-IS.
4. **Container withdrawal** — deprecate/unlist, don't delete.
5. **CI + allowlist as a formal release gate**, audited each release.
6. **COMMERCIAL.md** — define commercial triggers, and the patent/trademark
   grants withheld from the free license.

## gpt-5.6-sol — **COUNSEL: FIX FIRST**
Full opinion obtained (it is a slow thinking model; earlier capture attempts
misread it). Converges with grok on FIX FIRST; adds sharper points:
- **"Absence = Noncommercial" is the core weakness** (same as grok). Wants an
  affirmative header on every NC file: `// SPDX-FileCopyrightText: 2026 Mikko
  Parkkola` + `// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0`, with a
  shebang permitted before it.
- **"dual-licensed" is dangerous terminology** — conventionally it means the
  recipient may choose either license for the whole project. Use "mixed, per-file
  licensing"; reserve "dual license" for the separate commercial offer.
- **Scope the default to Mikko-owned original material** and expressly exclude
  third-party + generated files (else the rule wrongly claims NC over vendored
  code, generated files, and LICENSE-MIT itself). "There is no third state" is
  unsafe if any third-party material exists.
- **DCO is not enough — use a CLA.** A DCO certifies provenance; it does not give
  Mikko the ownership/relicensing authority needed to *sell* commercial licenses.
  The CLA needs copyright assignment (or a broad, sublicensable, relicensable
  license) + an express patent license + authority representations.
- **NOTICE: remove admissions.** "intended to be Enterprise" / "by mistake" are
  unnecessary internal-intent admissions that could be quoted against him. It gave
  neutral replacement wording (in the PR discussion).
- **Verify license/notice files in EVERY artifact** (crates tarball, npm tarball,
  container filesystem, Homebrew archive, binaries) — not just the repo.
- **Audit chain of title** before asserting "sole copyright owner" (AI-assisted
  contributions, copied snippets, vendored material).
- **Withdrawal:** don't call old versions "unauthorized/infringing/insecure"
  (disparagement/misrepresentation risk); check customer contracts/SLAs before
  deleting containers; preserve immutable release evidence first.
- **COMMERCIAL.md** must have a working contact and not over-claim the definition
  of "commercial" beyond the license text.

## Synthesis — both counsel agree: FIX FIRST
Convergent MUST-FIX (2/2), in priority order:
1. **Affirmative per-file headers** — copyright + explicit NC SPDX on every
   licensor-owned NC file (not mere absence). *(Biggest gap, both.)*
2. **CLA with relicensing authority + patent grant** for contributors (DCO
   insufficient for selling commercial licenses).
3. **Neutral NOTICE** — keep the non-revocation sentence; remove "mistake"/
   "intended as Enterprise" admissions; scope to exact artifacts. *(Partly done.)*
4. **Terminology** — "mixed, per-file licensing," not "dual-licensed."
5. **Scope the default to Mikko-owned originals**; exclude third-party/generated.
6. **CI validates BOTH MIT and NC headers** + packaging + allowlist closure +
   unknown-license states.
7. **Verify license files in every published artifact**, not just the repo.
8. **COMMERCIAL.md** — working contact + commercial-license terms; don't over-claim.
Plus: chain-of-title audit; preserve release evidence; trademark policy.


## Status of the convergent must-fixes (all addressed 2026-07-11)
- [x] #1 Affirmative per-file headers — copyright + explicit SPDX id on all 399
      first-party `.rs` (MIT core: MIT; all else: PolyForm-Noncommercial-1.0.0).
      `scripts/ci/apply-license-headers.sh` (idempotent, shebang/inner-attr-safe);
      `cargo check --all-targets` green.
- [x] #2 CLA (not DCO) — `CLA.md`: contributor keeps copyright, grants a broad
      sublicensable **relicensable** copyright license (incl. commercial), an
      express patent license with defensive termination, and authority reps.
      `CONTRIBUTING.md` requires signing; its "new files need no header" error
      (which contradicted the new guard) corrected.
- [x] #3 Neutral NOTICE — intent/fault admissions ("by mistake", "intended as
      Enterprise") removed here and in README/LICENSES/COMMERCIAL/deprecate
      runbook; non-revocation sentence, AS-IS, exact-artifacts scope kept.
- [x] #4 Terminology — "mixed, per-file licensing" replaces "dual-licensed" in
      all active docs (superseded LICENSE-EE + historical CHANGELOG left as records).
- [x] #5 Scope — default scoped to Mikko-owned originals; third-party/generated
      and the license texts excluded via `.license-scope-exclude` (empty today —
      no vendored/generated source). Replaces the unsafe "no third state".
- [x] #6 CI validates BOTH ids — `check-license-headers.sh` now checks copyright
      + MIT/NC id + unknown-license + leak + NC-in-core, both directions.
- [x] #7 License files in every artifact — Docker COPY into image; Homebrew
      `license :cannot_represent` + caveat (and the release.yml generator fixed);
      `verify-artifact-licenses.sh` audits crates/npm/Docker/Homebrew, wired into CI.
- [x] #8 COMMERCIAL.md — working contact + sponsor link; states the PolyForm-NC
      text (not the doc) defines "noncommercial"; stale "Enterprise Edition"
      framing normalized.

Plus SHOULD items still open for the human review: chain-of-title audit,
preservation of immutable release evidence before withdrawal, trademark policy.

Net: the eight convergent MUST-FIX items are implemented and green in CI. This
is **engineering readiness, not legal clearance** — a bar-admitted attorney must
still confirm the per-file marking scheme, the CLA, and the NOTICE/withdrawal
wording before any release tag. No tag without that sign-off.

## Re-review round 2 (gpt-5.6-sol, 2026-07-11) — residual gaps closed

The re-review returned **COUNSEL: FIX FIRST** again, confirming the eight items
land but naming four residual gaps. All four now fixed:

- **#1 header scope** — the guard was Rust-only, so 23 first-party shell scripts
  fell back to the "absence = Noncommercial" fragility the affirmative-header
  model exists to kill. `apply-license-headers.sh` + `check-license-headers.sh`
  are now comment-style-aware (`//` for `.rs`, `#` for `.sh`) and scan
  `src crates tests examples benches scripts deploy tools`. All 23 scripts stamped
  Noncommercial; check green under bash 3.2 and 5.x; 422 files total covered.
- **#4 terminology** — the primary `LICENSE` file itself still opened with
  "dual-licensed on a per-file basis"; changed to "mixed, per-file licensing".
- **#7 artifact license text** — GitHub release uploaded raw binaries + checksums
  with no license text. `release.yml` "Prepare release files" now copies the six
  license/notice files into `release/`, so they ship as release assets and enter
  `SHA256SUMS.txt`.
- **Stale/contradictory docs** — deleted the dead `packaging/homebrew/mcp-gateway.rb`
  duplicate (v2.0.0, PLACEHOLDER sha, `license "MIT"`, referenced by no release
  path); corrected ADR-011's "Noncommercial without needing a header" line to the
  affirmative-header model.

Still engineering readiness, not legal clearance. The named-human-lawyer gate is
unchanged: no tag without sign-off.

## Round 3 (2026-07-11) — drafting-risk items neutralized

The re-review's "adequately resolved WITH drafting risk" flags were text-fixable
without a lawyer's judgment; done:

- **"sole copyright owner" overclaim** — the CLA has contributors *retain*
  copyright, so claiming sole ownership is internally contradictory and becomes
  false on the first external contribution. `CLA.md` and `COMMERCIAL.md` now say
  "copyright holder of the original work". (The factual chain-of-title audit
  remains a human-counsel item.)
- **Fault/intent admissions** — removed "by mistake" from
  `docs/LEGAL-REVIEW-BRIEF-v3.3.0.md` (now: "distributed enterprise features
  under MIT") and rewrote `ADR-011`'s "these were meant to be Enterprise / the
  allowlist was incomplete / shipped under MIT default" into the neutral
  structural rationale (enterprise logic is woven into the runtime, so a per-file
  allowlist is unworkable — hence the flip). No self-incriminating intent language
  in any active doc.

Remaining items are genuinely human-counsel calls, not script-fixable: CLA
venue/jurisdiction mechanics, patent-termination scope tuning, and the factual
chain-of-title audit (AI-assisted contributions, copied snippets, vendored
material). Engineering readiness holds; the sign-off gate is unchanged.

## Round 4 (2026-07-11) — operator clearances

The licensor confirmed two of the three remaining items directly:

- **Venue/jurisdiction (RESOLVED)** — Finnish jurisdiction cleared. `CLA.md` now
  names the courts of Finland as exclusive forum, District Court of Helsinki
  (Helsingin käräjäoikeus) as court of first instance, alongside the existing
  Finnish governing-law clause.
- **Patent posture (RESOLVED)** — the licensor has filed no patents. The CLA's
  patent-termination clause is a defensive grant on the *contributor's* patents
  (Apache-2.0 style) and functions independently of any licensor portfolio, so it
  needs no tuning. No active doc asserts the project holds patents, and
  COMMERCIAL.md promises no patent protection — verified, no overclaim.

**Only one human-counsel item now remains open:** the factual chain-of-title
audit (AI-assisted contributions, copied snippets, vendored material) before
asserting authorship. Everything else is engineering-ready and operator-cleared;
the bar-admitted-attorney sign-off on the overall scheme is still the tag gate.

## Round 5 (2026-07-12) — chain-of-title audit + dual-counsel review

The last open human-counsel item — the factual chain-of-title audit — was run as
a dual AI-counsel review (GPT-5.5 via codex + Grok) with independent web
verification of every legal anchor. Full analysis:
[`docs/CHAIN-OF-TITLE-ANALYSIS.md`](CHAIN-OF-TITLE-ANALYSIS.md). Raw transcripts:
`/Users/mikko/cot_gpt.txt`, `/Users/mikko/cot_grok.txt` (out-of-repo).

**Both models independently returned COUNSEL: SHIP-ABLE (risk manageable).**

- **Precedent** — every authority on point *helps*: *Thaler v. Perlmutter* (D.C.
  Cir. 2025, verified) bars only AI-as-sole-author with human input disclaimed;
  USCO "Copyright and AI" Part 2 (2025, verified) protects human selection /
  arrangement / modification of AI output; EU Software Directive 2009/24/EC Art
  1(3) + CJEU AOIC line (Infopaq / Painer / SAS / BSA, all verified) protect the
  integrated work via free and creative choices. No hallucinated cases in either
  output; one Grok reporter cite (130 F.4th 1039) left UNVERIFIED, low materiality.
- **Favorable law** — EU/Finland ("author's own intellectual creation") is at
  least as good as, arguably cleaner than, US law for software on these facts.
- **Residual risk** — copied snippets, not AI-authorship. Audit found **none**.

Chain-of-title de-risking implemented this round: `AUTHORSHIP.md` (dated
declaration), `docs/legal/snippet-provenance.md` (clean audit),
`docs/legal/dependency-licenses.md` + `.tsv` (426-crate SBOM, no copyleft
contamination), and the stale MIT claim in `docs/show-hn.md` reconciled.

**Every AI-counsel and operator-clearable item is now closed.** The single
remaining gate is unchanged: sign-off by a bar-admitted Finnish/EU IP attorney on
the per-file marking scheme, the CLA, and the NOTICE/withdrawal wording before
the release tag. AI counsel ≠ legal clearance.
