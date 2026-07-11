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


## Status of grok's must-fixes
- [x] #3 NOTICE tightening — done (exact-artifacts scope, code-mixing, AS-IS).
- [x] #4 Container withdrawal — runbook now deprecate/unlist, not delete.
- [ ] #1 Per-file headers (copyright + NC marker on ~330 files) — **not yet**;
      the largest item, tracked for a focused pass.
- [ ] #2 Contributor CLA/DCO — not yet.
- [ ] #5 CI/allowlist release gate — guard exists; wire into the release workflow.
- [ ] #6 COMMERCIAL.md commercial-trigger + patent/trademark clarity — not yet.

Net: **not clear to ship** until #1, #2, #6 are addressed. The human lawyer
should confirm the per-file marking scheme and the NOTICE/withdrawal wording.
