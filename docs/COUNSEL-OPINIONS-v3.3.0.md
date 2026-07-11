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

## gpt-5.6-sol — not obtained
The codex/gpt-5.6-sol path failed repeatedly in this environment (empty output,
trusted-dir error, prompt-echo across three attempts). Its opinion was not
captured. Recommend obtaining a second AI or human opinion separately.

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
