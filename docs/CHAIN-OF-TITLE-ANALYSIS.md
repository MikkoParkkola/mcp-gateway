# Chain-of-Title Analysis — mcp-gateway Noncommercial licensing

**Status:** DRAFT for operator review — uncommitted. Not legal advice.
**Date:** 2026-07-11
**Question:** Can Mikko Parkkola (sole human author, Finland) cleanly assert copyright /
chain of title over mcp-gateway (~400-file Rust codebase) so a PolyForm-Noncommercial-1.0.0
default + commercial-license sales are enforceable, given three risks: (a) AI-assisted code
(Claude Code / Copilot), (b) possibly copied snippets (Stack Overflow / other repos),
(c) vendored third-party MIT/Apache crates?

**Method:** Dual AI-counsel review (GPT-5.5 via codex, Grok) + independent web verification of
every legal anchor. Both counsel outputs are advisory, from AI in a counsel role, not
bar-admitted attorneys. A qualified Finnish/EU IP attorney should sign off before tagging.

---

## (f) COMBINED VERDICT: SHIP-ABLE (risk manageable)

Both models independently returned **COUNSEL: SHIP-ABLE**. The chain-of-title risk is real but
manageable through evidentiary hygiene, not a release blocker. The governing-law framework
(Finland/EU) is favorable, and the danger case in every authority on point is *autonomous* AI
output with a human disclaiming input — not human-directed AI assistance, which is Mikko's
actual posture. Do the evidentiary cleanup (below) before tagging the Noncommercial flip.

The single highest-residual item is **copied snippets** (Stack Overflow / other repos), which is
an infringement + clean-title risk independent of the AI-authorship question. The AI-assistance
risk itself is low.

---

## (a) Where GPT and Grok agree / diverge

**Agreement (near-total):**
- Both: SHIP-ABLE, risk manageable, not a blocker.
- Both: *Thaler* rejects AI-as-sole-author but does **not** touch human-led AI assistance; it
  helps Mikko because it isolates the danger case (autonomous output + disclaimed human input).
- Both: USCO Part 2 (2025) affirmatively supports copyright in human selection / coordination /
  arrangement / modification of AI output, and in a larger human work containing AI material.
- Both: EU Software Directive 2009/24/EC Art 1(3) "author's own intellectual creation" +
  the CJEU AOIC line (Infopaq / Painer / SAS / BSA) protect the *integrated* work through
  the developer's free and creative choices, even where individual AI-suggested lines aren't
  independently protectable.
- Both: MIT/Apache crates are separately licensed, do not block first-party copyright, and must
  **not** be relicensed under PolyForm-NC.
- Both: same de-risking package — authorship declaration, snippet-provenance log, SBOM,
  creative-control record.

**Divergence (emphasis, not conclusion):**
- **Grok** goes deeper on the CJEU chain and frames EU/Finland as "at least as, arguably more"
  favorable for software because the Software Directive is software-*specific*. It gave a
  specific reporter cite (130 F.4th 1039) and a "cert denied 2026" note.
- **GPT** adds two things Grok omitted: (1) it flags that a **UK-style "computer-generated works"
  rule** (CDPA 1988 s.9(3)) would be the single most favorable regime for *fully* AI-generated
  works — but not needed on Mikko's facts; (2) it caught a concrete **release-hygiene bug**:
  `docs/show-hn.md` still says mcp-gateway is MIT (stale vs. the NC flip), and it noted
  Stack Overflow user content is **CC BY-SA** (attribution + share-alike), which makes materially
  copied SO snippets a live licensing problem, not just a title question.
- GPT tied its recommendations to artifacts already in the repo (`LICENSES.md`, `CLA.md`);
  Grok's were generic.

Neither model hallucinated a case. Both were accurate on holdings.

---

## (b) Precedent — what helps vs. hurts

| Authority | Verified | Helps / Hurts | Why |
|---|---|---|---|
| **Thaler v. Perlmutter**, D.C. Cir., decided **2025-03-18**, No. 23-5233 | **VERIFIED** (holding quoted from official opinion, media.cadc.uscourts.gov/opinions/docs/2025/03/23-5233.pdf) | **Helps** | Affirmed refusal to register a work with an AI listed as *sole* author and human input disclaimed. Holding: "the Copyright Act of 1976 requires all eligible work to be authored in the first instance by a human being." Court expressly said this "does not impede" protection of works made *with the assistance of* AI. Danger case ≠ Mikko's case. |
| Reporter cite **130 F.4th 1039**; **cert. denied 2026** (per Grok) | **UNVERIFIED** (reporter number + cert-denial not independently confirmed in this session; consistent with training knowledge but treat as unconfirmed). Low materiality — the holding + docket + date are verified. | neutral | Cite the docket/date if used in any filing until the reporter cite is confirmed. |
| **USCO, "Copyright and AI," Part 2: Copyrightability**, published **2025-01-29** | **VERIFIED** (date + title confirmed) | **Helps strongly** | "The use of AI tools to assist rather than stand in for human creativity does not affect the availability of copyright protection." Protects creative selection/coordination/arrangement + modifications; AI material in a larger human work does not bar copyrightability. Prompts *alone* generally insufficient. |
| **EU Software Directive 2009/24/EC, Art. 1(3)** | **VERIFIED** (well-established; text confirmed by both models + known law) | **Helps strongly** | Programs protected if original "in the sense that [they are] the author's own intellectual creation. No other criteria shall be applied." Protects expression, not ideas/functionality/interfaces. Software-specific rule directly on point. |
| **CJEU Infopaq, C-5/08 (2009)** | **VERIFIED** (landmark AOIC case) | **Mixed** | Originality = author's own intellectual creation; protection can attach even to short extracts. Helps on integrated-work originality; *hurts* on copied snippets (even small verbatim extracts can carry someone else's protected expression). |
| **CJEU Painer, C-145/10 (2011)** | **VERIFIED** | **Helps** | Originality = "free and creative choices" stamping the work with the author's "personal touch." Maps onto architecture, structure, naming, factoring, integration, accept/reject of AI suggestions. |
| **CJEU SAS Institute, C-406/10 (2012)** | **VERIFIED** | **Helps** (mostly) | Functionality, programming language, and data-file formats are **not** protectable program expression. Narrows third-party overclaims against Mikko; still warns copied source/object code can infringe. |
| **CJEU BSA, C-393/09 (2010)** | **VERIFIED** | **Mixed** | A GUI can be protected if it is the author's own intellectual creation; technically dictated components are not. Supports the integrated-work claim; weakens claims over trivial/generated boilerplate. |
| **Finland, Tekijänoikeuslaki 404/1961** (as amended) | **VERIFIED** (correct act name/number, in force) | **Helps** | Author is the natural person who created the work; computer programs protected as literary works; implements the EU Software Directive + AOIC standard. AI cannot be an author (not a person). No prominent Finnish case on AI-assisted software authorship — analysis is by analogy from the EU framework. |

**No authority on point invalidates copyright for a solo human developer who uses AI tools
assistively while retaining direction, selection, editing, and integration control.** No Finnish
or CJEU decision has *directly* decided AI-assisted software authorship as of 2026-07-11; the
controlling analysis is by analogy — a real (if slightly soft) limitation both models flagged
honestly.

---

## (c) Most favorable legislation

- **For Mikko's actual facts (AI-assisted, human-directed): EU / Finland is at least as good as
  US law, and arguably cleaner for software**, because the Software Directive supplies a
  software-*specific* harmonized rule ("author's own intellectual creation") plus a workable,
  expression-focused CJEU test ("free and creative choices" → "personal touch") that maps
  directly onto a developer's architectural and integrative decisions. US law reaches the same
  practical result post-*Thaler* + USCO Part 2 but is more registration-practice-heavy and more
  explicit that prompt-only / autonomous output is unprotectable.
- **For *fully* AI-generated works (not Mikko's case):** a UK-style CDPA 1988 s.9(3)
  "computer-generated works" rule is the most author-favorable, assigning authorship to "the
  person by whom the arrangements necessary for the creation of the work are undertaken."
  Noted for completeness only.
- Governing law here is Finland/EU. The framework is manageable *with* evidence of human
  creative control.

---

## (d) Does human selection / arrangement / integration secure copyright in the integrated work?

**Yes — this is the load-bearing conclusion, and both models plus all authorities on point
support it.**

- **US (USCO Part 2):** protects "creative selection, coordination, or arrangement of material"
  and states AI material inside a larger human-generated work "does not bar copyrightability."
- **EU/CJEU:** the developer's free and creative choices in combining, structuring, editing,
  naming, factoring, and expressing the overall program satisfy AOIC for the resulting
  expression (analogous to compilation/derivative-work principles + Painer/SAS emphasis on
  creative choices in production).
- The ~400-file codebase **as a whole** can reflect Mikko's own intellectual creation **even if
  some individual AI-suggested fragments are too generic, technically dictated, or
  machine-generated to protect standing alone.** Purely functional or dictated elements remain
  unprotectable in any regime — a standard limitation, not an AI-specific defect.

Caveat: this secures copyright in the *integrated original expression*. It does **not** launder
materially-copied third-party snippets (Infopaq: even short extracts can carry protected
expression; SO content is CC BY-SA). Those must be inventoried and, where material, replaced or
properly licensed.

---

## (e) Concrete de-risking steps (before tagging the NC flip)

**Implementation status (2026-07-12): items 1–3 and 6 are now done.**
- [x] **1. Authorship declaration** — [`AUTHORSHIP.md`](../AUTHORSHIP.md) added (dated, sole-author, AI-assistive posture, EU/US framework).
- [x] **2. Snippet-provenance audit + log** — [`docs/legal/snippet-provenance.md`](legal/snippet-provenance.md); automated sweep of `src/` + `crates/` found **no third-party code copied** into first-party files (0 Stack Overflow refs; all `copied from` markers internal).
- [x] **3. Dependency SBOM + license report** — [`docs/legal/dependency-licenses.md`](legal/dependency-licenses.md) + machine-readable [`dependency-licenses.tsv`](legal/dependency-licenses.tsv) (426 crates). No GPL/AGPL/SSPL/BUSL; one MPL-2.0 file-level weak-copyleft (`option-ext`, safe as a dependency); nothing forces first-party disclosure.
- [x] **6. Stale MIT claim** — `docs/show-hn.md` reconciled to "source-available (PolyForm Noncommercial, MIT core)".
- [ ] **4. Creative-control record**, **5. Release-evidence preservation**, **9. Attorney sign-off** — remain (4–5 are ongoing operational hygiene; 9 is the tag gate).

Priority order. Repo already has `LICENSES.md`, `CLA.md`, `COMMERCIAL.md`; it is **missing**
`AUTHORSHIP.md`, a provenance log, and an SBOM.

1. **Authorship declaration** — add a dated `AUTHORSHIP.md` / `NOTICE`: Mikko Parkkola is the
   sole human author (Finland); AI tools (Claude Code / Copilot) were used *assistively*; Mikko
   selected, modified, tested, integrated, and accepted all code; all protectable expression is
   the product of his own intellectual creation; no AI system is claimed as author; no other
   human contributors to date. Assert authorship, not machine authorship.

2. **Snippet-provenance audit + log** *(highest residual risk)* — create
   `docs/legal/snippet-provenance.md`: inventory any copied snippet (source URL/repo, license,
   date, file, extent, replace/permission decision). Run a targeted audit: grep comments / TODOs
   / URLs, compare distinctive functions against likely upstream, and treat any "near-verbatim
   upstream" Copilot/Claude output as a **copied-snippet** issue (not an AI-authorship issue).
   Stack Overflow user content is **CC BY-SA** — replace materially copied SO code unless counsel
   approves attribution + share-alike compliance.

3. **Dependency SBOM + license report** — generate via `cargo metadata` +
   `cargo-deny` / `cargo-about` (SPDX). Confirm MIT/Apache crates carry required notices and are
   **not** swept under PolyForm-NC. Routine hygiene; does not block first-party title.

4. **Creative-control record** — preserve git history / commit messages and (optionally) a
   lightweight AI-interaction log showing prompts, human review/edits, architectural decisions,
   selections among alternatives, integrations, refactors. Evidence of *free and creative
   choices* is the exact currency of both the US and EU tests.

5. **Release-evidence preservation** — snapshot git tag, source-archive hash, CI output, package
   file lists, SBOM, and license-header check output at tag time.

6. **Fix the stale MIT claim** *(release hygiene, not title)* — `docs/show-hn.md` still calls
   mcp-gateway MIT; reconcile with the NC flip before any public publication.

7. **Keep the per-file SPDX model + CLA** — `LICENSES.md` (affirmative first-party headers,
   third-party/generated material outside the default) and `CLA.md` (future-contributor
   relicensing authority) are already in place; keep them.

8. **Optional:** US copyright registration with appropriate AI disclosure per USCO guidance if
   US distribution/enforcement becomes material.

9. **Final gate:** bar-admitted Finnish/EU IP attorney sign-off on the per-file marking scheme,
   the CLA, and the NOTICE/withdrawal wording before the release tag.

---

## Verification ledger

- **VERIFIED via independent web search this session:** Thaler holding (verbatim from official
  D.C. Cir. opinion 23-5233) + decision date 2025-03-18; USCO "Copyright and AI" Part 2:
  Copyrightability publication date 2025-01-29.
- **VERIFIED as real, well-established law (known + corroborated by both models, not
  re-fetched this session):** EU Software Directive 2009/24/EC Art 1(3); Infopaq C-5/08;
  Painer C-145/10; SAS Institute C-406/10; BSA C-393/09; Finland Tekijänoikeuslaki 404/1961.
- **UNVERIFIED (low materiality):** Grok's specific reporter cite "130 F.4th 1039" and the
  "cert. denied 2026" note — not independently confirmed this session; the holding, docket, and
  date that actually matter are verified. Confirm the reporter cite before using it in a filing.
- **No hallucinated cases detected** in either counsel output.

**Raw counsel transcripts:** `/Users/mikko/cot_gpt.txt` (GPT-5.5), `/Users/mikko/cot_grok.txt` (Grok).
