<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Public-repo docs hygiene: what is actually at risk

The open item read: *purge internal working docs, fix the hygiene gate,
relocate the 201 internal process docs*. All three clauses are re-derived here
against the tree rather than carried forward.

## The gate is green, and it is not the gap

`scripts/dev/check-public-repo-hygiene.sh` exits 0 on this branch. It enforces
that four private directories stay gitignored and scans every tracked doc for
fifteen blocked phrases — competitive scan, licensing strategy, patent
strategy, OPSEC review, and so on. Nothing in it is broken, so "fix the gate"
has no defect to point at.

What it does not cover is the class below. The blocked-phrase list was built
for *strategy* leakage. The leakage this tree actually has is *process*
leakage.

## Relocation would break the evidence trail

307 markdown files are tracked under `docs/`: 131 design, 67 release, 40
requirements, 13 ADRs, 56 elsewhere. The 238 in the first three directories are
the internal process record — and they are also the cited evidence for the
release criteria. `docs/requirements/RELEASE-4.0.0-scope-status.json` and the
Linear rows both cite them by path. Moving them relocates every citation in the
ledger at the same time.

So the count in the original item is stale (238, not 201) and the action is
wrong. Publishing engineering design docs is normal for an open repository;
the hazard is what some of them *say*, not that they exist.

## The real finding: 71 tracked docs narrate an agent session

| Class | Files | Example |
| --- | --- | --- |
| Names an AI review vendor as an actor | 42 | `gpt-review`, `grok-review`, `kimi-review`, `glm-review` |
| Narrates the authoring session | 41 | "token scan, this session"; "was commissioned this session" |
| Names the private tooling repo | 8 | `claude-elite` |
| First-person session reference | 1 | "my earlier" / "as I said" |

Union: **71 distinct files** (the classes overlap). By directory: 35 design, 19
release, 10 requirements, 2 reviews, 2 ADR, 3 elsewhere.

This is the same rule the commit-message convention already applies — state
facts about the code, never about the conversation that produced it — applied
to the docs the conversation produced. A reader of the public repository learns
which model vendors review this project and that a given table was produced by
a scan inside one agent session. Neither is a secret, and neither belongs in a
published design record.

## Three smaller findings

- `docs/release/v4.0.0-burndown-tracker.md` is the only tracked doc using
  `ARR`/`MRR` as words.
- `docs/evaluations/AP2_AND_GALILEO_EVALUATION.md` is the only tracked doc
  carrying money-per-year figures.
- Seven tracked docs name a competitor. Two are the allowlisted public
  competitive docs the gate already exempts. The other five —
  `docs/SHADOW_SCAN.md`, `docs/design/RFC-0070-universal-config-export.md`,
  `docs/design/RFC-0132-cloudflare-enterprise-mcp-gap-analysis.md`,
  `docs/design/RFC-0072-semantic-tool-search.md` and the evaluation above —
  have never been read against the competitive-candour rule.

## What to do, and in what order

1. **Extend the gate with the process-leakage class** — vendor-as-actor,
   session narration, the private tooling repo name. This must land *with* the
   sweep, not before it: adding the patterns to a gate that 71 tracked files
   violate turns CI red on the same commit.
2. **Sweep the 71.** Mechanical for the vendor names (a review seat is a seat,
   not a brand); prose edits for the session narration.
3. **Read the five unvetted competitor docs** against the rule that
   competitive candour stays in private trackers.
4. **Leave the 238 process docs where they are.** They are the evidence the
   criteria ledger cites.

None of this blocks the binary. It blocks nothing in the release criteria
either — no row covers docs hygiene. It is a publication-quality gate on a
world-visible repository, and it is cheapest to run once, before the tag draws
readers to it.

One exemption is needed at step 1: this document quotes the patterns in order
to define them, so the gate must allow the file that specifies it. That is the
same carve-out the gate already makes for the two public competitive docs.
