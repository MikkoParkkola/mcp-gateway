# MIK-3274.RANKING.1 — fuzzy ranking for abbreviations and word boundaries

Status: design, reviewed round 1 (two independent reviewers, both
SHIP-WITH-FIXES, all findings applied — see §8). Two questions in §7 await
an owner decision. Date: 2026-09-12.
Branch: `feat/v4-ranking-fuzzy`. Release: 4.0.0, package DISCOVERY.
Scope: this document covers **MIK-3274.RANKING.1 only**. RANKING.2 (authorization
and truncation ordering) and RANKING.3 (measured thresholds) are separate rows
with separate owners; this design must not silently absorb them.

## 1. Approved acceptance text (verbatim)

From [the approved scope update](../requirements/RELEASE-4.0.0-scope-update.md),
line 48 — "Approved capability scope update", Status: approved scope, Date: 2026-09-06:

```
| MIK-3274.RANKING.1 | Fuzzy ranking improves supported abbreviation and word-boundary discovery while exact identifiers, existing relevant matches and Code Mode globs remain reliable. | DISCOVERY |
```

From [the supplemental acceptance test plan](../requirements/RELEASE-4.0.0-scope-tests.md),
line 57 — "specifications for implementation, not claims that tests exist or
pass"; "Every product row starts unverified until the release integrator grades
evidence":

```
| MIK-3274.RANKING.1 | Held-out abbreviations and word boundaries over realistic conflicting tool names; exact identifier, unsupported match, Unicode and Code Mode glob controls. |
```

Neighbouring rows are quoted here as boundary context only, not as obligations
of this design:

```
| MIK-3274.RANKING.2 | Both discovery routes apply authorization before disclosure and rank before truncation; usage feedback cannot promote an irrelevant or forbidden tool over a relevant allowed tool. | DISCOVERY |
| MIK-3274.RANKING.3 | Held-out selection quality, discovery turns, invalid invocations and total completed-task tokens meet thresholds frozen after baseline measurement and before ranking implementation. | DISCOVERY |
```

### 1.1 What the wording constrains

Three clauses are load-bearing and each one decides a design choice:

- **"supported abbreviation"** — *supported* means the set is enumerable and
  reviewable. The test plan pairs it with an **unsupported match** control: a
  query that must keep returning nothing. A thresholded distance metric could in
  principle pass that control too, so the closed table is a **pragmatic choice,
  not a logical consequence** of the wording. It is chosen because a table makes
  the supported set auditable in review, needs no threshold tuned against the
  same corpus that grades it, and cannot drift as the catalogue grows. If a
  reviewer prefers a metric, that is a live alternative, not a contradiction.
- **"word-boundary discovery"** — boundary awareness must make the ranker
  *discriminate better*, but tightening the candidate filter to require
  boundaries would drop candidates that match today.
- **"existing relevant matches ... remain reliable"** — the candidate filter may
  only be made **more admitting**, never more restrictive. This is what splits
  the change across two stages (§3).

## 2. Current behaviour (verified by reading, 825f3be1)

### 2.1 Two public discovery routes

| Route | Entry | Candidate collection | Ranking |
|---|---|---|---|
| `gateway_search` (Code Mode) | `code_mode_search`, `src/gateway/meta_mcp/search.rs:378` | `collect_code_mode_capability_matches` (:190) and `collect_code_mode_backend_matches` (:228), both via the `code_mode_tool_matches` predicate (:176) | `ranker.rank(..)` :412, **only when `!use_glob`** |
| `search_tools` | `search_tools`, `src/gateway/meta_mcp/search.rs:724` | `collect_search_capability_matches` (:280) and `collect_search_backend_matches` (:321), both via `tool_matches_query` | `ranker.rank(..)` :762 |

Both collectors gate every tool on `profile.backend_allowed`,
`profile.tool_allowed` and `meta_route_isolation_refused` (INV-2, MIK-6742,
fail-closed omission) before a tool can become a candidate. `kill_switch.is_killed`
is **not** an omission: a killed backend's tools still enter `matches`, tagged
`status: "disabled"`. This design does not touch any of those gates; their
ordering is RANKING.2's row.

### 2.2 The filter is a hard gate in front of the ranker

`tool_matches_query` (`src/gateway/meta_mcp_helpers.rs:449`) decides membership:

```rust
pub(crate) fn tool_matches_query(tool: &Tool, query: &str) -> bool {
    let name_lower = tool.name.to_lowercase();
    let desc_lower = tool.description.as_deref().unwrap_or("").to_lowercase();
    query.split_whitespace()
        .any(|word| word_matches_text(word, &name_lower) || word_matches_text(word, &desc_lower))
}

fn word_matches_text(word: &str, text: &str) -> bool {          // :459
    if text.contains(word) { return true; }
    expand_synonyms(word).iter().any(|syn| *syn != word && text.contains(*syn))
}
```

**This is the finding the whole design hinges on.** A tool that fails
`tool_matches_query` never enters `matches`, so `SearchRanker::rank`
(`src/ranking/mod.rs:371`) never sees it and no scorer change can recover it. An
abbreviation such as `k8s` for `kubernetes` fails the substring test and is
filtered out before ranking exists. Abbreviation handling **must** be admitted at
the filter stage; a scorer-only change is provably inert for the primary
acceptance case.

Note what already works, so the change does not claim credit for it: because the
test is plain substring containment, every **prefix** abbreviation already
matches — `repo` already finds `repository`, `auth` finds `authentication`,
`env` finds `environment`, `dir` finds `directory`. The real gap is
**non-prefix** abbreviations, where a letter is dropped from the middle or the
form is a numeronym. That is what the table must cover, and only that.

Code Mode admits slightly more than `search_tools`: `code_mode_tool_matches`
(`search.rs:176`) accepts `tool_matches_query(tool, query)` **or**
`tool_ref.contains(query)` where `tool_ref` is the lowercased
`"{server}:{tool}"` reference, so a server-qualified query matches there and not
on the other route. The abbreviation table changes `tool_matches_query`, which
both routes share; the `tool_ref` clause is left alone.

### 2.3 The scorer

`score_text_relevance` (`src/ranking/scoring.rs:190`) is pure text scoring over a
lowercased tool name and description, with tiers documented at
`src/ranking/mod.rs:345-370`: 15 all words in name, `10+2N` all words in
name+desc, 10 exact single-word name match, `6+2N` keyword tags, `4+2N` schema
fields, `3+2M` partial coverage, 6 single-word exact schema field, 5 name
contains full query, 2 description contains full query. `rank()` then applies
`score = text_relevance * (1.0 + usage_factor) * signals.multiplier()`, drops
excluded results and sorts descending.

### 2.4 The existing precedent this design copies

Synonym expansion already solves exactly this shape of problem, and it already
reaches both stages from one table:

- `expand_synonyms` is defined once in `src/ranking/scoring.rs:17` and re-exported
  at `src/ranking/mod.rs:19` (`pub use scoring::{expand_synonyms, is_schema_field_match}`).
- The **filter** consumes it: `meta_mcp_helpers.rs:16` imports
  `crate::ranking::{SearchResult, expand_synonyms}` and calls it at :463.
- The **scorer** consumes the same function through
  `text_contains_with_synonyms` (`scoring.rs:113`) and
  `is_keyword_match_with_synonyms` (`scoring.rs:304`).
- Matches found only through expansion are discounted by
  `SYNONYM_MULTIPLIER = 0.8` (`scoring.rs:107`), which is what keeps a literal
  match ahead of an expanded one.

A table in the same file, consumed at the same two call sites, with its own
multiplier constant, therefore reaches both routes and both stages with **no new
plumbing and no new matching layer**.

## 3. Design

### 3.1 The split

| Stage | Change | Direction | Why |
|---|---|---|---|
| Candidate filter (`tool_matches_query`) | admit **supported abbreviations** | additive only — nothing that matches today stops matching | an abbreviation must become a candidate before ranking can do anything |
| Scorer (`score_text_relevance`) | reward **word-boundary** alignment; discount abbreviation-only hits | re-orders, never excludes | boundary strictness at the filter would drop existing relevant matches and fail the acceptance clause by construction |

Stating it the other way round is the mistake to avoid: boundary strictness in
the filter and abbreviation expansion in the scorer would both break the row —
the first removes existing matches, the second is inert (§2.2).

### 3.2 Abbreviation admission (filter)

Add a closed, reviewable table beside `expand_synonyms` in
`src/ranking/scoring.rs`, in the same shape (bidirectional groups, exhaustive
`match`, `_ => &[]`), exported the same way from `src/ranking/mod.rs`.

**Only non-prefix abbreviations belong in it.** Prefix forms already match by
substring containment (§2.2), so entering them would add table weight and change
nothing. Candidate seeds of the right shape: `k8s`/`kubernetes`, `cfg`/`config`,
`msg`/`message`, `svc`/`service`, `pkg`/`package`, `db`/`database`,
`img`/`image`, `perms`/`permissions`, `i18n`/`internationalization`. The final
list is fixed at implementation time against terms that actually occur in the
shipped catalogue — but it stays a **list**, and its size is reviewable in one
screen. Each entry carries a one-line justification naming the catalogue term it
serves.

**Authoring data is separate from evaluation data.** The table is written from a
development sample of the catalogue. The held-out corpus that grades RANKING.1
is retained by the evaluation owner and is not consulted while choosing entries;
freezing a corpus is not the same as holding it out, and a table tuned against
the grading set produces evidence a release integrator cannot accept.

Consumption rules, so two implementers cannot produce different rankings:

1. A term appears in **exactly one** expansion table. Overlap between the
   synonym table and the abbreviation table is a review error, checked at
   authoring time.
2. Abbreviation expansion is consulted **only after** literal containment and
   synonym expansion have both failed, at each of the four existing expansion
   sites: `word_matches_text` (`meta_mcp_helpers.rs:459`, the filter),
   `text_contains_with_synonyms` (`scoring.rs:113`),
   `is_keyword_match_with_synonyms` (`scoring.rs:304`), and the **single-word
   fallback loop** at `scoring.rs:241`. The fourth is easy to miss and is the one
   that matters most: a single-word query like `k8s` against an untagged
   `kubernetes_list` reaches no coverage tier at all, so without it an admitted
   abbreviation scores `0.0` and is admitted only to be ranked last.
   Four is verified repo-wide, not assumed: `expand_synonyms` is `pub` and
   re-exported at `mod.rs:19`, and a sweep of `src/` finds no caller outside
   these four sites and the unit tests. A fifth caller would otherwise inherit
   synonym behaviour with no abbreviation behaviour.
3. Abbreviation matches reuse the existing `SYNONYM_MULTIPLIER = 0.8` discount
   rather than introducing a second constant. Both are "matched only through
   expansion", the scorer already carries exactly one boolean of expansion
   provenance, and a second constant would have to justify itself with evidence
   this design does not have. The discount is **not compounded**: a match is
   discounted once or not at all.

"Supported" is therefore literally the table, and an abbreviation not in it
returns no new result — which is what makes the test plan's *unsupported match*
control a real negative control.

### 3.3 Word-boundary discrimination (scorer)

`score_text_relevance` uses `str::contains` throughout, so `cat` scores
identically inside `catalog_list` and inside `concat`. Boundary awareness is
added as a **tie-break, not a bonus**: among candidates whose base relevance
score is equal, the one whose match begins at a token boundary sorts first.

A multiplier was the first proposal and is rejected. The existing tiers
interleave (`6+2N`, `4+2N`, `3+2M`, flat 6, flat 5, 2) with gaps as small as one
point that vary with query word count, so "capped below one tier step" is not a
well-defined bound; a fixed multiplier would silently promote a weaker tier for
some query lengths, which is exactly the displacement the acceptance clause
forbids. A tie-break is within-tier **by construction**, needs no cap arithmetic,
and is a smaller change.

Boundary definition: a match position counts as boundary-aligned when it is at
the start of the haystack or immediately preceded by any **non-alphanumeric**
character (`char::is_alphanumeric` is false). Deriving it this way rather than
from a fixed ASCII separator list keeps it consistent with the Unicode
commitment in §3.5 and cannot miss a separator the catalogue adopts later.

Which positions are tested, stated once so two implementers cannot disagree: a
query word is boundary-aligned against a tool name when **at least one** of its
occurrences in that name is boundary-aligned, and the candidate is
boundary-aligned when **every** query word that matched the name is
boundary-aligned. A single-word query therefore reduces to "any occurrence
aligns"; a multi-word query is aligned only if all of its matched words are.
Words that did not match the name at all do not participate — they are already
accounted for in the score the tie-break is breaking.

Scope: tool names only, not descriptions. Conflicting siblings live in names
(`gmail_search` / `gmail_send` / `gmail_batch_modify`), and leaving description
scoring byte-identical shrinks the before/after surface the "existing relevant
matches" control has to cover.

### 3.4 Ordering invariants, and the one the current code does not hold

The comparator after this change, applied in `SearchRanker::rank`
(`src/ranking/mod.rs:371`), is:

1. exact identifier match (new, see below);
2. final score = `text_relevance * (1.0 + usage_factor) * signals.multiplier()`
   (unchanged);
3. boundary alignment, as a tie-break on equal final score (new);
4. existing order otherwise.

**Exact identifiers are not currently reliable, and this row owns that.**
`score_text_relevance` returns `10.0` for `tool_lower == query` at
`scoring.rs:199`, before any other path. For a single-word query, no competing
tier can beat that on text alone: the 15 tier and the `10+2N` coverage tier both
require `words.len() > 1`, and keyword/schema tiers with `N = 1` cap at 8. But
`rank()` then multiplies by `1.0 + usage_factor`, and `usage_factor` grows as
`log2(uses + 1) * 0.15` without bound — at ~100 recorded uses the multiplier is
about 2.0, so a sibling scoring 8 on text reaches ~16 and displaces the exact
identifier at 10. This is pre-existing behaviour, not something this design
introduces, but the acceptance row says exact identifiers must remain reliable
and the test plan makes it a control, so it is fixed here.

Minimal fix: carry an exact-identifier flag on the result and use it as the
**primary** sort key in `rank()`, ahead of score. A score floor cannot work —
usage is unbounded, so any floor is beatable by a sufficiently used sibling.
Both reviewers raised this independently; it is not RANKING.2's row, because
there both tools are relevant and allowed and the question is purely ordering.

Intended route, because it decides the cost: `rank()` already holds
`query_lower` and each `result.tool`, so the comparator computes exactness
inline. No field is added to `pub struct SearchResult`, so neither
`SearchResult::new` nor `json_to_search_result` changes and no public API
visibility widens — which is what makes §7 question 1 cheap to answer either way.

The remaining invariants hold by construction: abbreviation matches are
discounted to 0.8 of a literal match at the same tier (§3.2 rule 3), the
boundary tie-break cannot cross a score difference, and `usage_factor` is
untouched.

### 3.5 Unicode

The test plan names a **Unicode control**, and the current zero-result path
panics on one. `build_suggestions` (`meta_mcp_helpers.rs:478`) tests
`word.len() >= MIN_PREFIX_LEN && tag_lower.starts_with(&word[..MIN_PREFIX_LEN])`.
`len()` is bytes and `&word[..3]` is a byte slice, so a query word such as `éé`
(four bytes, two chars) slices through the middle of a character and panics.
It is reachable whenever a non-ASCII query returns no matches and at least one
keyword tag exists — precisely the Unicode control's shape on both discovery
routes. Repair it character-safely (take three `char`s, or skip the prefix rule
when the word has fewer than three chars). It is a two-line fix inside the
discovery search path, distinct from the `levenshtein` defect in §4.

All new matching code operates on `char`s or whole `&str` values and takes **no
byte-offset slices**, matching the existing glob path (`glob_match_chars`,
`meta_mcp_helpers.rs:424`, already char-based and Unicode-safe).

### 3.6 Code Mode globs

`code_mode_search` computes `use_glob = is_glob_pattern(&query)` (`search.rs:385`)
and, when true, routes matching through `tool_matches_glob` /
`tool_name_matches_glob` and **skips `ranker.rank` entirely** (:412). Glob queries
therefore bypass every change in this design by construction. The design adds no
branch to the glob path and no character with glob meaning to any table entry.

The Code Mode capability and backend collectors both route through
`code_mode_tool_matches` (`search.rs:176`), which takes `options.use_glob`
(:217, :268) and selects `tool_matches_glob` / `tool_name_matches_glob` when it
is set. `search_tools` has no glob mode at all. Verified by reading: there is no
path on which a glob query reaches `tool_matches_query`, so the abbreviation
table cannot leak into glob matching.

## 4. Out of scope (deliberate, verified)

- **`levenshtein` and issue #530.** `levenshtein` (`meta_mcp_helpers.rs:47`)
  sizes its DP rows by `b.len()` (bytes) while iterating `b.chars()` and
  returning `prev[b_len]`, which is wrong for non-ASCII input. Its only caller is
  `did_you_mean` (:75); `did_you_mean`'s only callers are
  `src/gateway/meta_mcp/invoke.rs:3006`, `src/gateway/meta_mcp/mod.rs:2006` and
  `src/gateway/meta_mcp/spec_preview.rs:191`, all misspelled-tool-name
  suggestion paths. None is reached from either discovery search route.
  RANKING.1 does not touch this function and must not appear in the same diff;
  the closed-table design gives no reason to call it.
- **Zero-result suggestions.** `build_suggestions` (prefix/tag fallback,
  `MIN_PREFIX_LEN = 3`, `MAX_SUGGESTIONS = 5`) runs only when `matches` is empty.
  Admitting abbreviations shrinks how often it fires but does not change it.
- **Authorization and truncation ordering, usage-feedback poisoning** —
  MIK-3274.RANKING.2.
- **Baseline capture, frozen corpus and threshold numbers** —
  MIK-3274.RANKING.3. This design deliberately states **no** numeric quality
  target: RANKING.3 requires thresholds to be frozen *after* baseline measurement
  and *before* ranking implementation, so inventing one here would pre-empt that
  row.
- **Semantic / embedding search** (`semantic-search` feature) — existing
  machinery, reused rather than rebuilt, and not modified here.

## 5. Acceptance mapping

The test plan row specifies held-out abbreviations and word boundaries over
realistic conflicting tool names, with four controls. This design supports each:

| Test-plan element | What the design must satisfy |
|---|---|
| Held-out abbreviations | Queries retained by the evaluation owner, never consulted while authoring the table (§3.2), return the intended tool. Freezing a corpus is not holding it out. |
| Word boundaries over conflicting names | With realistic sibling tools (`gmail_search` / `gmail_send` / `gmail_batch_modify`), a boundary-aligned match sorts above a mid-token one at equal score (§3.3). |
| Exact identifier control | An exact tool name returns that tool first **with a highly-used competing sibling present** — the case the current code fails and §3.4 fixes. Testing it with neutral usage would not exercise the control. |
| Unsupported match control | An abbreviation *not* in the table returns no new result. |
| Unicode control | Non-ASCII queries on both routes, including the **zero-result** path, return correctly and do not panic (§3.5). The zero-result case is the one that currently panics. |
| Code Mode glob control | Glob queries produce byte-identical results before and after the change (§3.6) — the cheapest falsifier in the set, and the one to run first. |

Per the test plan's own preamble, this section is a specification. No test is
claimed to exist or pass, and this row stays unverified until the release
integrator grades evidence.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Abbreviation admission widens the candidate set and dilutes results | Expanded matches carry the 0.8 discount, so they sit below literal ones at the same tier; `limit` truncation happens after ranking, so a diluted tail is not returned. Detected by the held-out corpus, not by inspection. |
| Table grows into an unreviewable dictionary | Non-prefix entries only, each justified by a catalogue term, capped at one reviewable screen. |
| Filter widening costs latency on large catalogues | The added work is a `match` on each query word, consulted only after literal and synonym matching fail — strictly less often than `expand_synonyms`, which already runs on every word of every query. |
| Exact-identifier primary sort key changes existing result order | It only moves a tool the caller named exactly; any reordering it causes is the acceptance clause being honoured. Covered by the before/after comparison for "existing relevant matches". |
| Fixing the `build_suggestions` panic changes zero-result suggestion output | The repair is character-safe truncation of the same rule; ASCII queries, which is every existing test, are byte-identical. |

## 7. Open questions for review

Round one resolved the three questions this section previously carried: one
expansion table per term reusing `SYNONYM_MULTIPLIER` (§3.2 rule 3), boundary
handling on tool names only (§3.3), and separators derived from
`char::is_alphanumeric` rather than a fixed ASCII set (§3.3). What remains open:

1. Is the exact-identifier primary sort key (§3.4) accepted as RANKING.1 work,
   or should it be raised as its own defect against the ranker? It is a
   pre-existing gap, it is what the acceptance control tests, and fixing it here
   is a few lines — but it is the only part of this design that changes ordering
   for queries containing no abbreviation.
2. Should the `build_suggestions` character-safety repair (§3.5) ship in this
   diff or as a separate one-line fix? It is reachable from the Unicode control
   this row owns, but it is not ranking code.

## 8. Review record

Two independent reviewers were run against this document at the design stage,
before any implementation code. Both returned **SHIP-WITH-FIXES**; every finding
is applied above.

| Reviewer | Verdict | Date | Output |
|---|---|---|---|
| Codex (`gpt-review`) | SHIP-WITH-FIXES | 2026-09-12 | `~/.claude/data/reviews/runs/gpt-20260912T143110Z-53608.md` |
| Synthetic (`kimi-review`) | SHIP-WITH-FIXES | 2026-09-12 | `~/.claude/data/reviews/runs/synthetic-20260912T143312Z-65777.md` |

Findings and disposition:

| Finding | Raised by | Disposition |
|---|---|---|
| Exact-identifier precedence is asserted, not established; usage weighting can displace it | both | Accepted. §3.4 now shows the arithmetic and adds a primary sort key; §5 requires the control to be tested with competing usage. |
| Boundary multiplier cannot guarantee within-tier ordering against interleaved tiers | both | Accepted. §3.3 replaces the multiplier with a tie-break on equal scores. |
| Single-word fallback at `scoring.rs:241` omitted, so an abbreviation-only match scores 0.0 | Codex | Accepted. §3.2 rule 2 names all four expansion sites. |
| `build_suggestions` byte-slices `&word[..3]` and panics on non-ASCII, on the zero-result path the Unicode control exercises | Codex | Accepted. §3.5 and §7 question 2. |
| Authoring the table against the held-out corpus destroys its independence | Codex | Accepted. §3.2 separates authoring data from evaluation data. |
| Baseline description wrong: `repo` already matches `repository`; Code Mode also admits `tool_ref.contains(query)`; killed tools are labelled `disabled`, not omitted | Codex | Accepted. §2.1 and §2.2 corrected; the seed list is now non-prefix only. |
| Closed table presented as forced by the acceptance wording when it is a pragmatic choice | Codex | Accepted. §1.1 reframed. |
| Precedence between the synonym and abbreviation discounts undefined | Synthetic | Accepted. §3.2 rules 1 and 3: one table per term, discount never compounded. |
| Use a single non-alphanumeric separator rule instead of a fixed ASCII set | Synthetic | Accepted. §3.3. |
| Split the `auth` seed group; authentication and authorization are confusable | Synthetic | Moot — `auth` is a prefix of both and already matches by substring, so it is not in the table at all. |
| Reuse `SYNONYM_MULTIPLIER` rather than adding a second constant | Codex | Accepted. §3.2 rule 3. |
| Resolve boundary scope to names only | Synthetic | Accepted. §3.3. |

Three points were tightened after the review round without reopening it, none
of them reversing a reviewer decision: the boundary tie-break now states which
match positions it tests (§3.3), the exact-identifier fix names its
no-API-widening implementation route (§3.4), and the "four expansion sites"
count is recorded as verified repo-wide rather than asserted (§3.2 rule 2).

No implementation code is written until the two questions in §7 are answered.
