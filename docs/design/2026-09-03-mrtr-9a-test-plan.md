# MRTR.9a — test plan

Reviewed as a plan per §P2. Two cases predate it: `ac_mrtr_9a_…_refused`
(RED, failing on its own assertion) and `ac_mrtr_9a_…_relayed` (GREEN) were
written at `aecced48` to pin the criterion before this plan existed. They are
recorded as pre-plan probes with those observed outcomes; every remaining case
is plan-first.

**Criterion.** `MIK-7212.MRTR.9a` — never send an elicitation request in a *mode*
the client has not declared. Design: `2026-09-03-mrtr-9a-declared-modes.md`.

## The coverage matrix

Both review legs found the same defect in the first draft of this plan: it
listed cases as prose rows, and the row that was missing could only be found by
inference. The matrix is the fix, and it is the artifact — an **empty cell is a
finding**, mechanically, without anyone having to notice an absence.

Rows are what the client declared. Columns are the mode the backend requests.
`R` = the gateway **relays**; `X` = the gateway **refuses**.

| declared \ requested | `"form"` | `"url"` | absent | `"telepathy"` |
|---|---|---|---|---|
| no `elicitation` key | X | X | X | X |
| `{}` | R | X | R | X |
| `{"form":{}}` | R | X | R | X |
| `{"url":{}}` | X | R | X | X |
| `{"form":{},"url":{}}` | R | R | R | X |
| `{"telepathy":{}}` | X | X | X | X |
| `elicitation` non-object (`null`, `"form"`, `7`, `[]`) | X | X | X | X |

Four rows and one column of that table are the whole criterion, and none of
them was in the first draft:

- **the `{"url":{}}` row.** Both vendors raised it independently. Without it,
  the minimal patch *"refuse url unless declared, leave form ungated"* passes
  every case and violates the criterion for every url-only client.
- **the `absent` column against `{"url":{}}`.** The design's rule is that an
  absent request mode *is* form. A url-only client must therefore be refused an
  absent-mode request. An implementation that skips the gate when the field is
  missing passes the form-only absent case and fails here.
- **the non-object `elicitation` row.** Both vendors raised it independently
  on the second pass. The specification says a client declaring `elicitation`
  MUST support at least one mode; a non-object value names none, so it declares
  nothing and every request is refused. Without the row, an implementation that
  defaults an uninterpretable payload to form passes every other case. The
  string variant matters most: today's flattening treats any non-null value as
  a declaration of the capability.
- **the `{"telepathy":{}}` row.** A declaration of nothing but unrecognised keys
  filters to empty — and must **not** then pick up the `{}` default. The default
  belongs to a *syntactically* empty object, applied before unknown keys are
  dropped; applying it after would make an unknown-only declaration form-capable,
  which is the exact "absent stays absent" requirement inverted.

## Cases

The matrix is implemented table-driven: one component test iterating 28 rows,
each asserting relay or refusal against a declaration built through the
production parser. What follows are the cases the matrix cannot express.

| # | case | level | type | can it fail, and on what | evidence |
|---|---|---|---|---|---|
| 1 | the 28 matrix cells | component | table-driven | fails on any cell whose implementation disagrees with the table; the two `{"url":{}}` cells, the `{"telepathy":{}}` row and the non-object row fail against the natural minimal patch | 2 exist, 26 new |
| 2 | a result carrying **three** input requests — allowed, forbidden, allowed — refuses and names the middle one | component | ordering | every matrix cell carries one request, so an implementation that checks only the first or only the last entry passes all 28. A **middle** forbidden entry fails both of those, which is why one case covers what a first-last pair would; asserts *which* entry was named, not just that something was refused | new |
| 3 | a declaration of ten thousand capability keys and ten thousand mode keys parses to a value whose every field is a fixed enum or flag, and which contains **one** recognised capability and nothing else | unit, parse boundary | property | fails against today's `Vec<String>` and against any implementation that keeps a side vector of caller strings. Two assertions, because neither alone suffices: the parsed value's *contents* (a size assertion is true by the new type's definition and cannot fail), **and** a compile-time `size_of` check pinning the type as a heapless `Copy` bitset — that one fails the *build* if a later change adds a `Vec` or `String` field, which is the retained-allocation case a contents assertion cannot observe | new |
| 4 | declaration-side values that are **not** objects: `elicitation` set to `null`, a string, a number, an array; and the same four as a mode value under `elicitation` | unit, parse boundary | negative | fails if any is treated as a declaration. Only an object-valued key declares — a *populated* object is still a declaration, and this case asserts that `{"form":{"maxLength":40}}` declares form, so the rule cannot be implemented as "empty objects only" | new |
| 5 | request-side `params.mode` values that are not a recognised string: `null`, a number, an array, an object, and `"Form"` | unit, parse boundary | negative | fails if any is honoured as a mode. `"Form"` pins the exact-and-case-sensitive rule; the rest pin that the field is a string. Split from case 4 because the two sides take different types — objects declare, strings request — and one combined case asserted an object was malformed on both | new |
| 6 | the refusal carries code `-32021`, the existing `requiredCapabilities` field, **and** the mode detail under the design's named key `unsupportedElicitationMode`, observed after `error_response_preserving_status` | component | contract | fails today by construction: that conversion forwards exactly one key (`meta_mcp/mod.rs:179-200`), so mode detail written at `handlers.rs:790` is dropped before the client sees it. This is the review finding, and this case is what stops the design's answer from being written and silently discarded | new |
| 7 | the refusal message for a mode refusal does not claim the capability was undeclared | component | regression | fails against the existing message, which says *"client did not declare the 'elicitation' capability"* — false and misleading for a client that declared elicitation but not the mode | new |

Case 2 exists because the matrix's own shape hides an ordering bug: 28
single-request cells cannot distinguish "checks every entry" from "checks one".
An earlier draft carried a second ordering case with the forbidden entry last;
it was cut, because a forbidden *middle* entry already fails a first-only and a
last-only check alike.

## What is deliberately **not** tested

- `sampling/createMessage` and `roots/list` mode behaviour. Neither carries a
  mode substructure in this revision; a test would pin an invention rather than
  a requirement. Out of scope per the design's §P0.
- Any `DE-9a` continuation variant. Separate sub-decision, separate rows.
- Parse latency. Case 3 asserts the bound structurally, which is decidable; a
  timing assertion on the same path would be a flake, not a check.
- Whether an unrecognised *requested* mode is refused by the gate or by request
  validation. The matrix asserts it is refused; which layer refuses it is an
  implementation freedom this plan does not spend a case on.

## Level rationale

Cases 3, 4 and 5 are unit tests at the parse boundary because that is where the
property lives — a component test cannot distinguish "dropped at parse" from
"ignored at comparison", and those two implementations differ exactly where the
security argument is. Everything else is a component test, because the criterion
is about what the gateway *sends*, which is only observable at the relay.

Every mode value in the matrix arrives through the same parse the production
path uses. A fixture that reimplemented the normalization would fail the
`{"telepathy":{}}` row rather than hide it.
