# MRTR.9a — test plan

Reviewed as a plan before any test code is written, per §P2. One row per thing the
criterion asserts; the rightmost column is what stops the row from being decorative.

**Criterion.** `MIK-7212.MRTR.9a` — never send an elicitation request in a *mode*
the client has not declared. Design: `2026-09-03-mrtr-9a-declared-modes.md`.

## Cases

| # | case | level | type | can it fail, and on what | evidence |
|---|---|---|---|---|---|
| 1 | a url-mode request to a form-only client is **refused** | component | negative | already RED at `tests/mik_7212_acs.rs:1759`, failing on its own criterion assertion — the free failure §P2 asks for | exists |
| 2 | a form-mode request to a form-only client is **relayed** | component | positive control | green today; it is what stops "refuse every elicitation" from satisfying case 1. A gate no client can pass is not a gate | exists |
| 3 | a url-mode request to a client declaring **both** modes is relayed | component | positive | fails if the gate refuses on the presence of a mode rather than on its absence from the declaration — the over-refusal case 2 alone cannot catch, because a form-only client has nothing to compare | new |
| 4 | a request with **no** `params.mode` to a form-only client is relayed | component | positive | fails on any implementation that treats absent as "declared nothing" and refuses. This is the finding the review raised; the design's answer is that absent means form on both sides | new |
| 5 | a client declaring `"elicitation": {}` accepts a form request and refuses a url one | component | boundary | two assertions on one fixture: fails if `{}` normalizes to *no modes* (first assertion) or to *all modes* (second). A single assertion here passes against one of the two wrong readings | new |
| 6 | an unrecognised mode key in a declaration is **dropped** — declaring `{"form":{},"telepathy":{}}` does not let a `telepathy` request through | unit, at the parse boundary | negative | fails if the parse retains caller strings. This is requirement 2 of the design applied one level down, and it is the case that would go unnoticed if only the comparison were tested | new |
| 7 | a declaration of ten thousand capability keys and ten thousand mode keys retains a **fixed** number of records | unit, at the parse boundary | property | fails against today's `Vec<String>`, which is caller-sized. Asserts on the parsed value's own size, not on memory or timing — a benchmark here would be a flake, not a check | new |
| 8 | the refusal carries code `-32021`, its existing `requiredCapabilities` field, and `error.data` naming the mode requested and the modes declared | component | contract | fails if the implementation mints a new code, which is what the design's DE-9 sub-decision rejected. Asserts the payload, so it also fails if `error.data` is absent | new |

No row is left without a case, and no case is listed whose fixture supplies the
answer it checks: every mode value in cases 1-6 arrives through the same parse the
production path uses, so a fixture that reimplemented the normalization would fail
case 6 rather than hide it.

## What is deliberately **not** tested

- `sampling/createMessage` and `roots/list` mode behaviour. Neither carries a mode
  substructure in this revision; a test would pin an invention rather than a
  requirement. Out of scope per the design's §P0.
- Any `DE-9a` continuation variant. Separate sub-decision, separate rows.
- Performance of the parse. The size bound is asserted structurally in case 7,
  which is decidable; a latency assertion on the same path would be neither.

## Level rationale

Cases 6 and 7 are unit tests at the parse boundary because that is where the
property lives — a component test cannot distinguish "dropped at parse" from
"ignored at comparison", and those two implementations differ exactly where the
security argument is. Everything else is a component test, because the criterion
is about what the gateway *sends*, which is only observable at the relay.
