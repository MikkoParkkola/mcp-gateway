# MIK-8499: HTTP intake copies a refused request body (design v3, for review before tests)

Status: design for gpt + agy review, round 2. Round 1 (gpt-20261020T012011Z-82698 SHIP-WITH-FIXES, agy-20261020T012012Z-83613 DO-NOT-SHIP) found a wrong attribution in v1. v3 corrects it. Base: origin/docs/ranking-1-release-line 7b555372b. Ticket: MIK-8499 (v4.0.0, Family http-intake-alloc).

## P1a: problem (INTAKE.1, Spark, per-thread allocation meter, the MIK-8412 bodies)

| stage | 1 MiB | 3 MiB | runs on the MIK-8412 fixture? |
|---|---|---|---|
| JSON parse (`serde_json::from_slice`) | 3,978,833 B | 12,054,369 B | yes |
| **meta-tool `_meta` merge (`merge_client_meta_ref`, insertion case)** | **3,170,272 B** | **9,499,376 B** | **yes** |
| protocol-field validation | 66 B | 66 B | yes |
| **input sanitizer (`sanitize_request`, Meta route)** | **8,981,467 B** | **27,051,067 B** | no (fixture sets `sanitize_input: false`; production default is true) |
| body read (`helpers::read_body`, 16 KiB stream chunks) | 1,058,895 B | to measure (the probe hit axum's 2 MB default limit; v3 raises it) | no (the fixture's body is one `Bytes`) |
| request firewall scan (`check_request`, default config) | 1,119,414 B | to measure | no (`firewall: None`) |

**Correction (round 1, both seats).** v1 attributed the ticket's 3.2 MB-per-MiB excess to the body read and the firewall, and neither runs on that fixture. The excess is the meta merge. The fixture's refused call is `gateway_invoke`, a meta tool, with `params._meta` set and no `_meta` in its arguments, so `merge_client_meta_ref` takes its insertion case and clones the whole argument tree (`helpers.rs:427`). Reconciled: plain refusal 7,197,148 B ≈ parse 3,978,833 + merge 3,170,272 B, with about 48 KB left.

In a default deployment (sanitizer on) a refused 1 MiB meta call therefore pays: parse ~4.0 MB, merge ~3.2 MB, sanitizer ~9.0 MB, plus the body read (~1.1 MB) and the firewall scan (~1.1 MB) outside the fixture. That is about 18 bytes per body byte.

## P1b: solution, in two PRs

**PR-A, the meta-merge clone (small, low risk).** Intake owns the request tree (`dispatch_intake_run.rs`, `let mut request`). After the sanitize step and `signing_context.restore`, intake asks the merge's own predicate (`client_meta_insert_required`) with the same inputs `tools_call` uses. When it holds, intake clones only `params._meta` (small) and moves it into `params.arguments` in place with `insert_client_meta`. `tools_call`'s `merge_client_meta_ref` then finds `_meta` present and returns a borrow, with no clone.

Readers of `params.arguments` between that point and the merge, checked:
- `dispatch_intake.rs:101` reads the tool name only;
- `dispatch_intake_run.rs:740` reads `server` and `tool` only;
- signing (`prepare_signing_for_call`, `dispatch_tools_call.rs:631`) already receives the merged view, so it gets the same value.

`client_meta_insert_required` is the single predicate, so the two sites cannot drift. The direct route is untouched (`is_meta_tool` is false there).

**PR-B, the sanitizer (larger; HIGH risk by placement: every entry point, a security control).**
- One production walker, as gpt asked: `sanitize_request_in_place(&mut Value, route) -> Result<()>`. A non-mutating `sanitize_request(&Value, route) -> Result<Value>` stays as a thin clone-then-walk wrapper for any caller that holds only a borrow (agy).
- Strings are checked first and rewritten in place with `String::retain` only when dirty (agy). A NUL is refused, as today. NFC stays the identity, as today.
- A map is rebuilt only when a key changes.
- `sanitize_arguments` stops cloning (`map.clone()`).
- `sanitize_slot` decodes a string-encoded slot straight from the string (`serde_json::from_str` through the gateway's decoder), with no `json!({"arguments": ..})` wrapper clone (agy). The decode, its -32602 refusal and the encoded-NUL refusal are unchanged.
- The four production callers (intake `dispatch_intake_run.rs:296`, `direct_caller.rs:593`, `task_service/host.rs:111`, `stdio_dispatch.rs:275`) own their request and switch to the in-place form. Each refuses the request on `Err`, so a partly rewritten value is never used.

## Tests (red first, per PR)

- PR-A: INTAKE.2(a). On the MIK-8412 fixture, a refused 1 and 3 MiB `gateway_invoke` call's total is at most parse plus a fixed cap, with no second payload term. Red today: 3.2 MB per MiB over parse. Control: the merged `_meta` reaches the meta tool exactly as before (the existing merge rows, plus a row that the delivered arguments are equal before and after).
- PR-B: INTAKE.2(b). The same bound with `sanitize_input: true`. Plus:
  - an equivalence corpus against the old sanitizer, kept verbatim in the test module as the reference: clean requests on every route and slot kind; dirty strings in every position and next to multi-byte text; key rewrites, including two keys that collide after stripping, with a NUL in the overwritten value (gpt); plain and encoded NULs in values, keys and chain steps; nested arrays; NFC, NFD, NFKC and NFKD forms plus combining marks; empty, non-object, 3 MiB and near-recursion-limit inputs;
  - planted bugs M1 (skip a dirty string), M2 (skip a key rewrite), M3 (strip a NUL instead of refusing it) and M4 (skip the slot decode), each caught by a named row.
- INTAKE.1 is completed in PR-B's probe: the body read and the firewall at 3 MiB, with the probe's body limit raised past axum's 2 MB default.

## INTAKE.2, re-proposed (the lead's earlier narrowing rested on v1's wrong numbers)

On the MIK-8412 router fixture (one-chunk body, firewall off), a refused 1 and 3 MiB `/mcp` call's total is at most parse plus a fixed, lead-ruled cap, with no second payload-proportional term, **with the sanitizer off (PR-A) and on (PR-B)**. Both PRs together meet the original wording on that fixture. Outside the fixture, and stated as not closed: the body read of a streamed upload (one buffer, inherent) and the request firewall scan (MIK-8535, v4.1.0).

## Questions for both seats

1. Does any caller depend on the old clone semantics: aliasing (reading the pre-sanitize value afterwards), key ordering, or reading a value left partly rewritten by an error? Answer per caller.
2. PR-A: does anything between the in-place `_meta` insertion and `tools_call` read `params.arguments` in a way that `_meta` being present would change (idempotency fingerprints, task storage, audit, the firewall's request scan, `intake_judgement`)?

## Impact analysis note

GitNexus could not resolve `sanitize_request` (stale index). The callers were found by search (`rg "sanitize_request\\("` and `rg "merge_client_meta_ref\\("` over `src`, outside tests). The brief says so.
