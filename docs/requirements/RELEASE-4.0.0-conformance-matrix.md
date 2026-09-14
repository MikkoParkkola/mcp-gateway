<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# v4.0.0 protocol-conformance matrix

Closes `NFR.CONFORMANCE.1` (`docs/requirements/RELEASE-4.0.0-scope-update.md:54`):

> The complete applicable role/transport/revision/outcome matrix has evidence
> references, including modern URL-elicitation completion removal and
> arbitrary-JSON structured results; every N/A cell has a reason.

The acceptance wording (`RELEASE-4.0.0-scope-tests.md:68`) adds the checks this
document must satisfy: required cells enumerated, explicit N/A reasons, evidence
existence, modern completion-removal versus retained legacy behaviour, and
scalar/array/object structured results with `outputSchema` preservation.

## The rules, written before the cells were filled

A matrix whose disposition labels are chosen after the evidence arrives is not a
measurement of coverage, it is a defence of it. The four rules below were
committed before any cell was populated.

### Rule 1 — the axes come from an authority, not from judgement

| Axis | Authority | Why that authority |
|---|---|---|
| Role | the dispatcher and client entry points in `src/` | a role this binary does not implement cannot have a conformance obligation |
| Transport | `src/transport/` and `src/gateway/`, per role | a transport that carries no MCP for a role serves no cell for it |
| Revision | `docs/release/v4.0.0-supported-matrix.md` | the same table `NFR.BUILD.1` is graded against, so the two criteria cannot disagree on what this release claims to serve |
| Outcome | the result type the dispatcher returns | outcomes are what the code can produce, not what a reviewer can imagine |

### Rule 2 — one inapplicability test

A cell is **inapplicable** if and only if the feature does not exist at that
revision, **or** that transport does not carry that role. Every N/A is therefore
a derivation from a cited line, not a judgement call, and a reader can check it.

### Rule 3 — three dispositions, because a missing test is not an N/A

| Disposition | Means | Requires |
|---|---|---|
| **COVERED** | a committed test asserts this cell | test name plus `file:line` |
| **N/A** | the cell cannot exist, per Rule 2 | the code or spec line that makes it impossible |
| **UNCOVERED** | the cell exists and nothing asserts it | the test that would close it |

Collapsing UNCOVERED into N/A is the specific failure this table exists to
prevent: an N/A without a reason is a skipped criterion wearing a label, and an
N/A *with* a plausible-sounding reason that is really a missing test is worse,
because it reads as complete. The precedent is `RELEASE-4.0.0-test-plan.md:41`,
where the one N/A row carries the file and line that justify it.

### Rule 4 — the grade is mechanical

`NFR.CONFORMANCE.1` is **MET if and only if UNCOVERED is empty** and
COVERED equals the 21-statement population. The N/A cells are axis cells —
a role, a transport or a surface that carries no statement at all — so they
sit outside that sum and cannot be added to it. Any other state is PARTIAL,
and the UNCOVERED list is the remaining work. The rule is fixed here so that the grade
follows from the count rather than from how the count is described.

## Population

The matrix itself is executable and lives at `tests/mik_7272_conformance.rs`:
one `Row` per normative statement of the 2026-07-28 changelog, each carrying
its `requirement`, `role`, `transport` and `evidence`. That file asserts its own
completeness — `matrix_has_no_empty_cells` fails on a statement with no test,
`every_cited_test_exists` resolves each cited name against the source tree, and
`a_tracked_gap_is_still_a_gap` fails when a listed exemption has been filled or
deleted. This document is the reading of that matrix plus the two axes the
`Row` struct does not encode (revision and outcome) and the N/A reasons.

**Population = 21 statements**, counted from the changelog's own headings
(`https://modelcontextprotocol.io/specification/2026-07-28/changelog`, read
2026-09-13): 9 under `Major changes`, 12 under `Minor changes`. Its later
`Deprecated`, `Other schema changes`, `Governance` and `Process` sections are
not normative statements about this release's wire behaviour and are outside
the population by Rule 1.

Both counts are now asserted rather than eyeballed. `MAJOR.len() == 9` already
was; `MINOR.len() == 12` was not, and minor item 11 had been missing from the
list since the file was written. A statement nobody lists is verified by
nothing and fails nothing, so a count taken against the changelog is the only
instrument that can see it.

## Matrix

### Statements with evidence — COVERED (19 of 21)

All nine major statements and minor 2-10 and 12 carry at least one evidence
reference, and every cited name resolves to a defined test. The cells, roles
and transports are in the source of truth rather than copied here, because a
copy drifts and the original is checked by CI: `tests/mik_7272_conformance.rs`,
`MAJOR` at `:52` and `MINOR` at `:175`.

### Statements without evidence — UNCOVERED (2 of 21)

| # | Statement | Why it is uncovered | The test that closes it |
|---|---|---|---|
| Minor 1 | `extensions` field on client and server capabilities | Tracked gap; the work is scoped and unstarted | E1-E5 of `docs/design/2026-08-31-cluster-b-capability-and-trace-metadata-test-plan.md` |
| Minor 11 | Remove `notifications/elicitation/complete` and the `elicitationId` field of URL mode elicitation | The row did not exist until this revision. Neither name appears anywhere in `src` or `tests`, so the gateway originates neither — but absence is not an assertion, and two forwarding paths are unverified | Two. (a) A URL-mode elicitation from a 2025-11-25 backend carrying `elicitationId` reaches a modern client with the field removed, and a legacy client with it retained. (b) A `notifications/elicitation/complete` from a backend does not reach a modern client. The hop is the streaming multiplexer, which tags a backend notification and fans it out to the session's subscribers without inspecting the method (`src/gateway/streaming.rs:266`); the modern-path refusal at `src/gateway/router/handlers.rs:940` runs on inbound client requests and lists five other methods, so neither end filters this one today |

Minor 11 is the cell `NFR.CONFORMANCE.1` names as "modern URL-elicitation
completion removal", and minor 10's second clause was the one it names as
"arbitrary-JSON structured results" until two tests closed it. Both were
absent from the matrix as evidence, which is the finding: a matrix that omits a
statement, or cites a
test that does not bear on it, looks identical to one that covers it.

For minor 10 the behaviour was already present; the evidence was not.
`ToolsCallResult.structured_content` is `Option<Value>`
(`src/protocol/messages.rs:360`), `extract_output_validation_target` returns
whatever `structuredContent` holds (`src/gateway/meta_mcp/invoke.rs:194`), and
`apply_validated_output` writes it back without inspecting its JSON type
(`:207`); a schema mismatch is advisory for proxied tools and does not reject
(`:160-177`). Four tests close the row —
`capability::schema_validator::tests::ac_schema_10a_accepts_2020_12_keywords_absent_from_draft_07`
(clause a),
`gateway::meta_mcp::invoke::response_transform_tests::ac_schema_10b_scalar_structured_content_survives_enforce_output_schema`
and `ac_schema_10b_bare_array_structured_content_survives_enforce_output_schema`
(clause b), and
`gateway::meta_mcp::tests::ac_schema_10c_declared_output_schema_is_byte_identical_on_the_wire`
(clause c) — each confirmed by breaking the mechanism it depends on and
watching the test fail before being restored.

## Revision and outcome axes

The `Row` struct encodes role and transport. The other two axes the criterion
names are properties of the statements rather than of the rows, and they
resolve as follows.

**Revision.** Authority: `docs/release/v4.0.0-supported-matrix.md`. Two paths,
not five columns. `2026-07-28` is served on the modern stateless path;
`2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05` are negotiated on the
legacy path. Every statement in this matrix is a 2026-07-28 statement — that is
what the changelog is — so the revision axis has exactly two applicable values
per statement: **does the modern path obey it**, and **does the legacy path
retain the prior behaviour**. Nine statements are removals or replacements where
both halves matter; the removed-method gate names five of them explicitly
(`REMOVED_IN_2026_07_28`, `src/protocol/meta.rs:253`) and is tested on both
sides by major row 5. The rest are additions, where the legacy half is "absent"
and carries no obligation.

**Outcome.** Three values, from what the dispatcher can return: a result with
`resultType: "complete"`, a result with `resultType: "input_required"`, and a
JSON-RPC error. All three are covered as statements in their own right — major
8 for the field and its legacy-omission default, major 7 for the interim
result, minor 6 and 12 for error-code placement and renumbering — so the
outcome axis is not a separate grid of cells but a set of statements already
inside the population. Treating it as its own grid would multiply rows without
adding a single new obligation.

## Inapplicable cells — N/A with reason

Each row derives from Rule 2: the feature does not exist at that revision, or
that transport does not carry that role.

| Cell | Reason | Citation |
|---|---|---|
| A2A × server (inbound peer) | The A2A adapter is outbound only — it calls other agents and exposes no inbound peer route, so no statement about serving A2A can apply | `src/a2a/client.rs:47`; no `/a2a` route in `src/gateway/router/` |
| WebSocket × server | The gateway does bind a WebSocket listener, and it carries no protocol: `run_websocket_listener` upgrades each connection and echoes text frames back as a loopback, serving no MCP, no backends and no credentials. `WebSocketTransport` is the outbound client half. A transport that answers no method cannot satisfy or fail a statement about one | `src/gateway/ws_listener.rs:14`; `src/transport/websocket.rs:500` |
| Legacy HTTP+SSE `/sse` × every statement | Reclassified by this same changelog and served here only as a deprecation stub that returns an error, so it carries no conformance obligation | `src/gateway/router/handlers.rs:454` |
| `outputSchema` emission on the Meta-MCP discovery surface | `gateway_list_tools` and `gateway_search_tools` emit name and description only, by the locked compact-surface decision; a field never emitted cannot fail to be preserved. Preservation applies on the direct passthrough `tools/list` path, and is claimed there — see minor 10, test (c) | `src/gateway/meta_mcp/search.rs:664`; `src/gateway/router/backend_handlers.rs:161` |

`completion/complete` was a candidate for this table and does not belong in it.
The method string appears nowhere in `src`, which makes it tempting to call the
gateway "not a completions server" and the cell inapplicable. But the
per-backend passthrough route forwards any method it is handed —
`backend.request(&method, params)` at
`src/gateway/router/backend_handlers.rs:829`, with `notifications/*` forwarded
at `:541` — so the gateway carries whatever a caller sends, including methods
it does not implement. An N/A resting on a missing string literal would have
been a missing test wearing a label, which is the one thing Rule 3 exists to
prevent. The obligation it actually creates is minor 11's second closing test.

## Tally

| Disposition | Count |
|---|---|
| COVERED | 19 |
| UNCOVERED | 2 |
| **Population (statements)** | **21** |

The two UNCOVERED statements are the two entries of `TRACKED_GAPS` in
`tests/mik_7272_conformance.rs`, and that is enforced rather than asserted
here: `matrix_has_no_empty_cells` fails on an untracked empty row, and
`a_tracked_gap_is_still_a_gap` fails on an exemption whose row has since gained
evidence or disappeared. This document and the executable matrix cannot drift
apart on the count without one of those two tests going red.

19 + 2 = 21, and only changelog statements are counted. The four N/A rows above
are axis cells, not statements: they record why a role/transport combination
raises no obligation, so they neither add to the population nor absorb any
statement from it. Clause-level gaps (minor 11 has two) are recorded as
closing tests inside their statement's row rather than as rows of their own,
because a statement is the unit the changelog and the `Row` struct both use,
and mixing units is how a tally stops being checkable.

## Grade

**PARTIAL.** Rule 4 makes this mechanical: UNCOVERED is not empty, so the
criterion is not met, and the named tests behind those two statements are the
remaining work. What this revision delivered is the matrix, its population
rule, the missing statement, the count assertion that would have caught it, the
N/A reasons, the one N/A that turned out to be a gap, and minor 10's row closed
by four mutation-tested tests — which is the bulk of the criterion and the
part that makes the remainder checkable.
