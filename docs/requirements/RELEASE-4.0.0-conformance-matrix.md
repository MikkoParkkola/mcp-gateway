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
| **COVERED** | a committed test asserts this cell *on the production path* | test name plus `file:line` |
| **N/A** | the cell cannot exist, per Rule 2 | the code or spec line that makes it impossible |
| **UNCOVERED** | the cell exists and nothing asserts it | the test that would close it |

Collapsing UNCOVERED into N/A is the specific failure this table exists to
prevent: an N/A without a reason is a skipped criterion wearing a label, and an
N/A *with* a plausible-sounding reason that is really a missing test is worse,
because it reads as complete. The precedent is `RELEASE-4.0.0-test-plan.md:41`,
where the one N/A row carries the file and line that justify it.

**"On the production path" is a reviewer obligation, not an enforced one.** The
two executable checks work at *row* granularity: they read `evidence` and can
only tell an empty list from a non-empty one. Neither can tell a test that
drives the production path from one that asserts a value the test itself handed
in, and neither can see a statement whose clauses are unevenly covered. A row
with one well-pinned clause and one unpinned clause looks identical to a fully
pinned row. So a citation satisfying `matrix_has_no_empty_cells` is necessary
for COVERED and not sufficient; the clause-level reading is done by the reviewer
and recorded below the tally. Minor 1 is the case that established this — see
the clause-level line in the Tally.

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

### Statements with evidence — COVERED (21 of 21)

All nine major statements and minor 1-12 carry at least one evidence
reference, and every cited name resolves to a defined test. The cells, roles
and transports are in the source of truth rather than copied here, because a
copy drifts and the original is checked by CI: `tests/mik_7272_conformance.rs`,
`MAJOR` at `:52` and `MINOR` at `:175`.

### Statements without evidence — UNCOVERED (0 of 21)

None. `TRACKED_GAPS` in `tests/mik_7272_conformance.rs` is empty, which is the
enforced form of this sentence: an entry there whose row has regained evidence
fails `a_tracked_gap_is_still_a_gap`, so the list above cannot be emptied in
prose alone.

Minor 1 was the last entry, and it closed on 2026-09-15 with MIK-7272.EXT.1
phase 2. Its stated cause was wrong in the same way minor 11's was. The matrix
said the client half could not be asserted because
`ExtensionSet::from_capabilities` had no production caller — true of that
function, false of the obligation. `declares_tasks_extension` in
`src/gateway/router/handlers.rs` read the same `_meta` field through its own
hand-rolled `pointer()` parse and gated dispatch on it. So the client half was
not unreachable; it was reachable through a *second* parser that disagreed with
the first — it asked only whether the extension identifier was present, so
`{"io.modelcontextprotocol/tasks": 3}` negotiated the extension at the gate
while `from_capabilities` refused the same bytes. That second parser is now
deleted and the gate consumes `RequestShape::declared_extensions()`. One parser,
one answer. See `docs/design/MIK-7272-ext-1-client-extension-recovery.md`.

The lesson repeats minor 11's: a gap whose reason is "nothing reads this" is
a claim about a *symbol*, and the obligation is about a *field*. Searching for
readers of the field, not callers of the helper, is what found it — an external
reviewer did, after the reason had stood in two documents.

Minor 11 is the cell `NFR.CONFORMANCE.1` names as "modern URL-elicitation
completion removal", and minor 10's second clause was the one it names as
"arbitrary-JSON structured results" until two tests closed it. Both were
absent from the matrix as evidence, which is the finding: a matrix that omits a
statement, or cites a
test that does not bear on it, looks identical to one that covers it.

### Minor 11, closed — and the tracked gap's mechanism was wrong

Three tests now carry it, and the finding that came with them is that the gap
note named the wrong hop. It said the risk was the streaming multiplexer
tagging a backend notification and fanning it out "without inspecting the
method" (`src/gateway/streaming.rs:266`). No backend-supplied method reaches
that code. Every client-delivery site builds its frame with a literal method
string — `src/gateway/proxy.rs` at `:242`, `:307`, `:351`, `:381`, `:433`,
`:474` and `:494` — and `src/gateway/webhooks/mod.rs:420` broadcasts a
transformed payload that carries no JSON-RPC method at all. The one site whose
method comes from a caller is `ClientChannel::send_request`
(`src/gateway/proxy.rs:530`, `src/gateway/server/stdio_channel.rs:105`,
`src/gateway/input_bridge.rs:328`), and its only production caller is
`InputBridge::ask` (`src/gateway/input_bridge.rs:505`), which passes
`prompt.kind.method()` — a `const fn` over three variants.

So the statement holds on both clauses, and it holds by construction rather
than by a filter. That distinction is the reason the closing tests say so in
their own doc comments:

- (a), live path —
  `gateway::proxy::tests::ac_conformance_minor_11a_elicitation_id_is_dropped_on_both_forward_paths`.
  Both `forward_elicitation` and `forward_elicitation_with_response`
  re-serialise from `ElicitationCreateParams` (`src/protocol/messages.rs:513`),
  which names four fields and carries no `#[serde(flatten)]`. Neither path
  reads the client's era, so the field is dropped for a modern client *and* for
  a legacy one — stricter than the changelog asks, and not an era filter.
- (a), legacy half —
  `mik_7212_mrtr7_bridge_acs::ac_conformance_minor_11a_a_legacy_bridge_relay_retains_elicitation_id`.
  `InputBridge::prompt` clones `request["params"]` whole
  (`src/gateway/input_bridge.rs:473`), so a 2025-11-25 exchange is relayed
  unedited. This pins a library contract: `InputBridge` has no production
  construction site in `src/` as of this revision, though the caller context
  already carries a real channel (`src/gateway/router/handlers.rs:1588`,
  `channel: state.proxy_manager.as_ref()`).
- (b) —
  `mik_7212_mrtr7_bridge_acs::ac_conformance_minor_11b_elicitation_complete_is_refused_unsent`.
  The removed notification is refused as `Refusal::UnrecognisedMethod` and no
  frame leaves, under the most permissive declaration there is.

What remains is latent fragility rather than a defect: a `#[serde(flatten)]`
added to `ElicitationCreateParams` for pass-through fidelity would regain the
field on the live path, and the first test is what would notice.

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
prevent. The obligation it actually created is minor 11's second closing
test, `ac_conformance_minor_11b_elicitation_complete_is_refused_unsent`, now
written.

## Tally

| Disposition | Count |
|---|---|
| COVERED | 21 |
| UNCOVERED | 0 |
| **Population (statements)** | **21** |

UNCOVERED is empty, and so is `TRACKED_GAPS` in
`tests/mik_7272_conformance.rs`. That correspondence is enforced rather than
asserted here: `matrix_has_no_empty_cells` fails on an untracked empty row, and
`a_tracked_gap_is_still_a_gap` fails on an exemption whose row has since gained
evidence or disappeared. This document and the executable matrix cannot drift
apart on the count without one of those two tests going red.

21 + 0 = 21, and only changelog statements are counted. The four N/A rows above
are axis cells, not statements: they record why a role/transport combination
raises no obligation, so they neither add to the population nor absorb any
statement from it. Clause-level gaps (minor 11 has two) are recorded as
closing tests inside their statement's row rather than as rows of their own,
because a statement is the unit the changelog and the `Row` struct both use,
and mixing units is how a tally stops being checkable.

### Clause-level coverage — one clause open

The counts above are at statement granularity, which is the granularity the two
executable checks enforce. At clause granularity one clause is open:

| Statement | Clause | Disposition | Basis |
|---|---|---|---|
| minor 1 | client declares `extensions` | COVERED | `ac_ext_1_e6…` / `ac_ext_1_e7…` drive the real axum router to the live gate |
| minor 1 | server advertises `extensions` on `server/discover` | **UNCOVERED** | the only cited row, `ac_ext_1_a_the_builder_serializes_the_map_it_was_given`, asserts a map it is handed — see its own comment at `tests/mik_7272_conformance.rs:911-922`. Deleting `discovery_extensions()` (`src/gateway/meta_mcp_helpers.rs:181`) leaves every cited test green while modern `server/discover` stops advertising the extension. |

This is *not* the minor 11 situation. Minor 11 also records clause-level detail
in-row, but each of its clauses is closed by a production-path test
(`gateway::proxy::tests::…` for the forward paths, the `mrtr7_bridge` route rows
for the rest). Minor 1's server clause is closed by nothing. The distinction is
the whole reason Rule 3 now says "on the production path": in-row recording is a
formatting choice, not a licence to leave a clause unpinned.

Closing it takes one test asserting the tasks extension in the capabilities
returned by a real `server/discover` call.

## Grade

**NOT MET — PARTIAL.** Rule 4's population test passes: UNCOVERED is empty and
COVERED equals 21, at the statement granularity the executable checks enforce.
That is necessary and, as of this revision, no longer sufficient. Rule 3 requires
a COVERED cell to be asserted *on the production path*, and minor 1's server
clause is not — the grade survives deleting the mechanism it certifies, which is
the one thing a conformance grade must not do.

The mechanical rule is kept, not weakened: it still decides the statement tally
without judgement, and it still could not be gamed by relabelling. What changed
is that passing it is now the floor rather than the finish. The rule was fixed
before the last cell closed, and it is being applied against the document that
declared it — including when the answer is that the grade does not hold.

Remaining work: the `server/discover` test named at the end of the Tally. One
test closes the clause and returns this criterion to MET.

What the revisions delivered: the matrix, its population rule, the statement
that was missing from it, the count assertion that would have caught that, the
N/A reasons, the one N/A that turned out to be a gap, minor 10's row closed by
four mutation-tested tests, minor 11's three, and minor 1's client half — whose
closing found that the two remaining tracked gaps both had the wrong cause
recorded against them. The grade is about coverage of the changelog's
statements; it is not a claim that every extension behaves per-extension
correctly, which is MIK-7311's scope.
