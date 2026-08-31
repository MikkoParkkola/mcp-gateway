# Cluster G — tool schemas must be valid under JSON Schema 2020-12

Criterion: **MIK-6865.SCHEMA.1** — every tool schema the gateway publishes MUST be a valid
JSON Schema document under the 2020-12 dialect.

Anchor commit: **`112a392c`**. Every file:line below was read at that commit, via
`git show 112a392c:src/capability/loader.rs` and equivalents, including files left dirty in the
working tree by a concurrent session. No citation mixes revisions.

Revision anchor: **`149e553a`** for the Seam-3 citations added when backend schemas came into
scope. `src/backend/metadata.rs`, `src/backend/registry.rs` and `src/backend/ops.rs` are byte-identical
between the two commits (`git diff 112a392c HEAD -- <path>` empty, working tree clean); the two
`src/gateway/meta_mcp/` files moved, so every line number cited from them was re-read at
`149e553a`. No citation mixes revisions.

**This change now addresses SCHEMA.1 in full, and it did not start that way.** The criterion
covers *every* tool schema the gateway publishes, and a proxied backend tool is published on the
gateway surface. The first draft covered only the two populations the gateway itself authors — the
19 compile-time meta-tool definitions and the capability YAML the loader reads — and left
backend-supplied schemas out, because what to do with an invalid backend schema is a policy
question (reject the tool? publish and flag? degrade it?) rather than a validity one. The owner
has since answered that question, so the exclusion is withdrawn (§P0 receipt, U6, Dispositions)
and the third population is in scope. **Three populations, three seams.** A stated limit against a
MUST is an unmet requirement; the history is kept here so the closure comment cannot quietly
inherit the old partial framing.

**The check has now been run, and the remainder survives it.** SCHEMA.1 is split across two rows
in `docs/requirements/RELEASE-4.0.0-criteria-status.md:101-102`, quoted verbatim so the next
reader does not re-derive this:

| row | criterion text | status | evidence |
|---|---|---|---|
| `:101` | "tool schemas MUST avoid nested-object-in-array shapes" | MET | `tests/mik_7272_exploit_acs.rs:323,343,365` via real `MetaMcp::handle_tools_list` |
| `:102` | "tool schemas MUST remain valid under JSON Schema 2020-12" | UNTESTED | — this design |

"Tool schemas" is **unqualified in both rows**. Nothing scopes it to gateway-authored schemas, so
the hoped-for escape is not in the text. The sibling clause settles it the other way: its evidence
runs through `MetaMcp::handle_tools_list`, and that entry point publishes proxied backend tools on
the same surface — `handle_tools_list_for_session` appends `self.surfaced_tools` and tags each
`backend:{server}` or `capability:{server}` (`src/gateway/meta_mcp/mod.rs:1131` for the entry point
and `:1157,:1159` for the tags, re-read at `149e553a`; the same code sat at `:1133-1141` at
`112a392c`). The population the MET clause was measured against therefore *includes* backend
schemas, and the UNTESTED clause inherited it too. **This paragraph is what put the question to the
owner** — it is the evidence that the exclusion could not stand, and the ruling that followed is
what closed the remainder.

## §P0 Scope

**FOR:** meta-validating the schema *documents* the gateway publishes on its own MCP
surface — `Tool.inputSchema` and `Tool.outputSchema` — against the JSON Schema 2020-12
meta-schema, at the point where an invalid document can still be rejected cheaply. Three
populations reach that surface and each gets its own seam: the 19 compile-time meta-tool defs
(seam 1), the capability YAML the loader reads (seam 2), and the tools an upstream MCP backend
returns from `tools/list` (seam 3). A backend tool that fails is dropped from the catalogue and
is not routable; the rest of the backend is unaffected.

**OUT:**

| out of scope | why |
|---|---|
| ~~schemas supplied by upstream MCP **backends** and proxied through~~ | **withdrawn 2026-08-31 — moved into scope.** The owner settled the routing policy: a backend tool whose schema fails 2020-12 validation is dropped from the catalogue and the rest of the backend stays. See the receipt below and the Dispositions row. |
| validating tool *arguments* against a schema | already exists — `src/capability/schema_validator/mod.rs`. Opposite direction, see Problem. |
| semantic quality of a schema, i.e. is it a *good* schema | 2020-12 admits keywords it does not define; the criterion is "valid", not "well-designed". |
| A2A and trust-descriptor payload shape beyond the embedded `inputSchema` | descriptor structure is its own contract. |

## Problem

Two things are easy to confuse, and only one of them exists in the repo.

- **Instance validation** — does this *argument object* satisfy this schema? Implemented at
  `src/capability/schema_validator/mod.rs:117` (`validate_arguments`) and
  `src/capability/schema_validator/mod.rs:252` (`validate_output`), over a documented bounded
  subset: required params, rejection of params the schema does not declare, type with coercion,
  enum, minLength, maxLength, minimum, maximum. Re-exported at `src/capability/mod.rs:69`,
  consumed at `src/capability/backend.rs:30`.
- **Meta-validation** — is this *schema document itself* a legal JSON Schema? **Nothing in the
  repo does this.** SCHEMA.1 asks for exactly this.

The existing validator is therefore neither coverage for SCHEMA.1 nor superseded by it. A
reviewer who sees `schema_validator` and marks the criterion met has read the wrong direction.

Consequence today: a capability YAML whose `schema.input` is malformed — a `required` that is a
string instead of an array, a `type` that is a number, a `properties` that is a list — loads
without complaint, is published in `tools/list`, and fails, if at all, inside a client own
schema handling at invoke time, with no gateway-side attribution.

## Measured constraints

Each row is a command run in this session at `112a392c`.

| fact | evidence |
|---|---|
| No JSON-Schema validator crate is in the dependency graph, at any feature set, on any edge kind, across the whole workspace | `cargo tree --workspace --all-features` -> 827 lines (positive control: output exists); piped to `rg -i` for jsonschema, boon, valico, schemars -> empty; piped to `rg -c gateway-core` -> 1, proving the workspace member is in scope |
| Feature flags were genuinely honored | `cargo tree --no-default-features --edges normal` -> 705 lines vs `--all-features --edges normal` -> 739. Two identical counts would have proven nothing. |
| No schema dep in either manifest | `rg -n schema Cargo.toml` -> no match; the same search over `crates/gateway-core/Cargo.toml`, widened to valico and boon -> no match |
| **No published schema declares a dialect** | searching src/ and capabilities/ for `2020-12`, `draft-07` and `$schema` -> only `src/validator/sarif.rs:19` and `src/validator/sarif.rs:366`, a serde field rename on SARIF output. Zero tool schemas carry `$schema`. |
| **A malformed schema survives YAML deserialization** | `SchemaDefinition.input` and `.output` are untyped `serde_json::Value` (`src/capability/definition/mod.rs:216-224`). Serde imposes no shape, so a fixture like `required: "name"` reaches the validator instead of dying at parse time — which is what makes G1 an executable case rather than one that passes for the wrong reason. |
| Gateway own meta tools: 19 schemas, compile-time literals | `src/gateway/meta_mcp_tool_defs.rs` — 19 `gateway_*` defs, each an `input_schema: json!` literal at lines 37, 55, 79, 111, 137, 184, 211, 243, 299, 326, 353, 379 and onward |
| Capability schemas are runtime data | `src/capability/definition/mod.rs:1015` — `input_schema: self.schema.input.clone()`, straight from YAML |
| Capability YAML is loaded from a runtime directory, not a repo path | `load_from_directory(dir)` called on the capability backend at `src/gateway/server/mod.rs:873` and `src/gateway/server/mod.rs:1515` with a configured directory; `src/capability/loader.rs:46` recurses it |
| OpenAPI-generated capabilities land in that same directory | `src/gateway/ui/import.rs:172` — `cap.write_to_file(&output_dir)`; the schema is built at `src/capability/openapi/convert.rs:370` by `build_input_schema`. Generated schemas re-enter through the loader, so a loader-level check covers the generator too. |
| Publication surface | `src/protocol/types.rs:10` through `src/protocol/types.rs:40` — `Tool` carries `inputSchema: Value` and `outputSchema: Option<Value>` beside name, title, description, annotations, role, projection; also embedded at `src/trust/descriptor.rs:80` |

Three populations, three risk profiles: **19 constants** that change only when someone edits Rust;
**110+ capability schemas** that arrive from a directory the operator controls; and **backend tool
schemas**, which arrive over the wire from software nobody here controls, can change between two
fetches of the same backend, and are the only population where the gateway is not the author of the
document it publishes.

## Load-time precedent — this is not an open question

`src/capability/loader.rs:111` through `src/capability/loader.rs:155` already runs a structural
validator and already decides what an error means:

> "Structural errors cause the capability to be skipped (this function returns `Err`); structural
> warnings are logged but the capability is still loaded."

`let has_errors = issues.iter().any(|i| i.severity == IssueSeverity::Error);` then
`Err(Error::Config("Capability {} has {} structural error(s); skipping"))`.

The validator is `validate_capability_definition` at `src/capability/validator/mod.rs:137`,
issuing `CAP-` prefixed codes at severity Error or Warning, also called from
`src/gateway/ui/capabilities.rs:558`.

The "where does it fire, and what happens when it fails" fork is therefore **already answered by
the repo**: per-capability, fail-closed, gateway still starts. A malformed schema costs one
capability, never the process. This design follows that precedent and invents no new
startup-abort path.

## Options

| option | what it is | verdict |
|---|---|---|
| **A. `jsonschema` 0.52.1** | Publisher metadata: `newest 0.52.1`, 85,161,067 downloads, license MIT, not yanked. Its own docs at docs.rs expose a dedicated `meta` module with `validate`, `validate_for`, `is_valid`, `is_valid_for`, `validator_for`, `options`. Dialect coverage counted from the same docs page: draft 2020-12 present alongside 2019-09, draft-07. | **RECOMMENDED.** The `meta` module is the discriminator: meta-validation is the shipped operation, not something reconstructed from the instance API. MIT matches the MIT core. |
| **B. `boon` 0.6.1** | Publisher metadata: 462,520 downloads, license MIT OR Apache-2.0, not yanked, description names "JSONSchema (draft 2020-12, draft 2019-09, draft-7, draft-6, draft-4) Validation" — the most explicit 2020-12 claim of the two. Smaller dependency tree. | **Fallback, not rejected on merit.** Kept live for U2: if the `jsonschema` transitive count breaches D27, boon is the answer. Rejected as first choice only because no dedicated meta-validation entry point has been evidenced from its own docs (U3). |
| **C. Hand-rolled meta-validator** | A bounded subset check over the schema document, in the style of the existing instance validator. | **REJECTED by the criterion.** The repo already contains one bounded hand-rolled validator, `src/capability/schema_validator/mod.rs`, and its existence is exactly why SCHEMA.1 is still open: a bounded subset of a specification is not the specification. "Valid under 2020-12" is a claim about a dialect, and only something implementing that dialect can make it. |
| **D. CI-only lint over `capabilities/*.yaml`** | Check the repo copies at build time; nothing at runtime. | **REJECTED on the measured population.** Capability YAML is loaded from a configured directory at `src/gateway/server/mod.rs:873`, and the OpenAPI import writes freshly generated YAML into it at `src/gateway/ui/import.rs:172`. CI cannot see either. A check that cannot observe the inputs silently passes. |

### Dialect pinning is part of the decision, not an implementation detail

No published tool schema carries `$schema` (measured above). A meta-validation entry point that
**infers** the dialect from `$schema` would therefore fall back to a default, and a document that
did declare `draft-07` would be validated as draft-07 and pass. That is not the criterion.
SCHEMA.1 says 2020-12, so the assertion must be against 2020-12 regardless of what the document
nominates.

**The obvious spelling of that is wrong, which is why it is here and not left to the
implementer.** Every free function in `jsonschema`'s `meta` module — `validate`, `validate_for`,
`is_valid`, `is_valid_for`, `validator_for` — documents "Draft version is detected
automatically", and `_for` denotes a *foreign representation* (`pub fn validate_for<F: …>`), not
a draft argument. None of them pins a dialect.

The first spelling of the pin written here was `jsonschema::meta::options().with_draft(...)`,
sourced from docs.rs alone, and it is **wrong** — a reviewer said so and the crate source settles
it. `jsonschema::meta::options()` returns `MetaSchemaOptions`, which has exactly three methods:
`with_registry`, `is_valid`, `validate` (`jsonschema-0.52.1/src/lib.rs:1863,1874,1886`). `with_draft`
lives on `ValidationOptions`, the *instance*-validation builder (`src/options.rs:156`), and cannot be
reached from the meta path. The dialect is pinned by the module, not by an argument:
**`jsonschema::draft202012::meta::validator()`** (`src/lib.rs:3178` for the draft module, `:3281` for
its `meta`), which yields a `MetaValidator<'static>`; `draft202012::meta::is_valid` is the boolean
form. Source is now the vendored crate under `~/.cargo/registry`, read 2026-08-31 — V, not I.

Signature existence is not the claim this section needs, so the body was read too. Two facts, both
load-bearing. `validator()` is `crate::meta::validator_for_draft(super::Draft::Draft202012)`
(`src/lib.rs:3288`): the dialect is a constant argument, not a dispatch on the document's `$schema`,
which is exactly the property G4 tests and the reason `meta::is_valid` is the wrong call. And
`MetaValidator` exposes both `is_valid -> bool` (`src/lib.rs:1948`) and
`validate -> Result<(), ValidationError>` (`:1961`), so the half of the ruling that requires naming
*which* keyword failed — the `CAP-` code at seam 2, the `warn!` at seam 3 — has a call that returns
the error rather than a bare boolean.
An implementer reaching for `meta::is_valid` would have shipped auto-detection, and G4 is the case
that would have caught it. Worth recording that the doc flagged this call as single-sourced and
unverified, and it was the one thing in the design that did not compile.

## Enforcement — three seams, matching the three populations

**Seam 1: the 19 compile-time defs — a unit test.**
`src/gateway/meta_mcp_tool_defs.rs` holds `json!` literals. A load-time check over constants
burns startup cost on values that cannot vary between builds. The test iterates every published
`gateway_*` def and asserts its `inputSchema` — and `outputSchema` where present — meta-validates
against 2020-12.

**Seam 2: the 110+ capability schemas — a new Error-severity issue in the existing validator.**
Add a `CAP-` prefixed code to `validate_capability_definition`
(`src/capability/validator/mod.rs:137`) reporting a schema document that fails meta-validation, at
severity Error. Nothing else changes: `src/capability/loader.rs:111` already turns any Error into
a skip, and `src/gateway/ui/capabilities.rs:558` already surfaces issues in the UI.

Stated plainly, because it is the operational consequence a reviewer should weigh: **on a
previously running deployment, a capability whose schema is invalid stops being served.** It is
skipped, logged, and the gateway starts. This is the behaviour the repo already has for every
other structural error, and diverging from it here would be the surprising choice.

**Seam 3: the tools a backend returns — a second predicate in the filter that already exists.**
`src/backend/annotations.rs:126` already drops individual tools from a backend list on a
schema-shaped defect: `exclude_invalid_header_tools` runs `tools.retain(...)`, logs
`warn!(server, tool, reason, "Excluding tool from tools/list: ...")` for each drop, and leaves the
rest of the backend alone. Seam 3 is a second `retain` predicate beside it, meta-validating
`inputSchema` — and `outputSchema` where present — inside the same
`prepare_tool_metadata(server, tools)` entry point (`src/backend/annotations.rs:152`).

That entry point is load-bearing and its own doc comment says why: it exists because exclusion
once reached the direct-passthrough response only, so an invalid tool stayed visible through
`Backend::get_tools_shared`. Both callers now go through it, and adding seam 3 anywhere else would
reintroduce the exact divergence that comment records. `get_tools_shared`
(`src/backend/metadata.rs:136-143`) calls it on the fetch path, inside `get_or_fetch_shared`, so on
*that* path the check runs once per cache fill, and every aggregate reader — `tools/list`, search,
surfaced tools — sees the filtered list.

**The second caller is not on the cache path and the first version of this section said it was.**
`src/gateway/router/backend_handlers.rs:196` calls `prepare_tool_metadata` inline while normalizing
a direct `tools/list` response, so on the direct route the check runs **once per request**, not once
per cache fill. That is a cost claim, corrected under Cost, not a correctness problem.

**One class of tool never reaches the seam at all.** The same normalizer parses the backend's list
element by element (`backend_handlers.rs:184-193`); an element that fails `serde_json::from_value::<Tool>`
is pushed to `unparsed` and re-appended after filtering, deliberately, because dropping it would hide
a tool a client may already depend on. Seam 3 sits inside `prepare_tool_metadata` and therefore never
sees those elements. They are published unvalidated. This is a **narrow, named residual**: an element
the `Tool` shape cannot accept is not a tool with a bad schema, it is a descriptor the gateway could
not read — but SCHEMA.1 says *every schema the gateway publishes*, and this route publishes one. The
disposal is in the Dispositions table; it is not silently accepted.

### Dropping the tool from the list is not enough to make it unroutable

`gateway_invoke` deliberately dispatches names it cannot find in the cache
(`src/gateway/meta_mcp/invoke.rs:1934-1938`, verbatim):

> "Eagerly check the cached tool list for a 'did you mean?' hint. Only fires when the cache is
> populated and the tool is not found there. **We still dispatch to the backend in case the cache
> is stale.**"

A tool filtered out of the cache is therefore indistinguishable from a tool the cache has not heard
of yet, and stale-cache tolerance would route straight to it. The owner's ruling — "do not list
**and do not route**" — needs the second half built, and it needs the gateway to remember *why* a
name is missing.

**Mechanism: a per-backend rejected-set, written at the same moment as the filter.** The retain
predicate records `{tool name -> meta-validation error}` for each drop into a slot beside
`tools_cache` on `Backend`, replaced wholesale on every fetch. The refusal is then consulted before
dispatch: a name in the rejected set is refused by the gateway with an error naming the tool, the
backend and the validation failure, and nothing goes upstream. A name that is simply unknown keeps
today's stale-cache behaviour untouched — the refusal is narrow, and it is the only thing that makes
the "not routable" half of the ruling true.

**Consulted where, exactly — the first version of this design got this wrong and a reviewer caught
it.** It named `gateway_invoke` alone. `gateway_invoke` is not the only production route to a
backend tool: a client speaking MCP directly to the per-backend endpoint reaches
`src/gateway/router/backend_handlers.rs:747-809`, which forwards `tools/call` to the backend after
the security pass and never touches the meta-MCP layer. Gating only the funnel would have left the
dropped tool callable on the route most likely to be used by a client that had already listed it.

The check therefore belongs where **both** routes converge, not in either caller:
`Backend::request_with_headers` (`src/backend/ops.rs:151-165`) is on the path for the direct route,
the meta-MCP funnel and `McpProvider` (`src/provider/mcp_provider.rs:62`) alike. A `tools/call`
whose tool name is in the backend rejected set is refused there.

One clause carries that claim and is worth stating rather than assuming, because getting it wrong
would rebuild the same defect one layer down: the direct route picks between **two** methods —
`backend.request(...)` when no headers are propagated and no identity key is set, and
`request_with_headers(...)` otherwise. `request` is a two-line delegation to `request_with_headers`
(`src/backend/ops.rs:46-48`), so both branches reach the gate. Had it been a parallel
implementation, the refusal would have had to sit wherever the two converge instead, and a gate on
`request_with_headers` alone would have left the header-free call path open. Choosing the shared chokepoint
over the two call sites is the same reasoning the `prepare_tool_metadata` doc comment records for
the listing half — the divergence it was created to end is exactly what a per-caller gate would
recreate.

Set semantics fall out of the cache it shadows: replaced on every fill, so a backend that corrects
its schema is served again at the next TTL expiry with no operator action, and no separate
invalidation path is invented.

**Two properties the gate inherits, both named rather than assumed away.** The confirmation review
raised each as a defect; both are real and neither is created here.

*The rejected set is as identity-scoped as the list it derives from, which is not at all.* The
reviewer's reading is that one caller's `tools/list` response would then control routing for every
identity-partitioned session on that backend. Checked at source: `tools_cache` is a single
`CachedMetadata<Vec<Tool>>` per `Backend` (`src/backend/mod.rs:54`) and `src/backend/metadata.rs`
contains zero references to identity — the identity key selects a connection `PoolKey`
(`src/backend/ops.rs:178`), never a cache. So the tool catalogue is *already* shared across
identities, and the rejected set shadowing it inherits exactly that scope. The proposed repair —
key rejection by the identity pool key — would key a derived set finer than the data it is derived
from, which cannot be built: there is no per-identity list to reject from. The honest statement is
that identity-scoped rejection becomes meaningful only if `tools_cache` itself becomes
identity-partitioned, and that is a change to the cache, not to this gate. **Owner ruling: out of
scope, and filed.** The finding is right about the property and wrong about whose change it is —
the shared tool catalogue is a pre-existing decision with its own blast radius (pool interaction,
invalidation, memory), which is human-sized rather than a review round. Inherited residual, carried
with the three citations above; the decision itself is [MIK-7334](https://linear.app/parm/issue/MIK-7334).

*The gate is a deny-list, not an allow-list, and before a backend's first successful list every tool
is unchecked.* A `tools/call` arriving in that window routes. That is not an oversight introduced by
this design: `src/gateway/meta_mcp/invoke.rs:1934-1938` dispatches names missing from the cache
deliberately, to tolerate a stale cache, and this design's stated rule is that an unknown name keeps
that behaviour untouched. Converting to an allow-list — refuse until a validated list exists — would
change stale-cache tolerance for every deployment, which is a second owner decision of the same
shape as the one that produced this ruling, not a repair the design can make on its own authority.
**Owner ruling: keep the deny-list, and do not touch stale-cache tolerance.** SCHEMA.1 binds on
*exposure*; a tool the gateway has never listed has never been exposed, so the pre-first-list window
sits outside the criterion's population rather than being a hole in it. An allow-list would change
dispatch for every deployment in order to close a window in which the gateway holds no knowledge to
refuse on. Recorded plainly, like the unparsed-element residual: **the refusal is authoritative for
every tool the gateway has listed, and silent for one it has not.**

**One interaction to get right:** `invalidate_tools_cache` (`src/backend/metadata.rs:39-46`)
discards an *empty* tool list so warm-start re-asks a backend that answered with nothing. A backend
whose every tool is rejected now also caches an empty list, so warm-start would re-fetch it on every
attempt and get the same answer each time. The guard is one condition: discard the empty list only
when the rejected set is *also* empty. Empty-because-rejected is a fact the gateway has already
established, not a fetch worth repeating.

### outputSchema — inside the criterion, not a widening of it

This design read the criterion's naming of `inputSchema` as a boundary and recorded the decision to
validate `outputSchema` too as a widening, for the owner to confirm or narrow. **Owner ruling: it
was never a widening.** The criterion's population is *"tool schemas exposed by the gateway"*, and a
published `Tool` carries both fields (`src/protocol/types.rs:10-40`) on one surface, so both are
bound by it. `inputSchema` is named because that is where the key-invention failure was found, not
to draw a line around it.

Seam 3 validating both — `outputSchema` only when present — is therefore correct as specified, and
there is no narrowing fallback to hold open. U7 stops being a pre-merge decision and becomes a
**confirmation**: check that the predicate reads both fields, and that a backend publishing a valid
`inputSchema` beside an invalid `outputSchema` is dropped rather than published. That second half is
test case G11; the first is a read of the predicate. No scope receipt is owed, because nothing
moved.

### Log and diagnostics

Per rejected tool, one `warn!` at the drop, carrying backend name, tool name and the meta-validation
error — beside the existing header-exclusion warning, at the same severity. **Once per cache fill on
the shared path only.** This paragraph said "rather than once per request" flatly and the
confirmation review was right that the repair had not reached it: the direct `tools/list` route runs
`prepare_tool_metadata` per request (`backend_handlers.rs:196`), so on that route a polling client
re-emits every rejection warning on every poll. The `warn!` therefore fires when a tool **enters**
the rejected set or its error changes, not on every evaluation — the set is already the state needed
to tell those apart, so this costs a comparison, not a mechanism. Without it a single misbehaving
backend plus one polling client is an operator-log flood, which is how a useful warning gets muted. For the operator-visible half, `BackendStatus`
(`src/backend/registry.rs:63`, built at `src/backend/ops.rs:474-489`) gains a rejected count
alongside `tools_cached`. **Adding the field does not surface it** — a claim the first version of
this section made and a reviewer disproved. Only the admin health JSON serde-serializes
`BackendStatus` whole (`src/gateway/router/handlers.rs:428`); every other reader copies selected
fields, so each one has to grow a line: `gateway_list_servers` builds its object field by field with
`"tools_count": status.tools_cached` (`src/gateway/meta_mcp/surfaced.rs:184`), and the UI does the
same at `src/gateway/ui/mod.rs:146,162,539,551,791`. Naming those sites is the difference between a
design that ships the diagnostic and one that ships a field nobody can see. Without a distinct field the
operator sees only a smaller `tools_cached` and cannot tell rejection from a backend that genuinely
has fewer tools — which is the difference between a gateway working as designed and a backend that
has broken.

No new subsystem, no new module, no new startup path — seam 3 reuses the filter, the warning shape
and the status struct that are already there.

## Cost

Load-time meta-validation runs once per capability at load, against a validator compiled once and
reused. The measurement, not an adjective: time `CapabilityLoader::load_from_directory` over the
110+ capability directory, before and after, same machine, same directory, median of five runs.
Budget is §10 as written — P50 within +5%. If it breaches, the fallback is stated in U4.

Seam 3 costs one meta-validation per backend tool per cache fill **on the shared path**, because
there it sits inside `get_or_fetch_shared`. It is **not** per-cache-fill everywhere: the direct
`tools/list` route calls `prepare_tool_metadata` inline per request
(`src/gateway/router/backend_handlers.rs:196`), so a client polling that route pays one
meta-validation per tool per poll. The first version of this section claimed "not per request" flatly
and was wrong. Two consequences, both real: the direct route needs its own measurement, which is U8b — U8
times `gateway_invoke` and never enters this route, so widening U8's wording would have left the
regression unmeasured; and if that measurement breaches the §10 budget, the answer is to hoist the direct route onto
the cached list rather than to weaken the check.

The per-request cost the design does add everywhere is the rejected-set lookup on the call path
(`src/backend/ops.rs:151-165`), a map probe against a set that is empty for every healthy backend —
measured under U8 rather than asserted, since "it is only a map lookup" is exactly the shape of claim
that turns out to be on a hot path.

## Dependency gates

- **D30 supply chain:** `cargo audit` at merge; `Cargo.lock` hashes pinned; a HIGH advisory on
  the new dependency or anything it pulls blocks the merge.
- **Licensing:** `jsonschema` is MIT, matching the MIT core. `boon` is MIT OR Apache-2.0. Neither
  touches the PolyForm EE surface.
- **D27 coupling:** **resolved 2026-08-31, option A confirmed.** Spike at
  `/private/tmp/claude-501/-Users-mikko-github/7292a5ab-547b-4299-8eef-e4e0fb012027/scratchpad/schema-spike`
  (`cargo tree -e normal --prefix none`, diffed against this repo's own `Cargo.lock` package names):
  **26 net-new transitive crates** in the isolated spike with
  `jsonschema = { version = "0.52", default-features = false }`. None is an HTTP or async-runtime
  crate — `rg -i "reqwest|ureq|hyper|tokio|async"` over the spike's dependency tree returns nothing,
  because `resolve-http` (`reqwest`+`rustls`) and `resolve-async` (`reqwest`+`tokio`+`async-trait`)
  are both optional features the default excludes, confirmed by reading the vendored
  `jsonschema-0.52.1/Cargo.toml` `[features]` table directly rather than docs.rs. **Re-measured
  in-tree 2026-08-31** after adding the dependency to this repo's own `Cargo.toml` and running
  `cargo check --lib` (an additive-only lock update — `git diff Cargo.lock` shows zero `-name =`
  lines, so no already-pinned crate was bumped): **27 net-new transitive crates**, one more than the
  isolated spike (this repo's existing tree already satisfies one of `jsonschema`'s transitive deps
  differently than the spike's bare `Cargo.toml` did — not investigated further, since the gate is
  the HTTP/async-runtime check, not the exact count). That check re-run in-tree: `git diff Cargo.lock`
  grepped for `reqwest|hyper|tokio|async-trait|h2|rustls|native-tls` as new `+name =` lines returns
  nothing. Accepted; boon was not spiked as U3 never triggers.
- **Trust boundary (C15), not just coupling:** `resolve-file` is *also* excluded by
  `default-features = false` — confirmed the same way, in the same feature table. Seam 3
  meta-validates schema documents supplied by backends the operator does not control; with both
  `resolve-http` and `resolve-file` off, the crate has **no compiled-in capability** to dereference a
  `$ref` over the network or the filesystem during meta-validation, closing both an SSRF vector (a
  backend schema containing `{"$ref": "http://169.254.169.254/..."}`) and a path-traversal one
  (`{"$ref": "file:///etc/passwd"}`) before either construct reaches a check. Empirically probed:
  meta-validating `{"$ref": "http://127.0.0.1:1/does-not-exist#"}` (a port nothing serves) returned
  `Ok` in 0ms — meta-validation treats `$ref` as an opaque string against the meta-schema's own
  `format: uri-reference`, it does not resolve it, and there is no HTTP client in the dependency tree
  to attempt the resolution even if a future code change tried. This closes the review finding
  recorded below ("disable `jsonschema` default features") with a verified mechanism, not an
  assertion.

## Test plan — one row per assertion, and whether it can fail today

The §P2 test plan expands this table and is reviewed on its own terms: `docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity-test-plan.md`. It adds the rows this table does not carry — the diagnostics half of the ruling, two negative controls, and the criterion's `$ref`/composition clause, which is uncovered here.

Selection rule that binds every fixture below: **an invalid fixture is chosen by running the
validator on it, never by reading it.** JSON Schema 2020-12 admits keywords it does not define,
so a document that looks malformed to a human frequently validates. A fixture is only usable once
the chosen validator has reported it invalid, on the keyword the case names.

| case | assertion | fails on HEAD? |
|---|---|---|
| **G1** — capability YAML whose `schema.input` sets `required` to a string instead of an array | `load_from_directory` over a directory containing only that file returns zero capabilities, **and the issue list carries the new `CAP-` code specifically** — a non-empty error list is not the assertion, because a fixture can die for a reason that never reaches meta-validation | **Yes.** On HEAD the file loads and the tool is published. The assertion is on absence, so it fails red before the change and passes only once seam 2 exists. |
| **G2** — the same capability, reached through `tools/list` | the tool name is absent from the published surface | **Yes**, same mechanism, one level up — this is the case that ties the criterion to what a client actually sees. |
| **G3** — all 19 `gateway_*` defs meta-validate against 2020-12 | every published `inputSchema`, and every `outputSchema` present, is valid under 2020-12 | **No — and this is stated, not hidden.** The defs are expected to be valid already, so this is a *regression guard*, not a disproof. Its falsifier is the §P2 probe below. |
| **G4** — a schema declaring `"$schema": "http://json-schema.org/draft-07/schema#"` and using a construct legal in draft-07 but not in 2020-12 | the check reports invalid | **Yes.** Nothing today reads `$schema` at all. This is the case that proves the dialect is pinned rather than inferred, and it is the only case that distinguishes option A used correctly from option A used carelessly. |
| **G5** — a backend whose `tools/list` returns valid tools plus one whose `inputSchema` fails 2020-12 | `get_tools_shared` returns only the valid tools, the invalid name is absent from the published `tools/list`, and the valid names still invoke normally | **Yes.** On HEAD the whole list is cached and published verbatim; nothing meta-validates a backend schema. The blast-radius half of the ruling — one tool, not one backend — is the assertion that would fail if seam 3 were written as a whole-list rejection. |
| **G6** — invoking the tool G5 rejected | `gateway_invoke` refuses with an error naming the tool and the validation failure, **and the backend receives no request** — asserted on the mock backend's call log, not on the error text alone | **Yes**, and it cannot pass without the rejected-set. Filtering the cache alone leaves the name looking merely unknown, and `invoke.rs:1934-1938` dispatches unknown names on purpose. This case is the design proof that the extra gate is load-bearing rather than defensive. |
| **G7** — the backend of G5 corrects its schema, TTL expires, list is re-fetched | the previously rejected tool is published **and** a `tools/call` for it reaches the mock backend — asserted on the call log, the same instrument as G6, so the case cannot pass on listing alone | **N/A on HEAD**, and that is the wrong question for this row: nothing on HEAD rejects, so there is nothing to recover from. What makes it a real case is that it fails against the *accumulating* implementation — a rejected set added to rather than replaced. The plan builds that variant as an explicit mutant and requires G7 to go red against it. A recovery case that has never been shown to fail against the mistake it guards is decoration. |
| **G8** — a backend whose tools are *all* rejected, then a warm-start attempt | the empty tool list is **not** discarded by `invalidate_tools_cache`, so the backend is not re-fetched on every attempt, and the rejected set survives with it | **Yes**, against the design's own naive form. The interaction is named in the design as the one thing to get right, and until this row existed nothing in the plan would have noticed getting it wrong — the design described a guard that no case exercised. |
| **G9** — the tool G5 rejected, invoked over the **direct** per-backend MCP route rather than through `gateway_invoke` | refused, and the mock backend's call log stays empty | **Yes**, and this is the row that would have caught the design's own defect. The first version gated `gateway_invoke` only; `backend_handlers.rs:747-809` forwards `tools/call` without consulting anything the meta-MCP layer knows. A `gateway_invoke`-only test suite would have gone green over a tool that was still callable. |
| **G10** — a backend `tools/list` element that fails `Tool` deserialization entirely | documents the residual: the element is re-appended unvalidated (`backend_handlers.rs:184-193`) and seam 3 never sees it | **No, deliberately.** This case asserts the *current* behaviour so the residual is pinned rather than assumed, and so a later change that starts dropping unparsed elements has to change a test and say why. It is a characterization test, labelled as one; it proves nothing about SCHEMA.1 and is not counted as coverage of it. |
| **G11** — a backend tool with a **valid `inputSchema`** beside an **invalid `outputSchema`** | the tool is dropped: absent from the published `tools/list`, and its name is in the rejected set | **Yes.** On HEAD nothing meta-validates either field. This is the executable half of the owner's ruling that both fields are inside the criterion — a predicate reading `inputSchema` only passes every other case in this table and fails this one alone. |


**G4 must name its construct, and the obvious candidates do not work.** Most draft-07-isms stay
*legal* under 2020-12: `definitions` and `dependencies` are simply keywords 2020-12 does not
define, and an undefined keyword is permitted, so neither fails meta-validation. A row reading
"some construct" is the defect class this repo has already shipped once — a test-plan row naming
a parameter that does not exist. The candidate is **`items` as an array** (`{"items": [{"type":
"string"}]}`): 2020-12 constrains `items` to a single schema, the array form having moved to
`prefixItems`, so the document should fail 2020-12 and pass draft-07. **Candidate, not yet fact.**
The binding fixture rule applies here as everywhere in this plan: the construct is chosen by
*running* the selected validator against both dialects and keeping one that actually splits them.
If none does, G4 is dropped with that result recorded, and the dialect-pinning decision loses its
only disproof — which is itself a finding, not a formality.

### Falsifier probe for G3 (required, because G3 is green on HEAD)

G3 cannot use the free failure, so it earns its keep the way `development-process.md` §P2
specifies: save the file uniquely under a trap, hand-edit one def to a schema the validator has
already reported invalid, run the test and confirm it fails **on the meta-validation assertion**
and not on a compile error, restore, then re-run the test and confirm it passes. The restore is
verified by re-running the test, never by `git status` — the defect and the repair are both
modifications and `status` reports them identically.

## Questions this design had to settle

Settled in this session, with the answer recorded:

| question | how | answer | what it changed |
|---|---|---|---|
| Is a JSON-Schema validator already in the tree? | `cargo tree --workspace --all-features`, 827 lines, filtered | No, under any feature set or edge kind | Made "add a dependency" a real decision rather than a preference |
| Where should validation fire, and what happens on failure? | read `src/capability/loader.rs:111` through `src/capability/loader.rs:155` and `src/capability/validator/mod.rs:137` | Per-capability, fail-closed, gateway still starts | Removed an operator question the repo already answers, and removed the temptation to invent a startup abort |
| Does the OpenAPI generator bypass the loader? | `src/gateway/ui/import.rs:172` | No — it writes YAML into the load directory | Kept the generator in scope without a second seam |
| Does the repo already meta-validate anywhere? | searched src/ and capabilities/ for `2020-12`, `draft-07`, `$schema` | No, and no schema declares a dialect | Turned dialect pinning into an explicit design decision |
| Does the `meta` module pin 2020-12, or infer it? | first from the docs.rs pages for `jsonschema` 0.52.1; **then, after review, from the vendored crate under `~/.cargo/registry`** | Every `meta` free function auto-detects the draft, and `_for` means foreign representation rather than draft — both still true. The pin is **not** `meta::options().with_draft(…)`: that does not compile, `with_draft` being a `ValidationOptions` method. It is `jsonschema::draft202012::meta::validator()`, which delegates to `validator_for_draft(Draft::Draft202012)` (`src/lib.rs:3288`) — a constant, not a dispatch on `$schema` | Named the exact call in the design; retired U1. **This row is left showing its own correction rather than rewritten clean**: the first answer was single-sourced to docs.rs, the design flagged it as unverified, and the flag alone did not stop it being written into a settled-decisions table. A settled row that quietly acquires the right answer teaches nobody why it was wrong. |
| Can a malformed schema reach the validator, or does serde reject it first? | `git show 112a392c:src/capability/definition/mod.rs` | `input`/`output` are untyped `serde_json::Value` | Made G1 executable — the fixture reaches the check rather than dying at parse |
| What does the gateway do with a **backend-supplied** schema that fails 2020-12 — reject, publish and flag, or degrade? | *askable, not checkable*: put to the repository owner as its own question, because it is a behaviour change for every deployment proxying a backend with a draft-07 schema | Drop that tool from the catalogue and keep the rest of the backend: validate at registration, do not list and do not route a tool that fails, log it and surface it in diagnostics | Withdrew the §P0 exclusion, retired U6, gave SCHEMA.1 a path to closing without a remainder, and added seam 3 with G5-G7 |
| Where can a backend tool be dropped without the two callers disagreeing? | read `src/backend/annotations.rs:126-155` and `src/backend/metadata.rs:136-143` | `prepare_tool_metadata` already exists as the single entry point, with a `retain`-based per-tool exclusion and a `warn!` shape to match; its doc comment records the divergence that made it the only entry point | Turned seam 3 from a new module into a second predicate in an existing filter. **The second half of this answer was wrong and is corrected here rather than deleted**: "once per cache fill, not once per request" holds on the shared path and not on the direct one, where `backend_handlers.rs:196` calls the same function inline per request. Reading `metadata.rs` alone was what made the wrong half look settled. |
| Does filtering the cached list make a rejected tool unroutable? | read `src/gateway/meta_mcp/invoke.rs:1934-1938` | No — the invoke path dispatches names missing from the cache on purpose, to tolerate a stale cache | Added the per-backend rejected-set and the invoke-time refusal; without it the owner's "do not route" half is unimplementable, and G6 is the case that proves it |
| Does an all-rejected backend interact with warm-start? | read `src/backend/metadata.rs:39-46` | Yes — `invalidate_tools_cache` discards an empty list so warm-start re-asks, and every-tool-rejected produces an empty list | Added the one-condition guard: discard the empty list only when the rejected set is empty too |

Deferred, each with owner, resolving check, trigger and fallback:

| id | question | owner | check | trigger | if it resolves badly |
|---|---|---|---|---|---|
| **U2** — *retired, answered* | Transitive dependency delta for `jsonschema` 0.52.1, against D27 | implementer | `cargo tree -e normal --prefix none` in a scratch spike, diffed against this repo's `Cargo.lock`, package names only (see Dependency gates section) | before adding the dependency | **26 net-new crates, none an HTTP/async-runtime crate; option A confirmed, boon not needed** |
| **U3** — *moot* | Does `boon` expose a meta-validation entry point in its own docs? | implementer | docs.rs page for `boon` 0.6.1 | only if U2 forces the fallback | U2 did not force the fallback; not evaluated |
| **U4** | Startup cost of meta-validating 110+ capabilities at load | implementer | median of five timed `load_from_directory` runs over the capability directory, before and after | before merge | validate on first publish rather than at load; the seam does not move, only when it runs |
| **U5** — *retired, answered* | Which construct actually splits draft-07 from 2020-12, for G4 | implementer | ran `jsonschema::draft202012::meta::validator().validate(...)` over two candidates in the scratch spike | before writing the G4 fixture | **`{"items": [{"type": "string"}]}` splits them** — 2020-12's meta-schema requires `items` to be `boolean` or `object` (tuple-form moved to `prefixItems`), error: `[{"type":"string"}] is not of types "boolean", "object"`. Backup candidate `{"$id": "#someAnchor"}` also splits (2020-12 requires `$id` to match `^[^#]*#?$`, no fragment) if a second disproof is ever wanted. |
| **U7** — *answered; now a confirmation* | Does the criterion cover `outputSchema` as well as `inputSchema`? | team lead — **answered 2026-08-31: both, and it was never a widening.** The population is "tool schemas exposed by the gateway"; a published `Tool` carries both fields, so both are bound. `inputSchema` was named because that is where the failure was found | what remains is *checkable*: read the seam-3 predicate for both fields, and run **G11** — valid `inputSchema`, invalid `outputSchema`, tool dropped | before merge, as a confirmation rather than a gate | none needed. There is no narrowing to fall back to; a predicate reading one field fails G11 |
| **U8** | Whether the added rejected-set slot and its invoke-time lookup cost anything measurable on the hot invoke path | implementer | time `gateway_invoke` against a mock backend, 1,000 calls, before and after, median of five | before merge, alongside U4 | keep the set but consult it only when the cached list is populated, which is the same condition the "did you mean?" hint already uses |
| **U8b** | The direct-route cost, which U8 as written cannot see | implementer | time the **direct** per-backend `tools/list` route against a mock backend publishing 50 tools, 1,000 requests, before and after, median of five — a separate measurement, not a wider reading of U8 | before merge, alongside U8 | hoist the direct route onto the cached list so seam 3 runs per fill there too; weakening the check is not on the table |

U8b is a separate row rather than a wider reading of U8, and the distinction is the whole point. The
Cost section was corrected to say seam 3 runs per request on the direct route, and U8 was then
described as covering that. It cannot: U8 times `gateway_invoke`, which never enters the direct
route, so a regression there would pass the gate unseen. Widening the prose around an instrument
does not widen the instrument — the confirmation review caught the repair stopping one line short of
it.

**U6 is retired**, answered in this session and recorded in the settled table above. It was the one
deferral that blocked something — not this design's implementation, but SCHEMA.1's closure — and it
was an **askable** unknown, because no command settles which behaviour the operator wants and a
check that cannot come back "no" is not a check.

**U7 was asked as a second question of the same owner and came back answered**, so it no longer
blocks the closure comment. What it leaves behind is a confirmation with a test attached, which is
the cheaper end state: the design's reading (both fields) turned out to match the criterion's
population, and G11 is what makes that reading falsifiable rather than asserted.

U4, U5 and U8 block nothing else in the design; U2 blocks only the choice between A and B. None of
these is a residual-risk paragraph, and none is closed by naming a command instead of running it.

### Scope receipt — 2026-08-31, the backend-schema exclusion is withdrawn

The scope froze at the first dual review with backend-supplied schemas listed OUT, on the reasoning
that what to do with an invalid backend schema is a routing-policy question rather than a validity
one. That reasoning was sound and it did not survive its own consequence: the exclusion stood against
a MUST, and the population SCHEMA.1's MET clause was measured over includes backend tools, so the
criterion could not close while the exclusion held. It was carried as a deferred unknown for exactly
this reason.

The owner has now answered the policy question, so the thing that made it un-scopable is gone. The
surface moves by one item: this design gains a validity check on each backend tool's schema at the
point the tool list is cached, and a rejected tool is neither listed nor routable. Nothing else in FOR
or OUT moves. The acceptance criteria gain **six** cases, not the one the ruling's wording
suggests: G5 for the listing half; G6 for the routing half through the funnel — which needs state the
gateway does not have today, see the Dispositions row; G7 for recovery when a backend fixes its
schema; G8 for the all-rejected warm-start interaction; and G9 for the routing half on the direct
per-backend route, which the first version of this design missed entirely; and G11 for a valid
`inputSchema` beside an invalid `outputSchema`, which is where the owner's both-fields ruling becomes
executable. The count going from one to six is itself the argument for reviewing a ruling's
*implementation* rather than its wording.

## Dispositions

| finding | disposal |
|---|---|
| Backend-supplied schemas are never meta-validated | **resolved by the owner, 2026-08-31; now in scope.** Question: what does the gateway do when a backend publishes a tool whose `inputSchema` is not valid under 2020-12? Asked of the repository owner. Answer: drop that tool from the catalogue and keep the rest of the backend — validate each backend tool's schema at registration, do not list and do not route a tool that fails, log the rejection and surface it in diagnostics. What it changed: SCHEMA.1 no longer carries a remainder against its MUST, the §P0 exclusion below is withdrawn, and this design gains a per-tool registration check whose blast radius is one tool rather than one backend. Rejected: publishing with a flag (leaves the MUST unmet and hands the client exactly the shapes the criterion exists to keep away from it), repairing the subschema (the gateway would assert a contract the backend never offered), and refusing the whole backend (forty-nine working tools removed for one broken one). |
| Should seam 3 reuse or extend `src/capability/schema_validator/mod.rs`? | **neither — separate, deliberately.** That module answers "does this *argument object* satisfy this schema" (`validate_arguments:117`, `validate_output:252`) over a documented bounded subset: required params, rejection of undeclared params, type with coercion, enum, minLength/maxLength, minimum/maximum. Seam 3 asks the opposite question — is the schema *document* legal under a dialect — and answers it over the whole dialect. Extending the bounded subset to cover 2020-12 is option C rebuilt under a different name, and option C is rejected by the criterion. The two live side by side: one validates instances at invoke time, the other validates documents at ingest. |
| The owner's ruling is not implementable as literally stated | **resolved in-design, and named here so the gap is visible.** "Do not list and do not route" reads like one action and is two: filtering the cached list satisfies the first half only, because `invoke.rs:1934-1938` dispatches uncached names on purpose to tolerate a stale cache. Building the second half needs state the gateway does not have today — the per-backend rejected-set. Recorded rather than silently absorbed, because an implementer working from the ruling alone would have shipped the listing half and believed the routing half came free. |
| `src/capability/schema_validator/mod.rs` validates a bounded subset and will silently accept constructs 2020-12 defines | **observation.** Independent of SCHEMA.1: it is instance validation. If it becomes a defect it is its own change. |
| **Review, GPT + Grok, 2026-08-31: the routing gate was specified on `gateway_invoke` only** | **fixed in this document — change of approach, not a patch.** Verified at source before writing: `src/gateway/router/backend_handlers.rs:747-809` forwards a direct `tools/call` to the backend with no meta-MCP involvement, so a dropped tool stayed callable there. Patching would have meant a second gate in the second caller; the elimination is to put the refusal at the shared chokepoint `Backend::request_with_headers` (`src/backend/ops.rs:151-165`), which the direct route, the funnel and `McpProvider` (`src/provider/mcp_provider.rs:62`) all traverse. After the fix the finding can no longer be stated. New case G9. |
| **Review, GPT, 2026-08-31: the named dialect pin does not compile** | **fixed — the correction is the whole value of the review.** Verified against the vendored crate, not docs.rs: `jsonschema::meta::options()` returns `MetaSchemaOptions` with exactly `with_registry`, `is_valid`, `validate` (`jsonschema-0.52.1/src/lib.rs:1863,1874,1886`); `with_draft` is on `ValidationOptions` (`src/options.rs:156`) and unreachable from the meta path. Correct pin is `jsonschema::draft202012::meta::validator()` (`src/lib.rs:3178,3281`). The design had flagged this exact call as single-sourced and unverified — the flag was right and the flag alone would not have caught it. |
| **Review, GPT, 2026-08-31: unparseable `tools/list` elements bypass seam 3** | **named as a residual with a characterization test (G10), not fixed here.** Verified: `backend_handlers.rs:184-193` re-appends an element that fails `Tool` deserialization, deliberately, so it never reaches `prepare_tool_metadata`. Fixing it means changing a documented behaviour whose stated reason is not to hide a tool clients depend on — a separate decision with its own blast radius, and outside this change's FOR. Pinned by a test so it cannot drift silently. |
| **Review, Grok, 2026-08-31: `src/gateway/server/mod.rs:922` is the playbook loader** | **fixed.** Verified: `:922` is `engine.load_from_directory` for playbooks; the capability loader is `:873` and `:1515`. Citation corrected, `:922` dropped. A wrong line number in a measured-constraints table is the failure mode this document spends a section warning about. |
| **Review, GPT + Grok, 2026-08-31: `BackendStatus` does not auto-surface** | **fixed.** Verified: `surfaced.rs:184` copies `status.tools_cached` into a hand-built object; only the admin health JSON (`handlers.rs:428`) serializes the struct whole. The design now names each copy site that must grow. |
| **Review, GPT + Grok, 2026-08-31: seam 3 is not once-per-cache-fill everywhere** | **fixed.** Verified: `backend_handlers.rs:196` calls `prepare_tool_metadata` inline per direct `tools/list` request. Cost section corrected and U8 widened to measure that route. |
| **Review, Grok, 2026-08-31: no case for the all-rejected warm start** | **fixed — new case G8.** The design named that interaction as the one thing to get right and no row exercised it, which is precisely the empty-cell finding a test-plan review exists to produce. |
| Review, GPT, 2026-08-31: disable `jsonschema` default features; pre-production gate for `McpProvider`/A2A | **folded into existing unknowns rather than filed.** Default-feature trimming is an input to U2's transitive count, not a separate decision; the provider path is now covered by moving the gate to the shared chokepoint. Filing either as a ticket would cost a human's attention for something already owned. |
| **Review, kimi, 2026-08-31: no verdict** | **cannot verify — recorded, not counted.** The third reviewer emitted raw tool-call syntax instead of a review and exited 65 ("COULD NOT REVIEW"). No finding, and no evidence either way about this document. Named so the two-vendor result is not silently reported as three. |
| **Confirmation pass, GPT, 2026-08-31: the rejected set is not identity-scoped** | **residual, named in the routing section — not repaired.** Verified at source: `tools_cache` is one `CachedMetadata<Vec<Tool>>` per backend (`src/backend/mod.rs:54`), `metadata.rs` has zero identity references, and identity selects a connection pool key (`ops.rs:178`) rather than a cache. The finding is a true property of the existing tool cache and the gate inherits it; the proposed fix would key a derived set finer than its source, which cannot be built. The claim died at source as an attribution, not as an observation — so it is recorded, not repaired. **Owner ruling 2026-08-31: out of scope, and filed as [MIK-7334](https://linear.app/parm/issue/MIK-7334)** — right about the property, wrong about whose change it is; the shared catalogue is a pre-existing decision with a human-sized blast radius. |
| **Confirmation pass, GPT, 2026-08-31: a `tools/call` before discovery bypasses the refusal** | **escalated, then ruled: keep the deny-list.** True as an observation: the gate is a deny-list, and `invoke.rs:1934-1938` dispatches uncached names deliberately. **Owner ruling 2026-08-31:** SCHEMA.1 binds on *exposure*, so a tool the gateway has never listed is outside the criterion's population rather than a hole in it, and an allow-list would change dispatch for every deployment to close a window in which the gateway has no knowledge to refuse on. Recorded as an inherited residual with the `invoke.rs` citation: the refusal is authoritative for every tool the gateway has listed, silent for one it has not. |
| **Confirmation pass, GPT, 2026-08-31: unparseable elements re-raised** | **disposal unchanged — still a residual with G10.** The proposed fix (meta-validate raw elements, drop those that fail) would reverse `backend_handlers.rs:184-193`, whose stated reason is not to hide a tool clients depend on. Re-raising a finding does not by itself move it; what would move it is the owner reversing that behaviour, which is the same question as the deny-list one above. |
| **Confirmation pass, GPT, 2026-08-31: U8 cannot measure the direct route** | **fixed — new U8b.** CERTAIN and correct: the Cost section was widened in prose and the instrument was not. U8 times `gateway_invoke`, which never enters the direct route. A separate direct-`tools/list` benchmark now exists rather than a wider reading of the old one. |
| **Confirmation pass, GPT, 2026-08-31: diagnostics still promise one warning per cache fill** | **fixed.** The repair had reached the Cost section and not the diagnostics one. The `warn!` now fires on entry into the rejected set or a change of error, not on every evaluation — otherwise one polling client on the direct route floods the operator log, which is how a useful warning gets muted. |
| **Confirmation pass, GPT, 2026-08-31: the settled-decisions table still asserts both disproved facts** | **fixed, by correcting the rows in place rather than rewriting them clean.** Both rows now show what was believed, what disproved it and why the first answer looked settled. A settled-decisions table that quietly acquires the right answer is the exact artefact this document argues against elsewhere; leaving the correction visible is the point. |
| **Team lead, 2026-08-31: `outputSchema` was recorded as a widening** | **corrected — it never was one.** The criterion's population is "tool schemas exposed by the gateway", and a published `Tool` carries both fields on one surface. Seam 3 validating both is correct as specified; the narrowing fallback is gone, and U7 becomes a confirmation with G11 as its executable half. Nothing moved, so no scope receipt is owed. |
| The 19 meta-tool schemas declare no `$schema` | **no change needed.** Pinning the dialect at the check makes the declaration unnecessary; adding it to 19 literals would be the larger diff and would give the check something to disagree with. |

## Implementer decisions — Increment 1 (dependency + shared validator wiring)

Recorded per §P3 — none changes an acceptance criterion or a contract; all are "how", not "what".

- **P3 population re-derived from source, not carried from an earlier session.** `rg -n 'name: "gateway_'
  src/gateway/meta_mcp_tool_defs.rs` returns exactly 19 literals: the 17 from `build_meta_tools` with
  every flag true (4 base + stats + cost_report + webhooks + 8 unconditional + reload + reload_capabilities)
  plus the 2 from `build_code_mode_tools` (`gateway_search`, `gateway_execute` — distinct names from the
  base surface's `gateway_search_tools`, no overlap). `build_meta_tools_all_enabled_has_17_tools` in
  `meta_mcp_tool_defs_tests.rs:59` already pins the 17; the 19 is the union with the disjoint Code Mode
  pair. P3's assertion set is these 19 exact names, not a count alone, per the test plan.
- **P4's both-directions probe, run before writing the test, not assumed.** Extended the scratch spike:
  `jsonschema::draft7::meta::validator().validate(&json!({"items":[{"type":"string"}]}))` returns `Ok`
  (clean under draft-07); `jsonschema::draft202012::meta::validator()` on the same fixture returns the
  same error U5 already recorded. Both directions confirmed on one fixture, empirically, not inferred
  from U5 alone. P4 needs no separate falsifier probe beyond this: the test-plan's falsifier-obligations
  section scopes the probe requirement to rows *green on HEAD* (P3, P6b, P8, P9, P12a); P4 is red on
  HEAD today because the crate is absent, which is the row's own stated state, not a compile accident
  the plan overlooked.
- **Module placement for the shared meta-validator: `src/capability/schema_validator/meta.rs`, `pub(crate)`.**
  Checked D27 first: `rg "use crate::backend" src/capability/` and `rg "use crate::capability" src/backend/`
  both return nothing today — no edge between the two siblings in either direction, so a new
  `backend -> capability` edge (seam 3 calling in) cannot create a cycle. `gateway` already depends on
  both (`use crate::capability` and `use crate::backend` both appear under `src/gateway/`), so this adds
  one new sibling edge rather than a new module. Placed beside the existing (currently private)
  `schema_validator` instance-validator so the opposite-directions distinction — meta-validates the
  *schema document*, `schema_validator` validates *arguments against* a schema — sits in one file's
  neighbourhood. `mod schema_validator;` in `src/capability/mod.rs` widens from private to `pub(crate)`
  to make this reachable from `gateway` and `backend`; this is a crate-internal-only widening (no new
  external API surface, D28 does not count it) made necessary by the design's own three-seam structure,
  not a new design decision — the design already committed to one shared validator across three call
  sites when it named seam 3 as a predicate reusing the same construct as seam 1/2 (see the settled
  questions table). No `OnceLock`-cached validator instance is exposed publicly; only the `pub(crate) fn`
  entry point is.
- **D27 net-new-crate count re-measured in-tree: 27, not the spike's 26** — see the Dependency gates
  section above. Additive-only lock change confirmed (`git diff Cargo.lock` has zero `-name =` lines);
  no HTTP/async-runtime crate among the new entries, re-checked against the repo's actual `Cargo.lock`
  rather than trusting the spike's isolated result to still hold.
