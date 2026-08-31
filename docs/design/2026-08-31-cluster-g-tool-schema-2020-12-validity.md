# Cluster G — tool schemas must be valid under JSON Schema 2020-12

Criterion: **MIK-6865.SCHEMA.1** — every tool schema the gateway publishes MUST be a valid
JSON Schema document under the 2020-12 dialect.

Anchor commit: **`112a392c`**. Every file:line below was read at that commit, via
`git show 112a392c:src/capability/loader.rs` and equivalents, including files left dirty in the
working tree by a concurrent session. No citation mixes revisions.

**This change addresses SCHEMA.1 partially, and the closure comment must say so.** The criterion
covers *every* tool schema the gateway publishes, and a proxied backend tool is published on the
gateway surface. This design covers the two populations the gateway itself authors — the 19
compile-time meta-tool definitions and the capability YAML the loader reads — and explicitly
leaves backend-supplied schemas out (§P0). That remainder is a real, named part of SCHEMA.1, not
a nicety: owner = team lead, to be scoped as its own change, because it is a policy question
(reject the backend? publish and flag? degrade the tool?) rather than a validity one. A stated
limit against a MUST is an unmet requirement; recording it here is what stops the eventual
closure comment claiming MET.

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
`backend:{server}` or `capability:{server}` (`meta_mcp/mod.rs:1133-1141` at `112a392c`). The
population the MET clause was measured against therefore *includes* backend schemas, and the
UNTESTED clause inherits the same population. The remainder is real and stays named.

## §P0 Scope

**FOR:** meta-validating the schema *documents* the gateway publishes on its own MCP
surface — `Tool.inputSchema` and `Tool.outputSchema` — against the JSON Schema 2020-12
meta-schema, at the point where an invalid document can still be rejected cheaply.

**OUT:**

| out of scope | why |
|---|---|
| schemas supplied by upstream MCP **backends** and proxied through | not authored here; what to *do* with an invalid backend schema is a routing policy decision, not a validity one. Team-lead call, accepted — but this is an exclusion against a MUST, so it is carried as the deferred unknown below, not as a clean boundary. |
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
| Capability YAML is loaded from a runtime directory, not a repo path | `CapabilityLoader::load_from_directory(dir)` called at `src/gateway/server/mod.rs:873`, `src/gateway/server/mod.rs:922` and `src/gateway/server/mod.rs:1515` with a configured directory; `src/capability/loader.rs:46` recurses it |
| OpenAPI-generated capabilities land in that same directory | `src/gateway/ui/import.rs:172` — `cap.write_to_file(&output_dir)`; the schema is built at `src/capability/openapi/convert.rs:370` by `build_input_schema`. Generated schemas re-enter through the loader, so a loader-level check covers the generator too. |
| Publication surface | `src/protocol/types.rs:10` through `src/protocol/types.rs:40` — `Tool` carries `inputSchema: Value` and `outputSchema: Option<Value>` beside name, title, description, annotations, role, projection; also embedded at `src/trust/descriptor.rs:80` |

Two populations, different risk profiles: **19 constants** that change only when someone edits
Rust, and **110+ capability schemas** that arrive from a directory the operator controls.

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
a draft argument. None of them pins a dialect. The pin is
`jsonschema::meta::options().with_draft(Draft::Draft202012)`: `meta::options()` returns a
`ValidationOptions`, which carries a `with_draft` method. Source: docs.rs for `jsonschema`
0.52.1, read 2026-08-31 — one source, so the exact call has to compile before it is load-bearing.
An implementer reaching for `meta::is_valid` would have shipped auto-detection and G4 is the
case that would have caught it.

## Enforcement — two seams, matching the two populations

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

No new subsystem, no new module, no new startup path.

## Cost

Load-time meta-validation runs once per capability at load, against a validator compiled once and
reused. The measurement, not an adjective: time `CapabilityLoader::load_from_directory` over the
110+ capability directory, before and after, same machine, same directory, median of five runs.
Budget is §10 as written — P50 within +5%. If it breaches, the fallback is stated in U4.

## Dependency gates

- **D30 supply chain:** `cargo audit` at merge; `Cargo.lock` hashes pinned; a HIGH advisory on
  the new dependency or anything it pulls blocks the merge.
- **Licensing:** `jsonschema` is MIT, matching the MIT core. `boon` is MIT OR Apache-2.0. Neither
  touches the PolyForm EE surface.
- **D27 coupling:** unresolved until U2 returns a number. This gates adoption of option A, not the
  design.

## Test plan — one row per assertion, and whether it can fail today

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
| Does the `meta` module pin 2020-12, or infer it? | read the `meta` module and `fn.validate_for` pages on docs.rs for `jsonschema` 0.52.1 | Every `meta` free function auto-detects the draft; `_for` means foreign representation, not draft. The pin is `meta::options().with_draft(…)` | Named the exact call in the design instead of leaving the wrong one to be discovered in review; retired U1 |
| Can a malformed schema reach the validator, or does serde reject it first? | `git show 112a392c:src/capability/definition/mod.rs` | `input`/`output` are untyped `serde_json::Value` | Made G1 executable — the fixture reaches the check rather than dying at parse |

Deferred, each with owner, resolving check, trigger and fallback:

| id | question | owner | check | trigger | if it resolves badly |
|---|---|---|---|---|---|
| **U2** | Transitive dependency delta for `jsonschema` 0.52.1, against D27 | implementer | `cargo add --dry-run jsonschema` | before adding the dependency | take option B; if boon also breaches, D27 needs an explicit justification recorded, not a silent pass |
| **U3** | Does `boon` expose a meta-validation entry point in its own docs? | implementer | docs.rs page for `boon` 0.6.1 | only if U2 forces the fallback | express meta-validation as compiling the document against the 2020-12 meta-schema as an instance |
| **U4** | Startup cost of meta-validating 110+ capabilities at load | implementer | median of five timed `load_from_directory` runs over the capability directory, before and after | before merge | validate on first publish rather than at load; the seam does not move, only when it runs |
| **U5** | Which construct actually splits draft-07 from 2020-12, for G4 | implementer | run the selected validator over the `items`-as-array candidate under both dialects | before writing the G4 fixture | try further candidates; if none splits them, drop G4 and record that the dialect pin has no disproof — a finding, not a formality |
| **U6** | What the gateway does with a **backend-supplied** schema that fails 2020-12 meta-validation — reject the tool, publish it and flag, or degrade it | team lead | *askable, not checkable*: a behaviour change for every deployment proxying a backend with a draft-07 schema, so it is the operator's call, put to them as its own change | before SCHEMA.1's closure comment is written — this is the clause that stops it reading MET | the remainder stays open and SCHEMA.1 closes as partial, naming `:102` over backend-supplied schemas as the unmet part |

U6 is the one deferral here that blocks something: not this design's implementation, but SCHEMA.1's
closure. It is an **askable** unknown — no command settles it, because the question is which
behaviour the operator wants, and a check that cannot come back "no" is not a check.

U4 and U5 block nothing else in the design; U2 blocks only the choice between A and B. None of
these is a residual-risk paragraph, and none is closed by naming a command instead of running it.

## Dispositions

| finding | disposal |
|---|---|
| Backend-supplied schemas are never meta-validated | **deferred unknown, four fields recorded** (was: observation). SCHEMA.1's text does not scope to gateway-authored schemas and the MET clause was measured over a population that includes backend tools, so this is a remainder against a MUST rather than a neighbouring concern. Out of scope by §P0 for the *policy*, not disposed. Recorded here so the next reader does not rediscover it as a gap. |
| `src/capability/schema_validator/mod.rs` validates a bounded subset and will silently accept constructs 2020-12 defines | **observation.** Independent of SCHEMA.1: it is instance validation. If it becomes a defect it is its own change. |
| The 19 meta-tool schemas declare no `$schema` | **no change needed.** Pinning the dialect at the check makes the declaration unnecessary; adding it to 19 literals would be the larger diff and would give the check something to disagree with. |
