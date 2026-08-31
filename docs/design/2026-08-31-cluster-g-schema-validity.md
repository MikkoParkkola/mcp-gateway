<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
# Cluster G — JSON Schema 2020-12 validity of gateway-advertised tool schemas

Design only. No production code, no dependency added, no `Cargo.toml` edit. A
later increment implements what this decides.

- Criterion: `MIK-6865.SCHEMA.1` (clause: *valid under JSON Schema 2020-12*),
  `docs/requirements/RELEASE-4.0.0-criteria-status.md` line 102, status `UNTESTED`,
  release-blocking `yes`.
- Sibling clause (*no nested-object-in-array*) is already `MET` at line 101 via
  `tests/mik_7272_exploit_acs.rs`, exercising the real `MetaMcp::handle_tools_list`.
  This design follows that shape: prove the property through the live path, not a
  hand-built fixture.

## 1. Problem

The criterion says tool schemas MUST remain valid under JSON Schema 2020-12.
Nothing in the repository establishes it. `rg -ni "jsonschema|json_schema|json-schema|valico|schemars|boon" Cargo.toml Cargo.lock`
returns zero lines: no validator crate is declared, and no 2020-12 dialect,
`$ref` or composition validator exists in `src/`.

`crate::protocol::types::Tool` carries `input_schema` and `output_schema` as
untyped `serde_json::Value`, so the type system checks nothing. The property is
plausible — see §2 — but plausible is not tested, and the criterion is blocking.

### What "valid under 2020-12" concretely means

A tool schema is valid when a 2020-12 **metaschema** check succeeds against it.
That is a specific, decidable list, not a vibe:

1. **Metaschema conformance.** The document validates against
   `https://json-schema.org/draft/2020-12/schema`. Catches `"type": "strig"`,
   `"required": "name"` (must be an array of strings), `"properties"` whose value
   is not an object, numeric keywords given non-numeric values.
2. **Dialect-correct keywords.** 2020-12 renamed and re-scoped things draft-07
   spelled differently: tuple validation is `prefixItems` (draft-07 used an array
   form of `items`), `$defs` replaces `definitions`, `exclusiveMinimum`/`exclusiveMaximum`
   are numbers not booleans, `$recursiveRef` is gone in favour of `$dynamicRef`.

   These do **not** all behave alike under a 2020-12 check, and the difference is
   exactly what a guard would and would not reject. Array-form `items` and boolean
   `exclusiveMinimum` are **hard metaschema failures**: 2020-12 constrains those
   keywords to a schema and to a number respectively. `definitions` and
   `$recursiveRef` are merely **unknown keywords** — metaschema-valid, silently
   inert, carrying no constraint. So "a draft-07 schema is not valid 2020-12" is
   true only for the first group; the second group passes the check while quietly
   meaning nothing. Both matter, for opposite reasons.
3. **Reference resolution.** Every `$ref` resolves — against `$id`/`$anchor`
   within the document, or to an external resource. An unresolvable `$ref` is a
   compile failure, not a validation failure, and it is the failure mode that
   turns into an availability incident.
4. **Composition well-formedness.** `allOf`/`anyOf`/`oneOf`/`not`/`if-then-else`
   take schema values, and a schema is an object or a boolean — never a string.

The check is "does this document compile as a 2020-12 schema", not "does some
instance validate against it". No instance data is involved.

## 2. Three schema populations, not one

The criterion reads as one property. The code has three disjoint populations with
different trust levels, different failure modes and different costs. Costing them
as one is the mistake this section exists to prevent. Revision 1 of this design
named two and missed the third; the correction is F2 in §11.

### G-A — the gateway's own surface (trusted, static)

Hand-authored in `src/gateway/meta_mcp_tool_defs.rs`: **19** `Tool { .. }`
constructors — 38 lines match `Tool {`, of which 23 are `-> Tool` return types and
19 are the literals themselves — with exactly one
`output_schema: Some(search_tools_output_schema())`. So **19 input schemas plus 1
output schema = 20 schema documents**, and that is the *union across every
configuration*: `build_meta_tools` pushes `stats`, `cost_report` and `webhook`
conditionally onto `build_base_tools`, and `build_code_mode_tools` returns a
disjoint pair. Any single running configuration advertises 14–17 (the figure in
`CLAUDE.md`). Revision 1 read 38 as a tool count; the correction is F5 in §11. Served through
`MetaMcp::handle_tools_list` (`src/gateway/meta_mcp/mod.rs`) and its
`_for_session` / `_filtered` / `_with_url_override` variants, reached from
`src/gateway/router/handlers.rs` and `src/gateway/server/mod.rs`.

A keyword census over that file for `$schema`, `$ref`, `oneOf`, `anyOf`, `allOf`,
`prefixItems`, `items`, `additionalProperties`, `enum`, `const`, `format`,
`pattern` and the `min*`/`max*` family returns **3 hits in 836 lines**. The
schemas are `type` / `properties` / `required` and nothing else. That is why the
property probably holds — and why proving it is cheap.

These schemas are known at compile time. They cannot change at runtime. **They
need no runtime validation at all.**

### G-B — backend schemas re-served verbatim (untrusted, dynamic)

`src/gateway/meta_mcp/spec_preview.rs` (`handle_tools_list_filtered`, SEP-1821)
builds its result from `collect_filtered_backend_tools`, which clones
`cap.get_tools()` and `backend.get_cached_tools_snapshot()` straight into
`ToolsListResult`. Only the description is touched, by `autotag::enrich_description`.
The `inputSchema` a backend supplied is what the client receives.

So the gateway's advertised surface includes schemas it did not author and does
not check. Whatever the criterion means for G-A, for G-B it is also a question
about **untrusted input on the trust path**.

### G-C — capability-YAML tools, built by the gateway from operator data (semi-trusted)

`CapabilityBackend::get_tools` (`src/capability/backend.rs`) returns
`self.capabilities.read().tools.clone()` — a **pre-built cache**, filled by
`IndexedCapabilities::upsert` and `replace_all` calling
`CapabilityDefinition::to_mcp_tool()`. The cache exists to amortise that call, and
its own doc comment says so. These tools are neither hand-authored Rust nor
backend-supplied JSON: they are derived from operator-supplied YAML, hot-reloadable
at runtime, SHA-256-pinned on load. They are advertised like any other tool.

### The ingest map, corrected

Revision 1 claimed "both populations enter through one chokepoint:
`Backend::get_tools_shared`". That is wrong three ways, and the third is the one
that matters:

1. `prepare_tool_metadata` has **two** call sites, not one — `Backend::get_tools_shared`
   in `src/backend/metadata.rs`, and `src/gateway/router/backend_handlers.rs`,
   which deserialises each `Tool` itself and then calls `prepare_tool_metadata`
   before `project_tool_descriptors_trust_cards`.
2. G-C **never reaches `prepare_tool_metadata` at all**. `to_mcp_tool()` output goes
   straight into the capability cache.
3. `to_mcp_tool()` has further un-chokepointed callers:
   `src/gateway/meta_mcp/search.rs` (twice), `src/trust/mod.rs`,
   `src/validator/cli_handler.rs`.

`prepare_tool_metadata` is still the right home for the **G-B** guard — it is where
`exclude_invalid_header_tools` and `normalize_tool_annotations` already live, and
both its call sites are on the backend-ingest path. But it is a *two-site* home for
*one* population, not a single door for all of them, and G-C needs its own check at
`to_mcp_tool()` or at the two cache-fill sites. Increment 2 covers G-B; G-C is
sequenced in §10 and is why §10's status line is qualified.

## 3. Candidate validators

All figures fetched from crates.io on 2026-08-31. Dependency counts measured in a
throwaway workspace outside this repository (`cargo tree --edges normal`,
resolver-locked at 234 packages), diffed against the 386 unique package names in
this repository's `Cargo.lock`.

| crate | latest | released | maint. | licence | 2020-12 | total deps | **new to this tree** |
|---|---|---|---|---|---|---|---|
| `jsonschema` (default feats) | 0.52.1 | 2026-08-30 | active — release yesterday, 19.4M recent downloads | MIT | yes, plus draft-07/2019-09, dialect auto-detect | 140 | 26 |
| `jsonschema` (`default-features = false`) | 0.52.1 | 2026-08-30 | as above | MIT | same | 62 | **26** |
| `boon` | 0.6.1 | 2025-01-07 | quiet — last release 19.8 months, last commit 2026-02-23 | MIT OR Apache-2.0 | yes, 2020-12 native | 55 | **7** |
| `valico` | 4.0.0 | 2023-05-13 | dormant — 3.3 years, no repository link on crates.io | MIT | draft-07 era, no 2020-12 | 66 | 14 |
| `jsonschema-valid` | 0.5.2 | 2023-11-08 | dormant — 2.8 years | **MPL-2.0** | draft-07 era, no 2020-12 | — | — |
| `schemars` | — | — | active | MIT | schema **generation** | — | — |

`jsonschema` MSRV is 1.85.0; this crate pins `rust-version = "1.95"`, so MSRV
constrains nothing here. `boon` declares no MSRV.

### Runners-up, and why each loses

- **`schemars` — wrong category.** It derives schemas from Rust types. It cannot
  answer "is this arbitrary `serde_json::Value` a valid 2020-12 schema", which is
  the entire question. It would also require typing `Tool::input_schema`, a
  protocol-level change far outside this criterion.
- **`valico` — no 2020-12.** Draft-07 vintage, last released 2023-05, and
  crates.io lists no repository. Using it would mean validating against the wrong
  dialect, which is worse than not validating: it manufactures a green check for a
  property nobody tested.
- **`jsonschema-valid` — no 2020-12 and MPL-2.0.** The dialect gap alone
  disqualifies it. MPL-2.0 is a file-level copyleft; it is compatible with
  distribution here, but this repository already runs a mixed
  MIT-core / PolyForm-Noncommercial licence split with a `.mit-core-allowlist`
  and `scripts/ci/check-license-headers.sh`, and adding a third licence family for
  a crate that fails on the merits is gratuitous.
- **`boon` — the close call, decided in §4.**

## 4. Recommendation

**`jsonschema` 0.52, `default-features = false`.** Introduced as a
**`[dev-dependencies]` entry first** (§5), promoted to a runtime dependency only
when the G-B guard of §6 is built.

`boon` is genuinely attractive on the numbers: 7 new crates against 26,
`MIT OR Apache-2.0` against bare MIT — strictly the better licence in a repository
that already juggles MIT core and PolyForm-Noncommercial — and its `compile()`
performs the metaschema check automatically, so the check is the API rather than
an extra call. It loses on one asymmetry: **which risk has a wired consequence in
this repository.**

- **Correction (F3).** Revision 1 argued that a RUSTSEC `unmaintained` advisory
  against `boon` would block the release, because the CI `audit` job runs
  `cargo audit`. That job runs `cargo audit` **bare** — no `--deny unmaintained`,
  no `--deny warnings` — and the repository has no `audit.toml` or `deny.toml`
  (`fd -H -t f 'audit\.toml|deny\.toml' .` returns nothing). Informational and
  `unmaintained` advisories warn; only a *vulnerability* makes that job non-zero.
  The blocked-release consequence does not exist. The claim is withdrawn, not
  repaired: a gate that is not wired cannot carry a decision.
- What survives is **release recency**, argued on its own terms and nothing else.
  `jsonschema` 0.52.1 was released 2026-08-30 — the day before this design.
  `boon` 0.6.1 was released 2025-01-07, twenty months earlier, last commit
  2026-02-23. Both are maintained; one is demonstrably tracking the specification
  now. On the untrusted-input path, that is worth 19 extra build-only packages.
- `jsonschema`'s bulk has no wired consequence: 26 additional packages on an
  existing 386, and a one-off compile cost behind `Swatinem/rust-cache`, which
  that same job already uses.

`boon`'s last *commit* is 2026-02-23 — six months, not the nineteen its release
date suggests, so it is not abandoned, and nothing here says it is. The decision
rests on recency alone, and it is a close one: were `boon` to cut a release
tracking current 2020-12 errata, this tiebreak would flip.

### `default-features = false` is mandatory, not tuning

`jsonschema`'s defaults are `["resolve-http", "resolve-file", "tls-aws-lc-rs", "idna"]`.
`resolve-http` makes the validator fetch external `$ref` targets over the network
during schema compilation. On the G-B path the schema is **supplied by a
backend**, so a hostile or compromised backend advertising

```json
{ "type": "object", "properties": { "x": { "$ref": "http://169.254.169.254/latest/meta-data/" } } }
```

would have the gateway issue that request from inside its own network position,
at tool-registration time, before any policy or firewall rule governing tool
*invocation* has a say. `resolve-file` is the same defect against the local
filesystem. Disabling both is a security requirement of this design, and the
implementing increment must assert it — a manifest line is not a test.

**Residual, stated:** with remote resolution disabled, a schema containing an
external `$ref` fails to compile rather than resolving. That is the correct
outcome, and §6 defines what happens to such a tool.

### Unsafe-code surface — measured, then dropped as an argument

`jsonschema`'s minimal tree pulls SIMD crates that cannot be feature-disabled:
`vsimd` 0.8.0 (489 `unsafe` sites), `uuid-simd` 0.8.0 (43), `outref` 0.5.2 (21),
`ahash` 0.8.12 (8) — roughly 553 sites. `boon`'s new crates total roughly 12.

That reads alarming until it is given a denominator. The same `rg` method over
**fifteen** crates already in this tree — `ring`, `aws-lc-rs`, `aws-lc-sys`,
`tokio`, `bytes`, `dashmap`, `parking_lot`, `parking_lot_core`, `serde_json`,
`hashbrown`, `memchr`, `regex-automata`, `rustls`, `smallvec`, `crossbeam-utils` —
counts **15,873** sites (one version of each; `aws-lc-sys` alone is 12,543).
`jsonschema`'s addition is ~3.5% of a sample drawn from 15 of 386 packages.

`#![deny(unsafe_code)]` is a crate-level lint. It has never applied to
dependencies and does not here. The honest conclusion: **the unsafe delta does not
discriminate between these two candidates**, and this design does not use it as
one. It is recorded because a reviewer would otherwise raise it, and because the
absolute number is worth knowing before the runtime increment lands.

### Licences of the transitives (D30, first half)

Measured with `cargo metadata --format-version 1` over the probe workspace,
restricted to packages new to this tree:

- `jsonschema` (minimal), 26 new packages: MIT 13, `MIT OR Apache-2.0` 8,
  `Apache-2.0 OR MIT` 1, `Apache-2.0/MIT` 1, `MIT/Apache-2.0` 1, `MIT-0` 1,
  `Apache-2.0` 1. All permissive.
- `boon`, 7 new packages: `MIT OR Apache-2.0` 4, MIT 2, `MIT-0` 1.

Neither introduces a copyleft obligation, and no new package is unlicensed.
`scripts/ci/check-license-headers.sh` governs source files in this repository, not
dependency licences, so this check has no existing automation and is recorded here
as evidence.

## 5. Where validation runs

Four candidate sites, and the answer is a **combination** — because the two
populations of §2 want different things.

| site | population | cost | verdict |
|---|---|---|---|
| CI test only | G-A | zero at runtime | **yes — this is what closes the criterion** |
| config load | — | — | no: schemas are not in configuration |
| tool registration (`prepare_tool_metadata`) | G-B | measured below | **yes, as a later increment** |
| every `tools/list` response | both | per-request, repeated | no |

### Measured cost

Probe workspace, `jsonschema` 0.52 with `default-features = false`, release build,
against a schema shaped like `gateway_invoke`'s (`type`/`properties`/`required`,
four properties, one nested array-of-object):

- `jsonschema::meta::validate` over 38 documents: **90 µs**
- `jsonschema::validator_for` (full compile) over the same 38: **429 µs**

Measurement contract, stated because revision 1 gave the numbers without one: n = 38
synthetic documents, single run, no warm-up, release build, `default-features = false`,
in the throwaway probe workspace. Host and exact command were **not recorded**, and
these figures are not repeated — they are an order-of-magnitude check, not a benchmark.
Two things follow. The 38 was a miscount of the surface (F5); the real G-A surface is
20 documents, so the true cost is *lower* than quoted, and the figures are deliberately
**not rescaled** — a number that was measured stays as measured. And the increment-1
implementer records n, host and command properly (U6a).

Sub-millisecond for the entire advertised surface. Startup cost is not a
consideration at this scale; the reason to keep validation off the per-request
path is that repeating a check whose inputs did not change is waste, not that it
is slow.

The metaschema check succeeds with `resolve-http` and `resolve-file` disabled,
which shows the 2020-12 metaschema is embedded in the crate and no network access
is required for the check itself.

### G-A: a CI test, and the validator stays a dev-dependency

The gateway's own schemas are static. A `#[test]` that drives the real
`MetaMcp::handle_tools_list` — the same entry point `tests/mik_7272_exploit_acs.rs`
already uses for the sibling clause — and validates every returned `inputSchema` and
`outputSchema` closes `MIK-6865.SCHEMA.1` **for G-A**. A regression introduced by a
future hand-edit then fails the build.

#### The absence check needs a positive control (F1)

Revision 1 specified only "metaschema-validates every returned schema". That
acceptance criterion **cannot fail**: a helper that returns `Ok(())` unconditionally,
or wiring that never reaches the schemas, satisfies it exactly as well as a working
check does. The repair is not a stronger sentence — it is criteria the same helper
must *reject*. The sibling clause already has this shape:
`ac_schema_1_the_detector_finds_the_shape_it_is_looking_for` in
`tests/mik_7272_exploit_acs.rs` asserts the detector fires on a crafted offender,
with the comment that an absence-check which cannot see the thing "would pass on an
empty tool list just as happily".

Increment 1 therefore carries five criteria, all against **one** helper:

| id | fixture | must |
|---|---|---|
| `SCHEMA.1.A1` | the live `tools/list` surface | pass |
| `SCHEMA.1.A2` | `"type": "strig"` | **reject** — `type` is constrained to the simple-type enum |
| `SCHEMA.1.A3` | `"required": "name"` (string, not array) | **reject** — `required` must be an array |
| `SCHEMA.1.A4` | `"oneOf": ["a"]` (string arm) | **reject** — an arm must be a schema |
| `SCHEMA.1.A5` | `"$ref": "#/$defs/nope"` (local, unresolvable) | **reject** |

A2-A4 are metaschema failures, caught by `jsonschema::meta::validate`. A5 is **not** —
any string is a metaschema-valid `$ref` — so it is caught at compile, by
`validator_for`. The helper must therefore call **both**, in that order. That is also
what binds the two timed APIs of §5 to their call sites, which revision 1 left
implicit. A5 uses a **local** ref deliberately: an external `$ref` would make the
criterion depend on `resolve-http`/`resolve-file` being off, which no unknown measured
(see U11).

#### A1 must reach the union, not one variant (improvement 2)

`MetaMcp::new(Arc::new(BackendRegistry::new()))` over an empty registry takes the
default branch of `handle_tools_list` and reaches neither code-mode nor surfaced
tools: `code_mode_enabled` defaults to `false`, and the code-mode branch returns
`build_code_mode_tools()` — a disjoint pair of two. A1 therefore drives, at minimum,
the default branch, a `with_code_mode(true)` instance, and one `with_surfaced_tools`
fixture (the pattern already used in `src/gateway/router/tests.rs`). Without all
three, "every returned schema" means "every schema in whichever variant the test
happened to construct" — which is how a 20-document surface gets certified by a
14-document test. `handle_tools_list_filtered` (`spec-preview`) is a fourth variant
and is deliberately **out of scope for increment 1**: it pulls in G-B and G-C.

Consequences of dev-dependency-only placement, all of them wanted:

- nothing new ships in the release binary or the container image;
- the validator is not on the trust path, so its unsafe surface and its
  network-resolution features are moot for this increment;
- it still lands in `Cargo.lock`, so `cargo audit` covers it — the supply-chain
  gate applies without the runtime exposure.

### G-B: a runtime check at the ingest chokepoint for MCP backends

`prepare_tool_metadata` is the one place every *MCP backend* tool list passes
through before it is cached, and it already drops malformed tools. Validation
belongs there, in the same pass. It is the chokepoint for G-B and only for G-B:
capability-YAML tools (G-C) never reach it, which is what increment 3 exists to
cover. Within G-B it is the only sensible site — validating at `tools/list` time
would
re-check identical cached data on every request and would not stop an invalid
schema from entering the cache in the first place.

This is increment 2. It requires promoting the crate to `[dependencies]`, and it
lands in `src/backend/annotations.rs`, whose SPDX header is
`PolyForm-Noncommercial-1.0.0` — so the runtime guard is an EE-licensed path.
That is a deliberate consequence of putting the check where the existing
tool-integrity filtering already lives, not an accident; splitting it out to keep
it MIT would mean a second ingest point, which is the defect this design avoids.

### Dialect resolution — name the rule or the guard causes an outage

MCP `inputSchema` documents usually carry no `$schema` keyword. The probes above
pinned the 2020-12 dialect explicitly. A backend emitting a schema that declares
`"$schema": "http://json-schema.org/draft-07/schema#"` and uses boolean
`exclusiveMinimum`, the array form of `items`, or `definitions` is **valid
draft-07** and would fail a forced-2020-12 check.

Revision 1 made auto-detection the rule for everything, which quietly means the
gateway keeps advertising documents the criterion says must be valid 2020-12. That is
a real conflict and it is not the implementer's to settle silently. **Decision, taken
here and owed upward:**

**G-A — forced 2020-12, no auto-detection, no exception.** We author these. A gateway
schema that declared draft-07 would be a bug, not a compatibility case. Increment 1
validates against 2020-12 unconditionally, so the dialect question does not exist for
the population that closes the criterion.

**G-B and G-C — declared-dialect validation, under a named SCHEMA.1 exception.** The
criterion binds what the gateway *authors*; dropping a third party's correct draft-07
tool is an availability incident caused by our own guard. So an explicit non-2020-12
`$schema` is validated against its declared dialect and **counted**, separately, in
the warn-mode metric of §6. The exception is recorded in the criterion, not hidden in
the code: SCHEMA.1 is met unqualified for G-A, and met-with-a-named-exception for
re-served third-party schemas.

**The common case is neither, and revision 1 missed it.** MCP `inputSchema` documents
*usually carry no `$schema` at all* — this document says so two paragraphs above. A
no-`$schema` document using array-form `items` or boolean `exclusiveMinimum` gets no
exception under the rule above: it is defaulted to 2020-12 and it fails. **That** is
the availability case, and it is the frequent one. It gets its own counter in the
warn-mode metric, distinct from the declared-dialect counter, so the operator sees
which of the two they actually have before any policy flips to rejection.

The distinction drawn in §1 does the rest of the work here: array-form `items` and
boolean `exclusiveMinimum` are hard failures; `definitions` and `$recursiveRef` pass
as unknown keywords. A guard rejects the first pair and silently tolerates the second,
and the metric should not conflate them.

Cost to existing backends: **none today.** Increment 2 ships warn-only (§6), so
nothing disappears from the surface in either case. What the decision buys is that the
numbers arrive before the policy does. Escalation: the exception narrows a release
criterion, so it is the operator's to accept — see U12.

## 6. Policy for an invalid backend schema

Three options. The question is which failure mode is worse.

| option | blast radius | failure mode |
|---|---|---|
| **drop the offending tool, keep the backend** | one tool | that tool disappears from the surface |
| serve it with a warning | every client | the gateway becomes an amplifier for a malformed schema |
| refuse the whole backend | every tool on that backend | one bad tool blacks out forty good ones |

**Decision: drop the offending tool, keep the backend.**

### Why, argued rather than asserted

*Serving with a warning* is the worst of the three. A warning is written to the
gateway's log, where the gateway's operator may read it; the malformed schema is
sent to the client, where a model consumes it. The party who can act never sees
the signal and the party who sees the signal cannot act. Worse, it makes the
gateway an amplifier: the whole premise of the compact Meta-MCP surface is that
clients trust what the gateway advertises. Re-serving something the gateway has
just determined to be invalid, while logging that it is invalid, is the one
outcome that adds a security property nobody had before — the gateway's
endorsement — to content that failed its own check.

*Refusing the whole backend* fails the proportionality test: blast radius should
equal fault radius. A backend advertising forty tools, one of which has a typo in
its schema, would go dark entirely. That converts a cosmetic defect in a third
party into a self-inflicted outage, and it hands any single compromised or buggy
tool a denial-of-service lever over its entire server.

*Dropping the tool* is the only option where blast radius equals fault radius, and
it is **not a new policy** — it is the policy this repository already applies at
exactly this call site. `prepare_tool_metadata` calls `exclude_invalid_header_tools`,
and `src/backend/tests.rs` pins the behaviour:
`prepare_tool_metadata_drops_only_the_violating_tool`,
`prepare_tool_metadata_drops_a_crlf_injection_attempt`,
`prepare_tool_metadata_keeps_a_well_formed_annotation`,
`prepare_tool_metadata_leaves_unannotated_tools_untouched`,
`prepare_tool_metadata_excludes_and_annotates_in_one_pass`.
Choosing anything else would mean two adjacent checks in one function disagreeing
about what a malformed tool deserves.

### The compatibility hazard, named

A tool that works **today** — because clients happen to tolerate its sloppy schema —
would vanish the day the guard ships. That is a behaviour change visible to users,
not an internal repair. Under the delivery process it is a design event and needs
the requester's agreement rather than an implementer's assumption.

Recommended shape for increment 2, therefore:

1. ship the check in **warn + metric** mode first — count invalid schemas per
   backend, emit a structured log line naming backend, tool and the failing
   keyword path, drop nothing;
2. let one release cycle produce a real count of how many live tools are affected;
3. flip to **drop** in a later release, behind a configuration flag whose default
   is the mode the observed count justifies.

Step 2 is the point. The right default is an empirical question, and the current
answer is unknown: this design has no measurement of how many real backend schemas
would fail. Shipping the drop first would answer it by breaking people.

`resolve-http` being disabled means an external `$ref` compiles as a failure. Such
a tool is treated exactly like any other invalid schema — warn now, drop later —
and the log line should distinguish "unresolvable reference" from "malformed
document", because the two have different remediations for the backend author.

## 7. DoD D30 supply-chain gate, concretely

D30 requires: new dependency audited at merge, lock hashes pinned, HIGH SCA
findings block. What that means here, step by step:

| requirement | how it is satisfied | evidence |
|---|---|---|
| advisory scan of the new subtree | `cargo audit` over a lockfile containing the candidate | run 2026-08-31 in the probe workspace: 1,233 advisories loaded, 238 crate dependencies scanned, **exit 0, zero findings** |
| audit runs at merge, not once | the existing `audit` job (`ci.yml:212`) already runs `cargo audit` on every push | no new CI wiring needed; a dev-dependency is in `Cargo.lock` and is therefore in scope |
| lock hashes pinned | `Cargo.lock` is committed and the published crate ships it (`include` list in the manifest) | existing repository practice |
| exact version pinned, not a range | the increment declares `jsonschema = { version = "0.52", default-features = false }` and lets `Cargo.lock` fix the patch | `Cargo.lock` is the pin |
| dependency licences reviewed | `cargo metadata` over the new subtree | §4: 26 new packages, all permissive, no copyleft, none unlicensed |
| feature surface reviewed | `default-features = false` asserted, not assumed | §4: `resolve-http` / `resolve-file` are an SSRF primitive on the G-B path |
| HIGH finding blocks | `cargo audit` non-zero fails the job, and the release path depends on that job | existing behaviour |

Three things D30 does **not** currently cover here, stated so they are not
mistaken for covered:

- **No `cargo deny`.** There is no licence-policy or duplicate-version gate in CI;
  the licence review in §4 is a one-off human check, not automation. Adding
  `cargo deny` is out of scope for this criterion and worth its own ticket.
- **Advisory latency.** `cargo audit` reports what RustSec knows. A validator that
  becomes unmaintained shows up when someone files the advisory, not when the
  maintainer stops. That latency is precisely the risk §4 weighs, and it is
  managed by picking the actively released crate, not by the gate.
- **The audit job does not fail on an unmaintained advisory.** Revision 1 claimed
  the CI audit gate would flag `boon` if RustSec ever marked it unmaintained. That
  claim is withdrawn: `ci.yml:223` runs a bare `cargo audit` with no
  `--deny warnings`, and there is no `audit.toml` or `deny.toml` anywhere in the
  tree, so informational and `unmaintained` advisories are printed as warnings and
  the job still exits 0. Only a vulnerability advisory fails the build. The choice
  of `jsonschema` in §4 therefore rests on release recency alone — the gate does
  not back it up (F3).

## 8. Options rejected, and what is out of scope

### Rejected

- **Hand-rolling a 2020-12 checker.** The metaschema is large, the dialect rules
  are subtle (`prefixItems`, `$dynamicRef`, `$defs`, the numeric-keyword type
  changes), and a partial checker that returns "valid" for a schema it did not
  fully understand is worse than no checker — it converts an untested property
  into a falsely tested one. Rejected on correctness, before cost.
- **Typing `Tool::input_schema` as a generated schema type.** Would require
  `schemars` plus a protocol change to `src/protocol/types.rs`, breaks the
  pass-through of backend schemas that the gateway must re-serve verbatim, and
  does not answer the question asked. Rejected on scope and on category.
- **Validating on every `tools/list` response.** Repeats an identical check
  against cached data on every request, and still admits invalid schemas to the
  cache. The ingest chokepoint dominates it on both counts.
- **A `build.rs` compile-time check of the gateway's own schemas.** Same coverage
  as the CI test, but it puts the validator on every contributor's build path and
  makes a schema error a build failure with worse diagnostics than a test failure.
  The test is the cheaper shape.
- **`valico` and `jsonschema-valid`.** No 2020-12 support; see §3.

### Out of scope for this criterion

- **Instance validation of tool *arguments* against `inputSchema`.** That is
  runtime argument checking on the `gateway_invoke` path, a different property with
  a different threat model. This criterion is about the schema documents only.
- **Semantic quality of schemas** — whether descriptions are useful, whether
  `required` is right, whether a model can actually fill the shape. Not validity.
- **The sibling nested-object-in-array clause**, already `MET`.
- **Adding `cargo deny`** (see §7).
- **Any change to `src/gateway/meta_mcp_tool_defs.rs`.** If the CI test of §5
  fails, the schemas get fixed — but this design predicts it passes, and fixing a
  failure that has not happened is not a design decision to take in advance.

## 9. Unknowns

Each one carries the command that resolves it. The runnable ones were run, and
their answers are recorded inline.

| # | unknown | resolving command | answer |
|---|---|---|---|
| U1 | Is any validator already present? | `rg -ni "jsonschema\|json_schema\|json-schema\|valico\|schemars\|boon" Cargo.toml Cargo.lock` | **RESOLVED** — zero matches. Nothing declared, nothing transitively present. |
| U2 | How many packages does each candidate add to *this* tree? | `cargo tree --edges normal` in a probe workspace, diffed against the 386 unique names in `Cargo.lock` | **RESOLVED** — `jsonschema` minimal +26, `jsonschema` default +26 (140 total vs 62), `boon` +7, `valico` +14. |
| U3 | Do the candidates or their new transitives carry advisories? | `cargo audit` on the probe lockfile | **RESOLVED** — 2026-08-31: 1,233 advisories loaded, 238 dependencies scanned, exit 0, no findings. |
| U4 | Are the new transitive licences compatible with the MIT-core / PolyForm split? | `cargo metadata --format-version 1`, licence per new package | **RESOLVED** — all permissive; `jsonschema` 26 new packages (MIT 13, dual-licence 11, `MIT-0` 1, Apache-2.0 1), `boon` 7 (dual 4, MIT 2, `MIT-0` 1). No copyleft, none unlicensed. |
| U5 | Is `boon` abandoned, or merely quiet on releases? | GitHub commits API on `santhosh-tekuri/boon` | **RESOLVED** — last commit 2026-02-23 (six months), last release 2025-01-07 (twenty months). Not abandoned; on the edge of the advisory window. That gap is what §4 turns on. |
| U6 | What does validation cost at startup? | timed `jsonschema::meta::validate` and `jsonschema::validator_for` over representative documents, release build | **RESOLVED, with a correction** — 38 *synthetic* documents: 90 µs metaschema, 429 µs full compile. The 38 was a miscount of the G-A surface (F5, §2); the real surface is 20 documents, so the true cost is lower than quoted. Sub-millisecond either way; not a constraint. Measurement contract in §5. |
| U6a | What are n, host and command for a figure this design quotes as cost? | record them alongside any timing the increment produces | **DEFERRED.** Owner: increment-1 implementer. Trigger: increment 1. The U6 numbers were taken in a throwaway probe workspace with host and command unrecorded, which is why they are an order-of-magnitude check and not a benchmark. Fallback if the real figures are worse: they are still compared against a per-`tools/list` budget, and §5 already shows two orders of magnitude of headroom. |
| U7 | Does the crate honour an explicit `$schema`, and what does it default to? | probe: draft-07 document using array-form `items` and `definitions`, validated three ways | **RESOLVED** — with `$schema: draft-07` present, `jsonschema::meta::validate` returns `Ok`; the same document forced to 2020-12 fails; with `$schema` removed it fails, i.e. the default is 2020-12. Rule 1 and rule 2 of §5 are the crate's own behaviour — no custom dialect dispatch is needed. |
| U8 | Does the metaschema check need network access? | probe built with `default-features = false` | **RESOLVED** — succeeds with `resolve-http` and `resolve-file` off; the 2020-12 metaschema is embedded. |
| U9 | Do the 20 gateway-authored schemas actually pass? | the CI test of §5, once the dev-dependency exists | **DEFERRED.** Owner: increment-1 implementer. Trigger: increment 1. Fallback if it fails: the schemas are `type`/`properties`/`required` only — a keyword census over `src/gateway/meta_mcp_tool_defs.rs` returns 3 hits in 836 lines — so any failure will be a local typo, fixed in the same increment; it does not reopen this design. |
| U10 | How many *live* backend schemas would the G-B guard reject? | the warn-mode metric of §6, over one release cycle | **DEFERRED.** Owner: operator. Trigger: increment 2 ships in warn mode. Fallback if the count is high: stay in warn mode and publish the failing keyword paths to backend authors before flipping the default. Nothing in increment 1 depends on this answer. |
| U11 | Does `jsonschema::validator_for` reject a *local* unresolvable `$ref` (`#/$defs/nope`) when `resolve-http` and `resolve-file` are off? | build the AC A5 fixture in the probe workspace and assert the compile errors | **DEFERRED.** Owner: increment-1 implementer. Trigger: writing AC `SCHEMA.1.A5`. U8 showed the 2020-12 metaschema is embedded and needs no network, but that is a different question from whether an unresolvable *local* pointer is an error at compile time. Fallback if it does not reject: A5 moves to an assertion over the compile result's own diagnostics, or is replaced by a second metaschema-level rejection case — either way it stays a criterion that can fail, which is the point of F1. |
| U12 | Does the operator accept a SCHEMA.1 exception for re-served third-party schemas? | put the §5 dialect decision to the operator | **DEFERRED.** Owner: operator. Trigger: before increment 2 changes any default. G-A is unconditional 2020-12 and needs no exception, so `MIK-6865.SCHEMA.1` closes for the population the gateway authors without this answer. What needs accepting is the narrower claim for G-B and G-C. Fallback if it is refused: the guard rejects declared draft-07 documents outright, which is an availability decision with a measured cost — the warn-mode counters of §6 exist to price it first. |

Five unknowns are deferred rather than assumed, and each names an owner, a
trigger and what happens if it resolves badly. Nothing increment 1 delivers turns
on any of them: U9 can only produce a local fix, U6a improves a figure whose
headroom is already two orders of magnitude, U11 changes the shape of one
acceptance criterion but not whether it exists, and U10 and U12 are both operator
decisions gating increment 2, not increment 1.

## 10. Sequencing

1. **Increment 1 — closes `MIK-6865.SCHEMA.1`.** Add `jsonschema` 0.52 with
   `default-features = false` to `[dev-dependencies]`. Add a test that drives the
   real `handle_tools_list` and metaschema-validates every `inputSchema` and
   `outputSchema` it returns. Nothing ships in the binary. Release-blocking
   criterion moves `UNTESTED` → `MET` **for G-A**, with a test path as its
   evidence and the G-B/G-C dialect exception named in the criterion (U12).
   This design does not touch that status row; increment 1 owns the edit, and
   `docs/requirements/RELEASE-4.0.0-criteria-status.md` line 102 deliberately
   still reads `UNTESTED`.
2. **Increment 2 — the untrusted half.** Promote the crate to `[dependencies]`,
   add the check to `prepare_tool_metadata`, ship in warn + metric mode, and
   record the drop-versus-warn default as a decision the operator makes on the
   evidence from U10.

3. **Increment 3 — the capability path.** `CapabilityBackend::get_tools` returns
   the `IndexedCapabilities` cache directly and never reaches
   `prepare_tool_metadata`, so increment 2 does not cover it (§2, F2). The check
   belongs at `to_mcp_tool()` or at the cache write in `upsert`/`replace_all`;
   that placement is increment 3's decision, not this design's, because it also
   has to account for the four other `to_mcp_tool()` callers.

Splitting this way keeps increment 1 to one hop, keeps the release binary
unchanged, and leaves the policy question of §6 to be answered by measurement
rather than by assumption.

## 11. Revision 2 — dispositions

Revision 1 was reviewed by two vendors. Every finding and improvement below is
answered; nothing is left to be inferred from a diff.

| # | finding | disposition |
|---|---|---|
| F1 | the acceptance criterion cannot fail | **repaired** — §5 now carries five criteria against one helper, four of which must be *rejected*. The absence check gets the positive control the sibling clause already has. |
| F2 | the single-chokepoint claim is wrong | **eliminated** — the claim is not patched, it is replaced. §2 now describes three populations (G-A authored, G-B re-served, G-C capability-YAML) and the corrected ingest map showing G-C bypassing `prepare_tool_metadata` entirely. §10 adds increment 3 to cover it. |
| F3 | the CI audit gate does not back the crate choice | **closed on inspection, claim withdrawn** — killing source: `ci.yml:223` is a bare `cargo audit` with no `--deny warnings`, and `fd` finds zero `audit.toml` or `deny.toml` in the tree, so an `unmaintained` advisory warns and exits 0. §4 now rests on release recency alone and §7 states the gap. |
| F4 | draft-07 auto-detection contradicts the criterion | **decided and escalated** — G-A forced 2020-12, no exception; G-B and G-C validated at their declared dialect under a named exception; and the case revision 1 missed, a document with no `$schema` at all, gets its own counter because it is the common one. Cost today is zero (increment 2 is warn-only). The exception narrows a release criterion, so U12 puts it to the operator. |
| F5 | the 38-schema count is not the surface | **repaired** — 38 was a line-match count. §2 now gives 19 `Tool { .. }` constructors plus one `output_schema` = 20 documents, and notes that a single configuration advertises 14-17 of them. The §5 timings keep their measured `n = 38` deliberately and say why. |
| I1 | bind the two timed APIs to call sites | **accepted** — the F1 helper calls `meta::validate` then `validator_for`, which is exactly the pair §5 times. |
| I2 | one `MetaMcp` variant is not the surface | **accepted** — AC A1 drives at least three variants (default, `with_code_mode(true)`, one `with_surfaced_tools`); the `spec-preview` filtered path is named as a fourth and put out of scope for increment 1. |
| I3 | the timings have no measurement contract | **accepted** — §5 states n, build profile, feature flags and single-run-no-warm-up, and admits host and command were not recorded. The figures are not rescaled to 20; U6a makes the increment-1 implementer record them properly. |
