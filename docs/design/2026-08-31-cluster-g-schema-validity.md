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
   A schema using the draft-07 spelling is *valid draft-07* and *not valid 2020-12*.
3. **Reference resolution.** Every `$ref` resolves — against `$id`/`$anchor`
   within the document, or to an external resource. An unresolvable `$ref` is a
   compile failure, not a validation failure, and it is the failure mode that
   turns into an availability incident.
4. **Composition well-formedness.** `allOf`/`anyOf`/`oneOf`/`not`/`if-then-else`
   take schema values, and a schema is an object or a boolean — never a string.

The check is "does this document compile as a 2020-12 schema", not "does some
instance validate against it". No instance data is involved.

## 2. Two schema populations, not one

The criterion reads as one property. The code has two disjoint populations with
different trust levels, different failure modes and different costs. Costing them
as one is the mistake this section exists to prevent.

### G-A — the gateway's own surface (trusted, static)

Hand-authored in `src/gateway/meta_mcp_tool_defs.rs`: 38 `Tool { .. }` literals
built by `build_list_servers_tool`, `build_list_tools_tool`, `build_search_tools_tool`,
`build_invoke_tool` and their annotation helpers, with exactly one
`output_schema: Some(search_tools_output_schema())`. Served through
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

Both populations enter through one chokepoint: `Backend::get_tools_shared`
(`src/backend/metadata.rs:136`) deserialises `ToolsListResult` and calls
`prepare_tool_metadata(&self.name, &mut tools)` before anything is cached. That
function (`src/backend/annotations.rs:152`) already runs
`exclude_invalid_header_tools` and `normalize_tool_annotations`. A schema check
belongs there or nowhere.

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

- An unmaintained validator on the untrusted-input path attracts a RUSTSEC
  `unmaintained` advisory. The CI `audit` job (`ci.yml:212`) runs `cargo audit`,
  and the release path depends on it. A RUSTSEC advisory against `boon` becomes a
  blocked release, on someone else's schedule. No such advisory exists today:
  U3's `cargo audit` run covered every candidate and returned nothing. The risk
  is prospective, so the tiebreak is really which failure mode is preferable to
  own — a larger build, or a release blocked on a third party's advisory timing.
- `jsonschema`'s bulk has no wired consequence: 26 additional packages on an
  existing 386, and a one-off compile cost behind `Swatinem/rust-cache`, which
  that same job already uses.

`boon`'s last *commit* is 2026-02-23 — six months, not the nineteen its release
date suggests, so it is not abandoned. But six months of commit silence and
twenty months of release silence sit on the edge of the advisory window, and the
tiebreak goes to the crate whose failure mode is "slightly larger build".

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

- metaschema validation, 38 schemas (the whole G-A surface): **90 µs**
- full `compile()` of the same 38: **429 µs**

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
already uses for the sibling clause — and metaschema-validates every returned
`inputSchema` and `outputSchema` closes `MIK-6865.SCHEMA.1` outright. A regression
introduced by a future hand-edit then fails the build.

Consequences of dev-dependency-only placement, all of them wanted:

- nothing new ships in the release binary or the container image;
- the validator is not on the trust path, so its unsafe surface and its
  network-resolution features are moot for this increment;
- it still lands in `Cargo.lock`, so `cargo audit` covers it — the supply-chain
  gate applies without the runtime exposure.

### G-B: a runtime check at the single ingest chokepoint

`prepare_tool_metadata` is the one place every backend tool list passes through
before it is cached, and it already drops malformed tools. Validation belongs
there, in the same pass, and nowhere else — validating at `tools/list` time would
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

Rule for the implementing increment:

1. If the document carries an explicit `$schema`, validate against **that**
   dialect. `jsonschema` auto-detects; draft-07, 2019-09 and 2020-12 are all
   supported.
2. If `$schema` is absent, default to **2020-12**, matching the MCP specification.

Both steps are the crate's own default behaviour: `jsonschema::meta::validate`
honours an explicit `$schema` and falls back to 2020-12 when none is present,
measured in U7. The implementer calls that function and writes no dialect
branch of their own.

Without rule 1 the security guard becomes an availability incident: correct
draft-07 tools would silently disappear from the surface.

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

Two things D30 does **not** currently cover here, stated so they are not mistaken
for covered:

- **No `cargo deny`.** There is no licence-policy or duplicate-version gate in CI;
  the licence review in §4 is a one-off human check, not automation. Adding
  `cargo deny` is out of scope for this criterion and worth its own ticket.
- **Advisory latency.** `cargo audit` reports what RustSec knows. A validator that
  becomes unmaintained shows up when someone files the advisory, not when the
  maintainer stops. That latency is precisely the risk §4 weighs, and it is
  managed by picking the actively released crate, not by the gate.

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
| U6 | What does validation cost at startup? | timed metaschema validation and `compile()` over a representative schema, release build | **RESOLVED** — 38 schemas: 90 µs metaschema, 429 µs full compile. Sub-millisecond; not a constraint. |
| U7 | Does the crate honour an explicit `$schema`, and what does it default to? | probe: draft-07 document using array-form `items` and `definitions`, validated three ways | **RESOLVED** — with `$schema: draft-07` present, `jsonschema::meta::validate` returns `Ok`; the same document forced to 2020-12 fails; with `$schema` removed it fails, i.e. the default is 2020-12. Rule 1 and rule 2 of §5 are the crate's own behaviour — no custom dialect dispatch is needed. |
| U8 | Does the metaschema check need network access? | probe built with `default-features = false` | **RESOLVED** — succeeds with `resolve-http` and `resolve-file` off; the 2020-12 metaschema is embedded. |
| U9 | Do the 38 gateway-authored schemas actually pass? | the CI test of §5, once the dev-dependency exists | **DEFERRED.** Owner: increment-1 implementer. Trigger: increment 1. Fallback if it fails: the schemas are `type`/`properties`/`required` only — a keyword census over `src/gateway/meta_mcp_tool_defs.rs` returns 3 hits in 836 lines — so any failure will be a local typo, fixed in the same increment; it does not reopen this design. |
| U10 | How many *live* backend schemas would the G-B guard reject? | the warn-mode metric of §6, over one release cycle | **DEFERRED.** Owner: operator. Trigger: increment 2 ships in warn mode. Fallback if the count is high: stay in warn mode and publish the failing keyword paths to backend authors before flipping the default. Nothing in increment 1 depends on this answer. |

U9 and U10 are deferred rather than assumed, and nothing this design decides
turns on either: increment 1 is scoped so U9 can only produce a local fix, and the
drop-versus-warn default in §6 is explicitly held open until U10 has a number.

## 10. Sequencing

1. **Increment 1 — closes `MIK-6865.SCHEMA.1`.** Add `jsonschema` 0.52 with
   `default-features = false` to `[dev-dependencies]`. Add a test that drives the
   real `handle_tools_list` and metaschema-validates every `inputSchema` and
   `outputSchema` it returns. Nothing ships in the binary. Release-blocking
   criterion moves `UNTESTED` → `MET` with a test path as its evidence.
   This design does not touch that status row; increment 1 owns the edit, and
   `docs/requirements/RELEASE-4.0.0-criteria-status.md` line 102 deliberately
   still reads `UNTESTED`.
2. **Increment 2 — the untrusted half.** Promote the crate to `[dependencies]`,
   add the check to `prepare_tool_metadata`, ship in warn + metric mode, and
   record the drop-versus-warn default as a decision the operator makes on the
   evidence from U10.

Splitting this way keeps increment 1 to one hop, keeps the release binary
unchanged, and leaves the policy question of §6 to be answered by measurement
rather than by assumption.
