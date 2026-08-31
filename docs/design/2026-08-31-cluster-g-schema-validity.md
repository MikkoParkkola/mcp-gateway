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
  blocked release, on someone else's schedule.
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
