# MIK-8425 MIG.2: design for swapping the YAML backend to granit-parser (the serde-saphyr family)

Status: **the 4.0.0 plan** (refreshed 2026-10-24; first written 2026-10-20
as a fallback). Refs MIK-8425. Docs only: no code and no library swap.
`.github/osv-scanner.toml` is not touched.

## 4.0.0 refresh (2026-10-24)

**Why it changed.** The operator ruled on 2026-10-24: "Swap library before
tag". This replaces the 2026-10-22 ruling that moved MIG.2 to 4.1.0 on the
RUSTSEC-2024-0449 extension. The sections below are the plan. This section
records what changed since 2026-10-20 and the order for 4.0.0.

**The clock.**
- The exception in `.github/osv-scanner.toml` runs to 2026-11-05 (#4034,
  ab7e0455c). osv-scanner may stop honouring it at 2026-11-05T00:00Z, so
  2026-11-04 is the last full day to tag and publish.
- MIG.2 must merge, MIG.6 must remove the entry after a real scan, and the
  freeze grading must run on a commit that holds both, all before that day.

**Facts re-checked at line tip a00a88113** (Spark probe in a throwaway crate,
2026-10-24):
- serde-saphyr 2.0.0 (2026-10-13) and granit-parser 2.0.0 are still the
  latest releases.
- granit-parser 2.0.0 depends only on `arraydeque` and `smallvec`.
  serde-saphyr with `deserialize` and `serialize` adds about ten more small
  crates.
- `cargo tree -i unsafe-libyaml` finds nothing in either.
- Both crates declare `#![forbid(unsafe_code)]`.
- **granit-parser is already a dependency.** `Cargo.toml:148` pins
  `granit-parser = "=2.0.0"` (default features off; `std` and
  `error_messages`) for the MIK-8639 pre-parse guard in `src/yaml.rs`. MIG.2
  widens that crate's use and adds no new dependency.

**The compatibility oracle is the guarded adapter, not bare serde_yaml.**
Since MIK-8639, every read runs the granit pre-parse guard before serde_yaml.
Several rows in the D table below describe bare serde_yaml 0.9.34 and are
superseded by the guard. Where the two disagree,
`tests/fixtures/mik_8425_yaml/behaviour.txt` and the redaction suite, as
recorded at the line tip, win. In particular:
- **D19:** every guard refusal (the `Limit` kinds at `src/yaml.rs:82` on: size, depth, aliases, `%TAG` directives, expansion, anchor reuse, anchor names, disputed line breaks, and syntax) anywhere in a stream refuses it as a whole, with one
  error and no earlier documents (`behaviour.txt:90`, `stream/malformed-later`).
  A later document's semantic error is that document's own error, after
  which the iterator stops (`src/yaml.rs:715`);
- **hard requirement 1:** the pinned quoted-scalar and depth texts are the
  guard's (see the corrected list there);
- **errors:** the guard's `map_scan_error` (`src/yaml.rs:422`) and
  `syntax_what` (`src/yaml.rs:447`) are THE parser-error sanitizer. MIG.2
  reuses them when it splits the adapter and adds no second one.

**Spike results so far** (lane brief `mik-8425-mig2-spike-unverified-rows.md`,
2026-10-22, MIK-8425 comment cff8daa6):

| Spike | Result | Decision |
|---|---|---|
| S0, the typed API with every option | Differs on 10 scalar rows (`0755`, `1_000`, null-likes into String) and on the D19 stream rows (an empty middle document dropped; a malformed later document loses the first) | Dropped. The event design stays. |
| S1, the event source (granit-parser) | Raw text and style, tags, anchors and aliases, `<<` kept as a key, both duplicate entries, document boundaries and positions are all present | O1 is decided: **granit-parser directly**, the crate the guard already pins. The adapter needs none of serde-saphyr's typed layer. |
| S1, still to run | (a) budgets refuse before allocation; (b) a parser error converts with `leaks=false` on the B3 and `behaviour.txt` fixtures; (c) whether a synthesized empty value has a zero-width span, which is what tells `v:` (`""`) from `v: ~` | Step K0 below |
| S2, serde-saphyr's writer (O2b) | Not byte-equal under either `tagged_enums` setting. It double-quotes every ambiguous string and writes enums in map form | O2 is decided: **O2a**, the adapter's own libyaml-matched emitter |
| S3, G3 and duplicate keys | Not run | Step K0 below |

**Code at a00a88113.**
- `serde_yaml` is named in `src/yaml.rs` (736 lines) and in three test
  files, all listed in `tests/fixtures/mik_8425_yaml/direct_users.txt`:
  - `tests/mik_8425_yaml_adapter.rs`: 26 references, including figment's
    `providers::Yaml`, the live parity oracle;
  - `tests/mik_8639_shipped_yaml.rs`;
  - `tests/mik_8639_yaml_guard_bounds.rs`.
- Hard requirement 8 (no `unsafe-libyaml` in `Cargo.lock`) rules out keeping
  serde_yaml even as a dev-dependency. So in the swap PR, before serde_yaml
  and figment's `yaml` feature are dropped, each file's serde_yaml and figment
  `Yaml` comparisons are first recorded as golden rows; then the calls are
  removed. For the shipped-YAML walk, the directory walk stays. Each walked
  file gets a row (path, input sha256, accepted or refused, document count),
  and the test fails on a walked file with no row, or on a row whose sha256,
  outcome or document count no longer matches, so YAML added or edited later
  is still covered. The 1,100-document bound row asserts its literal count.
- Adapter use in `src/` and `tests/`:
  - typed reads: `from_str` 370, `from_str_loose` 17, `from_value` 8;
  - writes: `to_string` 87, `to_value` 17;
  - the tree: `Value` 164, `Mapping` 5;
  - `documents` 19, `figment_data` 7, `to_json` 2.
- Census of the classes G3 cares about in `src/`: 9 `#[serde(untagged)]`,
  8 `#[serde(tag = ...)]` and 7 `#[serde(flatten)]` sites. The MIG.2 plan
  narrows these to the types reachable from an adapter `from_str` target.

**G1 after the swap.** serde_yaml is gone from the build, so the "old parser
reads it back" half of G1 cannot run in the repository's CI. It is shown
twice instead:
- in CI, byte-equality with the MIG.0 goldens, which serde_yaml 0.9.34 wrote
  and read back when they were recorded;
- once on the PR's exact head SHA, by an out-of-tree Spark harness pinned to
  serde_yaml 0.9.34. It reads every file the new writer produces, for the
  golden inputs AND the generated S2 corpus (multiline strings, escaping,
  tags, numeric boundaries), and compares the values. Its output names that
  SHA and is attached to the PR. A later head needs a fresh run.

**Order for 4.0.0, with kill points.**
1. **K0, about a day, on the throwaway Spark harness:**
   - S1 (a)-(c);
   - S3, with one correction: under last-wins into a typed map, serde_yaml
     deserializes each value before inserting it, so `a: invalid` followed by
     `a: 2` into `BTreeMap<String, u8>` is refused. K0 records the guarded
     adapter's result for that case, and MIG.2 keeps validating values in
     order before the last-wins insert;
   - **an O2a emitter sketch**, which must be byte-equal to the
     `behaviour.txt` write rows, the `grants.txt` writer text and
     `url_render.txt`, and whose output serde_yaml 0.9.34 must read back to
     the same values on a generated corpus. The estimate is redone from the
     sketch.

   If any fails, stop and take the result to the operator. The options are
   then a second dated extension or tagging 4.0.0 on the current exception.
2. **Red first:** a comparison suite over every MIG.0 fixture
   (`behaviour.txt`, `trees.tsv`, `grants.txt`, `url_render.txt`,
   `redaction.txt`, `capabilities.tsv`), plus the G2 additions and the
   `figment_data` golden. It runs against the new backend's entry points,
   compiled beside the old adapter, and fails until they exist. The
   serde_yaml-backed adapter keeps passing the same suite throughout.
   In the same step, the bypass detector (`tests/mik_8425_yaml_adapter.rs:347`)
   learns `granit_parser`. It is allowed only in the adapter's own modules
   (`src/yaml.rs`, `src/yaml/`) and the comparison code, with a negative
   control for each, so a second YAML stack outside the seam fails CI once
   the `serde_yaml` identifier is gone.
3. **The swap, one PR, committed in reviewable steps:**
   - parse representation and tree;
   - the `Deserializer` over the representation, and the one over `Value`;
   - the `Serializer` and the O2a emitter;
   - errors;
   - the figment provider;
   - removing serde_yaml and figment's `yaml` feature (hard requirement 8).

   It needs the lead's exception to the 15-file PR cap.
4. **MIG.6, a separate PR after the swap merges:**
   - remove the RUSTSEC-2024-0449 entry only after a real osv-scanner run
     on that head passes without it;
   - update the "Known limitations" release note and drop the
     `dependency-licenses.tsv` rows.
5. **UPGRADING:** parity is the design goal, so no note is planned. Any
   difference the comparison suite finds that is kept goes in `upgrading.d`
   and to the seats as a decision.

**Effort and who writes it.**
- About 2,000-3,500 lines of product code (the 2026-10-20 estimate, with
  the emitter now certain), and as much again in tests.
- muse is out of quota until 2026-10-26. Until then the lane writes the
  code under the operator's standing exception, with per-hunk provenance.
- Each step goes through two seats, and the PR through the full gate and
  exact-head CI.
- Realistic: 4 to 6 working days to a green PR if K0 passes, counted from
  2026-10-24, because the lane writes now and does not wait for muse.
- **Checkpoint, 2026-10-28:** K0 done, the red suite in, and the parse
  representation and tree passing their rows. If not, the lead and the
  operator hear it that day, not on the decision date.
- **Proposed decision date:** if the swap PR is not green by 2026-11-01,
  the operator chooses between tagging on the current exception and a
  second extension.
- **Reserved after the swap:** 2026-11-02 for MIG.6 (its review, the real
  osv-scanner run and exact-head CI), then 2026-11-03 to 2026-11-04 for
  freeze grading, the tag and publish.

Parent design: `docs/internal/design/2026-10-17-mik-8425-yaml-migration.md`
(MIG.0 to MIG.6, gates G1 to G3). This note details MIG.2 and does not
replace it.

## Where the code stands (line tip f3191c740)

- Every YAML read and write goes through `src/yaml.rs` (MIG.1, enforced by
  the bypass gate). As of the 4.0.0 refresh, `direct_users.txt` allows four
  files to name serde_yaml: `src/yaml.rs`, `tests/mik_8425_yaml_adapter.rs`
  and the two MIK-8639 suites (see the refresh's code census).
- The adapter surface is `Value`, `Mapping`, `Error` (its own type,
  redacted, B3), `Location`, `from_str`, `from_str_loose`, `figment_data`,
  `to_string`, `to_value`, `from_value`, `documents`, `to_json` and
  `redact_message`. All are `pub(crate)`.
- The public API carries no YAML type. `ImportedSkill.extra` became
  `serde_json::Value` (B2), so the swap is internal.

## Hard requirements (the swap PR merges only when all hold on its exact head)

1. **Redaction, unchanged (B3).** The sentinel suite
   `tests/mik_8425_yaml_redaction.rs` passes unchanged:
   - all 15 tests;
   - the `custom_errors_never_format_a_value` guard.

   The goldens `tests/fixtures/mik_8425_yaml/redaction.txt` keep
   `leaks=false` on every value row. The rule is "no error prints the value
   that caused it, and each keeps the key path, the expected type and the
   line and column". Any test edit in that file is a guard change and goes
   to the seats.

   The suite pins these fixed refusal texts:
   - `quoted text is not closed, or continues with too little indentation`
     (the guard's wording, `tests/mik_8425_yaml_redaction.rs:160`);
   - `duplicate entry with key`;
   - `nesting deeper than 128 levels` (the guard's wording, `:191`);
   - `repetition limit exceeded`;
   - `this duration is longer than 100 years`.

   A backend that words any of them differently has to map it back to
   this text. Changing the pin instead is a seat-reviewed guard change.
2. **G1, rollback:** the new code writes grants and config byte-equal to
   the MIG.0 goldens (in CI), and serde_yaml 0.9.34 reads them back to the
   same value (the out-of-tree harness on the exact head SHA; serde_yaml is
   no longer in the build, see the 4.0.0 refresh).
3. **G2:** the sentinel is absent on every path. Point 1 is necessary but
   not sufficient. MIG.2 adds G2 cases that the B3 suite does not have,
   each checking Display and Debug:
   - an undefined alias. serde_yaml's unknown-anchor wording is pinned. The
     sentinel is a resolved value elsewhere in the same document, so the
     check is not vacuous, and it is the alias name only if `Display`
     actually echoes that name;
   - figment `ConfigFile::data` and the full `Config::load` extract;
   - `doctor/hidden_keys` and `commands/backend_url_keys`;
   - a multi-document refusal.
4. **G3, read-side enum parity:** the map form `agent: {exact: ...}` is
   still refused in YAML. This applies to the externally tagged enums. The
   untagged and internally tagged enums (for example `TransportConfig`)
   keep accepting maps, as they do today. The census counts only enums
   reachable from an adapter `from_str` target. The MIG.2 plan
   lists each class with its count, from a census of `#[serde(untagged)]`
   and `#[serde(tag = ...)]`.
5. **Duplicate-key parity** in all four destinations: struct, nested map,
   tree, and figment `Dict`. This includes a flattened untagged field, such
   as `BackendConfig.transport` (`#[serde(flatten)]` over an untagged
   enum). A `behaviour.txt` row is recorded for it with serde_yaml before
   the swap.
6. **Resource limits:**
   - depth 128 loads and 129 is refused;
   - the alias fan-out document loads at level 3 and is refused at level 4.
7. **MIG.3, MIG.4 and MIG.5** pass inside the same PR. MIG.3 is the
   comparison fixtures, MIG.4 the load_error properties, MIG.5 byte-level
   output.
8. **No legacy parser in `Cargo.lock`:**
   - `spark-cargo tree -i unsafe-libyaml` reports no match;
   - figment's `yaml` feature is dropped.
9. **No change visible to users** other than what the upgrade note names.
   Every such change goes through the fallback rule and gets a new
   reviewed decision.

## Behaviour differences between serde_yaml 0.9.34 and serde-saphyr 2.0.0

Each row says where it comes from: the 2026-10-17 Spark probe
(`docs/internal/analysis/evidence/2026-10-17-mik-8425-yaml-upstream.md`),
docs.rs, or "unverified" (the spike must confirm it).

| # | Behaviour | serde_yaml 0.9.34 | serde-saphyr 2.0.0 | Source | MIG.2 must |
|---|---|---|---|---|---|
| D1 | Duplicate key into a struct | refused, `duplicate field` | refused, `duplicate mapping key` | probe | keep refusing |
| D2 | Duplicate key into a map (`HashMap`, `BTreeMap`, nested in a struct) | **last value wins** | **refused** by default (`DuplicateKeyPolicy`) | probe | keep last-wins for maps, refusal for structs and the tree |
| D3 | Duplicate key into the tree (`Value`) | refused, `duplicate entry with key` | no tree type of its own | probe, code | adapter tree refuses |
| D4 | Duplicate key into figment `Dict` | last wins (`from_str_loose`) | n/a | code | keep last-wins |
| D5 | Enum written | tag form `!exact runner` | map form `exact: runner` | probe | keep the tag form (G1) |
| D6 | Enum read, map form | refused | **accepted** | probe | keep refusing (G3) |
| D7 | Enum read, tag form, both shapes | accepted | accepted, same value | probe | accept |
| D8 | Merge key `<<: *b` | not applied: `<<` is an ordinary key, and strict keys refuse it | **applied** by default (`MergeKeyPolicy::Merge`) | probe, docs.rs | treat as an ordinary key |
| D9 | `yes`/`no`/`on`/`off` into `bool` | refused | **accepted** as YAML 1.1 booleans by default | probe, docs.rs | refuse (strict booleans) |
| D10 | `yes` into `String` | `"yes"` | `"yes"` | probe | same |
| D11 | Error text shape | `<key path>: <serde message> at line L column C` | `error: line L column C: <message>`, **no key path** | probe | keep serde_yaml's shape (see Design 3) |
| D12 | Error snippet | none | **source snippet with the offending line** by default (`with_snippet`) | probe, docs.rs | no snippet. The snippet is a CWE-532 leak |
| D13 | Type-error wording | `invalid type: string "x", expected u16` (value redacted by B3) | `invalid u16` (no value) | probe | B3's redacted form |
| D14 | Syntax-error wording | libyaml's (`did not find expected ',' or ']'`) | its own (`unclosed bracket '['`) | probe, `syntax_what` (`src/yaml.rs:447`) | keep the guard's wording (`unclosed bracket` and the rest of `syntax_what`), which callers and tests already assert; no mapping back to libyaml (corrected 2026-10-24). A test-text change goes to the seats |
| D15 | Depth limit | 128 loads, 129 refused (now the guard's `nesting deeper than 128 levels`) | `Budget` setting | MIG.0 behaviour.txt, docs.rs | set the same limits explicitly |
| D16 | Alias expansion limit | level 3 loads, level 4 refused (`repetition limit exceeded`) | `Budget` and alias limits | MIG.0 behaviour.txt | set the same limits explicitly |
| D17 | Custom tags on plain values | kept in `Value::Tagged` | `reject_unsupported_tags` defaults to false, so they are kept | docs.rs (corrected in review) | custom tags become `Tagged`; standard tags (`!!str`, `!!int`, `!!float`, `!!bool`, `!!null`, `!!map`, `!!seq`) resolve as serde_yaml does; `!!merge <<` is an ordinary string key (MIG.0 fixture); a non-local URI tag (`!<tag:example.org,2026:kind>`) is dropped and its scalar read as a string, as serde_yaml does. The comparison fixtures pin both local and URI tags before S1 passes |
| D18 | Non-string keys, tags and non-finite numbers in the tree | `Value` holds them | no `Value` type | code | the adapter's own tree holds them; `to_json` rules unchanged (B2) |
| D19 | Multi-document stream | `from_str`, `from_str_loose` and figment refuse a second document with serde_yaml's multi-document error; the `Deserializer` iterator yields each document, an empty one as null | unverified | code, `behaviour.txt:85-90` | the single-document entry points return the same multi-document refusal; `documents()` yields every document, empty as null; every guard refusal (the `Limit` kinds at `src/yaml.rs:82` on: size, depth, aliases, `%TAG` directives, expansion, anchor reuse, anchor names, disputed line breaks, and syntax) anywhere in the stream refuses the whole stream before any document is read (`behaviour.txt:90`); a later document's semantic error (a duplicate key, a type error) is yielded as that document's own error after the earlier documents, and the iterator then stops with no later document (the bound at `src/yaml.rs:715`; corrected 2026-10-24) |
| D23 | Leading-zero plain decimal (`0755`) into a String or the tree | the string `"0755"` | unverified | `behaviour.txt:40` | string |
| D24 | Underscored integer (`1_000`) | string | unverified | `behaviour.txt:49` | string |
| D25 | `.inf`, `-.inf`, `.nan` into a float or the tree | accepted as floats | unverified | `behaviour.txt:55-63` | accepted |
| D26 | A scalar's spelling into a `String` target (`0o755`, `True`, `1e3`, `null`) | the original text | unverified | MIG.0 fixtures | the original text: resolve only when the target asks for a non-string |
| D20 | Writer formatting (quoting, indent, `---`, sequence style) | libyaml's emitter | its own emitter | unverified | byte-equal to the MIG.0 goldens (G1, MIG.5) |
| D21 | figment provider | figment's `yaml` feature (serde_yaml) | optional `figment` feature in serde-saphyr | crates.io deps | drop figment's `yaml`; feed `Dict` from the adapter |
| D22 | Error API | `location()`, `Display`, `Debug` | own error type | code | the adapter's `Error`/`Location` contract unchanged |

## Design

The rows above pull in one direction. serde-saphyr is used as a **parser
only**. Every typed read and write goes through the adapter's own tree and
its own serde implementations, where the gateway decides each behaviour.
serde-saphyr's typed `from_str` is never called on gateway types.

Why not call serde-saphyr's typed deserializer directly:
- its error text has no key path (D11), which MIG.4 requires;
- its defaults differ on D2, D6, D8 and D9;
- its policies are one setting per parse, so no single setting reproduces
  the four duplicate-key destinations (D2 to D4).

### 1. The adapter tree (`src/yaml/tree.rs`)

`Value` and `Mapping` become owned types in the adapter:
- `Null`, `Bool`, `Number` (i64, u64 or f64, with serde_yaml's
  distinctions), `String`, `Sequence`, `Mapping` (ordered, with any
  `Value` as key) and `Tagged { tag, value }`;
- source locations live on the parse representation (section 2). A
  materialized `Value` node does not carry one, which keeps `Value`
  comparisons and the public shape unchanged.

Its accessors match the MIG.1a inventory of the `Value` and `Mapping` API in
use (indexing, `get`, `as_*`, `is_*`, tag access, `Number`), so call sites
do not change. `to_json` keeps its B2 rules.

### 2. Reading: events into a parse representation, policy at the destination

The parser's event stream is turned into an internal **parse
representation**, not straight into `Value`. The event stream comes from
serde-saphyr's event-level API or from `granit-parser` directly, whichever
S1 shows exposes events, tags and positions; open decision O1. The parse
representation keeps what the destinations disagree on:
- **Mappings are ordered multimaps.** A repeated key is kept with both
  entries, and each destination applies its own rule when it materializes
  (D2 to D4):
  - `Value` and struct targets refuse;
  - map targets and figment `Dict` keep the last value.
- **Scalars stay unresolved.** Each keeps its decoded text, its style
  (plain or quoted) and any explicit tag. Resolution happens only when the
  destination asks for a type, with the rules of D9 and D23 to D26:
  - a `String` target gets the original text;
  - the tree resolves plain scalars as serde_yaml 0.9.34 does.
    `tests/fixtures/mik_8425_yaml/behaviour.txt` is the resolver's
    specification, not any YAML schema name. serde_yaml is not plain YAML
    1.2 core: `0755` stays the string `"0755"` (D23).
- **Tags** follow D17: standard tags resolve, custom tags become `Tagged`,
  and `!!merge <<` stays an ordinary key (D8).
- **Positions:** every node keeps its `Location`.
- **Budgets are explicit (D15, D16).** Depth is counted while events
  arrive. Alias expansion is counted before a node is copied, so the budget
  refuses a document before it allocates past the limit.
- **Documents:** the builder records document boundaries. The
  single-document entry points refuse a second document with the
  multi-document error. `documents()` yields each document, an empty one as
  null. Every guard refusal (the `Limit` kinds at `src/yaml.rs:82` on: size, depth, aliases, `%TAG` directives, expansion, anchor reuse, anchor names, disputed line breaks, and syntax) anywhere in the stream refuses the whole stream
  before any document is read (`behaviour.txt:90`). A later document's
  semantic error (a duplicate key, a type error) is yielded as that
  document's own error after the earlier documents, and the iterator then
  stops: no later document is yielded (the bound at `src/yaml.rs:715`; D19,
  corrected 2026-10-24).

### 3. Typed reads: a serde `Deserializer` over the parse representation

`from_str::<T>` parses, then deserializes `T` from the parse representation
with the adapter's own `Deserializer`, which reproduces serde_yaml's rules:
- **Enums:** for an externally tagged enum, a unit variant is read from a
  scalar of any style (plain or quoted: `agent: any` and `agent: "any"`
  both work, as with serde_yaml), and a non-unit variant only from a tag,
  so the map form is refused (G3, D6). Untagged and internally tagged enums are deserialized
  through serde's buffered `Content` path and keep accepting maps, as they
  do today. The class census is in the MIG.2 plan.
- **Repeated keys:** a map target keeps the last value, and a struct target
  refuses (D2).
- **Errors:**
  - the key path is tracked through the walk, so errors read
    `<key path>: <serde message> at line L column C` (D11), with the line
    and column from the node's `Location`;
  - messages are built by the adapter and never copied from the parser.
    `redact_message` still runs on every `Display`/`Debug` (B3), and no
    snippet ever exists (D12);
  - a parser error, such as a syntax error, is converted into the
    adapter's error with only its kind and position kept. Parser text never
    reaches `Display`. S1 demonstrates this.

`from_str::<Value>` materializes the tree from the parse representation
(D3: it refuses duplicates). `from_value` deserializes from a tree the
caller already has; it is a second `Deserializer`, over `Value`, with the
same enum and error rules.

`from_str_loose` materializes figment `Dict` with last-wins at every level
(D4). `figment_data` wraps it as figment's `Provider`, so figment's `yaml`
feature can go (D21). Before figment's `yaml` is removed, the current
`figment_data` output on the T2b cases is recorded as a golden: profiles,
last-wins, and the error kind and message. MIG.2 must match it.

### 4. Writing: a serde `Serializer` into the tree, and an emitter

`to_value` serializes `T` into the tree. An externally tagged newtype or
struct variant becomes `Tagged { tag: "!variant", value }`, as serde_yaml
wrote it (D5). No type's `Serialize` impl changes. JSON grants and
`grant_digest` are untouched.

`to_string` emits the tree as text. The output must be byte-equal to the
MIG.0 goldens (D20), which come from libyaml's emitter. There are two
options; open decision O2:
- **O2a:** the adapter's own small emitter, written to libyaml's observed
  rules (quoting of scalars that look like other types, two-space block
  indent, `- ` sequences, tags before values), pinned by the goldens;
- **O2b:** serde-saphyr's serializer over the tree, if its options can be
  made to emit exactly the golden bytes. The spike decides.

### 5. Errors

`Error` stays the adapter's own type with the same contract (B3):
- `Display` and `Debug` are redacted;
- it has no `source()`;
- `location()` returns `Location`.

Its inner value becomes the adapter's own error enum, not serde_yaml's.
D13 and D14 wording changes are measured against the goldens. Any text
change a user can see goes in `upgrading.d`.

### 6. Dependencies

- `Cargo.toml`: keep the existing `granit-parser = "=2.0.0"` pin
  (`Cargo.toml:148`, the MIK-8639 guard; O1), widening its use only.
  serde-saphyr itself is not needed;
- drop `serde_yaml`;
- drop `yaml` from figment's features;
- `docs/legal/dependency-licenses.tsv` already lists granit-parser
  (`:125`), so the swap adds no licence row;
- MIG.6 later removes the serde_yaml and unsafe-libyaml rows and the
  exception, after a real OSV scan.

## Spikes before any MIG.2 code (throwaway Spark harness, outside the repository)

- **S0, the typed-API alternative, bounded:** before committing to a full
  serde implementation, try serde-saphyr's typed API with its options on
  the MIG.0 behaviour inputs:
  - `DuplicateKeyPolicy`;
  - `MergeKeyPolicy::AsOrdinary`;
  - `strict_booleans`;
  - `reject_unsupported_tags`;
  - `NonFiniteFloatPolicy` (including `PassThrough`, for D25);
  - `with_snippet: false`;
  - `Budget`.

  Count the rows that differ from the goldens, and check whether any key
  path can be recovered. If S0 matches every row and every error property,
  the event design is dropped for it.
- **S1, O1:** the event source passes only if its dump, for the MIG.0
  behaviour inputs, shows all of these:
  - raw plain-scalar text with style;
  - explicit tags;
  - anchors, with an alias resolved to its value and `<<` still present as
    a key;
  - repeated keys, both entries;
  - `.inf` accepted;
  - a following document as its own boundary;
  - positions for every node.

  S1 also converts a parser syntax error into the adapter's error and shows
  that no parser text reaches `Display`. It does this on the B3
  unterminated-quote fixture that carries the sentinel, and on the
  `behaviour.txt` flow-sequence error, and asserts the pinned substrings
  and `leaks=false`. It shows the budget refusing the
  level-4 alias document before allocation passes the limit (peak memory
  measured). The budget is also tested against an alias inside an ignored
  subtree (a field the target skips), a recursive alias, and a budget that
  resets per document in a stream, each compared with serde_yaml.
- **S2, O2:** the emitter must reach zero byte diffs on each of these:
  - every MIG.0 writer golden: config splice, URL persistence, `upgrade`,
    `cap`, `config_write`, grants;
  - the `behaviour.txt` write rows;
  - a round trip of tags, non-string keys and non-finite numbers;
  - generated round trips: a property test over the tree that writes,
    reads back with the old parser, and compares.

  Output: the diff count per golden.
- **S3:** the G3 and duplicate-key spike that the parent design scheduled
  beside MIG.0, and that has no result in the tree yet. Run it with the
  representation and deserializer sketch:
  - every externally tagged enum refuses the map form and accepts the tag
    form, and a unit variant is accepted plain and quoted;
  - untagged and internally tagged enums keep accepting maps (positive
    controls);
  - duplicate keys behave right in all four destinations;
  - key identity is destination-dependent: `1:` and `"1":` are different
    keys in the tree but the same key in a `String`-keyed map;
  - under last-wins into a typed map, an earlier value is still
    deserialized in order, so an invalid one is refused (corrected
    2026-10-24; K0 records the guarded adapter's result);
  - `#[serde(flatten)]` structs with a repeated key behave as serde_yaml
    does.
- **Kill gate:** stop and take the result to the lead if any of these
  holds. The fallback is the dated exception, decided by the operator.
  - S0 does not match and S1 finds no usable event stream;
  - S2 cannot reach byte-equality with O2b (serde-saphyr's serializer over
    the tree), tried first, nor with O2a (the adapter's own emitter);
  - S3 finds a parity gap.

## Size and order

- **Size:** this is not small. The data model alone is a parse
  representation, a tree, two `Deserializer`s, a `Serializer` and the
  errors. That is about 1,500 to 2,500 lines of product code, before the
  emitter.
- **The emitter is priced separately.** Under O2a it is a libyaml-matched
  writer: quoting of scalars that look like other types, flow and block
  choice, tag placement and line breaks. The `behaviour.txt:110-112` write
  rows show the edge cases. Expect another 500 to 1,000 lines, pinned by
  the goldens. S2 replaces this estimate with a measured one.
- **Layout:** split across `src/yaml/` under the 800-line file cap. The
  split stays a crate::-free unit, so `tests/common/yaml.rs` still compiles
  it through `#[path]`. This design supersedes the parent design's option
  list for MIG.2 (snippets off, merge keys `AsOrdinary` and so on), because
  serde-saphyr's typed options are used only if S0 wins.
- **PR size:** the parent design's 15-file cap per PR cannot hold for the
  swap. The swap is one atomic backend change, and splitting it would
  leave the crate on two parsers. The MIG.2 plan names the file count and
  asks the lead for an exception.
- **Tests:** at least as much again. MIG.3 to MIG.5 and the extra G2 cases
  go inside the same PR, and the existing suites run unchanged.
- **Process:** muse writes it, two seats review, and it goes through the
  full gate and exact-head CI. This is days of work, not hours, which is
  why the swap is a 4.x-minor candidate.
- **Order:** spikes S0 to S3, then a reviewed MIG.2 plan with a file list,
  the enum-class census and a red-first test plan, then the code.

## Rollback

MIG.2 reverts as one commit:
- `src/yaml/`, `tests/common/yaml.rs`, `Cargo.toml`, `Cargo.lock` and the
  licence rows;
- G1 guarantees that files the new code wrote load with the old one;
- if MIG.6 has already removed the exception, or it has expired, the revert
  needs a newly ratified exception date and a passing OSV scan first. That
  is unchanged from the parent design.

## Out of scope

- MIK-8542, JSON-path parity: 4.0.1, Backlog.
- MIG.6, the exception removal: a separate PR after MIG.2, with a real
  scan.
- YAML.4 stays open until MIG.6 merges.

## Open decisions

- **O1:** the event source. DECIDED by S1 (2026-10-22): granit-parser,
  used directly.
- **O2:** the emitter. DECIDED by S2 (2026-10-22): O2a, the adapter's own
  emitter. serde-saphyr's is not byte-equal to the goldens.
- **O3:** the release. DECIDED by the operator (2026-10-24): "Swap library
  before tag", so the swap is 4.0.0.

## Review record

The first round, 2026-10-20: gpt SHIP-WITH-FIXES (gpt-20261020T082305Z-76661)
and grok SHIP-WITH-FIXES (grok-20261020T082306Z-76794). Folded:
- duplicates are kept in an ordered multimap and the policy is applied per
  destination, so maps and `Dict` keep the last value. Both seats flagged
  this;
- scalars stay unresolved until the target is known (D23 to D26);
- standard tags resolve, and the D17 default is corrected;
- the multi-document contract (D19);
- G2 is widened beyond the B3 suite, and the frozen refusal substrings
  are listed;
- the enum classes: map-form refusal applies to externally tagged enums
  only;
- the `figment_data` golden is recorded before figment's `yaml` is
  removed;
- S0, a bounded typed-API alternative, comes first;
- S1 gets pass criteria, safe error conversion and budget-before-allocation;
- S2 diffs every writer golden and adds generated round trips;
- S3 adds positive controls;
- the size estimate is redone, with the emitter priced on its own.

The second round, 2026-10-20 (delta): gpt SHIP-WITH-FIXES
(gpt-20261020T084356Z-20818) and grok SHIP-WITH-FIXES
(grok-20261020T084358Z-20957). Folded:
- `behaviour.txt` is the resolver specification. The "YAML 1.2 core" gloss
  is gone, because `0755` stays a string;
- quoted unit variants are accepted;
- a non-local URI tag is dropped, as serde_yaml does;
- locations live on the parse representation only;
- `NonFiniteFloatPolicy` is in S0;
- the undefined-alias G2 case places its sentinel;
- flatten over untagged (`BackendConfig.transport`) is a hard requirement;
- S1 converts the B3 and `behaviour.txt` syntax fixtures;
- S1 budget edge cases (ignored subtree, recursive alias, per-document);
- S3 key identity, overwritten invalid values and flatten;
- S2 tries O2b then O2a before the kill;
- the `#[path]` unit is kept, and the parent option list is superseded;
- the 15-file cap needs a lead exception for the swap;
- the G3 census is limited to enums reachable from `from_str`.

The 4.0.0 refresh, round 1, 2026-10-24: gpt SHIP-WITH-FIXES
(gpt-20261024T131014Z-85373) and grok SHIP-WITH-FIXES
(grok-20261024T131014Z-85376). Folded:
- granit-parser is already pinned for the MIK-8639 guard, so the swap adds
  no dependency (grok);
- the guarded adapter, not bare serde_yaml, is the oracle: D19's malformed
  later document is a whole-stream refusal, and hard requirement 1 pins the
  guard's quoted-text and depth wording (both seats);
- `tests/mik_8425_yaml_adapter.rs` is the third direct serde_yaml and figment
  `Yaml` user; its comparisons become goldens before the calls go (grok,
  HIGH);
- K0 adds an O2a emitter sketch against the writer goldens and a generated
  read-back corpus, and the estimate is redone from it (both seats);
- the S3 rule on overwritten invalid values was wrong: serde_yaml validates
  each value in order before the last-wins insert (gpt);
- the bypass detector learns `granit_parser` with seam-only allowances and
  negative controls (both seats);
- the out-of-tree read-back names the exact head SHA and covers the
  generated corpus (both seats);
- the shipped-YAML walk keeps walking, with a per-file row (gpt, grok);
- the guard's `map_scan_error` and `syntax_what` are the one sanitizer (gpt);
- a 2026-10-28 checkpoint, and 2026-11-02 reserved for MIG.6 (gpt); the
  estimate counts from 2026-10-24, so the 2026-11-01 decision date stands
  (grok proposed 2026-11-03 on a count from muse's return).

The 4.0.0 refresh, round 2 (delta), 2026-10-24: gpt SHIP
(gpt-20261024T132359Z-95180) and grok SHIP-WITH-FIXES
(grok-20261024T132359Z-95184). Folded (grok):
- section 2 and D19 now say a stream with any malformed document is refused
  as a whole, matching the guarded oracle;
- D14 keeps the guard's syntax wording, with no mapping back to libyaml;
- the shipped-YAML ratchet also fails on a stale sha256, outcome or count;
- "Where the code stands" names the four allowed serde_yaml users;
- section 6 keeps the existing granit-parser pin and licence row;
- hard requirement 2 names the out-of-tree read-back on the exact head SHA.

The 4.0.0 refresh, round 3 (grok confirmation), 2026-10-24: SHIP-WITH-FIXES
(grok-20261024T141058Z-85074). Folded:
- the whole-stream class is named: guard refusals (syntax, depth, size, alias,
  `%TAG`, expansion) refuse the stream; a later document's semantic error stays
  per document;
- the D19 decision cell's leftover tail is removed;
- D14's source is `syntax_what` (`src/yaml.rs:447`).

The 4.0.0 refresh, round 4 (grok confirmation), 2026-10-24: SHIP-WITH-FIXES
(grok-20261024T141806Z-93992), improvements only. Folded: the oracle bullet,
section 2 and the D19 cell all state the same split: every guard `Limit`
refusal (including anchor reuse, anchor names and disputed line breaks)
refuses the whole stream; a semantic error is per document, and the iterator
stops after it (`src/yaml.rs:715`). The semantic clause no longer cites
`behaviour.txt:90`.
