# MIK-8425 MIG.2: design for swapping the YAML backend to serde-saphyr

Status: design for review, 2026-10-20. Refs MIK-8425. Docs only: no code
and no library swap. `.github/osv-scanner.toml` is not touched.

This is the fallback path. The lead, gpt, grok and the lane recommend
extending the RUSTSEC-2024-0449 exception and moving this swap to a 4.x
minor (brief `mik-8425-b1-exception-or-swap`). If the operator declines the
extension, this note is the plan. Either way it fixes what the swap must
do before any code exists.

Parent design: `docs/internal/design/2026-10-17-mik-8425-yaml-migration.md`
(MIG.0 to MIG.6, gates G1 to G3). This note details MIG.2 and does not
replace it.

## Where the code stands (line tip f3191c740)

- Every YAML read and write goes through `src/yaml.rs`; only that file and
  `tests/mik_8425_yaml_adapter.rs` name serde_yaml (MIG.1, enforced by the
  bypass gate).
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
2. **G1, rollback:** the new code writes grants and config byte-equal to
   the MIG.0 goldens, and the old parser reads them back to the same value.
3. **G2:** the sentinel is absent on every path. This is now the same suite
   as point 1.
4. **G3, read-side enum parity:** the map form `agent: {exact: ...}` is
   still refused in YAML.
5. **Duplicate-key parity** in all four destinations: struct, nested map,
   tree, and figment `Dict`.
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
| D9 | `yes`/`no`/`on`/`off` into `bool` | refused (YAML 1.2 core) | **accepted** as YAML 1.1 booleans by default | probe, docs.rs | refuse (strict booleans) |
| D10 | `yes` into `String` | `"yes"` | `"yes"` | probe | same |
| D11 | Error text shape | `<key path>: <serde message> at line L column C` | `error: line L column C: <message>`, **no key path** | probe | keep serde_yaml's shape (see Design 3) |
| D12 | Error snippet | none | **source snippet with the offending line** by default (`with_snippet`) | probe, docs.rs | no snippet. The snippet is a CWE-532 leak |
| D13 | Type-error wording | `invalid type: string "x", expected u16` (value redacted by B3) | `invalid u16` (no value) | probe | B3's redacted form |
| D14 | Syntax-error wording | libyaml's (`did not find expected ',' or ']'`) | its own (`unclosed bracket '['`) | probe | pin new wording or map it. A test-text change goes to the seats |
| D15 | Depth limit | 128 loads, 129 refused (`recursion limit exceeded`) | `Budget` setting | MIG.0 behaviour.txt, docs.rs | set the same limits explicitly |
| D16 | Alias expansion limit | level 3 loads, level 4 refused (`repetition limit exceeded`) | `Budget` and alias limits | MIG.0 behaviour.txt | set the same limits explicitly |
| D17 | Unknown tags on plain values | kept in `Value::Tagged` | "preserve unsupported tags" option, default off | docs.rs, unverified | keep tags in the adapter tree |
| D18 | Non-string keys, tags and non-finite numbers in the tree | `Value` holds them | no `Value` type | code | the adapter's own tree holds them; `to_json` rules unchanged (B2) |
| D19 | Multi-document stream | `Deserializer::from_str` iterator, which can keep yielding after an error | unverified | code, unverified | keep "stop at the first refusal" (`documents`) |
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
- each node carries its source `Location`.

Its accessors match the MIG.1a inventory of the `Value` and `Mapping` API in
use (indexing, `get`, `as_*`, `is_*`, tag access, `Number`), so call sites
do not change. `to_json` keeps its B2 rules.

### 2. Reading: events into the tree

The tree is built from the parser's event stream. That is either
serde-saphyr's event-level API or `granit-parser` directly, whichever the
spike shows exposes events, tags and positions; open decision O1. The
builder applies the gateway's rules itself:
- duplicate keys are refused in the tree (D3);
- merge keys stay ordinary keys (D8);
- scalars are resolved with YAML 1.2 core rules, as serde_yaml does, so
  `yes` stays a string (D9);
- every tag is kept (D17);
- the explicit depth and alias budgets come from D15 and D16. The builder
  counts expanded nodes itself, so the limit does not depend on a library
  default;
- a multi-document stream stops at the first refusal (D19).

### 3. Typed reads: a serde `Deserializer` over the tree

`from_str::<T>` builds the tree, then deserializes `T` from it with the
adapter's own `Deserializer`. That deserializer reproduces serde_yaml's
rules:
- a unit variant is read from a plain scalar, and a non-unit variant only
  from a tag, so the map form is refused (G3, D6). This covers all 184
  `Deserialize` enums at once;
- a map target keeps the last value of a repeated key, and a struct target
  refuses it (D2);
- the key path is tracked through the walk, so errors read
  `<key path>: <serde message> at line L column C` (D11), and the node's
  `Location` gives the line and column;
- error messages are built by the adapter, never copied from the parser.
  `redact_message` still runs on every `Display`/`Debug` (B3), and no
  snippet ever exists (D12).

`from_str_loose` builds `figment::value::Dict` from the tree with last-wins
at every level (D4). `figment_data` wraps it in figment's `Provider`, so
figment's `yaml` feature can go (D21). `from_value` is the same
deserializer started on a tree the caller already has.

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

- `Cargo.toml`: add `serde-saphyr = "=2.0.0"` (or `granit-parser`, per O1)
  with default features off, and only what the design uses;
- drop `serde_yaml`;
- drop `yaml` from figment's features;
- `docs/legal/dependency-licenses.tsv` adds the new rows in this PR;
- MIG.6 later removes the serde_yaml and unsafe-libyaml rows and the
  exception, after a real OSV scan.

## Spikes before any MIG.2 code (throwaway Spark harness, outside the repository)

- **S1, O1:** does serde-saphyr 2.0.0 expose a parse event stream with
  tags, anchors and aliases, and positions? If not, does granit-parser 2.0.0
  alone? Output: a 30-line event dump for the MIG.0 behaviour inputs.
- **S2, O2:** can either emitter write the MIG.0 golden bytes for the
  config writers and the grants writer, with no diff? Output: the diff
  count per golden.
- **S3:** the G3 and duplicate-key spike that the parent design scheduled
  beside MIG.0, and that has no result in the tree yet. Run it with the
  tree and deserializer sketch: does every enum refuse the map form, and is
  the duplicate-key behaviour right in all four destinations?
- **Kill gate:** if S1 finds no usable event stream, or S2 cannot reach
  byte-equality, or S3 finds a parity gap, stop. Take the result to the
  lead. The fallback is the dated exception, decided by the operator.

## Size and order

- About 1,000 to 1,500 lines of product code: the tree, the builder, the
  deserializer, the serializer, the emitter and errors. Split across
  `src/yaml/` under the 800-line file cap.
- About as much again in tests: MIG.3 to MIG.5 inside the same PR, plus the
  existing suites, which run unchanged.
- muse writes it, two seats review, and it goes through the full gate and
  exact-head CI.
- Order: spikes S1 to S3, then a reviewed MIG.2 plan with a file list and a
  red-first test plan, then the code.

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

- **O1:** the event source, serde-saphyr's event API or granit-parser.
  Decided by S1.
- **O2:** the emitter, the adapter's own or serde-saphyr's. Decided by S2.
- **O3:** the release. The operator rules on the exception (4.0.0 swap or
  a 4.x minor). This note's design does not depend on the answer.
