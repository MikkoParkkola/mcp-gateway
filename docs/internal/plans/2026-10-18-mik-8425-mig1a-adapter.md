# MIK-8425 MIG.1a: the YAML adapter (design and test plan)

Status: for review before any code, 2026-10-18. Refs MIK-8425. Parent
design: `docs/internal/design/2026-10-17-mik-8425-yaml-migration.md`
(MIG.1a, PR 2 of the sequence). Branch `feat/mik-8425-mig1a-yaml-adapter`,
cut from the MIG.0 head (#3919). It is pushed only after #3919 merges.

## Goal and non-goals

Goal: add one crate-private seam, `src/yaml.rs`, through which every later
stage routes YAML. MIG.1a changes no behaviour, because the backend is still
serde_yaml 0.9.34. Routing consumers through the seam is MIG.1b to MIG.1f;
swapping the backend is MIG.2.

Non-goals, so the PR stays small: no consumer moves, no new dependency, no
options fixture. The options file in the parent design matters only once
there are options to set, in MIG.2.

## Surface

These items are counted from current use, with `rg -o
'serde_yaml::[A-Za-z_]+(::[A-Za-z_]+)?' src tests`, run on 2026-10-18:

| Item | Uses | Adapter item |
|---|---|---|
| `from_str` | 296 | `yaml::from_str<T: DeserializeOwned>(&str) -> Result<T, yaml::Error>` |
| `to_string` | 80 | `yaml::to_string<T: Serialize>(&T) -> Result<String, yaml::Error>` |
| `Value` (with `as_str`, `as_mapping`, `as_sequence`, `as_sequence_mut`, `as_bool`, `as_u64`, `get`, `is_null`, the variants and `Value::from`) | 78 + accessors | `yaml::Value`, re-exported for now |
| `to_value` | 12 | `yaml::to_value` |
| `Mapping` | 5 | `yaml::Mapping`, re-exported for now |
| `Error` | 5 | `yaml::Error`, re-exported for now |
| `Deserializer::from_str` (stream) | 4 (1 in production, `kubernetes.rs:361`) | `yaml::documents(&str) -> impl Iterator<Item = Result<Value, Error>>` |
| `from_value` | 3 | `yaml::from_value` |
| figment `Yaml` provider, and `from_str::<figment::value::Dict>` | 6 sites | `yaml::from_str_loose(&str) -> Result<figment::value::Dict, Error>` |

The re-exported types stay serde_yaml's own until MIG.2, so MIG.1 routing
is a pure path rename. The tree API above is the checklist the MIG.2 owned
tree must meet; each item names its parity fixture in MIG.2.

`documents` stops after the first refusal and reads at most 256 documents.
That matches `kubernetes.rs:361`, which already returns at its first error.
It also removes the hazard found in MIG.0: serde_yaml's stream iterator kept
yielding after a malformed document, and a loop that did not stop grew
without bound.

Visibility: `pub(crate)` throughout, with no widening. The module is mounted
in both crate roots, `src/lib.rs` and `src/main.rs`, because the binary
compiles `mod commands;` and `mod runtime;` itself (`main.rs:18`, `:46`).

## Integration-test helper

`tests/common/yaml.rs` gives integration tests the same functions over
serde_yaml (`from_str`, `to_string`, `documents`, `from_str_loose`). The
crate-private adapter is not visible from `tests/`, and visibility is not
widened. MIG.1f routes the 45 integration-test files through it. MIG.2 swaps
its backend together with the adapter's.

## Identity read-back check

`scripts/release/check_identity_sources.py:216` recognises only
`serde_json|serde_yaml|toml|serde_yml::from_*`. MIG.1a extends `READ_BACK`
to `yaml::from_str`, `yaml::from_str_loose`, `yaml::from_value` and
`yaml::documents`, with or without a `crate::` prefix. Routing in MIG.1b
then cannot hide an identity deserialization from that release check.

## Bypass gate

A unit test lists every production source file that still names
`serde_yaml` directly: the 46 recorded on 2026-10-17, plus `src/yaml.rs`.
It fails if any other production file starts naming it. Each MIG.1 PR
removes its files from that list, and MIG.2 requires the list to hold only
`src/yaml.rs`. Production means `src/**/*.rs` minus test modules, using the
same rule as the 46-file count (names ending `_tests.rs`, `tests.rs`, or
under a `tests/` directory, and fixtures).

## Test plan (red first)

Each test is written to fail before the implementation and to pass after
it.

- **T1** `documents_stops_at_the_first_refusal` (unit, `src/yaml_tests.rs`):
  `"a: 1\n---\nb: [1, 2\n"` gives Ok, then Err, then the end. A 300-document
  stream gives 256 items and stops. Red: the function does not exist.
- **T2** `from_str_loose_keeps_the_last_repeated_key`, and
  `from_str_refuses_a_repeated_key_in_a_tree`: these are anchors, not new
  behaviour. They pin the duplicate-key destination rule (Dict keeps the
  last value; Value refuses) on the adapter's own paths. Red: the functions
  do not exist.
- **T3** `adapter_reads_like_serde_yaml_on_the_behaviour_cases`: for the
  MIG.0 behaviour inputs (duplicates, merge, scalars, documents, limits,
  enum forms), the adapter's result equals serde_yaml's direct result. Red:
  the functions do not exist. In MIG.1 it guards the routing; in MIG.2 it
  becomes the comparison against the goldens.
- **T4** (Python, `scripts/release/test_check_identity_sources.py`):
  `let t: Tok = yaml::from_str(s)?` and `crate::yaml::from_value(v)` into a
  carrier are violations. Controls: `yaml::to_string(&t)` is not a
  violation, and `my_yaml::from_str` is not a match. Red: the pattern does
  not recognise `yaml::`.
- **T5** `no_new_file_names_serde_yaml_directly` (the bypass gate above). It
  starts green, with the allowlist equal to today's 46 files. Its red proof
  is a negative control in the same test: a scan of a synthetic file list
  that adds one unlisted file must fail. Green is not taken on trust.

The MIG.0 goldens stay untouched in MIG.1a; they still call serde_yaml
directly until MIG.1f routes them through the helper.

## Files (8 paths, under the 15-file cap and the 800-line ceiling)

`src/yaml.rs` (new), `src/yaml_tests.rs` (new), `src/lib.rs` (+1 line),
`src/main.rs` (+1 line), `tests/common/yaml.rs` (new),
`scripts/release/check_identity_sources.py` and its test, and this plan.

## Overlap and rollback

Overlap: `src/lib.rs` and `src/main.rs` are shared roots. The edit is one
`mod yaml;` line each, checked against open PRs before the push. No other
lane holds `scripts/release/check_identity_sources.py` (checked before the
push). Rollback: revert the single commit; nothing routes through the
adapter yet.

## Note for MIG.2 (not built here)

G3 (read-side enum parity) needs no per-enum inventory if MIG.2 deserializes
typed targets from the adapter's own tree through a `serde::Deserializer`
that applies serde_yaml's rules: a unit variant is read from a plain
scalar (`agent: any`), and a non-unit variant only from a tag
(`!exact ...`), so the map form is refused. That covers all 184 `Deserialize` enums in
`src/` generically. Each rule still gets a fixture. This is proposed here
for the MIG.2 design review; it does not change MIG.1a.
