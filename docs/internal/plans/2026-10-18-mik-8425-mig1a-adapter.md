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
'serde_yaml::[A-Za-z_0-9]+(::[A-Za-z_0-9]+)?' src tests`, run on 2026-10-18 (the
pattern includes digits, so `as_u64` is not cut to `as_u`):

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
| `from_str::<figment::value::Dict>` and figment `Yaml::from_str::<Dict>` | 5 sites | `yaml::from_str_loose(&str) -> Result<figment::value::Dict, Error>` |
| figment `Yaml::string(text).data()` (`config/config_file.rs:80`, the config loader) | 1 site | `yaml::figment_data(&str) -> figment::Result<Map<Profile, Dict>>`, delegating to figment's provider in MIG.1a so that profiles, error kind and message are identical |

The re-exported types stay serde_yaml's own until MIG.2, so MIG.1 routing
is a pure path rename. The tree API above is the checklist the MIG.2 owned
tree must meet; each item names its parity fixture in MIG.2.

`documents` yields every document and ends after the first refusal. It
has no count cap: `kubernetes.rs:361` reads every document today, so a cap
would silently drop valid trailing documents. Stopping at the first refusal
matches `kubernetes.rs`, which already returns at its first error, and it
removes the hazard found in MIG.0: serde_yaml's stream iterator kept
yielding after a malformed document, and a loop that did not stop grew
without bound.

Visibility: `pub(crate)` throughout, with no widening. The module is mounted
in both crate roots, `src/lib.rs` and `src/main.rs`, because the binary
compiles `mod commands;` and `mod runtime;` itself (`main.rs:18`, `:46`).

## Integration-test helper

`tests/common/yaml.rs` compiles the adapter's own source,
`#[path = "../../src/yaml.rs"] mod adapter;`, and re-exports it. Integration
tests therefore get the complete surface (types and conversions included)
from one implementation, with no visibility widening and no second copy to
drift. This requires `src/yaml.rs` to depend only on `serde`, `serde_yaml`
and `figment`, never on `crate::` paths, and a compile of the helper proves
it. MIG.1f routes the 45 integration-test files through it. MIG.2 swaps
both at once because they are the same file.

## Identity read-back check

`scripts/release/check_identity_sources.py:216` recognises only
`serde_json|serde_yaml|toml|serde_yml::from_*`. MIG.1a extends `READ_BACK`
to `yaml::from_str`, `yaml::from_str_loose`, `yaml::from_value` and
`yaml::documents`, with or without a `crate::` prefix. Routing in MIG.1b
then cannot hide an identity deserialization from that release check.

## Bypass gate

A test lists every Rust source file under `src/` and `tests/` that names
either parser directly: `serde_yaml`, or figment's YAML provider
(`figment::providers::Yaml`, or `Yaml` imported from `figment::providers`).
That is 193 files on 2026-10-18, plus `src/yaml.rs` and the helper. The
test fails if any other file starts naming either one. It scans every file
and does not exempt test code by filename, so a production module cannot
escape it through its name. Each MIG.1 PR removes its files from the list,
and MIG.2 requires the list to hold only `src/yaml.rs` and
`tests/common/yaml.rs`.

## Test plan (red first)

Each test is written to fail before the implementation and to pass after
it.

- **T1** `documents_stops_at_the_first_refusal` (in `tests/mik_8425_yaml_adapter.rs`, through the helper):
  `"a: 1\n---\nb: [1, 2\n"` gives Ok, then Err, then the end. A stream of
  300 valid documents yields all 300. A stream with a malformed document
  after 260 valid ones yields 260 Ok values, then that Err, then the end.
  Red: the function does not exist.
- **T2** `from_str_loose_keeps_the_last_repeated_key`, and
  `from_str_refuses_a_repeated_key_in_a_tree`: these are anchors, not new
  behaviour. They pin the duplicate-key destination rule (Dict keeps the
  last value; Value refuses) on the adapter's own paths. Red: the functions
  do not exist.
- **T2b** `figment_data_matches_the_yaml_provider`: for the config fixtures
  in the MIG.0 trees golden, and for the redaction cases (type error, syntax
  error, duplicate key), `yaml::figment_data` equals
  `Yaml::string(text).data()`. Ok compares profiles and Dicts; Err compares
  `Kind` and the rendered message. Red: the function does not exist.
- **T3** `adapter_reads_like_serde_yaml_on_the_behaviour_cases`: for the
  MIG.0 behaviour inputs (duplicates, merge, scalars, documents, limits,
  enum forms), the adapter's result equals serde_yaml's direct result. Red:
  the functions do not exist. In MIG.1 it guards the routing; in MIG.2 it
  becomes the comparison against the goldens.
- **T4** (Python, `scripts/release/test_check_identity_sources.py`): each
  of `from_str`, `from_str_loose`, `from_value` and `documents`, called as
  `yaml::...` and as `crate::yaml::...` into a carrier, is a violation:
  eight rows. Controls: `yaml::to_string(&t)` is not a violation, and
  `my_yaml::from_str` is not a match. Red: the pattern does not recognise
  `yaml::`.
- **T5** `no_new_file_names_a_yaml_parser_directly` (the bypass gate
  above). It starts green, with the allowlist equal to today's files. Its
  red proof is a negative control: the same scan function, run over a
  synthetic temporary source tree, must flag an unlisted file that names
  `serde_yaml`, and one that imports `figment::providers::Yaml`. It must
  not flag a file that mentions the word only in a comment-free string
  such as `"serde_yaml_like"`. Green is not taken on trust.

The MIG.0 goldens stay untouched in MIG.1a; they still call serde_yaml
directly until MIG.1f routes them through the helper.

## Files (8 paths, under the 15-file cap and the 800-line ceiling)

`src/yaml.rs` (new), `tests/mik_8425_yaml_adapter.rs` (new), the allowlist fixture, `src/lib.rs` (+1 line),
`src/main.rs` (+1 line), `tests/common/yaml.rs` (new),
`scripts/release/check_identity_sources.py` and its test, and this plan.

## Overlap and rollback

Overlap: `src/lib.rs` and `src/main.rs` are shared roots. The edit is one
`mod yaml;` line each, checked against open PRs before the push. No other
lane holds `scripts/release/check_identity_sources.py` (checked before the
push). Rollback: revert the single commit; nothing routes through the
adapter yet.

## Review record

Round 1, 2026-10-18, on ee3250c33. Both seats returned SHIP-WITH-FIXES;
findings were checked at source and folded:
- the 256-document cap is removed, because it silently dropped trailing
  documents. Kimi proposed a loud cap instead; that would refuse manifests
  over 256 documents that load today, a behaviour change, so the gpt fix
  (no cap, stop at the first refusal) is taken;
- the bypass gate covers figment's YAML provider and scans every file,
  with no filename exemption;
- the integration helper compiles the adapter source through `#[path]`;
- `config_file.rs:80` gets `figment_data` and T2b;
- T4 covers all four names, bare and prefixed;
- the usage survey includes digits.

Implementation note, 2026-10-18: T1 to T3 and T5 run in the integration
test `tests/mik_8425_yaml_adapter.rs` instead of a unit file. The helper
compiles the same `src/yaml.rs`, so the coverage is the same, and no
`cfg(test)` code sits in a file that integration tests also compile. The
code review (gpt, kimi) is folded there: whole `use figment` declarations
are scanned, limits and enums are added to T3, writer parity is checked,
T2b gets a profile-shaped document, and the allow is tied to MIG.1f.
Kimi's HIGH ('from_str_loose does not compile') was refuted at source: in
figment 0.10.19, Yaml::from_str returns serde_yaml::Error, and the adapter
builds and passes on Spark.

## Note for MIG.2 (not built here)

G3 (read-side enum parity) needs no per-enum inventory if MIG.2 deserializes
typed targets from the adapter's own tree through a `serde::Deserializer`
that applies serde_yaml's rules: a unit variant is read from a plain
scalar (`agent: any`), and a non-unit variant only from a tag
(`!exact ...`), so the map form is refused. That covers all 184 `Deserialize` enums in
`src/` generically. Each rule still gets a fixture. This is proposed here
for the MIG.2 design review; it does not change MIG.1a.
