# MIK-8425 MIG.1c: route serializers and tree walkers through the YAML adapter (plan)

Status: for review before any code, 2026-10-18. Refs MIK-8425. Parent:
`docs/internal/design/2026-10-17-mik-8425-yaml-migration.md` (PR 4,
MIG.1c), MIG.1a adapter (#3922), MIG.1b (#3925). Plan branch
`docs/mik-8425-mig1c-plan`; routing branch
`feat/mik-8425-mig1c-serializers`, both cut from the line tip 45ccc519c.

## Goal

Route the 13 serializer and tree-walker files with no holder (design
"Order", item 3) through `crate::yaml`. The `validator/mod.rs` doctest,
deferred from MIG.1b, moves on to MIG.1d-i, so that the new Kubernetes
test below fits the 15-path cap. There is no behaviour change, and the files
leave the bypass allowlist. The backend is still serde_yaml 0.9.34 behind
the adapter.

## Overlap (checked 2026-10-18 on the line tip)

The scan covered 1 open PR and 571 remote branches, with merge base taken
against the release line. Nothing touches any of the 14 sources. Control:
the same scan returns the 16 files of the merged MIG.1b branch. It is
re-run before the push.

## Inventory: 70 occurrences in 13 files, plus one new test

| File | What | Change |
|---|---|---|
| `src/identity_grants.rs:252,319` | grants read (listed read-back `read_identity_grants_file`) and YAML write | `crate::yaml::from_str`, `crate::yaml::to_string` |
| `src/identity_grants_matching.rs` (13) | `&serde_yaml::Error` parameter, `Tree::Yaml(serde_yaml::Value)`, `from_str`, `from_value` (listed read-backs `parse_refusal`, `remainder_error`), `Value::Tagged` match on tag `exact`, accessors; doc comment at :109 names the parser | path rename; `Value::Tagged(tagged)` keeps working because `Value` is a re-export; comment reworded to "the YAML parser" |
| `src/skills/parser.rs` (9) | frontmatter tree, `Mapping` accessors, public field `pub extra: BTreeMap<String, serde_yaml::Value>` (:92) | path rename. The public field becomes `crate::yaml::Value`, the same type named through a `pub(crate)` re-export. Its type changes in MIG.2 (decided: `serde_json::Value`), not here |
| `src/kubernetes.rs:35,361` | `use serde_yaml::Value`; stream `Deserializer::from_str(input).enumerate()` then `Value::deserialize(document)?` | `use crate::yaml::Value`; `crate::yaml::documents(input).enumerate()`, with `document.map_err(..)?` in place of `Value::deserialize`. Both stop at the first error (MIG.1a T1, T3 parity) |
| `src/gateway/ui/capabilities.rs` (12) | tree reads and variant matches; code comment at :188 names the parser | path rename; comment reworded |
| `src/gateway/ui/backend_ops.rs:481` | `to_string` of a capability | `crate::yaml::to_string` |
| `src/commands/upgrade.rs` (7), `src/commands/api_key_rewrite.rs` (5), `src/commands/config_write.rs` (3), `src/commands/mod.rs` (2, test module), `src/commands/cap.rs` (4) | tree reads, accessors, `to_string` of reports | path rename |
| `src/commands/retired_config_keys.rs` (8) | `from_str::<figment::value::Dict>` (:65), `to_value`, tree types | `crate::yaml::from_str_loose(text)` at :65; checked at source that figment 0.10.19 formats YAML with `serde_yaml::from_str` (`providers/data.rs:522`), so it is the same call; the rest is a path rename |
| `src/protocol_imports/planner.rs:197,637` | read into `serde_json::Value`, `to_string` | path rename |

Crates: `src/commands/` is compiled only by the binary (`main.rs:18`); the
rest compile in the library, and `runtime` in both. Both roots mount `yaml`.
Identity read-back check: the three listed functions keep their (file,
function) keys, and the MIG.1a pattern matches `yaml::from_str` and
`yaml::from_value` there, so they stay allowed and visible.

## Tests (red first)

- **R1, red:** remove the 13 files from
  `tests/fixtures/mik_8425_yaml/direct_users.txt`. T5 must fail listing
  exactly those 13; after routing it passes. `src/commands/upgrade/tests.rs`
  (7 uses, test-only) stays on the allowlist and is not one of the 13. It
  names the same `Value` type and moves with the test-only files in
  MIG.1e.
- **R1b, Kubernetes caller behaviour:** this is the one site that is not a
  path rename. In `src/kubernetes_tests.rs`, add `parse_resources` cases for
  - a valid document followed by a malformed one, refused as
    `KubernetesPlanError::Parse`;
  - a stream with an empty middle document, where the next document's
    `MissingField` index is its stream position, counting the empty one.
  They are written before the rewrite and must pass both before and after
  it. This is a parity test, not a red test, because the behaviour must not
  move.
- **R2, unchanged behaviour:**
  - the MIG.0 golden suites (grants writer bytes and digests, trees,
    capabilities, behaviour, redaction) and the adapter suite;
  - the modules' own tests: lib `identity_grants`, `skills`, `kubernetes`,
    `gateway::ui`, `protocol_imports`; bin `commands::`;
  - `tests/kubernetes_manifest_tests.rs`, `tests/identity_grants*` and the
    skills tests under `tests/`;
  - the Python identity checker and the repository check.
- **R3, writer output:** `identity_grants.rs:319` is covered byte for byte
  by the MIG.0 grants golden. `backend_ops.rs:481`, `cap.rs` and
  `planner.rs:637` keep their existing tests. Those check semantically, not
  byte for byte, which is enough because the backend is the same call.
  Byte goldens before the swap are MIG.5.

## Files

The plan lands alone as a docs-only PR. The routing PR holds the 13
sources, `src/kubernetes_tests.rs` and the allowlist: 15 paths, inside the
cap. `cap.rs` (777 of 800
lines) and `gateway/ui/capabilities.rs` (739) gain at most the rustfmt
rewraps of a one-character-longer path, which the line ceiling is
re-checked against.

## MIG.1 sequence notes

- MIG.1d-i gains the `validator/mod.rs` doctest. The doctest keeps its
  `CapabilityDefinition` annotation and reads through the public
  `parse_capability`:
  `let cap: CapabilityDefinition = mcp_gateway::capability::parse_capability(yaml).unwrap();`.
  So the import stays used, and the doctest still documents the result type.
  `parse_capability` is the same call with only the error mapped
  (`capability/parser.rs:15-17`).

- U1 v2 merged on the line (#3920, 45ccc519c), so the MIG.1e hold
  (`config/config_file.rs`, `config/load_error.rs`,
  `commands/backend_url_keys.rs`, `commands/doctor/hidden_keys.rs`) is
  lifted.
- Allowlist joiners after MIG.0: `src/gateway/router/mcp_setup_refusal_tests.rs`
  (via #3922, moves in MIG.1e) and `src/config/strict_keys_tests.rs`
  (MIK-8102's P5 split, #3926, moves with `strict_keys.rs` in MIG.1d-ii).

## Review record

Plan round 1, 2026-10-18, on 6638c81a9: gpt SHIP and grok SHIP. Folded:
- explicit Kubernetes caller tests (both seats);
- the doctest keeps its type annotation (gpt; this also answers grok's
  unused-import point);
- `upgrade/tests.rs` is stated to stay on the allowlist (grok);
- the doctest moves to MIG.1d-i to keep the cap.

## Rollback

Revert the routing commit; the call sites and the allowlist go back
together.
