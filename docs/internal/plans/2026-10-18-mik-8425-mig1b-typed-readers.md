# MIK-8425 MIG.1b: route the typed readers through the YAML adapter (plan)

Status: for review before any code, 2026-10-18. Refs MIK-8425. Parent:
`docs/internal/design/2026-10-17-mik-8425-yaml-migration.md` (PR 3,
MIG.1b) and the MIG.1a adapter (#3922). Branch
`feat/mik-8425-mig1b-typed-readers`, cut from the #3922 head (5a53069f8).
It is pushed only after #3922 merges.

## Goal

Route 14 of the 15 files with no holder (design "Order", item 2) through
`crate::yaml`, with no behaviour change, and remove them from the bypass
allowlist. The 15th, the `validator/mod.rs` doctest, moves to MIG.1c to
keep this PR at 15 paths. The backend is still serde_yaml 0.9.34 behind the adapter, so
every rename is the same call.

## The 28 uses routed here, on 26 lines (inventory, 2026-10-18)

| File | Uses | Change |
|---|---|---|
| `src/capability/parser.rs:16` | `parse_capability` typed read | `crate::yaml::from_str` |
| `src/capability/discovery/detector.rs:26` | read into `serde_json::Value` | `crate::yaml::from_str::<Value>` |
| `src/capability/definition/webhook.rs:60` | test-module read | `crate::yaml::from_str` |
| `src/capability/openapi/convert.rs:110` | typed read (JSON then YAML fallback) | `crate::yaml::from_str` |
| `src/capability/openapi/convert.rs:589,596` | `to_string` of schemas into the generated capability text | `crate::yaml::to_string`; byte output unchanged (same backend) |
| `src/capability/backend_rug_pull.rs:73-88` | tree read, `Value::as_str` | `crate::yaml::from_str::<crate::yaml::Value>`, `crate::yaml::Value::as_str` |
| `src/commands/trust.rs:203`, `src/commands/trust/baseline.rs:23`, `src/commands/trust/lab.rs:374` | typed read after a JSON attempt | `crate::yaml::from_str` |
| `src/commands/protocol_import.rs:379` | typed read of untrusted specs (after the size and alias guard) | `crate::yaml::from_str` |
| `src/commands/protocol_import.rs:395` | doc comment naming `serde_yaml` | reworded to "the YAML parser", because the comment would keep the file on the allowlist |
| `src/commands/setup.rs:412`, `src/commands/add_remove.rs:301,389`, `src/commands/doctor/provenance.rs:35`, `src/mtls/config.rs:170-248` (6) | test-module reads | `crate::yaml::from_str` |
| `src/runtime/provision.rs:255` | typed read | `crate::yaml::from_str` |

Eight of the 14 files are under `src/commands/` (trust, trust baseline,
trust lab, protocol import, setup, add/remove, doctor provenance), which
only the binary compiles (`main.rs:18`), and `src/runtime/` (provision),
which both roots compile. Both crate roots mount `yaml` (MIG.1a), so
`crate::yaml` resolves in each. `scripts/release/check_identity_sources.py`
keys its allowed read-backs by file and function; `parse_capability` stays
an allowed site, and the pattern now matches `yaml::from_str` there (MIG.1a
T4).

## Tests (red first)

- **R1, red:** remove the 14 files from
  `tests/fixtures/mik_8425_yaml/direct_users.txt` before routing them.
  T5 (`no_new_file_names_a_yaml_parser_directly`) then fails, listing
  exactly those 14. After routing it passes. That is the proof each file no
  longer names the parser, including in comments and doctests.
- **R2, no behaviour change:** these must stay green, unchanged:
  - the MIG.0 capability golden (all 143 definitions through
    `parse_capability`) and the trees golden;
  - the existing tests of every touched module (the test-module reads
    above are those tests);
  - `scripts/release/test_check_identity_sources.py` and the repository
    check.
- **R3, writer bytes:** `openapi/convert.rs` writes YAML into generated
  capabilities. The existing protocol-import and OpenAPI tests that compare
  generated text (`commands/protocol_import_tests.rs`,
  `capability/openapi` tests) must pass unchanged. Those tests check the
  generated text semantically and by substring, not byte for byte. That is
  enough here only because the backend is the same serde_yaml call; byte
  equality of writer output is MIG.5's gate, before the backend changes.

## Overlap

Checked before the push: no open PR or lane branch touches these 14 files
(overlap map, 2026-10-17; re-run on the merged tip before the push). The
holders of nearby files (MIK-8102 splits, U1) hold none of them.
`commands/cap.rs` is not in this PR.

## MIG.1 sequence note

`src/gateway/router/mcp_setup_refusal_tests.rs` joined the allowlist in
#3922; it came from another lane with the release-line tip. It is
test-only, next to the router lanes' files, so it moves with the test-only
files in MIG.1e. The allowlist must keep shrinking to `src/yaml.rs` and
`tests/common/yaml.rs` by MIG.2. Any file that joins later gets a row in
this list.

## Files: two PRs

This plan lands alone as a docs-only PR. The routing PR, based on it, holds
only the 14 sources above and the allowlist fixture: 15 paths, inside the
cap. The `validator/mod.rs`
doctest moves to MIG.1c. A doctest compiles against the public crate and
cannot reach the crate-private adapter, so its change there is to read
through the public `mcp_gateway::capability::parse_capability(yaml)`, which
does exactly this read.

## Review record

Plan round 1, 2026-10-18, on 71a47ba41: gpt SHIP-WITH-FIXES. The kimi seat
failed twice (backend 503, no verdict) and was replaced by agy (Gemini), on
the lead's instruction; agy returned SHIP, with improvements folded (full
paths in the table, the binary and library crate wording). Folded from
gpt:
- the plan goes in its own PR, so the routing PR keeps the 15-path cap;
- the use count is corrected (28 occurrences on 26 lines);
- the writer-test coverage is described honestly (semantic, not bytes).

## Rollback

Revert the routing commit; the allowlist and the call sites go back
together, and the adapter (MIG.1a) stays.
