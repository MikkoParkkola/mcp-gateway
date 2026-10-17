# MIK-8425: design for migrating YAML to serde-saphyr

Status: design for review, 2026-10-17. Refs MIK-8425 (YAML.4). The decision
and the inventory are in
`docs/internal/analysis/2026-10-17-mik-8425-yaml-reassessment.md`; the raw
evidence is in
`docs/internal/analysis/evidence/2026-10-17-mik-8425-yaml-upstream.md`.

Goal: remove unsafe-libyaml from the dependency tree before the 4.0.0
freeze, with no unreviewed change to how YAML behaves. The fallback, if the
comparison tests in MIG.3 do not pass in time, is a reviewed dated extension
of the RUSTSEC-2024-0449 entry.

## What the Spark probe showed (serde_yaml 0.9.34 vs serde-saphyr 2.0.0)

These are default settings, from one `spark-cargo run`, rc 0. The full
output is in the evidence file.

| Case | serde_yaml 0.9.34 | serde-saphyr 2.0.0 |
|---|---|---|
| Duplicate key, into a struct | error (`duplicate field`) | error (`duplicate mapping key`) |
| Duplicate key, into a map | **last value wins** | **error** |
| Enum serialized | tag: `agent: !exact runner` | map: `agent: {exact: runner}` |
| Reading the other parser's enum output | refuses the map form | reads both forms |
| `!exact runner` and `!exact {source, id}` read | OK | OK, same value |
| Merge key `<<: *b` | not applied, so `<<` is an ordinary key | **applied** |
| `yes` read as a bool | refused | **`true`** |
| `yes` read as a String | `"yes"` | `"yes"` |
| Type error on `port: sk-SECRET-123` | `invalid type: string "sk-SECRET-123", expected u16` | `invalid u16`, **plus a source snippet that prints the line `port: sk-SECRET-123`** |

What follows from the table:

- figment's YAML provider deserializes into a map, and that is why
  `Config::load` keeps the last value. To preserve it, the adapter's map
  path uses `DuplicateKeyPolicy::LastWins` and its typed path keeps the
  error.
- The serializer must keep writing the tag form, so grants and config
  written by the new code stay readable by the old code. Use serde_yaml's
  form as the reference and emit tags. The option to check is
  serde-saphyr's `Tagged`/serializer options; if no option gives the tag
  form, keep a tag-form writer for enums inside the adapter. MIG.2 does not
  ship until the write-new/read-old test passes.
- Set merge keys to `AsOrdinary`, so `<<` reaches strict keys and is
  refused as it is today. Set `strict_booleans: true`.
- **Error snippets leak values.** The CWE-532 rule in `load_error.rs` makes
  this a blocker. `Options::with_snippet` defaults to true; setting it to
  false (docs.rs 2.0.0) returns the unwrapped error. The adapter sets it to
  false, and MIG.4 proves that the sentinel value is absent from both the
  message and any rendering.

The serializer form is not yet solved. serde-saphyr 2.0.0 documents
`Tagged<T>` for emitting a tag, but no global switch from enum-as-map to
enum-as-tag. The plan: `GrantAgent` (`identity_grants.rs:85`) gets
`serialize_with` emitting `Tagged("!exact", id)`. MIG.3 then proves that
serde_yaml reads the output. If that fails, the grants writer stays on the
tag form through the adapter's own emitter for that one enum. MIG.2 is
blocked until one of the two passes. Every other serialized type is checked
in MIG.5 for enums written by serde_yaml as tags (`rg 'Serialize' + enum` on
the 8 serializer files).

## Stages

### Gating criteria (MIG.2 cannot merge until both pass on its exact head)

- **G1, grants rollback.** Every type the gateway serializes and reads back
  (identity grants first) is written by the new backend and read by
  serde_yaml 0.9.34. The read value must be semantically equal, and the
  `!exact` tag form must be kept byte for byte against the MIG.0 golden
  files. A map-form `agent: {exact: ...}` in any written file fails G1.
- **G2, CWE-532 sentinel.** A sentinel value goes into a type error, a
  syntax error, a duplicate key, an unknown variant, an alias error and a
  budget refusal. It must be absent from the rendered error of every public
  adapter function (`from_str`, `from_str_map`, tree parse) and of the
  figment provider path (`ConfigFile::data`, the full `Config::load`
  extract, and `doctor/hidden_keys`/`backend_url_keys`). Both `Display` and
  `Debug` are checked. Setting `with_snippet: false` is necessary but not
  enough: the test proves the result, not the setting.

Each stage is its own PR off the release line, reviewed by two non-author
seats, with a one-pass pre-push and exact-head CI. Each is revertable as one
commit.

- **MIG.1a: add the adapter.** A new crate-private module `src/yaml.rs` with
  `from_str`, `from_str_map` (last value wins), `to_string`, and a tree type,
  `yaml::Value`. The tree is a re-export of `serde_yaml::Value` in MIG.1, and
  an owned tree with tags and non-string keys in MIG.2. The only shared edit
  is one `mod yaml;` line in `src/lib.rs`. No behaviour changes.
- **MIG.1b–e: route consumers through the adapter**, one group per PR, in
  the order of the overlap map below. Purely mechanical:
  `serde_yaml::` becomes `crate::yaml::`. The existing tests are the oracle.
- **MIG.2: swap the backend. BLOCKED until G1 and G2 pass on the swap PR's
  exact head, along with MIG.3 to MIG.5.** No swap without the
  write-new/read-old test passing.
  Only `src/yaml.rs`, `Cargo.toml` and `Cargo.lock` change: add `serde-saphyr = "=2.0.0"`, drop `serde_yaml`, and
  drop `yaml` from figment's features. The figment provider becomes
  `yaml::from_str_map` into `figment::value::Dict` inside `ConfigFile::data`
  and the other two figment call sites. Before this, MIG.1e routes those
  call sites through the adapter. Options: merge keys `AsOrdinary`,
  `strict_booleans`, map path `LastWins`, typed path `Error`, and snippets
  off (`with_snippet: false`). Record `spark-cargo tree -i unsafe-libyaml`:
  "did not match any packages".
- **MIG.3: comparison tests**, landed in MIG.1a as a dev-only module and run
  against both backends in MIG.2. Fixtures:
  - every `capabilities/*.yaml` (143) gives an identical parsed definition,
    compared as JSON, and an identical pin hash;
  - `gateway.example.yaml`, `deploy/single-node` and Helm values configs,
    and the config test fixtures, load to an identical `Config` (compared
    through `Debug`/JSON);
  - `tests/fixtures/identity_grants_3x/grants-3.4.0.yaml`, plus
    `!exact {source, id}`: the same value is read; written by the new code
    and read by serde_yaml with semantic equality;
  - `merge_key_refused_at_root` and `merge_key_refused_under_a_backend`
    still refuse;
  - `value_the_loader_accepts_loads` (last value wins) and a direct typed
    parse of a duplicate (refused);
  - the splice tag/alias tests (`config_persistence_splice_tests.rs:118-135`)
    and `count_yaml_aliases`;
  - scalars `yes`, `no`, `on`, `off`, `0755`, `0o755`, `.inf`, `~`, `null`
    and an empty value, read into String, bool and the tree type;
  - multi-document input gives the same outcome;
  - an alias input within the budget loads, and an alias bomb is refused.
- **MIG.4: redaction security gate.** Every case in
  `src/config/tests/load_error.rs`, plus a new type-error case carrying a
  `sk-` sentinel, renders no sentinel and keeps the key path, line and
  column. The assertions on exact error text are rewritten to these
  properties and reviewed as a CWE-532 surface.
- **MIG.5: byte-level output.** Config writes (splice, URL persistence,
  upgrade, `cap`, `config_write`) and grants writes are compared byte for
  byte before and after. Any accepted difference goes into
  `docs/UPGRADING-4.0.md`.
- **MIG.6: remove the exception.** After MIG.2 merges, remove the
  RUSTSEC-2024-0449 entry with a real OSV scan (rc 0 without the entry) and
  exact-head Docker and release security checks, then update
  `docs/legal/dependency-licenses.tsv` (add serde-saphyr and granit-parser,
  remove serde_yaml and unsafe-libyaml).

## PR sequence (at most 15 files each; fixtures first)

The golden fixtures are recorded with the **old** parser before anything
moves, so every later stage is proved against serde_yaml's actual output and
not against expectations written by hand.

| PR | Stage | Files | Content | Wait |
|---|---|---|---|---|
| 1 | MIG.0 | ~6 new test files and golden files | Golden capture with serde_yaml: JSON of all 143 parsed capability definitions plus pins; `Config` of each config fixture; byte output of the config writers (splice, URL, upgrade, `cap`, `config_write`) and of the grants writer; a behaviour table (duplicates map/struct, merge, scalars, multi-document, alias budget, both `!exact` forms); G2 harness over the figment path, plus a recorded baseline of the direct-path errors | none |
| 2 | MIG.1a | 2 (`src/yaml.rs`, one line in `src/lib.rs`) | Adapter over serde_yaml, with the comparison harness reading the MIG.0 golden files | PR 1 |
| 3 | MIG.1b | 15 | Typed-only readers (list under "Order", item 2) | PR 2 |
| 4 | MIG.1c | 13 | Serializers and tree walkers with no holder (item 3) | PR 2 |
| 5 | MIG.1d-i | 10 | The remaining files with no holder (item 4) | PR 2 |
| 6 | MIG.1d-ii | 1–4, one PR per released split | Held files (item 4) | each MIK-8102 split |
| 7 | MIG.1e | 4 plus test-only files, split to stay at 15 or fewer | Figment provider path (item 5) | U1 merged |
| 8 | MIG.2 | 3 (`src/yaml.rs`, `Cargo.toml`, `Cargo.lock`) plus any updated golden assertions | Backend swap; G1, G2 and MIG.3 to MIG.5 green on the exact head | PRs 3–7 |
| 9 | MIG.6 | 2 (`.github/osv-scanner.toml`, `docs/legal/dependency-licenses.tsv`) | Exception removal after a real scan | PR 8 |

PRs 3, 4 and 5 touch disjoint files and can run in parallel lanes. Before
each one opens, re-run the overlap check.

Observed while drafting G2: the direct paths already leak values today. For
example, `capability/parser.rs:16-17` formats the full serde_yaml error
(`invalid type: string "<value>"`). That is a pre-existing CWE-532 surface,
outside the figment path that `load_error.rs` protects. MIG.0 records it as
the baseline. After MIG.2, with snippets off and serde-saphyr's
value-free type errors (`invalid u16` in the probe), G2 requires absence on
these paths as well. If any direct path still leaks after the swap, the
adapter redacts the message rather than shipping the leak.

Note on the count: "46 production files" means files outside test
directories and `*_tests` modules. A few of them, for example
`mtls/config.rs`, use serde_yaml only inside their own `#[cfg(test)]`
module. They still move, because the dependency goes away.

## Overlap map and ordering

Checked 2026-10-17 against open PRs (`gh pr diff --name-only`) and the pushed
lane branches, using the merge base with the release line. No open PR or
pushed lane branch touches any of the 46 consumer files. The collisions are
with holds and planned work:

| Holder | Files held / planned | Our files affected | Rule |
|---|---|---|---|
| U1 window (u1-window-2469, `feat/mik-7211-u1-window-v2`, PR #2469) | `src/config/mod.rs`, `config/secret_file_population_tests.rs`, router, `meta_mcp/mod.rs` | none directly; `config/config_file.rs`, `config/load_error.rs` and `config/strict_keys.rs` are siblings in `config/` | never edit `config/mod.rs`; MIG.1e and MIG.2's figment change wait for U1 to merge |
| MIK-8102 splits (events P3 now; firewall, strict_keys, idempotency next) | `events/`, `config/features/events.rs`, `security/firewall/`, `config/strict_keys.rs` (780/800 lines) | `events/upstream.rs`, `config/features/events.rs`, `security/firewall/anomaly_config.rs`, `config/strict_keys.rs` | each waits for its split to merge; strict_keys moves only after its split, and it is at the ceiling |
| MIK-8353 3d-2, MIK-8387 PR-B, MIK-8451 | `gateway/router/**`, `gateway/meta_mcp/**` | none of the 46 production files (only test fixtures under router/meta_mcp use serde_yaml) | no wait; leave those test files to the last MIG.1 group |
| File ceiling 800 (`scripts/dev/check-file-size.py`) | `commands/cap.rs` 777, `gateway/ui/capabilities.rs` 739 | — | a mechanical rename keeps the line count; no added lines in those files |

Order:

1. **MIG.1a** (adapter plus comparison harness): no holder; it can go now.
2. **MIG.1b**, 15 files with no holder: the capability parser, validator,
   discovery detector, webhook, OpenAPI convert, `backend_rug_pull`;
   `commands/` trust, trust baseline and lab, `protocol_import`, setup,
   `add_remove`, `doctor/provenance`; `runtime/provision`; `mtls/config`.
3. **MIG.1c**, 13 files, the serializers and tree walkers with no holder:
   `identity_grants.rs` with `identity_grants_matching.rs` together,
   `skills/parser`, `kubernetes`, `gateway/ui/capabilities`,
   `gateway/ui/backend_ops`, `commands/upgrade`, `cap`, `config_write`,
   `api_key_rewrite`, `retired_config_keys`, `commands/mod.rs`,
   `protocol_imports/planner`.
4. **MIG.1d-i**, 10 files with no holder, which can go any time after
   MIG.1a: `playbook/engine`, `security/audit_rotation_config`,
   `security/caller_identity`, `control_plane/role_mapping`,
   `discovery/mod`, `discovery/secret_map`, the two executors (`graphql`,
   `jsonrpc`), and the two `config_persistence_*` files.
   **MIG.1d-ii**, 4 files that wait on MIK-8102: `events/upstream` and
   `config/features/events` after the events P3 split merges;
   `security/firewall/anomaly_config` after the firewall split;
   `config/strict_keys` after its split (it is at 780 of 800 lines).
5. **MIG.1e**, 4 files: `config/config_file.rs`, `config/load_error.rs`,
   `commands/backend_url_keys.rs` and `commands/doctor/hidden_keys.rs`,
   plus the test-only files that use serde_yaml. None of these is a file U1
   holds. Waiting for U1 to merge is a deliberate conservative choice,
   because U1 is reworking the same load path in `config/mod.rs`.

Group sizes: 15 + 13 + 10 + 4 + 4 = 46.
6. **MIG.2**, then MIG.4 and MIG.5 green on the swap PR, then **MIG.6**.

Before each MIG.1 PR, re-run the overlap check. If a holder appears,
the group moves later; files are never shared.

## Rollback

- MIG.1: revert any one group; the adapter still uses serde_yaml.
- MIG.2: revert the single commit (`src/yaml.rs` backend, `Cargo.toml`,
  `Cargo.lock`). That is safe only because MIG.3 proves that files written
  by the new code are read by serde_yaml.
- If MIG.6 has already merged, the revert also restores the
  RUSTSEC-2024-0449 entry with a newly ratified future date, and needs a
  passing OSV scan on the rollback commit.

## Fallback trigger

If MIG.3, MIG.4 or MIG.5 cannot pass before the freeze, stop at MIG.1. That
is no behaviour change and still has value. Take the dated extension
(`.github/osv-scanner.toml:40`, 2027-01-26 ceiling) to the operator as a new
reviewed decision.
