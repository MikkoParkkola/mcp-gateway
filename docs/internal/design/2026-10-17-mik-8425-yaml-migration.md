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

- Duplicate keys depend on the destination, not on a typed-versus-map
  split. serde_yaml refuses them in a struct (serde's `duplicate field`)
  and in `serde_yaml::Value` (`strict_keys.rs:345-347`). It keeps the last
  value in any map, including figment's `Dict` and nested `HashMap` and
  `BTreeMap` fields inside typed structs. That is why `Config::load`, the
  `Dict` fallback in `strict_keys.rs:351` and `retired_config_keys.rs:64`
  (`loose`) keep the last value. serde-saphyr's policy is one setting per
  parse, and neither setting reproduces all four destinations: `Error`
  tightens nested maps, while `LastWins` may relax structs. MIG.0 records
  all four (struct, nested map in a struct, tree, `Dict`). **Exact parity in
  all four destinations is an unconditional MIG.2 precondition.** No
  difference ships as an accepted change. If the adapter cannot reach
  parity, for example with a pre-pass over its own tree that refuses
  duplicates where serde_yaml did, the fallback applies: the dated
  extension, by a new reviewed decision. The `Dict` call sites go through an
  explicit `from_str_loose` (`LastWins`).
- The serializer must keep writing the tag form, so grants and config
  written by the new code stay readable by the old code. Use serde_yaml's
  form as the reference and emit tags. The option to check is
  serde-saphyr's `Tagged`/serializer options; if no option gives the tag
  form, keep a tag-form writer for enums inside the adapter. MIG.2 does not
  ship until the write-new/read-old test passes.
- Grants acceptance must not widen. serde-saphyr also *reads* the YAML map
  form `agent: {exact: ...}`, which serde_yaml refuses. YAML grants accept
  only the tag form; JSON keeps the map form. The 3.x bare
  `!exact runner` rows (`grants-3.4.0.yaml`) are refused today, because
  `GrantAgent::Exact` holds a `GrantAgentKey` (`identity_grants.rs:85-90`),
  so they stay refusal fixtures. Successful reads and rollback use
  qualified `!exact {source, id}` rows.
- Set merge keys to `AsOrdinary`, so `<<` reaches strict keys and is
  refused as it is today. Set `strict_booleans: true`.
- **Error snippets leak values.** The CWE-532 rule in `load_error.rs` makes
  this a blocker. `Options::with_snippet` defaults to true; setting it to
  false (docs.rs 2.0.0) returns the unwrapped error. The adapter sets it to
  false, and MIG.4 proves that the sentinel value is absent from both the
  message and any rendering.

The serializer form is not yet solved. serde-saphyr 2.0.0 documents
`Tagged<T>` for emitting a tag, but no global switch from enum-as-map to
enum-as-tag. **No type's `Serialize` impl changes.** `GrantAgent` is also
serialized to JSON, both for JSON grants files and for `grant_digest`
(`identity_grants/journal.rs:173-177` hashes `serde_json::to_vec(grant)`),
so a `serialize_with` hook would break JSON compatibility and every stored
journal digest. Instead, the adapter's `to_string` serializes into its own
tree. In that tree an externally tagged newtype or struct variant becomes a
tagged node (`!variant <content>`), as serde_yaml wrote it. The adapter then
emits the tree through serde-saphyr. MIG.0 records goldens for JSON grants
and for `grant_digest`, and they must stay unchanged in every stage. MIG.2
is blocked until G1 passes with this emitter. MIG.1a runs a static audit before the
swap's shape is fixed: every type serialized through the adapter that
serde_yaml writes with a tag (enums: `rg` for `Serialize` plus `enum` in the
8 serializer files and in the types they emit). Each type found gets the
same tagged-node treatment and a golden file in MIG.0. The same MIG.1a
inventory of the `Value` and `Mapping` API in use (indexing, `get`,
`as_*`, tag access, `Number`) fixes the contract of the MIG.2 owned tree.

## Stages

### Gating criteria (MIG.2 cannot merge until G1, G2 and G3 pass on its exact head)

- **G1, grants rollback.** Every type the gateway serializes and reads back
  (identity grants first) is written by the new backend byte-equal to the
  MIG.0 golden files, which serde_yaml 0.9.34 was proven in MIG.0 to read
  back to the same value. The throwaway harness re-reads the MIG.2 head's
  actual output with serde_yaml 0.9.34 for semantic equality, and the
  output is attached to the PR. A map-form `agent: {exact: ...}` in any
  written file fails G1.
- **G2, CWE-532 sentinel.** A sentinel value goes into a type error, a
  syntax error, a duplicate key, an unknown variant, an alias error and a
  budget refusal. It must be absent from the rendered error of every public
  adapter function (`from_str`, `from_str_loose`, tree parse) and of the
  figment provider path (`ConfigFile::data`, the full `Config::load`
  extract, and `doctor/hidden_keys`/`backend_url_keys`). Both `Display` and
  `Debug` are checked. Setting `with_snippet: false` is necessary but not
  enough: the test proves the result, not the setting.
- **G3, read-side enum parity.** serde-saphyr accepts the map form
  (`agent: {exact: runner}`) where serde_yaml 0.9 refuses it (probe). MIG.1a
  inventories every enum reachable from a YAML deserialization: the field
  types of every type passed to the adapter's `from_str`. MIG.0 records,
  for each one, the tag form (accepted) and the map form (refused by
  serde_yaml). On the MIG.2 head each map-form fixture must still be
  refused. How is not decided yet. It is a Spark spike (a serde-saphyr
  option, or a check in the adapter's tree pre-pass), run alongside MIG.0
  so that the fallback decision comes a stage earlier. The arbiter is the
  spike's output against the MIG.0 goldens, reviewed by both seats. If
  neither approach reaches parity, the fallback applies.
- **Resource limits.** MIG.2 sets serde-saphyr's `Budget` and alias limits
  explicitly, naming each field and value in `src/yaml.rs`. Each value sits
  at or beyond serde_yaml's refusal point measured in MIG.0, for nesting
  depth and alias-expansion size. A tighter value refuses documents that
  load today, which is a behaviour change: it is recorded in MIG.3 and in
  `docs/UPGRADING-4.0.md`, and goes through the fallback rule. The alias
  fixtures test at and just past each limit.
- **G1 harness provenance.** The throwaway harness's source, exact
  `spark-cargo` command, `Cargo.lock` and output SHA-256 are attached to the
  MIG.2 PR, not the output alone.
- Dependency provenance (unsafe policy, maintenance, MSRV, advisory history
  for serde-saphyr and granit-parser) is recorded in the reassessment note's
  candidate table. MIG.2 re-checks it against OSV and crates.io on the day
  it opens.

Each stage is its own PR off the release line, reviewed by two non-author
seats, with a one-pass pre-push and exact-head CI. Each is revertable as one
commit. The MIG.3 to MIG.5 tests land in MIG.0 (goldens) and MIG.1a
(harness), and run against the new backend inside the MIG.2 PR; they are
not separate PRs after the swap. The MIG.1a inventories (enums and the
tree API) are committed as checklists, and each item names its parity
fixture.

- **MIG.1a: add the adapter.** A new crate-private module `src/yaml.rs`.
  Its surface matches what the consumers use today (`rg -o
  'serde_yaml::[a-zA-Z_]+'`): `from_str` (237 uses), `Value` (62),
  `to_string` (39), `to_value` (10), `Mapping` (5), `from_value` (3),
  `Error` (2) and a document stream for the one `Deserializer` use. It also
  adds `from_str_loose` for the `Dict` call sites. `Value` and `Mapping` are
  re-exports of serde_yaml's types in MIG.1, and become an owned tree with
  tags and non-string keys in MIG.2. The module is mounted in **both** crate
  roots, `src/lib.rs` and `src/main.rs`. The binary compiles
  `mod commands;` and `mod runtime;` itself (`main.rs:18`, `:46`), so
  `crate::yaml` must resolve there too. Those are the only shared edits. No
  behaviour changes.
  MIG.1a also extends the `READ_BACK` pattern in
  `scripts/release/check_identity_sources.py:216` to recognise the adapter's
  parse functions (`yaml::from_str`, `from_str_loose`, `from_value`, and the
  document stream). It adds a recognition test and a negative control, so
  that routing consumers through the adapter in MIG.1b cannot hide an
  identity read-back from that CI check.
  Integration-test crates under `tests/` (45 files use serde_yaml) cannot
  reach the crate-private adapter, and API visibility is not widened.
  MIG.1a adds `tests/common/yaml.rs`, a test helper that wraps serde_yaml
  for now. MIG.1f routes the 45 files through it in PRs of at most 15
  files. MIG.2 then swaps the helper's backend to `serde_saphyr` (a normal
  dependency, so visible to tests) with the adapter's options. Equality is
  by construction: both the adapter and the helper assert their options
  against one shared fixture file (`tests/fixtures/mik_8425_yaml/options.txt`),
  so neither has to inspect the other.
- **MIG.1b–e: route consumers through the adapter**, one group per PR, in
  the order of the overlap map below. Purely mechanical:
  `serde_yaml::` becomes `crate::yaml::`. The existing tests are the oracle.
- **MIG.2: swap the backend. BLOCKED until G1, G2, G3 and duplicate-key parity pass on the swap PR's
  exact head, along with MIG.3 to MIG.5.** No swap without the
  write-new/read-old test passing.
  Only `src/yaml.rs`, `Cargo.toml` and `Cargo.lock` change: add `serde-saphyr = "=2.0.0"`, drop `serde_yaml`, and
  drop `yaml` from figment's features. The figment provider becomes
  `yaml::from_str_loose` into `figment::value::Dict` inside `ConfigFile::data`
  and the other two figment call sites. Before this, MIG.1e routes those
  call sites through the adapter. Options: merge keys `AsOrdinary`,
  `strict_booleans`, map path `LastWins`, typed path `Error` (subject to the
  duplicate-key block above), and snippets off. Snippets are off with
  `with_snippet: false`; `crop_radius: 0` also disables snippet wrapping
  (docs.rs 2.0.0). Both are set, and G2 proves the result. The same PR adds
  serde-saphyr and granit-parser to `docs/legal/dependency-licenses.tsv`.
  Both are MIT OR Apache-2.0 per their published Cargo.toml; GitHub's
  `NOASSERTION` for granit-parser comes from its license detector. That
  licence check therefore happens while rollback is trivial. Record
  `spark-cargo tree -i unsafe-libyaml`: "did not match any packages".
- **MIG.3: comparison tests.** They compare against the golden files that
  MIG.0 recorded with serde_yaml. Where MIG.0 needs to read data back, it
  proves that serde_yaml reads its own goldens. After MIG.2, new output must
  equal those goldens byte for byte, so serde_yaml's readability carries
  over without serde_yaml staying in the graph. **No legacy parser remains
  in the product dependency graph, including dev-dependencies**, because OSV
  scans `Cargo.lock`. Any live old-against-new check on the MIG.2 head runs
  in a throwaway Spark harness outside the repository, like the probe, with
  its output attached to the PR. Fixtures:
  - every `capabilities/*.yaml` (143) gives an identical parsed definition,
    compared as JSON, and an identical pin hash;
  - `gateway.example.yaml`, `deploy/single-node` and Helm values configs,
    and the config test fixtures, load to an identical `Config` (compared
    through `Debug`/JSON);
  - grants: `grants-3.4.0.yaml` (bare rows) and a YAML map-form
    `agent: {exact: {source, id}}` stay **refused**. Qualified
    `!exact {source, id}` rows read to the same value, and the new code's
    output is byte-equal to the tag-form golden;
  - `merge_key_refused_at_root` and `merge_key_refused_under_a_backend`
    still refuse;
  - `value_the_loader_accepts_loads` (last value wins), plus duplicate keys
    in each of the four destinations: struct, nested map inside a struct,
    tree, and `Dict`. Include a backend-key typo after a repeated key
    (`unrecognised_key_after_a_loader_accepted_value_refused`);
  - write-new/read-old for tree values: tags, non-string keys and
    non-finite numbers, round-tripped against the goldens;
  - the splice tag/alias tests (`config_persistence_splice_tests.rs:118-135`)
    and `count_yaml_aliases`;
  - scalars `yes`, `no`, `on`, `off`, `0755`, `0o755`, `.inf`, `~`, `null`
    and an empty value, read into String, bool and the tree type;
  - documents: a single document; an explicit `---` single document; a
    Kubernetes multi-document stream (`kubernetes.rs`, the one
    `Deserializer` use) including empty documents and a malformed later
    document. Each gives the same values or the same refusal as serde_yaml;
  - write-side quoting: strings that look like other scalars (`"yes"`,
    `"no"`, `"on"`, `"off"`, `"0755"`, `"null"`, `"~"`, `".inf"`) go through
    every writer, are byte-compared to the goldens, and read back as
    strings;
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
  exact-head Docker and release security checks. Remove the serde_yaml and
  unsafe-libyaml rows from `docs/legal/dependency-licenses.tsv`.

## PR sequence (at most 15 files each; fixtures first)

The golden fixtures are recorded with the **old** parser before anything
moves, so every later stage is proved against serde_yaml's actual output and
not against expectations written by hand.

| PR | Stage | Files | Content | Wait |
|---|---|---|---|---|
| 1 | MIG.0 | ~6 new test files and golden files | Golden capture with serde_yaml: JSON of all 143 parsed capability definitions plus pins; `Config` of each config fixture; byte output of the config writers (splice, URL, upgrade, `cap`, `config_write`) and of the grants writer; JSON grants bytes and `grant_digest` values (must never change); the current leak at `capability/parser.rs:16-17` as a documented "before"; a behaviour table (duplicates map/struct, merge, scalars, multi-document, alias budget, both `!exact` forms); G2 harness over the figment path, plus a recorded baseline of the direct-path errors | none |
| 2 | MIG.1a | 6 (`src/yaml.rs`, plus one `mod yaml;` line each in `src/lib.rs` and `src/main.rs`; `tests/common/yaml.rs`; `check_identity_sources.py` and its test) | Adapter over serde_yaml, with the comparison harness reading the MIG.0 golden files | PR 1 |
| 3 | MIG.1b | 15 | Typed-only readers (list under "Order", item 2) | PR 2 |
| 4 | MIG.1c | 13 | Serializers and tree walkers with no holder (item 3) | PR 2 |
| 5 | MIG.1d-i | 10 | The remaining files with no holder (item 4) | PR 2 |
| 6 | MIG.1d-ii | 1–4, one PR per released split | Held files (item 4) | each MIK-8102 split |
| 7 | MIG.1e | 4 plus test-only files, split to stay at 15 or fewer | Figment provider path (item 5) | U1 merged |
| 7f | MIG.1f | 45 integration-test files in 3 PRs of 15 | Route `tests/*.rs` through `tests/common/yaml.rs` | PR 2 |
| 8 | MIG.2 | 5 (`src/yaml.rs`, `tests/common/yaml.rs`, `Cargo.toml`, `Cargo.lock`, `dependency-licenses.tsv`) plus any updated golden assertions | Backend swap; G1, G2, G3, duplicate-key parity and MIG.3 to MIG.5 green on the exact head | PRs 3–7f |
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
| U1 window (u1-window-2469, `feat/mik-7211-u1-window-v2`; historical PR #2469) | `src/config/mod.rs`, `config/secret_file_population_tests.rs`, router, `meta_mcp/mod.rs` | none directly; `config/config_file.rs`, `config/load_error.rs` and `config/strict_keys.rs` are siblings in `config/` | never edit `config/mod.rs`; MIG.1e and MIG.2's figment change wait for U1 to merge |
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
the group moves later; files are never shared. Before MIG.2 and MIG.6,
also re-run it for `Cargo.toml`, `Cargo.lock` and `.github/osv-scanner.toml`
across every open PR and lane branch. Any lane changing manifests
(MIK-8387 PR-B was reported to; its pushed branch
`test/mik-8387-oracle-red` shows no manifest diff on 2026-10-17)
coordinates the merge order with this lane.

The U1 hold is released by the merge of the v2 branch the lead named,
`feat/mik-7211-u1-window-v2`. It is not released by historical PR #2469
(`fix/mik-7211-u1-window`, last pushed 2026-09-30). The v2 branch was not
yet on the remote on 2026-10-17.

## Rollback

- MIG.1: revert any one group; the adapter still uses serde_yaml.
- MIG.2: revert the single commit (`src/yaml.rs` backend, `Cargo.toml`,
  `Cargo.lock`). That is safe only because G1 proves that files written by
  the new code are read by serde_yaml.
- Whenever a revert puts unsafe-libyaml back and the RUSTSEC-2024-0449
  entry is absent or expired, whether or not MIG.6 has merged (the current
  entry expires 2026-10-26), the revert needs a newly ratified exception
  date and a passing OSV scan on the rollback commit before it merges.

## Fallback trigger

If MIG.3, MIG.4 or MIG.5 cannot pass before the freeze, stop at MIG.1. That
is no behaviour change and still has value. Take the dated extension
(`.github/osv-scanner.toml:40`, 2027-01-26 ceiling) to the operator as a new
reviewed decision.

## Review record

- Round 1, 2026-10-17. The gpt seat reviewed 464294ad1 and returned
  SHIP-WITH-FIXES. The kimi seat's first run on 464294ad1 produced no
  verdict (exit 65) and was excluded. Its re-run on 85d8e474e returned
  SHIP-WITH-FIXES.
- The gate-NOW findings were checked at source and folded:
  - duplicate keys follow the destination (`strict_keys.rs:345-353`,
    `retired_config_keys.rs:60-66`);
  - the adapter is mounted in both crate roots, and its API surface comes
    from usage counts (`main.rs:18`, `:46`);
  - grants refusal fixtures (`identity_grants.rs:85-90`);
  - no legacy parser stays in the graph, so live cross-reads happen
    outside the repository;
  - manifests are added to the overlap check;
  - rollback restores an expired exception.
- The MIK-8387 manifest change was not confirmed: its pushed branch has
  no `Cargo.toml` or `Cargo.lock` diff. The general check was adopted
  anyway.
- Also folded: the enum and API audit moves to MIG.1a, write-side quoting
  fixtures, the licence check moves to MIG.2, both snippet settings are
  named, and the U1 v2 landing condition is stated.
- Round 2 (confirmation), 2026-10-17, on 9fb6b9ce5. Both seats returned
  SHIP-WITH-FIXES with HIGH findings, so the design stays open for another
  round. The kimi seat produced no verdict twice (exit 65, raw tool-call
  tokens); those runs were excluded. The third run, with the cited source
  excerpts inlined, returned a verdict. Folded after source checks:
  - the `GrantAgent` hook would change JSON grants and `grant_digest`
    (`journal.rs:173-177`), so tags are emitted inside the adapter only;
  - the `READ_BACK` pattern (`check_identity_sources.py:216`) is extended
    before routing;
  - `tests/` access goes through a test helper (MIG.1f);
  - Kubernetes stream fixtures are added;
  - exact duplicate-key parity is unconditional;
  - G3 adds read-side enum parity (map form refused);
  - budgets are named, harness provenance is attached, and dependency
    provenance is re-checked.
- Round 3 (final full round), 2026-10-17, on 9322eaa8a. The gpt seat
  returned SHIP and the kimi seat SHIP-WITH-FIXES. Neither found a HIGH,
  so the design is closed. Folded:
  - the PR 8 gate cell now names G3 and duplicate-key parity;
  - a budget tighter than serde_yaml's is a recorded behaviour change;
  - helper and adapter options are compared through a shared fixture;
  - the MIG.3 to MIG.5 tests run inside the MIG.2 PR;
  - the inventories become checklists;
  - the G3 and parity spike runs alongside MIG.0.
  Not folded: automating the overlap re-check as a script, recorded as a
  LATER improvement.
