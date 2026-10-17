# MIK-8425: reassessment of the abandoned YAML parser (RUSTSEC-2024-0449)

Status: proposed decision, 2026-10-17. Refs MIK-8425, MIK-8424. It needs an
operator decision (see "Decision required"). This note changes no code,
lockfile or scanner config.

## Verdict

No small, safe migration exists that can land before the exception expires
on 2026-10-26. The only candidate that removes the abandoned C-translated
parser is serde-saphyr. It is pure safe Rust and permissively licensed, but
adopting it means rewriting both paths that reach unsafe-libyaml. It also
has no YAML `Value` type, and four of its defaults change config semantics.

Recommendation: option C. The operator ratifies a dated extension of the one
RUSTSEC-2024-0449 entry, tied to a staged migration ticket that carries the
named criteria below. Option B, letting the exception expire, is the
alternative. Choosing between them belongs to the operator.

## Current state (observed, release line 13590f362, 2026-10-17)

- Exception: `.github/osv-scanner.toml:38-41` holds one `[[IgnoredVulns]]`
  entry for RUSTSEC-2024-0449 with `ignoreUntil = 2026-10-26`, added in
  b6ac37734 (#3883, MIK-8424). The repository has no `deny.toml`,
  `audit.toml` or `.cargo/audit.toml`.
- The exception is read by the OSV v2.6.0 gate in `docker.yml:198-201` (the
  GHCR image) and `release.yml:61-64` (crates.io publish and the jobs that
  depend on it). `ci.yml:951` runs a plain `cargo audit` without
  `--deny warnings`, so it reports the advisory as a warning and passes.
- `spark-cargo tree -i unsafe-libyaml --all-features -e normal,build,dev`
  (rc 0) shows two edges:

  ```
  unsafe-libyaml v0.2.11
  └── serde_yaml v0.9.34+deprecated
      ├── figment v0.10.19
      │   └── mcp-gateway v4.0.0-beta.3
      └── mcp-gateway v4.0.0-beta.3
  ```

  The figment edge comes from the `yaml` feature at `Cargo.toml:152`
  (`figment = { version = "0.10", features = ["yaml", "env"] }`). The direct
  edge is `Cargo.toml:146` (`serde_yaml = "0.9"`). Removing only one edge
  leaves the advisory in the tree. The `/home/mikko/mirrors/...` path in the
  tree output is spark-cargo's Spark mirror of this worktree, at the same
  release-line commit.

## Advisory status (primary sources, all read 2026-10-17)

| Source | Finding |
|---|---|
| [rustsec.org RUSTSEC-2024-0449](https://rustsec.org/advisories/RUSTSEC-2024-0449.html) | INFO / Unmaintained; "no patched versions". The repository was archived 2024-03-25 and the last release is 0.2.11. The advisory names `serde_yaml` and `serde_yaml_ng` as users and lists saphyr/serde-saphyr and noyalib as alternatives. The page reads "Reported March 25, 2024, Issued October 12, 2026". |
| [OSV API RUSTSEC-2024-0449](https://api.osv.dev/v1/vulns/RUSTSEC-2024-0449) | `informational: unmaintained`. Affects every version (introduced 0, no fix event). Published 2024-03-25, modified 2026-10-12. |
| OSV API for unsafe-libyaml | RUSTSEC-2023-0075 (unaligned write) was fixed in 0.2.10, so it does not apply to the locked 0.2.11. |
| OSV API for serde_yaml | RUSTSEC-2018-0005 affects only pre-0.8.4 releases, so it does not apply to 0.9.34. |
| [crates.io serde_yaml](https://crates.io/api/v1/crates/serde_yaml) | The latest release is `0.9.34+deprecated`, published 2024-03-25. GitHub `dtolnay/serde-yaml` is archived. |
| [crates.io unsafe-libyaml](https://crates.io/api/v1/crates/unsafe-libyaml) | The latest release is 0.2.11, published 2024-03-17. GitHub `dtolnay/unsafe-libyaml` is archived. |
| [Figment master Cargo.toml](https://github.com/SergioBenitez/Figment/blob/master/Cargo.toml) | `yaml = ["serde_yaml"]` with `serde_yaml = "0.9"`. The latest release is 0.10.19 (2024-05-17). The repository is active (pushed 2026-10-13), but there is no upstream fix: the figment edge stays for as long as its `yaml` feature is enabled. |

Classification: this is a maintenance advisory, not a known exploitable
vulnerability. The residual risk is that bugs in c2rust-translated unsafe
code inside a config and capability parser will never be fixed upstream.
That risk is unchanged since MIK-8424.

## Candidates (crates.io API, OSV API and GitHub API, read 2026-10-17)

| Crate (latest) | Parser it pulls | Removes the risk? | License | Maintenance / advisories |
|---|---|---|---|---|
| serde_yaml_ng 0.10.0 | `unsafe-libyaml` (the same crate) | No: the advisory still fires | MIT | last push 2025-09-14 |
| serde_norway 0.9.42 | `unsafe-libyaml-norway` 0.2.15, a fork of the same c2rust code | No. The advisory ID stops matching, which turns the gate green, but the abandoned code stays. Rejected under the ticket's kill gate. | MIT OR Apache-2.0; the parser crate is MIT | the parser fork's last release and push were both 2024-12-21 |
| serde_yaml_bw 2.5.8 | `unsafe-libyaml-norway` plus granit-parser | No, for the same reason | MIT OR Apache-2.0 | active |
| serde_yml 0.0.13 | noyalib | Rejected: RUSTSEC-2025-0068 (unsound, every version) | MIT OR Apache-2.0 | repository archived |
| noyalib 0.0.58 | own parser | Pre-1.0, 56 releases since 2026-05-10. RUSTSEC-2026-0333 (budgets not enforced, fixed in 0.0.53) shows the young parser has already had an advisory. Same maintainer as serde_yml. | MIT OR Apache-2.0 | active, 10 stars |
| saphyr 0.2.2 / yaml-rust2 0.13.0 | pure Rust | Yes, but neither has serde support. Every typed load would need hand-written mapping. | MIT OR Apache-2.0 (Cargo.toml) | active |
| **serde-saphyr 2.0.0** | granit-parser 2.0.0 (pure Rust; normal dependencies are arraydeque and smallvec only) | **Yes.** The crate states "unsafe forbidden" and runs Miri and fuzz CI. It passes the YAML Test Suite 2022-01-17 (README). | MIT OR Apache-2.0, and granit-parser is also MIT OR Apache-2.0 (Cargo.toml) | active (pushed 2026-10-14), no OSV advisories. Version 2.0.0 was released 2026-10-13, four days before this note. MSRV is 1.89. |

Licensing: MIT and Apache-2.0 dependencies are compatible with distributing
mcp-gateway under PolyForm Noncommercial 1.0.0, provided the notices are
kept. Any new crate is added to `docs/legal/dependency-licenses.tsv`.

serde-saphyr's optional `figment` feature depends on figment `^0.10` with
`default_features: true`. Figment 0.10.19 as published declares no
`default` feature (crates.io features: `env`, `json`, `parse-value`, `test`,
`yaml`), so that dependency does not enable figment's `yaml` feature.
serde-saphyr's MSRV of 1.89 is below mcp-gateway's `rust-version = "1.95"`
(`Cargo.toml:5`).

## YAML.1 inventory (release line 13590f362)

Size, in counts:

- `serde_yaml` appears 467 times in 184 `.rs` files. 46 of those files are
  production code: outside test modules, `*_tests` paths and fixtures.
  By API use, 21 of them only parse into typed values and 8 also
  serialize. Another 15 walk a `Value`/`Mapping` tree, 6 of which also
  serialize. Three use the figment `Yaml` provider: `config_file.rs`,
  `doctor/hidden_keys.rs`, and `backend_url_keys.rs`, which is also one of
  the tree walkers.
- 100 of the references are `serde_yaml::Value`, `Mapping` or `Sequence`,
  spread over 31 files. 13 of those files are production code.
- `serde_yaml::to_*` serializers appear in 14 production files.
- figment's `Yaml` provider is used in `config/config_file.rs:80`, the main
  config load path, and also in `commands/backend_url_keys.rs`,
  `commands/doctor/hidden_keys.rs` and the doctor tests.
- There are no uses of `serde_yml`, `serde_yaml_ng`, `yaml_rust` or direct
  `unsafe_libyaml`.

Consumers, grouped by contract:

- **Gateway config** (`gateway.yaml`, public, documented): figment extract
  through `ConfigFile`; strict unknown-key checks in `config/strict_keys.rs`
  (which walks a `serde_yaml::Value`); comment-keeping writes in
  `config_persistence_splice.rs` and `config_persistence_url.rs`; and the
  `commands/` rewriters (upgrade, retired keys, backend URL keys, API key
  rewrite, `cap`, setup, add/remove, trust).
- **Capability definitions** (143 `capabilities/*.yaml` files, public
  catalog): `capability/parser.rs`, the validator, OpenAPI conversion and
  `backend_rug_pull.rs`. The SHA-256 pin hashes the file text with the
  `sha256:` line stripped (`capability/parser.rs:49-51`), so it does not
  depend on the parser. A parser change does not invalidate any pin.
- **Identity grants** (an on-disk file the gateway writes and reads):
  `identity_grants.rs:252` reads and `:319` writes with `serde_yaml`. The
  enum variant is a YAML tag, `agent: !exact runner` (fixture
  `tests/fixtures/identity_grants_3x/grants-3.4.0.yaml`). The user-facing
  error at `identity_grants_matching.rs:95-99` tells users to write
  `agent: !exact {source: ..., id: ...}`. The source comment at
  `identity_grants_matching.rs:108-110` says serde_yaml refuses the JSON map
  form of `exact`, and `Tree::bare_rows` walks the tags in a
  `serde_yaml::Value`.
- **Other inputs**: skills frontmatter (`skills/parser.rs`, which keeps
  extra keys as `serde_yaml::Value`), Kubernetes manifests, protocol imports
  (`count_yaml_aliases` caps aliases, an alias-bomb guard), mTLS, firewall,
  audit rotation, events and playbooks.

YAML features that current behaviour depends on:

- **Tags**: `!exact` selects an enum variant, as described above. The splice
  test `config_persistence_splice_tests.rs:118` keeps a `!!str` scalar.
- **Anchors and aliases**: `config_persistence_splice_tests.rs:125` resolves
  an alias across the document, and `protocol_import_tests.rs:37-42` counts
  aliases.
- **Merge keys are not applied.** serde_yaml 0.9 does not expand `<<`, so
  strict keys refuse it. Tests `merge_key_refused_at_root` and
  `merge_key_refused_under_a_backend` in
  `tests/c1_unrecognised_config_keys.rs:83-98` pin this, and
  `docs/UPGRADING-4.0.md:906` documents it.
- **Error text**: `config/load_error.rs` (MIK-8375, CWE-532) removes values
  from figment and serde errors before they reach logs. The parsing in
  `redact_message` relies on serde's `", expected "` and
  `"unknown variant `"` markers. `src/config/tests/load_error.rs:191-272`
  asserts exact serde_yaml text, for example `at line 1 column 4` and
  `found unexpected end of stream at line 4 column 1`. The text
  `unknown field` and `unknown variant` (27 occurrences in Rust sources)
  comes from serde's derive and does not depend on the format crate.
- Features tree (`spark-cargo tree -e features -i serde_yaml
  --all-features`, rc 0): `figment feature "yaml"` leads to
  `figment feature "serde_yaml"`, which is the figment edge described
  above.

## What serde-saphyr 2.0.0 changes

Sources: the 2.0.0 docs.rs page for `Options`, and the README.

- It has no YAML `Value` type. It can deserialize into `serde_json::Value`,
  but that drops tags and non-string keys. So `strict_keys`, `bare_rows`,
  the splice code, skills `extra` and the 31 files that use `Value`/`Mapping`
  all need a replacement tree type.
- `merge_keys` defaults to `Merge`. That would accept configs that are
  refused today, unless the option is set to `AsOrdinary` or `Error`.
- `strict_booleans` defaults to false, which accepts YAML 1.1
  `yes`/`no`/`on`/`off` as booleans. serde_yaml 0.9 follows YAML 1.2 here,
  so untyped and `bool` targets can change meaning.
- Duplicate keys are a configurable policy. The README says the default is
  an error; the docs.rs example shows `LastWins` set explicitly. The 2.0.0
  default still has to be confirmed by a test.
- Tags: unknown local tags remain available to select enum variants by
  default. Its serializer's output form for enums (tag or single-key map) is
  not established, and serde_yaml refuses the map form, so rollback can
  break.
- Error messages use a different format and snippet rendering. It does offer
  value redaction in its own diagnostics, but `load_error.rs` must be
  re-proved against it.

## Options and trade-off

- **A. Migrate before 2026-10-26.** Rejected. It touches 46 production
  files, two dependency edges, a new tree type and four semantic defaults,
  on a crate whose major version is four days old. Landing that inside the
  window means skipping the compatibility proof the ticket requires.
- **B. Let the exception expire.** Runtime behaviour does not change, and
  `cargo audit` keeps warning without failing. From 2026-10-27 the OSV gate
  blocks the GHCR image build and the crates.io publish chain (`docker.yml`,
  `release.yml`) until the migration lands. This is honest and costs
  nothing, but it holds v4.0.x publishing hostage to a maintenance advisory
  with no known exploit.
- **C. Extend under a new, dated, reviewed decision.** Replace the one entry's
  `ignoreUntil` and `reason`, keeping the same ID and no broader scope, so
  that the reason cites this note and the migration ticket. The new date
  equals the migration ticket's due date, which the operator sets. It is not
  a free-standing renewal. A missed migration then re-fires the gate on its
  own.

**Recommendation: C, together with filing the staged migration (Stage 1 and
Stage 2 below) as its own ticket.** Release work keeps moving, the debt
stays visible behind an expiry date, and the change of parser gets the
compatibility proof it needs. The cost: the residual risk of the unsafe
parser continues for one more bounded window. Gateway config and capability
files are operator-supplied, so this is not untrusted network input; protocol
imports and skills frontmatter are the most exposed inputs.

## Decision required (operator)

1. Choose B or C. If C, set the new `ignoreUntil` date and the migration
   ticket's due date to the same day.
2. Approve filing the migration ticket with the criteria below.

Proposed for C: `.github/osv-scanner.toml:40`, change `ignoreUntil` from
2026-10-26 to **2027-01-26**. Line 41 (`reason`) gets new text that cites
this note, the migration ticket and the decision date. The reason for that
date: 92 days is one quarterly review cycle, and it is the ceiling. Any later
date needs a fresh reviewed decision, so a slipped migration re-fires the
gate rather than drifting. This is a review cadence, not an estimate of the
migration. The operator may choose an earlier date.

What a reader of the release notes needs (v4.0.x, if C is ratified): "The
container and publish security gate carries one time-boxed exception,
RUSTSEC-2024-0449. It is an informational advisory: unsafe-libyaml, reached
through serde_yaml, is unmaintained. It is not a known vulnerability, and no
patched release exists. It is used to parse operator-supplied configuration,
capability and grants files. The exception expires on <date>, and a
replacement parser (pure Rust, no unsafe code) is planned under <ticket>.
YAML behaviour does not change in this release." If B is chosen instead,
there is no release note, because no image or publish happens until the
migration lands.

The config edit for C belongs to a separate, reviewed change with the same
OSV controls as MIK-8424.OSV.3 (an expired entry fails and an unrelated
advisory fails). This note does not make that edit.

## Migration criteria (paste-ready for the follow-up ticket)

- **MIG.1 Adapter, no behaviour change.** Add one internal `yaml` module
  (parse, serialize, tree type) that still uses serde_yaml underneath. Route
  every consumer through it, including the figment provider in
  `ConfigFile::data`, which parses into `figment::value::Dict` itself. Every
  existing test passes unchanged. API visibility stays crate-private.
- **MIG.2 Backend swap behind the adapter.** Use serde-saphyr `=2.0.x` with
  options `merge_keys: AsOrdinary` (so `<<` is still refused by strict keys)
  and `strict_booleans: true`. For duplicate keys, each consumer keeps its
  current behaviour. Today `Config::load` keeps the last value (through
  figment's `Dict`, pinned by `value_the_loader_accepts_loads` and
  `unrecognised_key_after_a_loader_accepted_value_refused` in
  `tests/c1_unrecognised_config_keys.rs:170-185`), while direct typed
  deserialization refuses a duplicate key. Remove figment's `yaml` feature.
  Record `spark-cargo tree -i unsafe-libyaml` reporting no match.
- **MIG.3 Comparison fixtures (old parser compared with new, through
  `serde_json::Value` or the typed struct, in one test binary during the
  swap):**
  - all 143 `capabilities/*.yaml` produce identical parsed definitions and
    identical pins;
  - `gateway.example.yaml`, `deploy/**` configs and the config test
    fixtures;
  - `grants-3.4.0.yaml`, plus `!exact {source, id}`; a grants file written
    by the new serializer must still be readable by serde_yaml (rollback);
  - `merge_key_refused_at_root` and `merge_key_refused_under_a_backend`;
  - splice tag and alias tests, and `count_yaml_aliases`;
  - duplicate keys at the root and inside a backend, run both through
    `Config::load` (last value wins) and through direct deserialization
    (refused);
  - the scalars `yes`, `no`, `on`, `off`, `0755`, `0o755`, `.inf`, `~`,
    `null`, and an empty value;
  - multi-document input, which must give the same outcome as serde_yaml
    gives today;
  - an alias input that stays within the budget and loads, and an
    alias-bomb input past the budget that is refused.
  - Write-new/read-old checks compare semantic equality, not only that the
    parse succeeds. They run on fixtures for tags, non-string keys and
    non-finite numbers.
- **MIG.4 Redaction security gate.** For every case in
  `src/config/tests/load_error.rs`, the secret sentinel value is absent from
  the rendered error and the key path, line and column are present. Changes
  to error text are reviewed as a CWE-532 surface, not refreshed as
  snapshots.
- **MIG.5 Serialized output.** Write tests for config and grants output
  (splice, URL persistence, upgrade, `cap`) compare bytes before and after.
  Any change in diff format is listed in `docs/UPGRADING-4.0.md`.
- **MIG.6 Exception removal.** Remove the RUSTSEC-2024-0449 entry only after
  real OSV scanner and exact-head CI evidence, then update
  `docs/legal/dependency-licenses.tsv`.

Order in which the 46 production files move to the adapter in MIG.1. Each
group is one commit and keeps the suite green.

1. The 21 typed-only readers. Capability parser and validator first,
   because the 143-file comparison covers them; then trust, mTLS, firewall,
   audit rotation, events, playbook, provisioning and the rest.
2. The 8 serializer-only files (OpenAPI convert, protocol-import planner,
   discovery, executors, UI backend ops, `identity_grants.rs`), each with
   byte-output tests.
3. The 15 tree walkers. Grants matching moves together with
   `identity_grants.rs` because of the tag semantics. Then skills,
   rug-pull, Kubernetes, the UI capabilities page, upgrade, `cap`, the
   rewriters, both config persistence modules and `strict_keys.rs`.
4. Last, the figment provider files (`config_file.rs`,
   `doctor/hidden_keys.rs`, `backend_url_keys.rs`), together with
   `load_error.rs` and its redaction tests. Only after this group can MIG.2
   drop figment's `yaml` feature.

**Rollback:** revert the MIG.2 commit (the dependency plus the adapter
backend). If MIG.6 removed the exception, or it has expired, restore the
entry with a newly ratified future expiry, and require a passing OSV scanner
run on the rollback commit. MIG.1 can stay in place. Rollback is only safe if
the write-new/read-old checks in MIG.3 pass.

## Review record (YAML.2)

Two independent non-author seats reviewed commit 925aef8e5, the decision
only, on 2026-10-17. Both returned SHIP. Their findings were checked against
source before folding:

- Duplicate keys: `Config::load` keeps the last value. Confirmed at
  `tests/c1_unrecognised_config_keys.rs:170-185`, and MIG.2 and MIG.3 now
  say so.
- Rollback without an unexpired exception: added to the rollback text.
- Figment default features: corrected from crates.io 0.10.19. The seat's
  claim that the default is `test` was itself wrong.
- MSRV: checked; 1.89 is at or below `rust-version = "1.95"`.
- Budget accept/reject cases and semantic write-new/read-old checks: added
  to MIG.3.
- Not folded, because they are residuals for the migration ticket: an
  empirical check of the serde-saphyr 2.0.0 duplicate-key default (MIG.2
  sets the policy explicitly in any case), and archiving the raw upstream
  manifests and advisory responses.

## Sources (all read 2026-10-17)

- https://rustsec.org/advisories/RUSTSEC-2024-0449.html
- https://api.osv.dev/v1/vulns/RUSTSEC-2024-0449,
  https://api.osv.dev/v1/vulns/RUSTSEC-2025-0068,
  https://api.osv.dev/v1/vulns/RUSTSEC-2026-0333,
  https://api.osv.dev/v1/vulns/RUSTSEC-2023-0075,
  https://api.osv.dev/v1/vulns/RUSTSEC-2018-0005, and the OSV `v1/query`
  endpoint for each candidate
- crates.io API `/api/v1/crates/<name>` and `/<name>/<version>/dependencies`
  for every crate in the candidate table
- GitHub API `/repos/<owner>/<repo>` for the archived flag and last push
- https://github.com/SergioBenitez/Figment/blob/master/Cargo.toml
- https://github.com/bourumir-wyngs/serde-saphyr (README),
  https://docs.rs/serde-saphyr/2.0.0/serde_saphyr/options/struct.Options.html
- https://github.com/bourumir-wyngs/granit-parser/blob/master/Cargo.toml,
  https://github.com/saphyr-rs/saphyr/blob/master/Cargo.toml
