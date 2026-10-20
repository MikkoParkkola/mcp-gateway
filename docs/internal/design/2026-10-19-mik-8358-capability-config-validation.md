# MIK-8358: capability config validation (CAPCFG)

Status: P1a ratified 2026-10-19 (gpt-20261018T235959Z-89345 SHIP,
agy-20261018T235959Z-89347 SHIP); P1b and the final rounds reviewed (see the
last two sections); in PR #3964.
Class B3: refusing configs that load today ships only with the major
version. The ticket set v4.0.1; the operator ruled it ships in v4.0.0
(2026-10-19). Base: origin/docs/ranking-1-release-line b51f53140.

## P1a: problem

### What goes wrong, for whom

Two operator misconfigurations load silently and then mislead the gateway's
own registry-membership test:

(a) **Name collision.** `Config::validate_backend_names`
(`src/config/validation.rs:351`) checks registry backend names only (empty,
`/ \ : *`). `capabilities.name` (default `"gateway"`,
`src/config/features/capability.rs:177`) is checked only for `*`
(`src/config/pattern_grammar.rs:184`). Nothing refuses a `capabilities.name`
equal to a `backends.<name>` key. The per-caller view (`visible.rs`
`visible_tool`), `surfaced_schema_withheld` and `descriptor_blocked` decide
"registry backend or capability" by `self.backends.get(server)`; on a
collision a capability is judged as the registry backend's tool (a schema-less
capability is withheld for its null schema; a descriptor block on the backend
applies to it).

(b) **Capability input schema shape.** CAP-003, `check_schema_input`
(`src/capability/validator/checks.rs:70`), returns early for null or `{}`, and
otherwise checks only `type` and `properties` when present. A scalar (`"text"`,
`42`, `true`) or an array (`[..]`, `[]`) carries neither, so it raises no
error and the loader (`src/capability/loader.rs:118-157`, which skips a file
with structural errors) serves it. Since MIK-8340 capability tools are exempt
from the runtime schema reason, so the malformed schema is advertised.
The wire twin already refuses non-objects
(`validator::input_schema_is_structurally_valid`, MCP backend tools).

Who feels it: an operator with such a config or capability file; callers see
a wrongly withheld capability (a) or an unusable schema (b). Neither discloses
a withheld tool (ticket, confirmed by the reads above).

### Why now

Both checks refuse configs/files that load today, a compatibility break the
release bar allows only in a major version (B3). If it misses 4.0.0 it waits
for 5.0.

### Measured constraints

- K1. Refusal must be a `ConfigValidation` error at load (CAPCFG.1) naming both
  sides; for (b) a CAP-003 error that keeps the capability from loading
  (CAPCFG.2).
- K2. A null or empty-mapping `{}` input schema (webhook-only) must still load.
  "Empty" means `{}` only: `""` and `[]` are scalars/arrays and are refused.
- K3. The upgrade note (CAPCFG.3) names the newly refused configs/files and the
  action; changelog fragments via `scripts/release/changelog_fragments.py`,
  upgrade notes under `upgrading.d`.

### Acceptance signal

Rows red on b51f53140, green after: a colliding config fails `validate()` with
a message naming `capabilities.name` and `backends.<name>`; scalar and array
schema files are not served by `CapabilityLoader::load_directory`; null, `{}`
and object schemas still are (control).

### Exclusions

- (Was excluded, now in scope by lead ruling; see the last section.) The
  registry search index (`src/registry/mod.rs:183-185`) validated with the
  legacy `validate_capability` only, not CAP-003.
- Collisions between two capabilities, or with meta-tool names.

## P1b: solution (draft, second gate)

1. CAPCFG.1: in `validate_backend_names`, after the per-name checks, refuse
   `self.backends.contains_key(&self.capabilities.name)` with
   `ConfigValidation("capabilities.name = \"X\" is also backends.X; the
   capabilities backend shares the backend name space. Rename one.")`.
   Checked whether either side is `enabled` (the MIK-8298 precedent at
   `validation.rs:79-81`: turning a section on never surfaces a rule for the
   first time). Alternative rejected: check only when both are enabled; a
   disabled backend is re-enabled at runtime by config reload, which then
   loads a collision no restart would have refused.
2. CAPCFG.2: in `check_schema_input`, after the null/`{}` early return, push a
   CAP-003 error on field `schema.input` when `!input.is_object()`
   ("schema.input must be a mapping (object), got a <kind>"). One check serves
   both serving paths: `input_schema_is_structurally_valid` keeps its own
   `!is_object` short-circuit (it must also refuse null/`{}` over the wire), so
   its verdict does not change. Alternative rejected: a separate loader check;
   it would split CAP-003 from `cap validate` and the UI validator.
3. CAPCFG.3: one `upgrading.d` note and one changelog fragment (Changed,
   breaking): which configs/files are refused and the fix (rename the
   capabilities backend or the registry backend; make `schema.input` a mapping,
   or drop it for a webhook-only capability).

Rows: `src/config/tests/capability_name.rs` (collision under enabled and
disabled; default name `gateway`; distinct-name control),
`src/capability/schema_shape_load_tests.rs` (scalars and arrays not loaded;
null, `{}`, object loaded; CAP-003 error on `schema.input`).

Declined from the P1a round, with reasons:
- Apply the empty and `/ \ :` backend-name rules to `capabilities.name` too
  (agy): no acceptance criterion asks for it and no harm is shown; it would
  refuse more configs in the one release that may. Recorded for the lead.
- A runtime witness row showing a null-schema capability withheld on a
  collision (gpt): the harm is in the cited reads; CAPCFG.1 makes the state
  unloadable, and its row is the refusal itself.

## Final round and the search index (2026-10-19)

- Final seats at da8a713bb: gpt SHIP-WITH-FIXES (gpt-20261019T003630Z-19609:
  the upgrade note's `**Startup:**` marker failed the grammar; fixed to
  `refuses to start, ...; fails a capability file, ...`), agy SHIP
  (agy-20261019T003630Z-19611). CAP-003 row now covers all six shapes and
  the kind named in the message.
- Lead ruling: the registry search index listing a file the loader skips is
  fixed here, not deferred. The loader's checks are one function,
  `capability::refuse_unloadable` (`pub(crate)`), which `CapabilityLoader`
  and `Registry::build_index` both call. Row
  `registry::tests::the_index_leaves_out_a_file_the_loader_skips`: red with
  the index on the legacy check alone, green with the shared check.

## Discovery writes, after CI (2026-10-19)

CI found `tests/zed_config_round_trip.rs` failing: `setup export` names its
entry `gateway` by default, the default `capabilities.name`, so `cap discover
--write-config` wrote a backend CAPCFG.1 refuses. Both seats said the writer
is the wrong side, not the rule (gpt-20261019T071119Z-412,
agy-20261019T071119Z-415). Decisions, each reviewed or ruled:

- The writer skips a discovered server whose name is `capabilities.name`,
  warns on stderr and still exits 0. It does not rename (rename needs batch
  collisions, alias persistence and shadow reconciliation) and does not fail
  (lead accepted, G2).
- `cap discover --shadow` still lists such a server (gpt finding: hiding it
  from an inventory is worse); adopting it goes through the writer, which
  skips it.
- The writer reports how many servers it wrote, and shadow adoption prints
  that number (lead ruling).
- The default round trip is pinned: a default-name export followed by
  discover warns and exits 0 (lead, G3); the transport round trips export
  as `zed-gateway`.
- The search index runs the loader's check quietly. A real run of `cap
  search mail` printed 24 warning lines from the shipped catalogue once the
  index used the loader's logging check, so the index passes
  `IssueLog::Quiet` and logs one debug line per build (lead, G6). The loader
  still logs each issue.

Rows: `the_default_entry_name_is_skipped_on_import`,
`shadow_adoption_counts_only_what_it_wrote`, and two writer unit rows in
`src/main_tests.rs`.
