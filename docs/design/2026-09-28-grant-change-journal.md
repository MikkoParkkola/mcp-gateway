# Grant-change journal and governance records (MIK-7570.AUDIT.4, #1869)

Status: design for review. Base: `docs/ranking-1-release-line` at `59465ca76`.
Binding inputs: requirement `MIK-7570.AUDIT.4` (`docs/requirements/RELEASE-4.0.0-scope-update.md:104`),
its acceptance row (`docs/requirements/RELEASE-4.0.0-scope-tests.md:63`), maintainer decision 22
(`docs/requirements/RELEASE-4.0.0-operator-decisions.md`), and #1869 criteria AUDIT4.1-4.8.
The mechanism (CLI journal, gateway ingestion, startup snapshot as reconciliation) is decided;
this document settles how.

## 1. Problem at source

| # | Fact | Where |
|---|---|---|
| P1 | The CLI changes grants only by rewriting the grant file, on upsert and revoke. | `src/commands/identity.rs:176`, `:199` |
| P2 | `--replace` rewrites a grant under the same id, so an id comparison cannot see it. | `src/commands/identity.rs:161-175` |
| P3 | A running gateway applies a CLI change on its next reload; the CLI says so. | `src/commands/identity.rs:273-280` |
| P4 | A reload records grants in the tracing log only. | `src/config_reload/mod.rs:1874-1882`; `docs/identity_grants.md:259-261` |
| P5 | Startup installs the grant file before the governance store opens. | `src/gateway/server/mod.rs:1195-1207` (load), `:1786` (store) |
| P6 | With auth on, an unopenable default store directory degrades to no store, with a warning. | `src/gateway/server/control_plane_store.rs:104-110` |
| P7 | The governance log accepts one writer per log (lease). The CLI cannot take it while a gateway runs. | #1570, `src/control_plane/store.rs:732-742` |
| P8 | No production path writes governance entries today; the control plane refuses grant writes. | `src/control_plane/store.rs:305-371` (only tests call the audited writes) |

Result: grant approvals, replacements and revocations leave no governance record. An edit made while
the gateway is stopped leaves no record anywhere.

## 2. Fail-fast rulings

### R1. The record type for events with no actor

Every record is a `ControlPlaneAuditEvent` (`src/control_plane/mod.rs:452`) with:

- `actor_id: "unknown"`, a literal meaning "no authenticated actor". Nothing is synthesized from the OS
  account, the config, or the caller that triggered the reload.
- `action: MutateGrant` (grant records are the only kind this log holds for grants).
- `target_id`: the grant id, or the run id for the closing snapshot record.
- `event_id`: deterministic per source (section 5.3), so a replay can recognise an entry it already wrote.
- a new optional field `grant_change: Option<GrantChangeRecord>`, where `GrantChangeRecord` is a new
  `#[non_exhaustive]` struct in `src/control_plane/grant_change.rs`:

| Field | Type | Meaning |
|---|---|---|
| `verb` | `GrantChangeVerb` | `add`, `replace`, `revoke`, `loaded`, `loaded_complete`, `out_of_band`, `indeterminate` |
| `digest` | `Option<String>` | `sha256:<hex>` of the grant row after the change; `None` for a deleted row and for the closing record |
| `expires_at` | `Option<DateTime<Utc>>` | expiry of the row after the change |
| `occurred_at` | `Option<DateTime<Utc>>` | the CLI's clock at the change (journal records only) |
| `os_account_hint` | `Option<String>` | OS account that ran the CLI, unauthenticated |
| `run_id` | `Option<String>` | startup run id (snapshot records only) |
| `count` | `Option<u64>` | active grants in the snapshot (closing record only) |

`count` is the one value beyond the six named in the ruling; the closing record needs a machine-readable count.
The log line's own `timestamp` (written by the transparency logger) is the ingestion time.
`reason` carries a one-line human summary; no field is packed into it.

The existing readers keep working: `audit_event_from_entry` reads the new field when present and
`None` otherwise; entries written before this change deserialise unchanged. `serde(default,
skip_serializing_if = "Option::is_none")` keeps existing entries byte-identical.

Cost: `ControlPlaneAuditEvent` struct literals outside the crate stop compiling (UPGRADING item 79).
Fourteen literals in-tree gain `grant_change: None`.

Rejected: a new log `kind` with its own reader (the audit API, export and UI would not see it,
and the crash check in 5.3 would need a second reader); packing fields into `reason`.

### R2. Where startup records are written

After the store opens and before any listener binds. Section 6 gives the sequence. The grant set
loaded at `server/mod.rs:1195` stays unserved until then: nothing reads it before the listeners start.
If a `loaded` or closing append fails, the loaded set is replaced with an empty store before serving.

## 3. The journal (CLI side, AUDIT4.1)

Path: the grant file path plus `.journal.jsonl` (for `grants.yaml`, `grants.yaml.journal.jsonl`).
One JSON object per line:

```json
{"v":1,"entry_id":"<uuid v4>","verb":"add|replace|revoke","grant_id":"...","prev_digest":"sha256:<hex>|null",
 "digest":"sha256:<hex>","expires_at":"<rfc3339>|null","at":"<rfc3339>","actor":"unknown","os_account":"<$USER|$USERNAME>|null"}
```

- `verb`: `add` for a new id; `replace` when `--replace` overwrote an existing id; `revoke`.
- `digest`: SHA-256 over `serde_json::to_vec` of the parsed `IdentityGrant` row as written, prefixed `sha256:`.
  The gateway computes the same function over the rows it reads. Hazard: a new serialised field on
  `IdentityGrant` changes every digest; the first reload after such an upgrade would report every
  grant out-of-band. A future field must be `skip_serializing_if` its default, and the digest test (T1c) pins the bytes.
- `os_account`: read from the environment. It is a hint and is labelled as one in the docs.

The CLI change becomes one locked unit, in the library (`identity_grants::journal`, `#[doc(hidden)]`,
"exists for the bundled CLI; not a stable API"):

1. Take `ExclusiveFileLock` (`src/fs_lock.rs`) on `.<grant file name>.journal.lock` beside the grant file.
2. Read the grant file, apply the change, write it atomically (`write_identity_grants_file`).
3. Only if step 2 succeeded, append the entry: open with create + append, mode 0600 at creation, and
   `force_owner_only` on an existing file; if the file does not end in a newline (an earlier torn append),
   write one first so the new entry starts on its own line; one `write_all` of the line and newline; `sync_data`.
4. Release the lock.

A refused change (existing id without `--replace`, unknown id on revoke, bad input, failed write) returns
before step 3, so it appends nothing. If step 3 fails after step 2, the CLI exits non-zero with
"grant file changed but the journal append failed; the gateway will record this change as out-of-band".
The CLI never opens the governance log.

The lock also closes an existing lost-update race between two concurrent CLI runs, which is not the goal
here but costs nothing extra.

## 4. Trust statement

The journal is exactly as trustworthy as the grant file: anyone who can write one can write the other.
It separates CLI edits from other edits; it does not separate authorised from unauthorised ones, and
`os_account` is not an identity. The gateway reads the journal under the same mode check as the grant file
(`read_checked_file`, `CheckedFile::IdentityGrants`): readable by others is accepted, writable by others is refused.
A refused or unreadable journal ingests nothing and writes one `indeterminate` record (section 5).

## 5. Ingestion and reconciliation (gateway side)

### 5.1 Components

`GrantAuditor` (new, `src/config_reload/grant_audit.rs`) holds the store handle, the state-file path and the
in-memory state behind a mutex. It hangs off `IdentityGrantSink` as `Option<Arc<GrantAuditor>>`.
The meta-tool reload context and the watcher share one sink (`server/mod.rs:1557-1573`, `:1986-1992`),
so every reload path (meta-tool, admin UI, the watcher's `spawn_reload_task`) reaches the auditor through
one object. `None` means no governance store, and the tracing event stays the only record.

State file: `<control-plane store dir>/grant-journal-state.json`, written with
`config_persistence::write_text_atomic`, mode 0600:

```json
{"v":1,"grants_path":"...","generation":7,"consumed":["<entry_id>","torn:<sha256>"],
 "grants":{"<grant id>":"sha256:<hex>"},"gap":false,"pending":null}
```

- `consumed`: journal entry ids already recorded, plus `torn:<sha256 of line>` for unparseable lines
  already reported. It grows by one short string per CLI change (`ponytail:` ceiling: prune ids older
  than the journal when a journal rotation feature exists).
- `grants`: grant id to digest at the last committed reconciliation (the baseline).
- `generation`: incremented by each committed reconciliation; it makes non-journal event ids unique.
- `gap`: some applied change was not recorded when it happened (AUDIT4.7).
- `pending`: the write-ahead plan of 5.2, or `null`.
- A state file for a different `grants_path`, or none at all, means "no baseline" (5.2 step 3).

No byte offset: the journal is re-parsed in full each run and `consumed` decides what is new. That makes a
truncated or replaced journal visible (a consumed id is missing) without losing entries a replacement adds.
The journal grows by one line per CLI change, so a full parse stays small.

The state lives in the store directory, which the one-writer lease covers (#1570). Two gateways that share
a grant file but use different stores each keep their own state and record into their own log.

### 5.2 One reconciliation

The journal entry of section 3 also carries `prev_digest`: the row's digest before the change (`null` for
`add`). It lets the gateway see a direct edit that a later CLI change overwrote.

`reconcile` runs with the sink lock and the journal lock (5.4) held. Order: finish any old plan, plan,
persist the plan, publish, append, commit.

1. Finish an old plan. If `pending` is set (a crash or a failed append in an earlier run), append the
   plan's records that are not yet in the log (5.3), then commit it (step 7). If that still fails, stop:
   publish the new rows (5.2 never blocks a publish), keep `gap: true`, and report UNRECORDED.
2. Parse the journal. A newline-terminated line that does not parse, or an unterminated line followed
   by more bytes (a torn append), is a torn line. An unterminated line at end of file waits (a CLI
   mid-append). New entries are those whose id is not in `consumed`. A consumed id missing from the journal
   means it was truncated or replaced: one `indeterminate` record for the discontinuity.
3. Expected set: the baseline, then each new entry in journal order. If the expected digest for the entry's
   grant differs from its `prev_digest`, first plan an `out_of_band` record for that grant (the
   intervening direct edit), then plan the entry's own record and set expected to its `digest`.
   No baseline (first start with this feature, or a changed `grants_path`): expected starts empty and
   every journal entry is new, so grants the journal never mentions are not compared (they predate it and
   appear in the snapshot as `loaded`), while a journalled grant whose file row differs is still caught.
4. Actual set: digests of the rows just read. For each grant id where expected and actual differ
   (changed, added outside the CLI, or missing, which covers row deletion and an empty `grants` list),
   plan `out_of_band` with the actual digest and expiry (`None` for a missing row).
5. If `gap` is set: plan one `indeterminate` record for the gap itself, and plan every step-3/4 mismatch as
   `indeterminate` instead of `out_of_band`. A torn line or journal discontinuity also plans `indeterminate`.
6. Persist the plan: `pending = {records, next_state}` with `next_state = {generation + 1, consumed +
   new ids + torn hashes, grants: actual, gap: false}`. Then publish (reload) and append each record
   in order. Event ids: `grant-journal:<entry_id>`; every other record
   `grant-<verb>:<next generation>:<grant id or cause>`, so a repeated transition in a later reconciliation
   gets a fresh id and a recovered plan reuses its own.
7. Commit: all appends succeeded, so state = `next_state`, `pending = null`. On the first failed append,
   stop, keep `pending`, set `gap: true` in the state file and report UNRECORDED. Step 1 retries.

A failed plan write (step 6) still publishes: the change is applied, the outcome says UNRECORDED and
`gap` is set in memory. Recovering the gap durably is then impossible for that run, because the state
file sits in the same directory as the audit log and neither can be written; the outcome says so. A failed
commit write keeps the committed state in memory, so the running process does not repeat records, and the
next reconcile retries the write. A persistently unreadable journal plans its `indeterminate` record once
per cause per process (cause kept in memory). While the journal is unreadable (missing is not
unreadable: a missing journal is an empty one), steps 3-4 are skipped and the baseline is kept, so CLI
changes are not misreported as `out_of_band`; they are recorded once the journal is readable again.

The reload outcome gains one clause: `grant records: N written`, or `grant change UNRECORDED: <reason>`.
A failed append never unpublishes, never reverts the epoch, and never turns an applied reload into a
refusal (AUDIT4.6: publish first, record second).

Paths through `reload_identity_grants` (`config_reload/mod.rs:1809`):

- Unchanged rows (`:1840`): still reconciles, because an identical-content `--replace` has an entry to ingest.
- Read or parse refusal (`:1822`): no reconciliation. The journal stays pending, the live set is unchanged,
  and the next successful reload ingests it.
- Busy (`:1813`): unchanged; same retry rule as today.

### 5.3 Exactly once across a crash (AUDIT4.8)

The plan is written before its first record and cleared after its last, so after any crash the state file
says exactly which records might already be in the log: the pending plan's. Nothing else writes
`actor_id = "unknown"` records between persisting a plan and committing it (the lease excludes other
gateways; the auditor mutex serialises this gateway). So step 1 pages `read_audit`
(`actor_id = "unknown"`, `action = MutateGrant`, following `next_cursor` across segments) newest-first
until it has examined as many records as the plan holds, or reached the start of the log, and appends
only the plan records whose event ids it did not see, in plan order. The scan is bounded by the plan's size,
not by a fixed page, so a large backlog has no window.

### 5.4 The CLI/gateway race

Without a shared lock, a reload between the CLI's file write and its journal append would see a changed
file with no entry, record `out_of_band`, then record the entry on the next reload: two records for one
change. So the reload takes the journal lock around reading the grant file and the journal, waiting at
most `RELOAD_LOCK_WAIT`. A timeout is the existing busy refusal, which publishes nothing (existing cell
T10b). The CLI holds the lock for one file write and one append. The gateway polls
`ExclusiveFileLock::try_lease` (cross-platform, `Ok(None)` on contention; `try_acquire` is unix-only,
`src/fs_lock.rs:57-63`) off the runtime until the deadline. The CLI uses the blocking `acquire`.
The lock and the two reads sit in one `journal` helper, so no grant-file reader in the gateway can take
one without the other.

## 6. Startup sequence (AUDIT4.3, AUDIT4.5)

HTTP (`run`) and stdio (`run_stdio`) both follow this sequence. Stdio follows the D1 precedent: with
auth on, `serve --stdio` obeys the same audit rule as HTTP (`docs/UPGRADING-4.0.md:1076`).

1. Load the grant file into `meta_mcp` (unchanged, `server/mod.rs:1195`). Nothing serves it yet.
2. Open the governance store (`build_control_plane_store`, lease taken). New refusal: with auth on, grants
   enabled and no store (the `:104` degrade), startup fails with "identity grants need the governance
   audit log when auth is on" (UPGRADING item 79). With auth off there is no store and no auditor.
3. Build the auditor and load the state file.
4. Take the journal lock, read the grant file and journal, and reconcile (5.2; step 1 finishes any plan a
   crash left). Publish the rows just read, so the recorded set and the served set are the same bytes.
5. Snapshot under a fresh run id (uuid v4): one `loaded` record per grant active by
   `IdentityGrant::is_active_at(now)` (grant id, digest, expiry; event id `grant-loaded:<run>:<grant>`),
   then one `loaded_complete` record (target and run id, `count`, zero included; event id `grant-loaded:<run>`).
6. If any step-5 append fails, publish an empty grant set and log `error!`: this run serves no grants (fail
   closed). A step-4 failure sets `gap` and startup continues; step 5 still records what is served.
7. Release the lock and bind the listeners.

The active-set computation lives in `identity_grants::journal`, so `is_active_at` stays private.

## 7. Crash table

One row for each boundary between durable writes. "Recovery" is the next startup.

| # | Crash point | Durable state left behind | Recovery result |
|---|---|---|---|
| C1 | CLI: after the grant file write, before the journal append | file changed, no entry | `out_of_band` for that grant (correct: no entry exists; the CLI also exited non-zero) |
| C2 | CLI: mid-append (partial line) | unterminated last line; file already changed | the torn line waits while at end of file; once later bytes follow it, one `indeterminate` (torn line), and the change it described is `out_of_band` |
| C3 | Gateway: before the plan write | old state, no records | recomputed from scratch; once |
| C4 | Gateway: after the plan write, before the first append | `pending`, no records | step 1 finds none of the plan's ids; appends all; once |
| C5 | Gateway: after k of n appends | `pending`, k records | step 1 scans n newest grant records, finds k ids, appends the other n-k in order; once |
| C6 | Gateway: after the last append, before the commit write | `pending`, n records | step 1 finds all n; appends none; commits; once |
| C7 | Gateway: after the commit write | committed state | nothing pending; once |
| C8 | Gateway: during the startup snapshot | some `loaded`, no `loaded_complete` | that run never bound a listener; next run writes a full snapshot under a new run id. A run without `loaded_complete` reads as incomplete |

Test crash points are fault hooks inside the auditor at C4, C5 and C6 (a test-only `GrantAuditFault`),
not the store's `FaultPoint`, which covers collection-file replacement only.

## 8. Outcome rules

| Case | Behaviour | AC |
|---|---|---|
| Auth on, grants on, store cannot open | refuse to start (HTTP and stdio) | 4.5 |
| Auth off | no store, no auditor, tracing event only | 4.5 control |
| Reload append fails | change stays in force; outcome says UNRECORDED; plan kept, `gap` persisted | 4.6, 4.7 |
| Commit write fails after appends | committed in memory; outcome names it; next reconcile retries; after a crash, step 1 finds every record | 4.8 |
| `gap` set | one `indeterminate` gap record, mismatches as `indeterminate`; `gap` cleared only by a committed plan | 4.7 |
| Snapshot append fails | this run serves no grants | 4.3 |
| Reload parse refusal | prior grant set unchanged; journal stays pending | acceptance row positive control |

## 9. File layout and the 800-line ceiling

Files at or over the ceiling may not grow (`scripts/dev/check-file-size.py`): `gateway/server/mod.rs`,
`config_reload/mod.rs`, `control_plane/mod.rs`, `gateway/ui/control_plane.rs`, `identity_grants.rs`.
`control_plane/store.rs` is under its recorded baseline and may grow.

- Prep commit (pure move, no behaviour change): `IdentityGrantSink`, `reload_identity_grants` and
  `changed_grant_subjects` move from `config_reload/mod.rs` to `config_reload/grant_reload.rs`;
  `load_configured_identity_grants` and `identity_grant_sink_for` move from `gateway/server/mod.rs` to
  `gateway/server/identity_grants.rs`. This makes room for the startup wiring lines in `mod.rs`.
- New: `identity_grants/journal.rs` (entry type, digest, locked CLI change, journal reader, active set),
  `control_plane/grant_change.rs` (`GrantChangeRecord`, `GrantChangeVerb`), `config_reload/grant_audit.rs`
  (`GrantAuditor`, state file, reconcile).
- `control_plane/mod.rs`: the field adds 4 lines; an equal number of doc lines is tightened in that file.
- `gateway/ui/control_plane.rs`: three literals gain one line each; offset the same way.
- Tests go in new files (`*_tests.rs`), never appended to an over-ceiling test file.

No existing item's visibility is widened. New public items: the `journal` module (`#[doc(hidden)]`,
"exists for the bundled CLI; not a stable API") and the `grant_change` field with its types.

## 10. Test plan (red-first)

Each cell names the failure it goes red on. The test plan document expands these into exact assertions.

| Cell | AC | Setup | Red on base because |
|---|---|---|---|
| T1a | 4.1 | CLI add, `--replace`, revoke on a temp file | no journal file exists |
| T1b | 4.1 | CLI add of an existing id without `--replace`; revoke of an unknown id | (control) journal must stay absent |
| T1c | 4.1 | digest of a fixed row | pins `sha256:` bytes; fails if a field is added without skip |
| T1d | 4.1 | journal mode after first append (Unix) | file absent |
| T2a | 4.2 | reload after a CLI add then revoke | no governance record |
| T2b | 4.2 | two reloads with no change in between | second reload must add zero records |
| T2c | 4.2 | watcher path: config touch triggers `spawn_reload_task` | no record through the watcher |
| T2d | 4.2 | identical-content `--replace` | unchanged path returns before recording |
| T3a | 4.3 | startup with 2 active, 1 revoked, 1 expired grant | no `loaded` records; expects 2 + closing with `count: 2` |
| T3b | 4.3 | startup with zero grants | expects closing record with `count: 0` |
| T3c | 4.3 | injected failure on a `loaded` append | the run would serve grants; expects empty served set |
| T4a | 4.4 | direct file edit, then reload | no `out_of_band` record |
| T4b | 4.4 | row deleted; `grants: []` | no record per missing id |
| T4c | 4.4 | edit while stopped, then startup | no record at startup |
| T4d | 4.4 | direct edit of a row, then CLI revoke of it, one reload | journal absorbs the edit; expects `out_of_band` then `revoke` |
| T4e | 4.4 | A-to-B direct edit, reload, B-to-A, reload, A-to-B again, reload | expects three `out_of_band` records (fresh id per generation) |
| T4f | 4.4 | first start, journal says digest D, file row differs | expects `out_of_band` with no baseline |
| T4g | 4.4 | torn journal line followed by a later entry; unreadable (mode-refused) journal | expects one `indeterminate` each, repeated reloads add none, no CLI change reported `out_of_band` |
| T4h | 4.4 | journal replaced by a shorter one with a new entry | expects one `indeterminate` and the new entry recorded |
| T5a | 4.5 | auth on, grants on, unopenable default store; HTTP and stdio | gateway starts today; expects startup error |
| T5b | 4.5 | auth off, grants on | (control) no store file is created |
| T6 | 4.6 | append fails after publish | expects change in force and UNRECORDED in outcome |
| T7a | 4.7 | reload append fails, then restart with a further direct edit | expects a gap record and `indeterminate`, not `out_of_band` |
| T7b | 4.7 | reload append fails, restart with the file unchanged | expects the gap record even with no mismatch |
| T8 | 4.8 | auditor fault at C4, C5 (k=1 of 3 and k=300 of 301), C6; restart | expects exactly one record per planned id, in order |
| T9 | wiring | through `identity_grant_sink_for` and the real startup helpers | a sink built without the auditor passes every other cell |
| T10 | race | CLI holds the journal lock between its file write and append; reload runs | expects busy or one `add` record, never `out_of_band` |
| T11 | R1 | durable write and readback of every `grant_change` field through `FileControlPlaneStore` | `audit_fields` drops the field |
| T3d | 4.3 | injected failure on the `loaded_complete` append | expects empty served set |

Fault injection: the auditor's test-only `GrantAuditFault` hooks (section 7) and a test-only
`ControlPlaneStore` wrapper whose `append_audit` fails on the Nth call.

## 11. Mutation targets

M1 skip the journal append (T1a). M2 step 1 appends the whole plan without the log scan (T8). M3 unchanged
path returns early again (T2d). M4 drop the `out_of_band` step (T4a). M5 serve grants after a failed
snapshot append (T3c). M6 keep the `:104` degrade with grants on (T5a). M7 report `out_of_band` when `gap`
is set (T7a). M8 drop the `prev_digest` check (T4d). M9 content-only event ids (T4e).

## 12. Out of scope

- An authenticated CLI actor (needs a CLI identity; decision 21).
- Signing the journal. It has the grant file's trust level (section 4).
- Rotation of the journal. It grows by one line per CLI change; a size note goes in the docs.
