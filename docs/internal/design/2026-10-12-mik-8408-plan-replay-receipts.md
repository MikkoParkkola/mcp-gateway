# MIK-8408 design d3 final (frozen 2026-10-12, lead ruling): a replayed plan renews its relay receipts

Base: docs/ranking-1-release-line 6c62a0985. Owner: mutretro. Family: relay-replay-receipt. Criteria: MIK-8408.REPLAY.3/.4/.5/.6 (REPLAY.1/.2 superseded; nested plans → MIK-8409, v4.0.1).

d3 replaces d1/d2. Lead rulings it carries:
- persist the run's provenance (option (a));
- persist live retention's *decision*, not a re-hash. Fingerprints are keyed per process (collusion.rs:380 `key().hash_one`) and die on restart, so the persisted form is a key-independent **position mask** with three conditions: sampling boundary, normalization version, restart row;
- task record version bump, not a sidecar;
- provenance (steps) recorded at dispatch, failures included, independent of relay detection; present-but-empty provenance is not a source;
- executed_steps: `Declared` by default, `Recorded` only under one positive condition;
- the recording scope opens unconditionally on both transports;
- nested labels stage nothing (known limit);
- a plan bench is added, and fail-fast if under 99% of bench plans fit the bound.

## 1. Problem

A stored answer that is read again is a second delivery. A single-target replay renews the reader's relay receipt; a plan's does not. On the task path, `stage_stored_receipt` returns early on more than one target (task_replay.rs:112-114). On the sync path, `stage_replay` resolves no target for `gateway_execute` or `gateway_run_playbook` (invoke/relay.rs:525-531). Past the 600 s window (collusion.rs:51), a relay of re-read plan text is missed, and the reader loses the same-source excuse. This was a documented COLLUDE.1 limit (docs/design/2026-09-28-asi10-verbatim-relay.md, "Redelivery renews" item 3).

Why replay cannot simply re-derive receipts from the stored answer, as found across two seat rounds: live receipts are staged before the final checks, and `retain_delivered` keeps only fingerprints that survive into the delivered answer. Re-hashing the stored (final) answer receipts gateway-inserted text: redaction markers, gateway notices served from cache (pre_dispatch.rs:136-145), and k-grams spanning them. It also loses the step verdicts that a playbook's output mapping drops (budget.rs:303-310). So replay must reproduce live retention's decision, not recompute it.

## 2. Design

### D1. What is recorded, and where

`PlanProvenance` (crate-internal, beside `gateway_writes::WriteRecord`) has two parts.

**(i) `steps: Vec<(label, server, tool)>`: which accounts the run touched (for MIK-8406 and the task-path targets check).**
- Noted at one site, `invoke_tool_with_source`, beside `dispatch_log::note_completed(args)` (grant_audit.rs:645-650), under the same condition as `Record::targets` (#2450): every step past the authorization chokepoint, whether it succeeded, failed upstream or failed its audit. Only `Error::Forbidden` is excluded. The cache-hit returns run inside that future.
- A resumed chain also notes labels `0..next_step` from the chain array bound by `chain_digest` (chain_interim.rs:156-163, :176; resume entry chain_exec.rs:39-48). `steps` is therefore cumulative across rounds.
- Recorded whether or not relay detection is on (D5). Deduplicated on the exact tuple.

**(ii) `receipts: Vec<ReceiptMask>`: live retention's decision, one entry per committed in-plan receipt, seams included.** Written only when relay detection was on at delivery (D6).

```rust
struct ReceiptMask {
    label: Option<u32>,              // the step label; None for a seam
    source: Source,                  // (server, tool), or the seam's composite source list
    sensitive: bool,                 // the committed digest's is_sensitive()
    evidence: Vec<FormRuns>,         // positions of evidence fingerprints (segments, retained, joins)
    excuse_only: Vec<FormRuns>,      // positions of cut_fps and seam_excuses (MIK-8066, MIK-8205)
}
struct FormRuns { form: u16, runs: Vec<(u32, u32)> } // k-gram index ranges, inclusive
struct MaskHeader { norm_version: u16, k: u16, sample: u16 } // once per record
```

**Coordinates.** A mask position is (form, k-gram index). It is built from the delivered answer exactly as `Delivered::kgrams` builds its universe (collusion_delivered.rs:157-174): each value leaf, then the leaves newline-joined, the leaves run together, and each key-path join. Each form is normalized by `CollusionDetector::normalized` (collusion.rs:390-398), and the k-gram index is the character offset of the K-char window. None of this depends on the hash key.

**Building a mask (live, at the commit point, after `retain_delivered` and the seam pass).** For each committed in-plan receipt, walk the forms of the delivered answer and hash each k-gram with the current key. At each *sampled* position, the decision is "kept" if that hash is in the receipt's evidence set (or, for the excuse mask, its excuse-only set), and "dropped" otherwise.
- **Sampling boundary (lead condition 1).** A run spans from one kept sampled position to the next kept sampled position, with no dropped sampled position between them. A run is closed at its outermost kept sampled position. Positions between a kept and a dropped sample are outside every run. Under a new key, a newly sampled position there is therefore not kept, so ambiguity fails toward a missed renewal, never an undue receipt.
- An unsampled position inside a run (between two kept samples) is kept. Live retention keeps or drops by the text a gateway change touched, and that text lies between dropped samples.

**Replaying a mask (D3).** Rebuild the forms from the stored answer, hash with the current key, and apply the usual sample. A sampled position inside a run becomes a fingerprint of that set. The receipt's digest is rebuilt from the evidence and excuse-only sets, `sensitive` and `source`. Caps (`RECORD_CAP`, `MAX_SOURCE_FINGERPRINTS`, thinning) are applied by `record_digest` as for any receipt.
- **Version check (lead condition 2).** If the stored header's `norm_version`, `k` or `sample` differs from this build's, the record stages nothing, counted in `mcp_gateway_collusion_plan_provenance_stale_total`. `norm_version` is a new constant beside `K`, bumped whenever `normalized` or the k-gram walk changes.
- A form or run that falls outside the rebuilt answer, because of shape drift, skips that receipt. It never errors.

New API (firewall module, `pub(crate)`): `Firewall::receipt_masks(&receipts, answer) -> Vec<ReceiptMask>` at commit, and `Firewall::replay_masks(&masks, answer) -> Vec<(label, Source, DeliveryDigest)>` at replay. The digest's private fields stay private; the firewall module builds the digest (answers muse H-4).

**Where masks are taken.** At the same commit points that record a plan's receipts today: the HTTP `emit_http` commit, the stdio delivery commit (`complete_delivery_read`, admission.rs:84 via stdio_delivery.rs:152, muse H3), and task settlement (`settle_durable`). Taken from the receipts as committed, after `keep_plan_receipts` and `add_seams`.

### D2. Placement (agreed with secD and a2a-1)

- **Sync:** `StoredDelivery.plan` (admission_stored.rs:13), `#[serde(default, skip_serializing_if = "PlanProvenance::is_empty")]`, placed beside `writes` and written at admission.rs:123 (stdio through `complete_delivery_read`). StoredDelivery tolerates extra fields, so an older binary ignores it.
- **Task:** `Record.plan`, placed before `gateway_writes` (which stays last for damage-locality, record.rs:268). It is carried by `Commit`/`Recover` (execution.rs:155/174) and surfaced on `CommittedTask`. A row that carries it is written at `PLAN_PROVENANCE_VERSION = PENDING_CANCEL_VERSION + 1`, and `MAX_LOADABLE_VERSION` is raised. Rows without it keep their version and bytes.
- **Decode tolerance (muse M-4):** a custom `Deserialize` drops a damaged `plan` field to empty, as `WriteRecord` degrades per entry (gateway_writes.rs:153-175). The row still loads, and the replay stages nothing.
- **Threading, not a task-local (round 1 H7):** `stored_response` returns it, and `SyncAdmission::Replay(JsonRpcResponse, ReplayStored { audit, plan }, Option<ReplayTarget>)` carries it (`ReplayTarget` is STORED.2's, its own element). `audit_replay` takes `ReplayStored` and hands `.plan` to `stage_replay`. The call sites are dispatch_tools_call.rs:585, stdio_dispatch.rs:645 and the direct-route arm (direct_idempotency.rs:143, muse L-1).

### D3. Replay staging

`stage_plan_replay(who, plan, answer)` is called by `stage_replay` for `gateway_execute`/`gateway_run_playbook`, and by `stage_stored_receipt` in the `Completed` arm only (task_replay.rs:119-128). A multi-target `InputRequired` or `Failed` read stages nothing.
1. Decode the delivered form: task, the stored slot as `Literal`; sync, `replay.result` with `AnswerShape::of(tool)` (relay_delivered.rs:478). Both go through `plan_answer`.
2. Rebind the stored forms through any credential-redaction key rename (gateway_writes::rebind precedent), so the mask's coordinates align.
3. Version check (D1). Run `Firewall::replay_masks` → `(label, source, digest)`.
4. Task path: drop any entry whose source is not in `stored.targets`.
5. A label that carries more than one distinct call (a nested plan) stages nothing: the known limit, MIK-8409, counted in `..._plan_replay_nested_skipped_total` (separate from the bound drops, muse L-4).
6. Stage each entry with its label, read through `plan_step()` so the label is inherited, not overwritten (muse L-2/M1). Inside a live plan step, the entries take the outer label. Entries are marked `Kind::Replayed`.
7. The final pass still runs (sync: handlers.rs:697 / stdio_dispatch.rs:190; task: `tasks/get` inside `meta_mcp_dispatch`, handlers.rs:612 → :697). For `Kind::Replayed` receipts it only keeps them to the answer as delivered *now* (a replay-time redaction removes text, row G11). It does not re-run `add_seams`, because seams were persisted. Keeping to the same answer is idempotent.
8. Notify path (task_notify.rs:61-159): it commits without the final pass. Persisted receipts are already kept and seamed, and a redacted or refused frame commits nothing (:100-105), so nothing more is needed there (row G27).

### D4. executed_steps (shared with MIK-8406; owner mutretro)

`Declared` is the default. `Recorded { from }` is returned only when:
- the list is a non-empty `PlanProvenance.steps` (`from: Provenance`); or
- a parse maps one-to-one onto unique declared steps, contiguous from the first. For a playbook, each `steps_completed`/`steps_failed` name names one step, with no duplicates, as a prefix in declared order, skipped steps aside. For a chain, indices 0..n with no gap, each `server:tool` equal to the declared step. For a single call, its one target from the arguments (`from: Parsed`).

Otherwise it returns `Declared`, which is empty ("could not tell") when the walk is impossible. 8406 judges every step on `Declared`, and refuses outright on an empty one. 8408 stages from the masks and uses `steps` only for the targets check.

Merge order (muse M-7): 8408 is expected to merge first and writes `executed_steps`. If 8406 lands first, a2a-1 writes it to this exact signature and 8408 takes it over. There is no second parser.

### D5. Recording scope opens unconditionally

`collecting_http` returns early when detection is off (relay.rs:361-363), and so does stdio (stdio_single.rs:339). A new `provenance_scope` (PLAN_MEMBERS, steps, gateway_writes) opens on both transports regardless, and receipt collection stays inside it, gated as today. This also closes an existing gap of the same cause: a record written with detection off and replayed with it on would receipt the gateway's own text today, single-target included (row G25).

### D6. Detection off at delivery

No receipts exist, so no masks are stored, and renewals for that record never start. After detection is turned on, renewal begins with plans delivered from then on. This is a known limit, stated in the changelog and in upgrading.d. `steps` is still recorded, so 8406 is unaffected.

### D7. Staging position and REPLAY.3

Unchanged: staged where it is today, and committed only on delivery (`commit_with` drops when the frame is not delivered, relay.rs:654-660). In STORED.2's order (lift → spend/redeem → relay → mark) this is the relay step.
- Sync: admission refusals and MIK-8406's gate run before `audit_replay` (dispatch_tools_call.rs:546-585).
- Task: staging is inside `refused.is_none()` (task_replay.rs:40-42).
- Gateway text, notices and redaction: excluded because live retention excluded them and the mask reproduces that decision.

## 3. Bound, bench, cost (NFR.WORKLOAD)

- **Estimate.** A mask costs about 8 B per run. A receipt has runs only in the forms that hold its kept text: its own leaves, plus the newline-joined, run-together and key-path forms. Typically that is 3-6 forms with 1-3 runs each, so about 100-250 B, plus its source names. A 3-5 step plan with its seams (2-4) comes to about 1-2.5 KiB. `steps` adds about 40 B per call.
- **Bound.** Per record: at most 128 receipt masks, 64 forms per mask and 64 runs per form; names at most 128 B; a pointer or form index at most 512 B; at most 16 KiB serialized. That is inside the lead's 64 KiB ceiling and 3% of the default 512 KiB `max_record_bytes` (config/features/tasks.rs:20), and it counts against that budget. Over any bound, the whole provenance is dropped and counted (`..._plan_provenance_dropped_total`), and the replay stages nothing. Bounds are enforced while recording, latched on the first overflow (gpt improvement).
- **Drop tier order on the task path (muse M-3).** `settle_durable` tries full, then writes-stripped, then bounded (store_targets.rs:259-315). Provenance is dropped first, folded into the first retry: full with provenance, then full without it, then writes-stripped, then bounded. The drop counter increments once per committed row that lost it. The version-9 bump applies only when the committed row carries provenance. An `output_free` row carries none.
- **Plan bench (new, muse M-5; lead condition).** `benches/plan_provenance.rs` runs representative plans: a 3-step chain and a 5-step playbook, each step returning JSON text of 0.5, 2, 8 and 32 KiB, with one redacted credential and one gateway notice. It reports the serialized provenance size per plan, the bound, and the share that fits. NFR.WORKLOAD.1 compares plan latency with and without recording.
- **Fail-fast.** If under 99% of the bench plans fit 16 KiB, stop and return to the lead before lowering fidelity.

## 4. Compatibility, rollback, docs

- **Rollback.** A binary that reads at most version 8 meeting a version-9 plan row refuses the whole task store (store_disk.rs:323-329): the HTTP gateway does not start (run.rs:472-490), and stdio runs without tasks (stdio_tasks.rs:90-96). This is the existing 4.0 rule for versions 5-8 (docs/UPGRADING-4.0.md:3132-3140). The older loader already logs each such row with its path and version (store_disk.rs:326), and run.rs:484-487 points the operator at that warning. Remedy: restore the backed-up `tasks.store_dir`, or remove the version-9 rows named in the warning.
- **upgrading.d (`upgrading.d/<pr>.md`):**
  - version 9 and the remedy above;
  - plan results stored before the upgrade renew nothing until they expire (24 h);
  - a plan delivered with relay detection off never renews (D6).

  The UPGRADING-4.0 Rollback paragraph names version 9.
- **Changelog:** plan replays renew relay receipts; the two known limits (nested plans, MIK-8409; detection off at delivery).
- **Ticket:** the Rollback line is already corrected.

## 5. Test plan

Conventions:
- Clock: the relay clock is advanced with `advance_collusion_clock_for_test` (collusion_gate_seams.rs:163). Task workers are joined first, so a late live commit cannot mask the base defect (gpt improvement).
- Plans: every plan row uses distinct tools per step, all dispatched, and asserts `stored.targets.len() == 2` as setup, because DispatchLog deduplicates pairs (muse H-2).
- Sensitivity: "verdict" means a context-integrity sensitive verdict on the step result; "rule" means a `sources` rule match.
- Paths: T = task, H = sync HTTP, S = sync stdio.
- Gating: relay rows are `cfg(feature = "firewall")`.
- Key change: a `cfg(test)` key override (`collusion::test_key::reseed()`, thread-local, mirroring `clock::test_clock`) swaps the per-process key for in-process rows. G24 also runs as a two-process integration test.

| Row | Path | Setup → expected | Sens. | Base / mutant |
|---|---|---|---|---|
| R1 | T | alice runs a two-step chain (S1 sensitive, S2 plain) as a task; clock +601 s; alice `tasks/get`; bob relays S1 text → flagged | rule | red |
| R2 | T | as R1, two-step playbook | rule | red |
| R3/R3s | H/S | as R1, keyed retained replay of `gateway_execute` | rule | red |
| R4/R4s | H/S | as R2, `gateway_run_playbook` | rule | red |
| R5 | T | carol holds S1 text fresh; alice's original receipt expired; alice re-reads, sends S1 text → not refused. Control: bob refused for the same text | rule | red |
| R6 | T | text spanning the S1/S2 boundary, relayed by bob after the re-read → flagged (persisted seam) | rule | red |
| R7 | T | playbook step sensitive by verdict only, output mapping drops the step root → flagged after re-read | verdict | red |
| R8 | T | step served from the idempotency cache; re-read; bob relays → flagged | rule | red |
| C1 | T | single-target `gateway_invoke` task re-read past the window; bob flagged | rule | green on base (fail-fast) |
| G1 | T,H | a member the gateway wrote; bob relays it → not flagged | rule | mutant: mask built from the raw answer, not from committed receipts |
| G2 | T,H | re-read whose frame is not delivered → nothing recorded | rule | mutant: commit regardless |
| G3 | T | provenance names a call missing from `stored.targets` → that entry stages nothing | rule | mutant: drop the check |
| G4 | T,H | record without provenance → nothing staged, no error | rule | mutant: error on missing |
| G5 | T | row with provenance round-trips at v9; row without keeps version and bytes | n/a | mutant: always write v9 |
| G6 | T | nested label: bob not flagged AND alice not excused against a fresh holder of the nested text (muse H-3) | rule | mutant: stage under each call (sensitive and plain) |
| G7a-e | T | one row per bound (receipts, forms, runs, names, 16 KiB) → dropped whole and counted | n/a | mutant: truncate |
| G8 | T | an `output_free` row carries no provenance | n/a | mutant: keep it |
| G9 | T | `a_newer_or_rebound_record_still_refuses` at `MAX_LOADABLE_VERSION + 1`, warning names the file | n/a | mutant: accept the newer version / skip the warning |
| G10 | T | multi-target `InputRequired`/`Failed` read stages nothing | rule | mutant: route them in |
| G11 | H | a member redacted at replay time → removed text renews nothing, delivered text renews | rule | mutant: skip the replay final keep |
| G12 | T,H | sync: admission refusal → never reaches staging; task: `authorize_stored` refusal → nothing staged; add the 8406 gate when it lands | rule | mutant: stage before the gate |
| G13 | H | keyed plan replay inside a live plan step stages only its own receipts, under the outer label | rule | mutant: shadow the label |
| G14 | H | sync record without the field decodes with empty provenance | n/a | mutant: remove the serde default |
| G15-G17 | unit | `executed_steps`: no provenance and no arguments → `Declared`; resumed chain starting at 2 → `Declared`; duplicate name → `Declared` | n/a | mutant: return `Recorded` |
| G18 | T | chain pauses at step 1 and resumes: `steps` includes step 0; replay stages nothing under label 0 | n/a | mutant: skip the merge |
| G19 | unit | empty provenance plus unreadable answer → `Declared` | n/a | mutant: empty treated as `Recorded` |
| G20 | T,H | detection off: a two-step plan's `steps` lists both targets | n/a | mutant: note only when relay is active |
| G21 | T | playbook `on_error: continue`, step 1 fails upstream: in `steps`; replay stages nothing for it | n/a | mutant: note only on success |
| G22 | T | **sampling boundary:** gateway text adjacent to backend text; key reseeded; replay → no fingerprint from the gateway text or straddling it | rule | mutant: extend runs to the next dropped sample |
| G23 | T | **version:** header `norm_version` differs → nothing staged, counted | n/a | mutant: ignore the header |
| G24 | T,H | **restart:** record; restart (new key); replay → the replayed digests equal those of a fresh live delivery of the same answer (fingerprint sets and sensitivity) | rule+verdict | mutant: persist raw fingerprints |
| G25 | T,H | record with detection off, replay with it on: gateway-written member never receipted; single-target included | rule | mutant: open the writes scope only when relay is active |
| G26 | T | a step refused before dispatch → no receipt (gpt #1) | rule | mutant: mask pre-dispatch results |
| G27 | T | notify frame of a plan task: persisted receipts committed; a redacted frame commits none | rule | mutant: commit on a withheld frame |
| G28 | T | damaged `plan` field → row loads, nothing staged | n/a | mutant: strict decode |
| G29 | T | task-augmented repeat (call_dispatch.rs:354) renews like R1 | rule | red |
| G30 | T | credential redaction renames an output key; replay still renews the value | rule | mutant: skip the rebind |

Mutants run on CI throwaway branches. Feature combos: `--no-default-features`, `firewall` alone, default.

## 6. Round-2 dispositions

- gpt CRITICAL #1: steps at dispatch, failures included (D1(i)), plus G26.
- gpt HIGH #2: persisted masks (lead ruling).
- gpt HIGH #3: D5 plus G20/G25.
- gpt HIGH #4: superseding REPLAY.5/.6 and MIK-8409.
- gpt MEDIUM rename: G30.
- gpt MEDIUM missing mutants: G8/G9/G14 now have them.
- muse round 2:
  - H-1 (notices): excluded by the mask.
  - H-2: test conventions.
  - H-3: G6.
  - H-4: firewall-built digest API.
  - H-5: G12 now.
  - M-1: D3.8 and G27.
  - M-2: path column.
  - M-3: tier order.
  - M-4: G28.
  - M-5: bench.
  - M-6: G29.
  - M-7: D4 merge order.
  - M-8: sensitivity column.
  - L-1: direct arm.
  - L-2: `plan_step()`.
  - L-3: skip on drift.
  - L-4: separate counters.
  - L-5: the ticket's Rollback line, already fixed.
  - L-6: exact-tuple dedup.
  - L-7: G7a-e.
  - L-8: the helper takes the selected value.
  - L-9: an edited playbook refuses on sync via the digest pin (admission.rs:472-476); the task path needs no definition, so renewal holds there.

---

# MIK-8408 d3 confirming delta (lead ruling after round 3): exact receipts in a process-local store

This delta supersedes d3's §2 D1(ii) (position masks), the mask parts of D2/D3, the bound in §3, and rows G22-G24. Everything else in d3 stands.

Why: both seats showed in round 3 that no key-independent coordinate reproduces live retention exactly. Fingerprints are keyed per process (collusion.rs:380), and the relay detector's own state is in memory and lost on restart. The sync replay store is in memory too (idempotency/admission.rs: a `HashMap`, no disk write). So exact receipts are only useful inside the process that made them, and persisting them would gain nothing.

## E1. The replay receipt store

- **What.** A process-local `ReplayReceipts` store on the `Firewall`, holding for each stored entry the committed in-plan receipts of its live delivery: `Vec<(label: Option<u32>, source, DeliveryDigest)>`. These are the digests after `keep_plan_receipts`, `add_seams` and `add_subset_seams`, exactly as `commit_with`/`record_digest` record them. That covers evidence, cut middles, seam excuses, seam receipts, sensitivity and judged state. There is no re-hash, no coordinates and no sampling question.
- **Key.** `StoredKey::Sync(admission operation digest)` or `StoredKey::Task(task id, revision)`: the stored entry the replay serves, never the reader.
- **Written** at the same commit points that record a plan's receipts today: the HTTP `emit_http` commit, the stdio delivery commit (`complete_delivery_read`, admission.rs:84 via stdio_delivery.rs:152), and task settlement. Only when relay detection is on (otherwise there are no receipts) and only for a plan answer that is being stored.
- **Budget**, following the MIK-8200 sketch store pattern (collusion_sketch.rs:38): `REPLAY_RECEIPT_BYTES` = 32 MiB in total, measured as the digests' fingerprint bytes plus overhead. One entry may use at most 1 MiB, and a larger one is not stored (counted). Past the total, the oldest entry goes: evict-oldest, counted in `mcp_gateway_collusion_plan_replay_evicted_total`.
- **Lifetime.** An entry is removed when its stored entry expires or is removed (sync retention, `RETENTION_SECS`; task expiry or deletion), or lazily on lookup past that retention.
- **Nothing fingerprinted reaches disk.** Keyed hashes stay in the process that keyed them.

## E2. Replay

`stage_plan_replay(who, key, answer, targets)`:
1. Run it only where d3 already allows: after authorization (D7), on the task path only in the `Completed` arm.
2. Look up `key`. If there is no entry (a restart, an eviction, detection off at delivery, or an entry too large to store), stage nothing and count it by reason.
3. Task path, targets check with the **composite fix** (gpt d3 HIGH): a plain source must be in `stored.targets`. A seam's composite source (relay_seams_record.rs:156-169) is accepted only if every constituent `server:tool` is in `stored.targets`, and it keeps its composite identity and its flow policy (every source must allow).
4. Nested label (more than one distinct call under a label) stages nothing (MIK-8409).
5. Stage each digest (a clone) for `who`, under its source, with its label through `plan_step()`, marked `Kind::Replayed`. The final pass keeps a `Replayed` receipt to the answer as delivered now. A replay-time redaction removes text (G11), the keep is idempotent on an unchanged answer, and no seam pass is re-run.
6. Commit on delivery, as today.

Safety: the entry is keyed by the stored entry that was just authorized and served, so it holds only that entry's own committed receipts. A digest names no principal: it is recorded for `who` at commit. Gateway text, notices and redaction were excluded by live retention, and the digest is that result.

## E3. What is persisted

- **Task `Record`:** only `PlanProvenance.steps` (for 8406 and the targets check), recorded at dispatch with failures included, cumulative across a resume (d3 D1(i)). The v9 bump, rollback note and decode tolerance stay as in d3. The 16 KiB bound now covers `steps` only (at most 64 entries, names at most 128 B). Over the bound, it is dropped whole and counted; `executed_steps` then returns `Declared`.
- **Sync `StoredDelivery`:** `plan.steps` beside `writes` (in memory anyway).
- No member pointers, masks or headers are persisted. d3's D1(ii), its header and version check, and its coordinates are withdrawn.

## E4. Stated limits (changelog and upgrading.d)

All four fail toward a missed renewal.
- A plan result read after a gateway restart does not renew its receipts.
- An entry evicted under the 32 MiB budget does not renew.
- A plan delivered with relay detection off does not renew.
- Nested plans do not renew (MIK-8409).

Single-target replays are unchanged.

## E5. Bench and fail-fast (lead condition, revised)

`benches/plan_provenance.rs` (3-step chain and 5-step playbook; steps of 0.5, 2, 8 and 32 KiB of JSON text, varied entropy and fragmentation, one redacted credential, one gateway notice) reports:
- memory per stored entry (the digests' real byte size);
- how many typical plans the 32 MiB budget holds;
- the share of bench plans under the 1 MiB entry cap.

If under 99% are under the entry cap, stop and return to the lead.

## E6. Rows

Removed: G22 (sampling boundary), G23 (version header), G24 (restart equality).

| Row | Path | Setup → expected | Base / mutant |
|---|---|---|---|
| G31 | T,H | same process: the replayed digests equal the committed digests of the original delivery (fingerprints, cut, seam excuses, sensitivity, seam sources) | mutant: re-derive from the stored answer |
| G32 | T | restart, modelled by building a fresh `Firewall` over the same task store: the re-read stages nothing, counted `reason=absent`; `steps` still loads | mutant: re-derive when absent |
| G33 | T,H | fill past 32 MiB: the oldest entry is evicted and counted; its replay stages nothing; a newer entry still renews | mutant: never evict / evict newest |
| G34 | T | entry over 1 MiB: not stored, counted; replay stages nothing | mutant: store it |
| G35 | T | composite seam: all constituents in `stored.targets` → renewed (R6 holds); one constituent missing → that seam stages nothing | mutant: compare the composite string to the targets |
| G36 | T,H | stored entry expires or is removed → its side entry goes; a later key reuse cannot pick up the old receipts | mutant: keep the side entry past retention |

R1-R8, C1 and G1-G21, G25-G30 stand. G1 and G26's mutants now read "re-derive from the stored answer".

---

# Binding final text (confirming-pass findings; lead ruling: freeze)

These supersede the d3 body and the delta wherever they conflict.

**F1. Sync key.** `StoredKey::Sync(identity, round, operation)`, using the identity and operation hashes admission.rs:218-222 already computes, plus the round from `admit_round` (admission.rs:302). The operation is verified on lookup. A new commit overwrites the entry, and a non-plan commit under the same key deletes it. The key travels inside `ReplayStored` (secD's `SyncAdmission::Replay` shape is unchanged). Task key: `(task id, revision)`.

**F2. An immutable `ReplayReceipt` snapshot, never a live digest.** At commit, the firewall exports for each committed in-plan receipt: `segments`/retained fingerprints, `sensitive`, `seam_sources`, `cut_fps`, `seam_excuses` and `cut_lost`, plus label and source. It carries no `ViewCharge` or step-evidence charge (it is charged only to the replay store's budget, measured as its real bytes), no one-shot `recorded` flag, and no reservation. Each replay builds a fresh `DeliveryDigest` from it through a `pub(crate)` replay constructor in the firewall module, so the recorded flag starts unset and the replay actually records (G31).

**F3. Big-step receipts are not stored.** A receipt with a judged big-step excuse (`Kept(Some)`/`Unread{step: Some}`, whose reservation is bound to the original caller's pair, collusion_big.rs:424) is dropped from the snapshot and counted (`reason=big_step`). Fail toward a miss. Re-reserving for the replay reader is a possible follow-up, not in 8408.

**F4. Keeping to the replayed answer.** If the replayed answer is byte-identical to the stored one (the normal case), the snapshot is re-recorded with no retention pass. If it changed (a replay-time redaction), every component is filtered against the delivered answer. A component that cannot be filtered safely (the `cut_fps` and `seam_excuses` sets) is dropped and counted. Never keep text the replay did not deliver.

**F5. Nested entries drop their seams.** If `steps` shows any label with more than one distinct call, every seam receipt of that entry is dropped too (seams carry `step: None`, relay_seams_record.rs:87-99), counted. G6 covers a seam spanning nested text.

**F6. Store placement.** The store lives on the `Firewall`, shared wherever the detector is shared. Its lock is never held while the detector's state lock is taken. An entry expires with its stored entry, and is checked lazily on lookup against that entry's retention.

**F7. Rows (added or rewritten).**
- G3: a snapshot whose source (or a composite constituent) is not in `stored.targets` stages nothing.
- G7a-c: the `steps` bounds (64 entries, 128 B names, 16 KiB) → dropped whole, `executed_steps` → `Declared`.
- G37: double replay. Two re-reads both renew; each records.
- G38: a big-step receipt is not stored; the replay stages the other receipts and counts the drop.
- G39: sync collision. Caller B replaying caller A's stored operation finds no entry and stages nothing.
- G40: a seam spanning nested text stages nothing.
- G41: a replay-time redaction. Removed text renews nothing; cut and seam-excuse sets are dropped and counted; delivered text renews.
- G31 setup includes a seam and a cut, and asserts that the replay records (the detector holds the reader).

Process next: test plan (gpt + muse) → red rows on the release line → implementation after STORED.2 merges (plan path after MIK-8406).
