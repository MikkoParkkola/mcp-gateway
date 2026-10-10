// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task execution / lifecycle adapter, at the production route.
//!
//! Test-first for increment **I1** of the approved design
//! (`claude-task-execution-adapter-design-r3/adapter-design.md`,
//! sha256 `01c2b593bdbb4862f0fb605f7cf0429541d3552b2330ca916450925dab38d26e`,
//! P1 SHIP). Source-bound to `mcp-v4-task-execution-adapter` @ `13e97b30`.
//!
//! Every row here drives the real `/mcp` router and a real injected backend
//! transport. Nothing constructs an `AppState`, opens a store, or reads a task
//! record directly: the adapter's claims are claims about what a client sees.
//!
//! # What is red today, and why
//!
//! At `13e97b30` `handlers.rs:1194` answers a task-augmented `tools/call` by
//! minting a record and returning — above the router's authorization loop
//! (`:1252`), above the firewall pre-scan (`:1303`), above the caller context
//! (`:1393`) and above every dispatch arm. So the rows below fail on behaviour:
//! handles never leave `working`, backends are never reached, refusals that must
//! precede the commit run after it or not at all. That is the intended RED. The
//! controls in [`x1_dispatch`] run the same calls with no `task` member and do
//! reach the backend, which is what separates "the adapter does not dispatch"
//! from "this fixture was never wired".
//!
//! # Increment boundary
//!
//! I1 only. Nothing here asserts `notifications/tasks` (I2), a restart branch
//! (I3), expiry or TTL sweeping (I4), or a recovery adapter (I5). The design's
//! X6/X10/X11/X15 rows belong to those increments and are deliberately not
//! written yet.
//!
//! # Rows that cannot compile against `13e97b30`, and are therefore not declared
//!
//! Original P2 compile state (the two modules are now declared below; their
//! composed compile and behavior checks remain required):
//! Two files carried complete assertions for approved rows whose test seams
//! did not yet exist. They are written, they are not
//! weakened, and they are not `#[ignore]`d — they are simply not reachable from
//! this module until the declaration each one names lands. Activating one is a
//! single `mod` line here, and each row's oracle is already final.
//!
//! * `capacity.rs` — **X5, X5b, and X16b's permit half**. Needs the `tasks`
//!   configuration block, specifically `tasks.max_workers` (design §8, lane 3):
//!   worker-cap saturation is the barrier all three rows are built on and there
//!   is no other way to produce it. Activate with `mod capacity;`.
//! * `interlock.rs` — **X4, X9, X16a**. Needs the executor's commit seam
//!   observable from a test — design §6's `TaskExecutor::commit`/`published`
//!   tail call, exposed as a `CommitStage` hook — plus
//!   `TaskStore::mark_dispatched` (design §7) and `TaskExecutor::drain`
//!   (design §3.2). Each row's barrier is a durable-write stage, and a stage
//!   nothing can observe cannot be a barrier. Activate with `mod interlock;`.
//!
//! Both are compile limits, not behaviour findings, and the receipt reports them
//! under a separate heading for exactly that reason.

mod support;

#[cfg(feature = "firewall")]
mod egress_task;
/// MIK-7887.RECEIPT.4: the POST route receipts the answer it delivered.
#[cfg(feature = "firewall")]
mod relay_delivered_route;
/// MIK-7887.RECEIPT.2: a redacted plan answer keeps each step's delivered text.
#[cfg(feature = "firewall")]
mod relay_plan_route;
/// MIK-8113: seams between plan steps at the POST route.
#[cfg(feature = "firewall")]
mod relay_plan_seam_route;
/// MIK-7934.PLANRCPT.1: a task plan redacted at settlement keeps step receipts.
#[cfg(feature = "firewall")]
mod relay_plan_task;
/// COLLUDE.1 M9: a task's relay receipt is committed at settlement.
#[cfg(feature = "firewall")]
mod relay_settlement;
/// COLLUDE.1 M15: an upstream task's result is a relay source.
#[cfg(feature = "firewall")]
mod relay_upstream;

mod grant_audit_order;
/// D3-a: grant decision records at the route.
mod grant_decision_tasks;
mod grant_decisions;
mod grant_slot_release;

mod admission_identity;
/// MIK-7570.ATTEST.1 part 3: surfaced-tool tasks carry their attestation token.
mod attestation_tasks;
/// MIK-7828.FIX.2: a running task's caller key outlives the idle TTL.
mod caller_key_ttl;
/// G4: a task keys its arm and hints on its caller.
mod caller_keyed_hints;
mod capacity;
mod client_extensions;
mod confirmation;
mod dedupe;
mod drain;
/// MIK-7311.LIFECYCLE.1 increment 1b: the input round on `/mcp`.
mod input_round;
mod input_round_deadline;
mod input_round_races;
mod interlock;
mod lifecycle;
mod pending_input_policy;
mod proven_subject_admission;
mod provide_input_guards;
/// I5's during-the-wire half: one query per record at a time, worker and
/// authenticated reader alike.
mod query_serialization;
mod refusals;
mod replay_policy;
mod result_shapes;
mod settlement;
/// MIK-7116.MIN.1 gap 1: the settlement record of a recovered upstream task.
#[cfg(feature = "firewall")]
mod settlement_record;
mod signing_joint;
mod slot_release_tasks;
/// `MIK-7993.STORE.1`/`.2`: a task row records the members the gateway wrote.
#[cfg(feature = "firewall")]
mod stored_gateway_writes;
mod stored_result_policy;
/// MIK-7974: a task keeps its request's meta-tool surface for its hints.
mod surface_hints;
#[cfg(feature = "metrics")]
mod unkeyed_task;
mod upstream_cancel;
/// I5's before-the-wire half: the recovery descriptor's capacity, decided
/// before the first `tools/call` rather than after the handle comes back.
mod upstream_descriptor;
mod x1_dispatch;

mod notifications;
