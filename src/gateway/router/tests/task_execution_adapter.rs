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
use super::*;

mod support;

mod capacity;
mod confirmation;
mod dedupe;
mod interlock;
mod lifecycle;
mod refusals;
mod result_shapes;
mod settlement;
mod signing_joint;
mod x1_dispatch;
