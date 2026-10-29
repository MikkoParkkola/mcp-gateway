// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Server-module tests that need more than one file.
//!
//! Existing server tests are flat siblings (`http_lifecycle_tests`,
//! `test_support`). This directory exists because the allocation checkpoint
//! needs three files that only make sense together: the meter, the fixture and
//! the oracles.
//!
//! Loaded by `server/mod.rs` as `#[cfg(test)] #[path = "tests/mod.rs"] mod
//! signing_allocation_tests;` — the name `tests` is already taken by the inline
//! test module further down that file.

mod admission_allocations;
pub(crate) mod alloc_meter;
#[cfg(all(unix, feature = "firewall"))]
mod allowed_root_route_rows;
#[cfg(all(unix, feature = "firewall"))]
mod allowed_root_routes;
mod descriptor_copies;
mod fresh_slot_verdict;
mod input_key_allocations;
mod invoke_argument_copies;
mod is_connected_count;
#[cfg(feature = "firewall")]
mod judge_allocations;
mod mik8488_alloc_probe;
mod per_call_timing;
mod signing_nonce_allocations;
pub(in crate::gateway::server) mod signing_nonce_allocations_support;
mod trust_card_list_allocations;
mod visibility_allocations;
mod visibility_reload_race;

mod signing_stdio_routing;

mod dispatcher_admission_arms;
mod unkeyed_admission;

mod stdout_death_admission;

#[cfg(feature = "firewall")]
mod collusion_stdio;
#[cfg(feature = "firewall")]
mod collusion_stdio_delivered;
#[cfg(feature = "firewall")]
mod collusion_stdio_plan;
/// MIK-8408 R3s/R4s: a keyed stdio plan replay renews its step receipts.
#[cfg(feature = "firewall")]
mod collusion_stdio_plan_replay;
/// MIK-8408 stage 4: the stdio guard rows (G25-S).
#[cfg(feature = "firewall")]
mod collusion_stdio_plan_replay_guards;
#[cfg(feature = "firewall")]
mod egress_matrix_stdio;
mod r2_stdio_keys;
/// Backend-planted gateway members over stdio.
mod reserved_member_stdio;
/// Secret injection delivers a header rule as a header, a query rule never in the arguments.
mod secret_injection_targets;
mod stdio_cache_scope;
mod stdio_list_changed;
mod stdio_listing_scope;
#[cfg(feature = "firewall")]
mod stdio_response_firewall;

mod stdio_initialize_order;
#[cfg(feature = "firewall")]
mod stdio_tenant_reads;
/// MIK-8392.STORED.1 T2: stdio tasks/get judges the caller's current view.
mod stored_read_stdio;
/// MIK-8044.SURF.2: a gateway.yaml `protocol_version` reaches the HTTP transport.
mod surf2_protocol_version_config;

mod stdio_hardened_signing;

mod stdio_sole_operator;

mod playbook_retry_stdio;

mod plan_replay_liveness_stdio;
mod stdio_catalogue_sole_operator;
mod stored_replay_liveness_stdio;

// MIK-8364: stdio saves protocol telemetry off the request path.
mod stdio_telemetry_save;

#[cfg(feature = "cost-governance")]
mod stdio_cost_persistence;

mod grant_decision_stdio;
#[cfg(feature = "cost-governance")]
mod http_cost_persistence;

// MIK-7272.OWNER.3 and OWNER.5 (the sub4 stdio owner test plan, I1).
mod owner3_stdio_keying;
mod owner5_stdio_context;

// MIK-7272.OWNER.1 and OWNER.4 (the sub4 stdio owner test plan, I2).
mod owner1_stdio_management;
mod owner1_stdio_reload;
mod owner4_stdio_policy;

// MIK-7272.LIFE.1 (the sub4 stdio owner test plan, I3).
mod life1_stdio_cancel;
// MIK-8176 stage 3: stdio slots kept when written, given back otherwise.
mod stdio_slot_release;
// MIK-7642.PR.B: a client cancel reaches the backend by its own request id.
mod mik7642_backend_cancel;
mod owner2_stdio_tasks;
#[cfg(feature = "firewall")]
pub(super) mod route_matrix_stdio_tasks;
/// MIK-8353 slice 3c: the stdio twin of the R4a nonce give-back row.
mod s3c_stdio_refund;
/// MIK-8353 slice 3d-2 (K6): a stdio task-intent refusal and its nonce.
#[cfg(feature = "firewall")]
mod s3d2_stdio_task_intent;
mod stdio_task_policy_recheck;
mod submit_authz_stdio;
// MIK-7839.CANCEL.3: a dropped run_stdio future stops its task workers.
mod stdio_session_drop;
// MIK-7757: a drain timeout cancels the running workers on both shutdown paths.
mod stdio1_discover_versions;
mod stdio_reused_id;
mod task_drain_timeout;
mod task_shutdown_tail;

// #2480: a stdio idempotent replay writes its invocation record.
mod stdio_replay_audit;

// MIK-7324.COV.3: the stdio chain-nonce refusal in `prepare_signing`.
mod stdio_chain_nonce_refusal;

// MIK-8378: envelope rows over stdio (ENV.2, ENV.4).
mod mik8378_stdio;

// MIK-7324.COV.3: the firewall `response_firewall` builds carries anomaly blocking.
#[cfg(feature = "firewall")]
mod response_firewall_anomaly;

#[cfg(feature = "firewall")]
mod hardened_destination;

// MIK-7685 (#2530): stdio EOF teardown is bounded.
mod stdio_teardown_bound;

// MIK-7684: the stdio reader never waits for stdout room.
#[cfg(feature = "firewall")]
mod oracle_parity_stdio;
mod stdio_reader_unparked;
/// MIK-8340: a withheld surfaced name answers on stdio as an absent one.
#[cfg(feature = "firewall")]
mod withheld_parity_stdio;

// MIK-8356 C3, C10: a stdio call judged by the sole operator's own slot.
mod slot_verdict_g2_stdio;
