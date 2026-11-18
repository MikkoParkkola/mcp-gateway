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

#[cfg(tp5)]
mod admission_allocations;
pub(crate) mod alloc_meter;
#[cfg(tp5)]
#[cfg(all(unix, feature = "firewall"))]
mod allowed_root_capability_rows;
#[cfg(tp5)]
#[cfg(all(unix, feature = "firewall"))]
mod allowed_root_route_rows;
#[cfg(tp5)]
#[cfg(all(unix, feature = "firewall"))]
mod allowed_root_routes;
#[cfg(tp5)]
#[cfg(all(unix, feature = "firewall"))]
mod allowed_root_secret_rows;
#[cfg(tp5)]
mod descriptor_copies;
#[cfg(tp5)]
mod fresh_slot_verdict;
#[cfg(tp5)]
mod input_key_allocations;
#[cfg(tp5)]
mod invoke_argument_copies;
#[cfg(tp5)]
mod is_connected_count;
#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod judge_allocations;
#[cfg(tp5)]
mod mik8488_alloc_probe;
#[cfg(tp5)]
mod per_call_timing;
#[cfg(tp5)]
mod signing_nonce_allocations;
pub(in crate::gateway::server) mod signing_nonce_allocations_support;
#[cfg(tp5)]
mod trust_card_list_allocations;
#[cfg(tp5)]
mod visibility_allocations;
#[cfg(tp5)]
mod visibility_reload_race;

#[cfg(tp5)]
mod signing_stdio_routing;

#[cfg(tp5)]
mod dispatcher_admission_arms;
#[cfg(tp5)]
mod unkeyed_admission;

#[cfg(tp5)]
mod stdout_death_admission;

#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod collusion_stdio;
#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod collusion_stdio_delivered;
#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod collusion_stdio_plan;
/// MIK-8408 R3s/R4s: a keyed stdio plan replay renews its step receipts.
#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod collusion_stdio_plan_replay;
/// MIK-8408 stage 4: the stdio guard rows (G25-S).
#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod collusion_stdio_plan_replay_guards;
#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod egress_matrix_stdio;
#[cfg(tp5)]
mod r2_stdio_keys;
/// Backend-planted gateway members over stdio.
#[cfg(tp5)]
mod reserved_member_stdio;
/// Secret injection delivers a header rule as a header, a query rule never in the arguments.
#[cfg(tp5)]
mod secret_injection_targets;
#[cfg(tp5)]
mod stdio_cache_scope;
#[cfg(tp5)]
mod stdio_first_list;
#[cfg(tp5)]
mod stdio_first_list_commit;
#[cfg(tp5)]
mod stdio_first_list_rows;
#[cfg(tp5)]
mod stdio_first_list_scope;
#[cfg(tp5)]
mod stdio_list_changed;
#[cfg(tp5)]
mod stdio_listing_scope;
#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod stdio_response_firewall;

#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod stdio_allow_attribution;
#[cfg(tp5)]
mod stdio_initialize_order;
#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod stdio_tenant_reads;
/// MIK-8392.STORED.1 T2: stdio tasks/get judges the caller's current view.
#[cfg(tp5)]
mod stored_read_stdio;
/// MIK-8044.SURF.2: a gateway.yaml `protocol_version` reaches the HTTP transport.
#[cfg(tp5)]
mod surf2_protocol_version_config;

#[cfg(tp5)]
mod stdio_hardened_signing;

#[cfg(tp5)]
mod stdio_sole_operator;

#[cfg(tp5)]
mod playbook_retry_stdio;

#[cfg(tp5)]
mod plan_replay_liveness_stdio;
#[cfg(tp5)]
mod stdio_catalogue_sole_operator;
#[cfg(tp5)]
mod stored_replay_liveness_stdio;

// MIK-8364: stdio saves protocol telemetry off the request path.
#[cfg(tp5)]
mod stdio_telemetry_save;

#[cfg(tp5)]
#[cfg(feature = "cost-governance")]
mod stdio_cost_persistence;

#[cfg(tp5)]
mod grant_decision_stdio;
#[cfg(tp5)]
#[cfg(feature = "cost-governance")]
mod http_cost_persistence;
#[cfg(tp5)]
mod not_found_stdio;

// MIK-7272.OWNER.3 and OWNER.5 (the sub4 stdio owner test plan, I1).
#[cfg(tp5)]
mod owner3_stdio_keying;
#[cfg(tp5)]
mod owner5_stdio_context;

// MIK-7272.OWNER.1 and OWNER.4 (the sub4 stdio owner test plan, I2).
#[cfg(tp5)]
mod owner1_stdio_management;
#[cfg(tp5)]
mod owner1_stdio_reload;
#[cfg(tp5)]
mod owner4_stdio_policy;
#[cfg(tp5)]
#[cfg(feature = "cost-governance")]
mod stdio_live_budget;

// MIK-7272.LIFE.1 (the sub4 stdio owner test plan, I3).
#[cfg(tp5)]
mod life1_stdio_cancel;
// MIK-8176 stage 3: stdio slots kept when written, given back otherwise.
#[cfg(tp5)]
mod stdio_slot_release;
// MIK-7642.PR.B: a client cancel reaches the backend by its own request id.
#[cfg(tp5)]
mod mik7642_backend_cancel;
mod owner2_stdio_tasks;
#[cfg(feature = "firewall")]
pub(super) mod route_matrix_stdio_tasks;
/// MIK-8353 slice 3c: the stdio twin of the R4a nonce give-back row.
#[cfg(tp5)]
mod s3c_stdio_refund;
/// MIK-8353 slice 3d-2 (K6): a stdio task-intent refusal and its nonce.
#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod s3d2_stdio_task_intent;
#[cfg(tp5)]
mod stdio_task_policy_recheck;
#[cfg(tp5)]
mod submit_authz_stdio;
// MIK-7839.CANCEL.3: a dropped run_stdio future stops its task workers.
#[cfg(tp5)]
mod stdio_session_drop;
// MIK-7757: a drain timeout cancels the running workers on both shutdown paths.
#[cfg(tp5)]
mod stdio1_discover_versions;
#[cfg(tp5)]
mod stdio_reused_id;
#[cfg(tp5)]
mod task_drain_timeout;
#[cfg(tp5)]
mod task_shutdown_tail;

// #2480: a stdio idempotent replay writes its invocation record.
#[cfg(tp5)]
mod stdio_replay_audit;

// API2.10 R0: one transport_finalized record per stdio frame.
#[cfg(tp5)]
mod stdio_one_record_tests;

// MIK-7324.COV.3: the stdio chain-nonce refusal in `prepare_signing`.
#[cfg(tp5)]
mod stdio_chain_nonce_refusal;

// MIK-8378: envelope rows over stdio (ENV.2, ENV.4).
#[cfg(tp5)]
mod mik8378_stdio;

// MIK-7324.COV.3: the firewall `response_firewall` builds carries anomaly blocking.
#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod response_firewall_anomaly;

#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod hardened_destination;

// MIK-7685 (#2530): stdio EOF teardown is bounded.
#[cfg(tp5)]
#[cfg(unix)]
mod stdio_orphan_watch;
#[cfg(tp5)]
mod stdio_teardown_bound;

// MIK-7684: the stdio reader never waits for stdout room.
#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod oracle_parity_stdio;
#[cfg(tp5)]
mod stdio_reader_unparked;
/// MIK-8340: a withheld surfaced name answers on stdio as an absent one.
#[cfg(tp5)]
#[cfg(feature = "firewall")]
mod withheld_parity_stdio;

// MIK-8356 C3, C10: a stdio call judged by the sole operator's own slot.
#[cfg(tp5)]
mod slot_verdict_g2_stdio;
