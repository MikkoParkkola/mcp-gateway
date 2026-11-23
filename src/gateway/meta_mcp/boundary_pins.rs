// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 PR-B boundary pins (design §4.2, test plan v2 §2-§3): what the
//! registry-ban lint cannot see, read from the crate's own source with `syn`.

#[cfg(tp2)]
mod allow_pins;
#[cfg(tp2)]
mod allowed_root_pins;
#[cfg(tp2)]
mod backend_json_rpc_builders;
#[cfg(tp2)]
mod backend_json_rpc_patterns;
#[cfg(tp2)]
mod caller_view;
#[cfg(tp2)]
mod ci_wiring;
#[cfg(tp2)]
mod creation_sites;
#[cfg(tp2)]
mod decision_builders;
#[cfg(tp2)]
mod delivery_framing;
#[cfg(tp2)]
mod discarded_sends;
#[cfg(tp2)]
mod discovery_output_sites;
#[cfg(tp2)]
mod echo_rows_real_transports;
#[cfg(tp2)]
mod email_sinks;
#[cfg(tp2)]
mod fold_sites;
#[cfg(tp2)]
mod fragments;
#[cfg(tp2)]
mod guard_tests;
#[cfg(tp2)]
mod heartbeat_scans;
#[cfg(tp2)]
mod identity_evidence;
#[cfg(tp2)]
mod identity_refusals;
#[cfg(tp2)]
mod identity_sources;
#[cfg(tp2)]
mod inbound_parse_sites;
#[cfg(tp2)]
mod invoke_stages;
#[cfg(tp2)]
mod invoke_stages_allow;
#[cfg(tp2)]
mod invoke_stages_dest;
#[cfg(tp2)]
mod invoke_stages_r6;
#[cfg(tp2)]
mod invoke_stages_rules;
#[cfg(tp2)]
mod invoke_stages_tests;
#[cfg(tp2)]
mod key_field_rows;
#[cfg(tp2)]
mod keyed_request;
#[cfg(tp2)]
mod live_config;
#[cfg(tp2)]
mod live_generation;
#[cfg(tp2)]
mod needle_attach_sites;
#[cfg(tp2)]
mod notification_egress;
#[cfg(tp2)]
mod packaged;
#[cfg(tp2)]
mod pinned_generation;
#[cfg(tp2)]
mod pinned_role_mapping;
#[cfg(tp2)]
mod plain_reads;
#[cfg(tp2)]
mod plain_refusals;
#[cfg(tp2)]
mod plain_refusals_fixtures;
#[cfg(tp2)]
mod plain_refusals_tests;
#[cfg(tp2)]
mod presend_exits;
#[cfg(tp2)]
mod raw_kill_pin_tests;
#[cfg(tp2)]
mod read_history_access;
#[cfg(tp2)]
mod response_funnels;
#[cfg(tp2)]
mod scan;
#[cfg(tp2)]
mod scan_tests;
#[cfg(tp2)]
mod secret_writers;
#[cfg(tp2)]
mod shipped_reads;
#[cfg(tp2)]
mod single_predicate;
#[cfg(tp2)]
mod single_reader;
#[cfg(tp2)]
mod spawn_sites;
#[cfg(tp2)]
mod to_rpc_code_sites;
#[cfg(tp2)]
mod transport_waits;
