// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 PR-B boundary pins (design §4.2, test plan v2 §2-§3): what the
//! registry-ban lint cannot see, read from the crate's own source with `syn`.

mod allow_pins;
mod ci_wiring;
mod creation_sites;
mod delivery_framing;
mod discarded_sends;
mod echo_rows_real_transports;
mod guard_tests;
mod inbound_parse_sites;
mod invoke_stages;
mod invoke_stages_allow;
mod invoke_stages_dest;
mod invoke_stages_r6;
mod invoke_stages_rules;
mod invoke_stages_tests;
mod keyed_request;
mod needle_attach_sites;
mod packaged;
mod presend_exits;
mod scan;
mod scan_tests;
mod shipped_reads;
mod single_predicate;
mod single_reader;
