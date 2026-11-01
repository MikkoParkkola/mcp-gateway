// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A request is judged by the role mapping of the generation pinned on it
//! when it arrived (ADR-023), never by the live config: a reload published
//! after the request arrived must not change the role it is judged by. This
//! pin is the family's table: every production function in the crate is a
//! row, so a new live read fails here instead of becoming a ticket.
//!
//! Syntax scan, per function: a function that reads a `live_config` field and
//! a `role_mapping` field fails, unless [`ALLOW`] lists it. That is a coarse
//! rule, not a data-flow check: a mapping read routed through a helper in
//! another function is missed, as an alias is missed in the other pins.
//!
//! One judge must read the live mapping for good: the delivery judge with no
//! request behind it (`auth_live::current_client`, which rechecks an open
//! stream). It judges each delivery by the generation current then, so a role
//! removed by a reload stops a stream already open. Today it reaches the
//! mapping through `key_server_credential`, which the request path shares, so
//! that function's one row covers both callers until the request path moves
//! to the pinned generation. The change that moves it deletes that row, and
//! adds a row for the delivery judge only where its own function reads both.

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// Production functions that may read the live role mapping: (file,
/// function, why). Each row must match a function that reads both, so a row
/// cannot outlive its site.
const ALLOW: &[(&str, &str, &str)] = &[(
    "src/gateway/auth_live.rs",
    "key_server_credential",
    "pending: the admin flag set at authentication reads the live mapping for \
     the request path and the delivery judge alike; the change that moves the \
     request path to the pinned generation deletes this row",
)];

/// The functions that read each field, per (file, function).
#[derive(Default)]
struct Reads {
    live: std::collections::BTreeSet<(String, String)>,
    mapping: std::collections::BTreeSet<(String, String)>,
}

impl Sink for Reads {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        let (Some(func), syn::Expr::Field(field)) = (&at.func, expr) else {
            return;
        };
        let syn::Member::Named(name) = &field.member else {
            return;
        };
        let key = (at.file.clone(), func.clone());
        if name == "live_config" {
            self.live.insert(key);
        } else if name == "role_mapping" {
            self.mapping.insert(key);
        }
    }
}

/// No production function judges a role by the live config, except as listed.
#[test]
fn role_checks_read_the_pinned_mapping() {
    let mut reads = Reads::default();
    walk(crate_root(), &ROOTS, &mut reads).expect("the walk reads every module");
    assert!(
        reads
            .mapping
            .iter()
            .any(|(file, _)| file.starts_with("src/gateway/ui/")),
        "premise: the scan sees the UI's role-mapping reads"
    );
    let both: Vec<(String, String)> = reads.live.intersection(&reads.mapping).cloned().collect();
    let allowed =
        |(file, func): &(String, String)| ALLOW.iter().any(|(f, n, _)| f == file && n == func);
    let unlisted: Vec<String> = both
        .iter()
        .filter(|site| !allowed(site))
        .map(|(file, func)| format!("{file}:{func}"))
        .collect();
    assert!(
        unlisted.is_empty(),
        "a function judges a role by the live config, not the request's pinned generation:\n{}",
        unlisted.join("\n")
    );
    let stale: Vec<String> = ALLOW
        .iter()
        .filter(|(f, n, _)| !both.iter().any(|(file, func)| file == f && func == n))
        .map(|(f, n, _)| format!("{f}:{n}"))
        .collect();
    assert!(
        stale.is_empty(),
        "an allowed live read no longer exists; delete its row:\n{}",
        stale.join("\n")
    );
}
