// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A UI check judges a caller by the role mapping of the generation pinned on
//! its request (ADR-023), never by the live config: a reload that publishes
//! after the request arrived must not change the role it is judged by.
//!
//! Syntax scan, per function under `src/gateway/ui`: a function that reads a
//! `live_config` field and a `role_mapping` field fails. That is a coarse
//! rule, not a data-flow check, and it holds with no exceptions: a mapping
//! read routed through a helper in another function is missed, as an alias is
//! missed in the other pins.

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 1] = ["src/lib.rs"];

const UI: &str = "src/gateway/ui/";

/// The field names a function under [`UI`] reads, per (file, function).
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
        if !at.file.starts_with(UI) {
            return;
        }
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

/// No UI function reads the live config and a role mapping together.
#[test]
fn ui_role_checks_read_the_pinned_mapping() {
    let mut reads = Reads::default();
    walk(crate_root(), &ROOTS, &mut reads).expect("the walk reads every module");
    assert!(
        !reads.mapping.is_empty(),
        "premise: the scan sees the UI's role-mapping reads"
    );
    let both: Vec<String> = reads
        .live
        .intersection(&reads.mapping)
        .map(|(file, func)| format!("{file}:{func}"))
        .collect();
    assert!(
        both.is_empty(),
        "a UI function judges a role by the live config, not the request's pinned generation:\n{}",
        both.join("\n")
    );
}
