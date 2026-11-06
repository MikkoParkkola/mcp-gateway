// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The cross-tenant read verdict is made in one place: every producer reaches
//! the process's read history through the outbound judge, which decides
//! whether to judge at all (`judge::judging`). A second path to the history
//! could judge, or skip judging, on a switch of its own.
//!
//! Syntax scan of the production nodes (test-only code is skipped by cfg
//! evaluation, never by filename): a method call `.reads()` (the firewall's
//! accessor to the history) outside the judge is a finding, and so is a
//! `.reserve(..)` call in a production file that names the history
//! (`ReadHistory` or `tenant_reads::`) outside the judge and the history's
//! own module. The positive control requires the judge's own `.reads()`
//! call, so the scan cannot pass by seeing nothing.

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];
const JUDGE: &str = "src/gateway/outbound/judge.rs";
const HISTORY: &str = "src/security/tenant_reads.rs";

#[derive(Default)]
struct Access {
    /// Files with a production `.reads()` call, one entry per call.
    readers: Vec<String>,
    /// Files with a production `.reserve(..)` call, one entry per call.
    reservers: Vec<String>,
}

impl Sink for Access {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        let syn::Expr::MethodCall(call) = expr else {
            return;
        };
        if call.method == "reads" && call.args.is_empty() {
            self.readers.push(at.file.clone());
        } else if call.method == "reserve" {
            self.reservers.push(at.file.clone());
        }
    }
}

/// Whether the production part of `file` names the read history.
fn names_the_history(file: &str) -> bool {
    let text = std::fs::read_to_string(crate_root().join(file)).expect("read source");
    let code = crate::test_source_text::production_text(&text);
    code.contains("ReadHistory") || code.contains("tenant_reads::")
}

#[test]
fn the_read_history_is_reached_from_the_judge_alone() {
    let mut access = Access::default();
    walk(crate_root(), &ROOTS, &mut access).expect("the crate walks");
    assert_eq!(
        access.readers,
        [JUDGE],
        "only the judge calls `.reads()` on a firewall (and the walk saw its call)"
    );
    let mut reservers: Vec<&String> = access
        .reservers
        .iter()
        .filter(|file| *file != JUDGE && *file != HISTORY && names_the_history(file))
        .collect();
    reservers.dedup();
    assert!(
        reservers.is_empty(),
        "reserves on the read history outside the judge: {reservers:?}"
    );
}
