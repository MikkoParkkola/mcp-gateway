// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The read token's must-fail probe. Built only by
//! `scripts/ci/check-reads-token.py` (`--cfg reads_token_probe`), never in a
//! product build. A sibling of the judge, so `super::judge` resolves while the
//! token's field stays private to it. Each probe holds one forgery with every
//! argument well-typed but the token; the judge's own tests compile the same
//! expressions, so each can fail here only on the token's privacy. The check
//! expects exactly one pinned error per probe and none anywhere else.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use super::ReadsToken;
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::tenant_reads::{ReadAttribution, ReadHistory};

const WINDOW: Duration = Duration::from_secs(60);

/// A call through a stored path, assembled at expansion (the out-of-model
/// shape a source scan cannot see).
macro_rules! later {
    ($m:path, $($a:expr),*) => {{
        let f = $m;
        f($($a),*)
    }};
}

/// A call assembled from token fragments at expansion.
macro_rules! frag {
    ($f:expr, $dot:tt, $name:ident, $args:tt) => {
        $f $dot $name $args
    };
}

fn firewall() -> Firewall {
    Firewall::from_config(FirewallConfig::default(), None)
}

fn attribution() -> ReadAttribution {
    ReadAttribution::of(BTreeSet::new(), false)
}

fn p1_reads() {
    let _ = firewall().reads(&ReadsToken(Cell::new(())));
}

fn p2_reserve(history: &Arc<ReadHistory>) {
    let _ = history.reserve(
        &ReadsToken(Cell::new(())),
        "k",
        &attribution(),
        WINDOW,
        false,
    );
}

fn p3a_later_reads() {
    let fw = firewall();
    let _ = later!(Firewall::reads, &fw, &ReadsToken(Cell::new(())));
}

fn p3b_later_reserve(history: &Arc<ReadHistory>) {
    let attr = attribution();
    let _ = later!(
        ReadHistory::reserve,
        history,
        &ReadsToken(Cell::new(())),
        "k",
        &attr,
        WINDOW,
        false
    );
}

fn p4a_frag_reads() {
    let fw = firewall();
    let _ = frag!(fw, ., reads, (&ReadsToken(Cell::new(()))));
}

fn p4b_frag_reserve(history: &Arc<ReadHistory>) {
    let attr = attribution();
    let _ = frag!(history, ., reserve, (&ReadsToken(Cell::new(())), "k", &attr, WINDOW, false));
}

fn p5_test_token() {
    let _ = super::judge::test_token();
}

fn p6a_reads_unit() {
    let _ = firewall().reads(&());
}

fn p6b_reserve_unit(history: &Arc<ReadHistory>) {
    let _ = history.reserve(&(), "k", &attribution(), WINDOW, false);
}

// probe: p7_copy
impl Copy for ReadsToken {}

// probe: p8_clone
impl Clone for ReadsToken {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
