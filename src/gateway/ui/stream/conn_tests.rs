// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The connection's own rules, apart from a router.

use super::*;

#[test]
fn a_log_kind_not_advertised_gets_no_merge() {
    let both = [Some("invocation"), Some("governance")];
    assert_eq!(
        advertised(&["status", "reload", "activity"], both),
        [Some("invocation"), None],
        "a scoped admin is offered no config, so no config merge is built"
    );
    assert_eq!(
        advertised(&["status", "reload", "activity", "config"], both),
        both,
        "a full admin gets both"
    );
    assert_eq!(
        advertised(&["status"], both),
        [None, None],
        "a status-only caller gets neither"
    );
}

#[test]
fn during_a_catch_up_each_upkeep_runs_once_between_pages() {
    let u = |recheck, keep, snapshot| Upkeeps {
        recheck,
        keep,
        snapshot,
    };
    // Every combination of what was served this gap: (served, servable
    // during a catch-up). Written out, so a swapped flag cannot pass.
    let table = [
        (u(false, false, false), u(true, true, true)),
        (u(true, false, false), u(false, true, true)),
        (u(false, true, false), u(true, false, true)),
        (u(false, false, true), u(true, true, false)),
        (u(true, true, false), u(false, false, true)),
        (u(true, false, true), u(false, true, false)),
        (u(false, true, true), u(true, false, false)),
        (u(true, true, true), u(false, false, false)),
    ];
    for (served, during_catch_up) in table {
        assert_eq!(
            servable(served, Phase::CatchUp),
            during_catch_up,
            "a catch-up after serving {served:?}"
        );
        // Following the live logs, only a snapshot is capped: after one, a
        // ready live row goes first. Checks and keep-alives never wait.
        assert_eq!(
            servable(served, Phase::Live),
            u(true, true, !served.snapshot),
            "the live logs cap only a repeated snapshot: {served:?}"
        );
    }
}
