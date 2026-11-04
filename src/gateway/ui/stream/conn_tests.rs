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
    let all = Upkeeps::ALL;
    assert_eq!(
        servable(all, Phase::CatchUp),
        Upkeeps::default(),
        "every upkeep served this gap: none is servable, so the page is next"
    );
    assert_eq!(
        servable(Upkeeps::default(), Phase::CatchUp),
        all,
        "a fresh gap: every due upkeep runs before the page"
    );
    let keep_only = Upkeeps {
        keep: true,
        ..Upkeeps::default()
    };
    assert_eq!(
        servable(keep_only, Phase::CatchUp),
        Upkeeps { keep: false, ..all },
        "a keep-alive already sent this gap waits for the page"
    );
    assert_eq!(
        servable(all, Phase::Live),
        all,
        "following the live logs, nothing is capped"
    );
}
