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
