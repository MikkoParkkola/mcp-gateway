// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7971: which key the per-caller controls score on, one branch per row.
//! The auth setting is not an input: a keyless caller is keyless whether
//! authentication is off or the path is public.

use super::{ANONYMOUS_SESSION_LESS_CALLER, control_identity};

#[test]
fn each_branch_picks_its_key() {
    let shared = ANONYMOUS_SESSION_LESS_CALLER;
    // (caller key, session id, presented header, expected)
    let rows = [
        ("credential:1:k", "gw-1", None, "credential:1:k"),
        ("credential:1:k", "gw-1", Some("gw-1"), "credential:1:k"),
        ("", "", None, ""),
        ("", "", Some("gw-1"), ""),
        ("", "gw-1", Some("gw-1"), "gw-1"),
        ("", "gw-2", Some("gw-1"), shared),
        ("", "gw-2", None, shared),
    ];
    for (key, session, presented, expected) in rows {
        let got = control_identity(key.to_string(), session, presented);
        assert_eq!(
            got, expected,
            "key {key:?} session {session:?} presented {presented:?}"
        );
    }
}
