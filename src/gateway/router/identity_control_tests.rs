// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7971: which key the per-caller controls score on, one branch per row.
//! The auth setting is not an input: a keyless caller is keyless whether
//! authentication is off or the path is public.

use super::{ANONYMOUS_SESSION_LESS_CALLER, control_identity};

#[test]
fn each_branch_picks_its_key() {
    let shared = ANONYMOUS_SESSION_LESS_CALLER;
    // (caller key, session id, presented header, degraded, expected)
    let rows = [
        ("credential:1:k", "gw-1", None, false, "credential:1:k"),
        (
            "credential:1:k",
            "gw-1",
            Some("gw-1"),
            false,
            "credential:1:k",
        ),
        ("", "", None, false, ""),
        ("", "", Some("gw-1"), false, ""),
        ("", "gw-1", Some("gw-1"), false, "gw-1"),
        ("", "gw-2", Some("gw-1"), false, shared),
        ("", "gw-2", None, false, shared),
        // MIK-8533: served without a session at the provisional cap. A keyed
        // caller keeps its key; a keyless one takes the shared key a keyless
        // minted request already takes, never the empty (refused) one.
        ("credential:1:k", "", None, true, "credential:1:k"),
        ("", "", None, true, shared),
        ("", "", Some("gw-9"), true, shared),
    ];
    for (key, session, presented, degraded, expected) in rows {
        let got = control_identity(key.to_string(), session, presented, degraded);
        assert_eq!(
            got, expected,
            "key {key:?} session {session:?} presented {presented:?} degraded {degraded}"
        );
    }
}

/// MIK-8533: degrading changes nothing for the anomaly detector. A keyless
/// legacy request served without a session scores under the same key as one
/// on a session minted just now.
#[test]
fn a_degraded_keyless_request_scores_like_a_minted_one() {
    assert_eq!(
        control_identity(String::new(), "", None, true),
        control_identity(String::new(), "gw-fresh", None, false),
    );
}
