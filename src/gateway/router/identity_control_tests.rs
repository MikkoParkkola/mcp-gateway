// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7971: which key the per-caller controls score on, one branch per row.

use super::{AUTH_DISABLED_SESSION_LESS_CALLER, control_identity};
use crate::config::AuthConfig;
use crate::gateway::auth::ResolvedAuthConfig;

fn auth(enabled: bool) -> ResolvedAuthConfig {
    let mut auth = ResolvedAuthConfig::from_config(&AuthConfig::default());
    auth.enabled = enabled;
    auth
}

#[test]
fn each_branch_picks_its_key() {
    let shared = AUTH_DISABLED_SESSION_LESS_CALLER;
    // (caller key, session id, presented header, auth on, expected)
    let rows = [
        ("credential:1:k", "gw-1", None, false, "credential:1:k"),
        (
            "credential:1:k",
            "gw-1",
            Some("gw-1"),
            true,
            "credential:1:k",
        ),
        ("", "", None, false, ""),
        ("", "", Some("gw-1"), true, ""),
        ("", "gw-1", Some("gw-1"), false, "gw-1"),
        ("", "gw-2", Some("gw-1"), true, "gw-2"),
        ("", "gw-2", None, true, "gw-2"),
        ("", "gw-2", Some("gw-1"), false, shared),
        ("", "gw-2", None, false, shared),
    ];
    for (key, session, presented, enabled, expected) in rows {
        let got = control_identity(key.to_string(), session, presented, &auth(enabled));
        assert_eq!(
            got, expected,
            "key {key:?} session {session:?} presented {presented:?} auth {enabled}"
        );
    }
}
