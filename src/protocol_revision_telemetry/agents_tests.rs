// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design row 7: missing-revision caller keys stay bounded and never hold a
//! raw User-Agent.

use super::*;

#[test]
fn a_named_client_wins_over_its_user_agent() {
    assert_eq!(
        missing_revision_agent("claude", Some("curl/8.4.0")),
        "claude"
    );
}

#[test]
fn an_unknown_client_falls_through_to_the_agent_family() {
    // `other` and `unattributed` name no caller, so the agent family decides.
    assert_eq!(missing_revision_agent("other", Some("curl/8.4.0")), "curl");
    assert_eq!(
        missing_revision_agent("unattributed", Some("python-requests/2.31")),
        "python-requests"
    );
    assert_eq!(missing_revision_agent("other", None), "absent");
    assert_eq!(missing_revision_agent("other", Some("   ")), "absent");
}

#[test]
fn each_family_is_recognised_from_a_real_agent_string() {
    for (agent, family) in [
        ("Python-urllib/3.12", "python-urllib"),
        ("python-requests/2.31.0", "python-requests"),
        ("python-httpx/0.27.0", "python-httpx"),
        ("curl/8.4.0", "curl"),
        ("xh/0.22.0", "xh"),
        ("HTTPie/3.2.2", "httpie"),
        ("node", "node"),
        ("undici", "node"),
        ("Go-http-client/1.1", "go"),
        ("reqwest/0.12", "reqwest"),
        ("Mozilla/5.0", "other"),
    ] {
        assert_eq!(
            missing_revision_agent("other", Some(agent)),
            family,
            "{agent}"
        );
    }
}

#[test]
fn a_thousand_distinct_agents_give_bounded_keys_only() {
    let keys: std::collections::BTreeSet<&str> = (0..1_000)
        .map(|n| format!("client-{n}/1.0 (secret-host-{n})"))
        .map(|agent| missing_revision_agent("other", Some(&agent)))
        .collect();
    assert!(keys.len() <= USER_AGENT_FAMILIES.len());
    assert!(
        keys.iter().all(|key| USER_AGENT_FAMILIES.contains(key)),
        "{keys:?}"
    );
    assert!(NAMED_CLIENTS.len() + USER_AGENT_FAMILIES.len() <= 16);
}
