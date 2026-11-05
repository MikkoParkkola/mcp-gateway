// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A watch row never carries an observed identity, and the watch route
//! refuses a key to one that does, so no identity-bearing row is keyed
//! without its observation being checked.

use std::sync::Arc;

use serde_json::json;

use super::*;

/// A `watch.*.changed` row with a recorded class, and, when `observed`, a
/// per-user observation basis and a stored identity naming nobody.
fn watch_row(observed: bool) -> Subscription {
    let mut row = json!({
        "v": 1, "id": "w", "principal": "p", "api_key": null, "url": "https://cb",
        "name": "watch.weather.changed", "arguments": {}, "secret": "s",
        "previous_secret": null, "previous_until": null,
        "granted_at": "2026-10-25T00:00:00Z", "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null,
        "watch_class": serde_json::to_value(WatchClass::Free).expect("class"),
    });
    if observed {
        let config: crate::config::Config = crate::yaml::from_str(
            "backends:\n  signed:\n    http_url: https://h/mcp\n    identity_propagation:\n      \
             strategy: signed_assertion\n      audience: https://mail\n      session_mode: per_user\n",
        )
        .expect("config");
        let witness = crate::key_server::oidc::VerifiedIdentity::checked(
            "https://idp".into(),
            "witness".into(),
            "w@h".into(),
            None,
            Vec::new(),
        )
        .expect("names someone");
        let basis =
            crate::events::observation::observe_subscriber(&config, "signed", Some(&witness))
                .expect("observes")
                .expect("per-user");
        row["obs_basis"] = serde_json::to_value(basis).expect("basis");
        row["observed_identity"] =
            json!({"subject": "", "email": "q@h", "groups": [], "issuer": "https://idp"});
    }
    serde_json::from_value(row).expect("a watch row")
}

#[test]
fn the_watch_route_keys_no_row_that_carries_an_observation() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    hub.install_watch_source(fake(Vec::new()) as Arc<dyn WatchHost>);
    let source = hub.source(SourceKind::RestWatch).expect("watch source");
    assert!(
        source.row_key(&watch_row(false)).is_some(),
        "control: a plain watch row with a recorded class is keyed"
    );
    assert_eq!(
        source.row_key(&watch_row(true)),
        None,
        "a watch row carrying an observation is never keyed by this route"
    );
}
