// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A watch row never carries an observed identity, and the watch route
//! refuses a key to one that does, so no identity-bearing row is keyed
//! without its observation being checked.

use std::sync::Arc;

use serde_json::json;

use super::*;

/// What a test watch row carries besides its recorded class.
#[derive(Clone, Copy)]
enum Carries<'a> {
    /// Nothing more: a plain watch row.
    Plain,
    /// A per-user observation basis, and a stored identity naming this
    /// subject when there is one.
    Observation(Option<&'a str>),
}

/// A `watch.*.changed` row with a recorded class, carrying `carries`.
fn watch_row(carries: Carries<'_>) -> Subscription {
    let mut row = json!({
        "v": 1, "id": "w", "principal": "p", "api_key": null, "url": "https://cb",
        "name": "watch.weather.changed", "arguments": {}, "secret": "s",
        "previous_secret": null, "previous_until": null,
        "granted_at": "2026-10-25T00:00:00Z", "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null,
        "watch_class": serde_json::to_value(WatchClass::Free).expect("class"),
    });
    if let Carries::Observation(identity) = carries {
        row["obs_basis"] = crate::events::stored_identity_fixture::basis();
        if let Some(subject) = identity {
            row["observed_identity"] =
                crate::events::stored_identity_fixture::identity("https://idp", subject);
        }
    }
    serde_json::from_value(row).expect("a watch row")
}

/// Neither way the watch source keys a row, its own row key or the key it
/// gives once the capability is offered, keys a row carrying a per-user
/// observation; a plain watch row is keyed by both.
#[test]
fn the_watch_route_keys_no_row_that_carries_an_observation() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    hub.install_watch_source(host as Arc<dyn WatchHost>);
    let source = hub.source(SourceKind::RestWatch).expect("watch source");
    assert!(
        source.offers("watch.weather.changed"),
        "premise: the capability is offered, so a key can come from key_of_row"
    );
    let plain = watch_row(Carries::Plain);
    assert!(
        source.row_key(&plain).is_some() && source.key_of_row(&plain, now()).is_some(),
        "control: a plain watch row is keyed by both routes"
    );
    // The refusal follows the observation basis, whatever the identity:
    // naming nobody, naming someone, or absent.
    for (case, identity) in [
        ("nobody", Some("")),
        ("someone", Some("q")),
        ("absent", None),
    ] {
        let observed = watch_row(Carries::Observation(identity));
        assert_eq!(source.row_key(&observed), None, "{case}: row_key");
        assert_eq!(
            source.key_of_row(&observed, now()),
            None,
            "{case}: key_of_row"
        );
    }
}
