// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A per-user subscription row as the events store reads it back from disk,
//! with a stored observed identity written out by hand: the one builder the
//! stored-identity rows share, so the on-disk shape is pinned in one place.

use serde_json::{Value, json};

use super::records::Subscription;

/// A gateway with one per-user backend, `signed`.
pub(crate) const SIGNED: &str = "backends:\n  \
     signed:\n    http_url: https://h/mcp\n    identity_propagation:\n      \
     strategy: signed_assertion\n      audience: https://mail\n      session_mode: per_user\n";

pub(crate) fn config() -> crate::config::Config {
    crate::yaml::from_str(SIGNED).expect("config parses")
}

/// The observation basis a subscribe on `signed` records.
pub(crate) fn basis() -> Value {
    let witness = crate::key_server::oidc::VerifiedIdentity::checked(
        "https://idp".into(),
        "witness".into(),
        "w@h".into(),
        None,
        Vec::new(),
    )
    .expect("names someone");
    let basis = super::observation::observe_subscriber(&config(), "signed", Some(&witness))
        .expect("observes")
        .expect("per-user");
    serde_json::to_value(basis).expect("basis serializes")
}

/// A stored identity as a row holds it on disk, field names written by hand.
pub(crate) fn identity(issuer: &str, subject: &str) -> Value {
    json!({"subject": subject, "email": "q@h", "groups": [], "issuer": issuer})
}

/// A per-user row on `name` holding `identity` and the `signed` basis.
pub(crate) fn per_user_row(name: &str, identity: &Value) -> Subscription {
    serde_json::from_value(json!({
        "v": 1, "id": "i", "principal": "p", "api_key": null, "url": "https://cb",
        "name": name, "arguments": {}, "secret": "s",
        "previous_secret": null, "previous_until": null,
        "granted_at": "2026-10-25T00:00:00Z", "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null,
        "observed_identity": identity,
        "obs_basis": basis(),
    }))
    .expect("a stored row loads")
}
