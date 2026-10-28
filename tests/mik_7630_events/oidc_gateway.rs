// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway for the per-subscriber rows: backend `x` on the upstream-event
//! config, one key-server policy per user (`u1`, `u2`) verifying the OIDC
//! issuer's bearers, trusting the receiver's and the issuer's CAs.

use std::path::Path;

use serde_json::{Value, json};

use super::gateway::Gateway;
use super::issuer;
use super::receiver::{Receiver, TRUST_CA};
use super::upstream_sub::upstream_config;

/// The email the issuer mints for `user`, which its key-server policy matches.
pub fn email(user: &str) -> String {
    format!("{user}@example.test")
}

/// A gateway with backend `x` = `backend`, verifying `issuer`'s bearers, and
/// trusting both the receiver's CA and the issuer's.
pub async fn start(
    root: &Path,
    rx: &Receiver,
    issuer: &issuer::Issuer,
    backend: Value,
    extra_trust: &[&Path],
) -> Gateway {
    start_with(root, rx, issuer, backend, extra_trust, |_| {}).await
}

/// [`start`], with `tweak` applied to the config before the gateway starts.
pub async fn start_with(
    root: &Path,
    rx: &Receiver,
    issuer: &issuer::Issuer,
    backend: Value,
    extra_trust: &[&Path],
    tweak: impl FnOnce(&mut Value),
) -> Gateway {
    let mut cfg = upstream_config(root, backend, &[]);
    let policies: Vec<Value> = ["u1", "u2"]
        .iter()
        .map(|user| {
            json!({
                "match": {"issuer": issuer.url, "email": email(user)},
                "scopes": {"backends": ["x"], "tools": ["*"]},
            })
        })
        .collect();
    cfg["key_server"] = json!({
        "enabled": true,
        "delegated_bearer": true,
        "max_oidc_token_age_secs": 3600,
        "oidc": [{"issuer": issuer.url, "auto_discover": true,
                  "audiences": [issuer::AUDIENCE]}],
        "policies": policies,
    });
    let both = root.join("trust-both.pem");
    let mut pem = std::fs::read_to_string(&rx.ca_file).expect("receiver CA");
    pem.push_str(&std::fs::read_to_string(&issuer.ca_file).expect("issuer CA"));
    for ca in extra_trust {
        pem.push_str(&std::fs::read_to_string(ca).expect("extra CA"));
    }
    std::fs::write(&both, pem).expect("combined trust file");
    tweak(&mut cfg);
    let trust = both.to_string_lossy();
    Gateway::start_with_env(root, cfg, &[("SSL_CERT_FILE", &trust), (TRUST_CA, &trust)]).await
}
