// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The events fence through the real wiring: the events side's
//! `fence_binding` and `mint` reach the vault strategy over live custody and
//! a real store. A mint names the binding the fence reads; a plain token
//! refresh leaves it; a rotation moves it.

use super::*;

const SUBJECT: &str = "fence-wiring-subject";

#[tokio::test]
async fn the_events_fence_reads_the_real_vault_grant() {
    let mut gateway = DirectAccountGateway::new(
        crate::config::AuthConfig::default(),
        &Binding::ConnectedFor(SUBJECT),
    );
    let audit = tempfile::tempdir().expect("a log directory");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: audit
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                ..crate::security::transparency_log::TransparencyLogConfig::default()
            },
        ))
        .expect("open log"),
    );
    let mut meta = gateway.take_meta();
    meta.enable_transparency_log(log);
    let meta = Arc::new(meta);
    let mint = crate::gateway::listener_mint_for_test(&meta);
    let identity = DirectAccountGateway::verified(SUBJECT);
    let fence = || async {
        mint.fence_binding(BACKEND, &identity)
            .await
            .expect("a view of the grant")
            .expect("a vault grant backs the backend")
    };

    let seeded = fence().await;
    let minted = mint
        .mint(BACKEND, &identity)
        .await
        .expect("the listener mints");
    assert_eq!(
        minted.fence.as_deref(),
        Some(seeded.as_str()),
        "a mint names the binding the fence reads"
    );

    // A plain refresh: a new token under the same grant.
    let key = account_key(SUBJECT, WORK);
    let (expected, refreshed) = reconnect_from(
        &grant(operator_token(WORK), u64::MAX),
        "synthetic-refreshed-fence-wiring",
    );
    gateway
        .custody
        .handle
        .commit_grant_if(&key, &expected, &refreshed)
        .await
        .expect("the refresh publishes through live custody");
    assert_eq!(fence().await, seeded, "a token refresh keeps the fence");

    // A rotation: revoked, then reconnected under a new generation.
    revoke_and_reconnect(&gateway.custody, &key, &refreshed, ROTATED_TOKEN).await;
    assert_ne!(fence().await, seeded, "a rotation moves the fence");
}
