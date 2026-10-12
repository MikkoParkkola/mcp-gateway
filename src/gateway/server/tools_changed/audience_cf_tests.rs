// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 D16 (lead ruling for MIK-8377): a stream admitted under a
//! Cloudflare Access assertion re-verifies it at every decision
//! (`ViewSubject::verify_held_cf`, in `resolve_caller` before `live()`). A
//! rotated signing key or a passed `exp` closes the open stream, counted
//! once as `reason="cf"`. GUARD rows for MIK-8350's code, which ship in its
//! PR.

use serde_json::json;

use super::audience_fixture::{World, tool};
use crate::key_server::oidc_test_harness::{AUD, Harness, ISS_A, config_yaml};
use crate::security::caller_identity::{
    CallerIdentityConfig, CallerIdentityMode, CloudflareAccessConfig,
};

/// The verifier's clock-skew tolerance (`oidc.rs`, `leeway = 60`).
const LEEWAY: u64 = 60;
const HEADER: &str = "cf-access-jwt-assertion";

fn alpha(read: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", "w"),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

/// A gateway in `cloudflare_access` mode whose Access verifier reads the
/// harness's JWKS, and the harness that mints and rotates its keys.
async fn cf_world() -> (World, Harness) {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let verifier = crate::key_server::OidcVerifier::with_http_client(
        harness.ks.config.oidc.clone(),
        reqwest::Client::new(),
    );
    let identity = CallerIdentityConfig {
        mode: CallerIdentityMode::CloudflareAccess,
        cloudflare_access: CloudflareAccessConfig {
            team_domain: "audience.cloudflareaccess.com".to_string(),
            audiences: vec![AUD.to_string()],
        },
        ..CallerIdentityConfig::default()
    };
    let world = World::start_with(move |meta| {
        meta.with_caller_identity(identity)
            .with_access_verifier_for_test(verifier)
    })
    .await;
    (world, harness)
}

/// The listen stream k-std opens under `assertion`.
async fn asserted_listen(w: &World, assertion: &str) -> super::audience_ear::Ear {
    let value: axum::http::HeaderValue = assertion.parse().expect("a header value");
    w.listen_with("k-std", move |request| {
        request.headers_mut().insert(HEADER, value);
    })
    .await
}

/// CF.2-rotation: after the signing key rotates, the held assertion no
/// longer verifies, so the open stream is closed at its next decision.
#[tokio::test]
async fn cf_2_rotation_an_open_stream_dies_when_its_signing_key_rotates() {
    let (w, harness) = cf_world().await;
    let assertion = harness.mint(ISS_A, "alice", &json!({}));
    let mut ear = asserted_listen(&w, &assertion).await;
    w.store_shared("alpha", alpha("r2"));
    assert_eq!(
        ear.told(&w).await,
        1,
        "premise: a verified assertion is told"
    );

    harness.key.rotate().expect("rotate the signing key");
    w.state
        .meta_mcp
        .access_verifier()
        .expect("cloudflare mode has a verifier")
        .expire_jwks_for_test();
    w.store_shared("alpha", alpha("r3"));
    assert!(
        ear.closed(&w).await,
        "a rotated signing key closes the stream"
    );
}

/// CF.2-exp: once the assertion's `exp` (plus the verifier's leeway) has
/// passed, the open stream is closed, never judged as the API-key subject.
#[tokio::test]
async fn cf_2_exp_an_open_stream_dies_when_its_assertion_expires() {
    let (w, harness) = cf_world().await;
    let exp = crate::clock::unix_secs().expect("clock after 1970") + 60;
    let assertion = harness.mint(ISS_A, "alice", &json!({ "exp": exp }));
    let mut ear = asserted_listen(&w, &assertion).await;

    let _past = crate::clock::test_clock::at_secs(exp + LEEWAY + 1);
    w.store_shared("alpha", alpha("r2"));
    assert!(
        ear.closed(&w).await,
        "an expired assertion closes the stream"
    );
}

/// CF.2 counter: the rotation death is counted once as `reason="cf"`.
#[cfg(feature = "metrics")]
#[test]
fn cf_2_metric_a_rotation_death_is_counted_once_as_cf() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    telemetry_metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(async {
                let (w, harness) = cf_world().await;
                let assertion = harness.mint(ISS_A, "alice", &json!({}));
                let mut ear = asserted_listen(&w, &assertion).await;
                harness.key.rotate().expect("rotate the signing key");
                w.state
                    .meta_mcp
                    .access_verifier()
                    .expect("cloudflare mode has a verifier")
                    .expire_jwks_for_test();
                w.store_shared("alpha", alpha("r2"));
                assert!(
                    ear.closed(&w).await,
                    "premise of the count: the stream died"
                );
            });
    });
    let text = handle.render();
    let counted: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("mcp_view_liveness_dead_total{"))
        .collect();
    assert_eq!(counted.len(), 1, "one death, one series: {text}");
    assert!(counted[0].contains(r#"reason="cf""#), "{text}");
    assert!(
        matches!(counted[0].rsplit(' ').next(), Some("1" | "1.0")),
        "counted once: {text}"
    );
}
