// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7806: an SSO admin (an OIDC bearer the live role mapping makes admin)
//! who replays dead letters, one and in bulk, is named on every `events.replay`
//! record by the verified issuer and subject, never by a display label.
//!
//! The issuer is the owned HTTPS OIDC issuer of the upstream-recovery proof, so
//! the gateway verifies the bearer through its production path. Unix; the child trusts the test CA through `SSL_CERT_FILE` (Linux) and the
//! debug-only `MCP_GATEWAY_TEST_TRUST_CA` (every platform; MIK-8188).
#![cfg(unix)]

#[path = "mik_7630_events/delivery.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod delivery;
#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;
#[path = "task_upstream_recovery_sdk/issuer.rs"]
#[allow(dead_code, reason = "shared fixture; this binary uses a subset")]
mod issuer;
#[path = "task_upstream_recovery_sdk/pins.rs"]
#[allow(dead_code, reason = "shared fixture; this binary uses a subset")]
mod pins;
#[path = "mik_7630_events/receiver.rs"]
#[allow(dead_code, reason = "shared receiver; each binary uses a subset")]
mod receiver;

use delivery::{
    DEADLINE, audit_records, dead_letters, delivery_config, fire, subscribe, wait_until,
};
use gateway::{ALICE, Gateway};
use receiver::{EventReply, Receiver, TRUST_CA, whsec};
use serde_json::{Value, json};

const ADMIN_EMAIL: &str = "sso-admin@example.test";
const ADMIN_SUBJECT: &str = "sso-admin-subject-7806";
const LIST: &str = "/ui/api/events/dead-letters";

#[tokio::test]
async fn an_sso_admins_replays_carry_the_verified_issuer_and_subject() {
    let root = tempfile::tempdir().expect("root");
    let issuer = issuer::Issuer::start(root.path()).await;
    let rx = Receiver::start(root.path()).await;
    // One trust file for the child: the receiver's CA and the issuer's.
    let both = root.path().join("trust-both.pem");
    let mut pem = std::fs::read_to_string(&rx.ca_file).expect("receiver CA");
    pem.push_str(&std::fs::read_to_string(&issuer.ca_file).expect("issuer CA"));
    std::fs::write(&both, pem).expect("combined trust file");

    let mut cfg = delivery_config(root.path(), &json!({}));
    cfg["key_server"] = json!({
        "enabled": true,
        "delegated_bearer": true,
        "max_oidc_token_age_secs": 3600,
        "oidc": [{"issuer": issuer.url, "auto_discover": true,
                  "audiences": [issuer::AUDIENCE]}],
        "policies": [{"match": {"issuer": issuer.url},
                      "scopes": {"backends": ["hooks"], "tools": ["*"]}}],
    });
    cfg["control_plane"] = json!({"role_mapping": {"rules": [
        {"issuer": issuer.url, "email": ADMIN_EMAIL, "role": "admin"}
    ]}});
    let gw = Gateway::start_with_env(
        root.path(),
        cfg,
        &[
            ("SSL_CERT_FILE", &both.to_string_lossy()),
            (TRUST_CA, &both.to_string_lossy()),
        ],
    )
    .await;
    gw.event_names(Some(ALICE), Some(gateway::EVENT)).await;
    let subscription = subscribe(&gw, ALICE, &rx.url, &whsec(32), json!({})).await;
    rx.script((0..3).map(|_| EventReply::Status(410)));
    for n in 0..3 {
        fire(&gw, &format!("d-7806-sso-{n}"), "o/r").await;
    }
    let all_dead = wait_until(DEADLINE, || {
        dead_letters(root.path())
            .iter()
            .filter(|d| d["reason"] == "gone")
            .count()
            >= 3
    })
    .await;
    assert!(all_dead, "three dead letters wait");
    let dead = dead_letters(root.path());
    let ids: Vec<String> = dead
        .iter()
        .filter_map(|d| d["event_id"].as_str().map(str::to_owned))
        .collect();

    let token = issuer.mint(ADMIN_SUBJECT, ADMIN_EMAIL);
    // The SSO admin is admitted: the live role mapping made the bearer admin.
    let (status, _) = gw.admin(Some(&token), "GET", LIST).await;
    assert_eq!(status, 200, "an SSO admin lists dead letters");
    let (status, _) = gw
        .admin(Some(&token), "POST", &format!("{LIST}/{}/replay", ids[0]))
        .await;
    assert_eq!(status, 200, "a single replay by the SSO admin");
    let (status, _) = gw
        .admin(
            Some(&token),
            "POST",
            &format!("{LIST}/replay?all=1&subscription={subscription}"),
        )
        .await;
    assert_eq!(status, 200, "a bulk replay by the SSO admin");

    let replayed = wait_until(DEADLINE, || {
        let seen: Vec<Value> = audit_records(root.path())
            .into_iter()
            .filter(|r| r["action"] == "events.replay")
            .collect();
        ids.iter()
            .all(|id| seen.iter().any(|r| r["event_id"] == id.as_str()))
    })
    .await;
    assert!(replayed, "one events.replay record per dead letter");
    for record in audit_records(root.path())
        .iter()
        .filter(|r| r["action"] == "events.replay")
    {
        assert_eq!(record["who"]["authority"], issuer.url.as_str(), "{record}");
        assert_eq!(record["who"]["subject"], ADMIN_SUBJECT, "{record}");
        assert!(
            !record.to_string().contains(ADMIN_EMAIL),
            "never the email label: {record}"
        );
    }
}
