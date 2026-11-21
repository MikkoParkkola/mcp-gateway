// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A mint's issuance row records how long its token can live, and the stored
//! token knows its own row.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::Value;

use super::KeyServer;
use super::issuance_row_tests::{bearer_of, mint, open_log};
use crate::config::KeyServerConfig;
use crate::key_server::email_hash::EmailHashKey;
use crate::key_server::oidc::VerifiedIdentity;
use crate::key_server::store::{
    ActivateError, InMemoryTokenStore, ReservationRequest, TemporaryToken, TokenScopes, TokenStore,
};
use crate::security::audit::AuditFailurePolicy;

const T: u64 = 1_800_000_000;

fn issuance_row(dir: &tempfile::TempDir, jti: &str) -> Value {
    std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .expect("the audit log reads")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("an audit line is JSON"))
        .find(|row| {
            row.is_object()
                && row["event"].as_str() == Some("token.issued")
                && row["token_jti"].as_str() == Some(jti)
        })
        .expect("the minted token has an issuance row")
}

async fn minted_token_and_row(ttl: u64) -> (TemporaryToken, Value) {
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = open_log(&dir, AuditFailurePolicy::FailClosed);
    let mut ks = KeyServer::new(
        KeyServerConfig {
            token_ttl_secs: ttl,
            ..KeyServerConfig::default()
        },
        EmailHashKey::for_test(),
    )
    .with_issuance_log(log);
    ks.store = Arc::new(InMemoryTokenStore::new(5, ttl));
    let response = mint(&ks).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bearer = bearer_of(response).await;
    let token = ks.store.get(&bearer).await.expect("the bearer is valid");
    let row = issuance_row(&dir, &token.jti);
    (token, row)
}

/// The issuance row records the configured lifetime and its latest expiry bound.
#[tokio::test]
async fn issued_row_records_the_ttl_and_the_expiry_bound() {
    let _clock = crate::clock::test_clock::at_secs(T);
    let (_, row) = minted_token_and_row(600).await;
    assert_eq!(row["ttl_secs"], 600);
    assert_eq!(row["expires_by"], 1_800_000_630);
}

/// Increasing the configured lifetime increases the row's bound equally.
#[tokio::test]
async fn a_different_ttl_moves_the_bound_by_the_same_amount() {
    let _clock = crate::clock::test_clock::at_secs(T);
    let (_, row) = minted_token_and_row(900).await;
    assert_eq!(row["ttl_secs"], 900);
    assert_eq!(row["expires_by"], 1_800_000_930);
}

/// Immediate activation expires thirty seconds before the issuance row's bound.
#[tokio::test]
async fn the_token_expires_strictly_before_its_bound() {
    let _clock = crate::clock::test_clock::at_secs(T);
    let (token, row) = minted_token_and_row(600).await;
    assert_eq!(token.exp, 1_800_000_600);
    let expires_by = row["expires_by"].as_u64().expect("an expiry bound");
    assert!(expires_by > token.exp);
    assert_eq!(expires_by - token.exp, 30);
}

/// The stored token identifies the exact issuance row written for its own jti.
#[tokio::test]
async fn the_stored_token_names_its_own_issuance_row() {
    let _clock = crate::clock::test_clock::at_secs(T);
    let (token, row) = minted_token_and_row(600).await;
    let reference = token.issuance_row.as_ref().expect("a stored issuance row");
    assert_eq!(
        reference.counter,
        row["counter"].as_u64().expect("a counter")
    );
    assert_eq!(
        reference.entry_hash.as_str(),
        row["entry_hash"].as_str().expect("an entry hash")
    );
}

fn token(jti: &str, now: u64) -> TemporaryToken {
    TemporaryToken {
        issuance_row: None,
        jti: jti.to_owned(),
        token: format!("mcpgw_{jti}"),
        identity: VerifiedIdentity::for_test(
            jti,
            "u@corp.invalid",
            None,
            Vec::new(),
            "https://issuer.invalid",
        ),
        scopes: TokenScopes::default(),
        iat: now,
        exp: now + 600,
        client_ip: None,
    }
}

/// Clock steps can activate only before the deadline, keeping expiry below the bound.
#[test]
fn activation_after_any_clock_step_stays_inside_the_bound() {
    let store = InMemoryTokenStore::new(5, 600);
    for now in [T - 100, T - 1, T, T + 15, T + 29, T + 30, T + 31] {
        let jti = format!("clock-step-{now}");
        // Each case has its own subject so the cap cannot mask the clock rule.
        let reserved = store
            .reserve(
                ReservationRequest {
                    issuer: "https://issuer.invalid".to_owned(),
                    subject: jti.clone(),
                    jti: jti.clone(),
                },
                T,
            )
            .expect("a fresh reservation");
        assert_eq!(reserved.deadline, 1_800_000_030);
        let token = token(&jti, now);
        let exp = token.exp;
        let result = store.activate(&reserved.id, token, now);
        if now < 1_800_000_030 {
            assert_eq!(result, Ok(()), "activation at {now}");
            assert!(exp < reserved.deadline + 600, "expiry at {now}");
        } else {
            assert_eq!(result, Err(ActivateError::Expired), "activation at {now}");
        }
    }
}
