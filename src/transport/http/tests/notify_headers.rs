// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2292: a notification carries the caller's resolved headers, and they
//! override a static header of the same name, as a request's do.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, StatusCode};

use crate::transport::Transport as _;

#[tokio::test]
async fn a_notification_carries_the_callers_headers_over_the_static_ones() {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let record = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |headers: HeaderMap| {
        let record = Arc::clone(&record);
        async move {
            let auth = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            record.lock().unwrap().push(auth);
            StatusCode::ACCEPTED
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });

    // Built at run time, as every credential-shaped value in this repo's tests.
    let static_auth = format!("Bearer {}", "gateway-static");
    let caller_auth = format!("Bearer {}", "caller-own");
    let mut configured = HashMap::new();
    configured.insert("Authorization".to_string(), static_auth.clone());
    let transport = super::make_transport_with_headers(&format!("http://{addr}/mcp"), configured);

    transport
        .notify_with_headers(
            "notifications/cancelled",
            None,
            &[("authorization".to_string(), caller_auth.clone())],
            None,
        )
        .await
        .unwrap();
    transport
        .notify_with_headers("notifications/cancelled", None, &[], None)
        .await
        .unwrap();

    assert_eq!(
        *seen.lock().unwrap(),
        vec![caller_auth, static_auth],
        "the caller's header overrides the static one; with none, the static one goes"
    );
}

/// A caller's credential that cannot be carried (its value does not parse as
/// a header) never lets the static credential go in its place: the message
/// goes with no credential of that name. The request path shares the rule.
#[tokio::test]
async fn an_unparsable_caller_credential_never_falls_back_to_the_static_one() {
    let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::default();
    let record = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |headers: HeaderMap| {
        let record = Arc::clone(&record);
        async move {
            let auth = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            record.lock().unwrap().push(auth);
            StatusCode::ACCEPTED
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });

    let mut configured = HashMap::new();
    configured.insert(
        "Authorization".to_string(),
        format!("Bearer {}", "gateway-static"),
    );
    let transport = super::make_transport_with_headers(&format!("http://{addr}/mcp"), configured);
    // A newline cannot appear in a header value.
    let unparsable = format!("Bearer {}\nx", "caller-own");
    transport
        .notify_with_headers(
            "notifications/cancelled",
            None,
            &[("authorization".to_string(), unparsable)],
            None,
        )
        .await
        .unwrap();

    // Sent, and with no credential of that name: neither the caller's value
    // nor the static one in its place.
    assert_eq!(*seen.lock().unwrap(), vec![None]);
}

// A name that is not a valid header name is skipped: it names no static
// header, so the static set is left as built and the walk carries on to the
// next pair rather than stopping at the bad one.
#[test]
fn an_unparseable_extra_header_name_is_skipped_and_the_rest_still_apply() {
    use reqwest::header::{HeaderMap, HeaderValue};

    let static_auth = format!("Bearer {}", "gateway-static");
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&static_auth).unwrap(),
    );
    let extra = vec![
        ("bad name\n".to_string(), "x".to_string()),
        ("X-After".to_string(), "kept".to_string()),
    ];

    super::super::extra_headers::merge_extra_headers(&mut headers, &extra);

    assert_eq!(headers.len(), 2);
    assert_eq!(headers["authorization"], static_auth.as_str());
    assert_eq!(headers["x-after"], "kept");
}
