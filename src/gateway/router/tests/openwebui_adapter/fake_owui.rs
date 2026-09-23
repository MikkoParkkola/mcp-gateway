// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fake Open `WebUI` session endpoint (design §11.1): a REAL listener on
//! `127.0.0.1:0`, so the bridge client's redirect, timeout and body-cap rules
//! meet a real socket. It records every `Authorization` value it receives.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

/// One Open `WebUI` user: the session token its browser holds.
#[derive(Clone)]
pub(super) struct User {
    pub(super) token: &'static str,
    pub(super) id: Value,
    pub(super) email: &'static str,
    pub(super) expires_at: Value,
}

/// How the endpoint answers.
#[derive(Clone)]
pub(super) enum Answer {
    /// The v0.9.6 `GET /api/v1/auths/` body for a known bearer, else 401.
    Session,
    /// This status and body, whoever asks.
    Fixed(u16, String),
    /// A 302 to this location.
    Redirect(String),
    /// [`Answer::Session`], after this delay.
    Slow(Duration),
}

#[derive(Clone)]
struct Script {
    users: Vec<User>,
    answer: Arc<Mutex<Answer>>,
    seen: Arc<Mutex<Vec<String>>>,
}

pub(super) struct FakeOwui {
    pub(super) url: String,
    script: Script,
}

/// The upstream v0.9.6 `get_session_user` body shape, synthetic values; the
/// extra fields are kept to prove the bridge drops them unread.
pub(super) fn session_body(user: &User) -> String {
    json!({"token": user.token, "token_type": "Bearer", "expires_at": user.expires_at,
           "id": user.id, "email": user.email, "name": "Synthetic User", "role": "user",
           "profile_image_url": "/user.png", "bio": null, "gender": null,
           "date_of_birth": null, "status_emoji": null, "status_message": null,
           "status_expires_at": null, "permissions": {"chat": {"file_upload": true}}})
    .to_string()
}

fn session(script: &Script, headers: &HeaderMap) -> Response {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match script.users.iter().find(|user| Some(user.token) == bearer) {
        Some(user) => (StatusCode::OK, session_body(user)).into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn answer(script: Script, headers: HeaderMap) -> Response {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .map(|value| value.to_str().unwrap_or("<non-ascii>").to_owned())
        .unwrap_or_default();
    script.seen.lock().unwrap().push(authorization);
    let current = script.answer.lock().unwrap().clone();
    match current {
        Answer::Session => session(&script, &headers),
        Answer::Fixed(status, body) => {
            (StatusCode::from_u16(status).unwrap(), body).into_response()
        }
        Answer::Redirect(location) => {
            (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
        }
        Answer::Slow(delay) => {
            tokio::time::sleep(delay).await;
            session(&script, &headers)
        }
    }
}

impl FakeOwui {
    /// Listen on `127.0.0.1:0`; every path answers per the current script.
    pub(super) async fn start(users: Vec<User>, first: Answer) -> Self {
        let script = Script {
            users,
            answer: Arc::new(Mutex::new(first)),
            seen: Arc::default(),
        };
        let served = script.clone();
        let app = Router::new().fallback(move |headers: HeaderMap| answer(served.clone(), headers));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            url: format!("http://127.0.0.1:{port}/api/v1/auths/"),
            script,
        }
    }

    pub(super) fn answer(&self, next: Answer) {
        *self.script.answer.lock().unwrap() = next;
    }

    /// Every `Authorization` value received, in order.
    pub(super) fn seen(&self) -> Vec<String> {
        self.script.seen.lock().unwrap().clone()
    }
}
