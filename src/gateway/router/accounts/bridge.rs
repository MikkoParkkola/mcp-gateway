// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `OwuiSessionBridge` (design §4.2 steps 2-5, §4.3): who the browser's Open
//! `WebUI` session belongs to, asked of Open `WebUI` itself.
//!
//! The session cookie's value is used for exactly one outbound request and
//! then dropped: it is never logged, persisted, returned or forwarded. Every
//! refusal is the same `None`, so no caller can tell which step failed.

use std::time::Duration;

use axum::http::{HeaderMap, header};
use serde::Deserialize;

use crate::gateway::openwebui_adapter::session_principal;

/// The session route answers in far less; anything slower is refused.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Read at most this much; one byte more refuses, never truncates.
const BODY_MAX: usize = 64 * 1024;

/// Only the id. Without `deny_unknown_fields`, serde drops the echoed
/// `token`, `email`, `name`, `role` and `permissions` unread.
#[derive(Deserialize)]
struct SessionUser {
    id: String,
    expires_at: Option<i64>,
}

/// The bridge adapter's `session` block and installation, from live config.
pub(super) struct Session {
    pub(super) installation_id: String,
    pub(super) user_endpoint: String,
    pub(super) cookie_name: String,
}

pub(super) struct OwuiSessionBridge {
    client: reqwest::Client,
}

impl OwuiSessionBridge {
    /// No redirect is followed (reqwest follows by default), no proxy sees
    /// the bearer, and the whole exchange is bounded in time.
    pub(super) fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(TIMEOUT)
            .build()?;
        Ok(Self { client })
    }

    /// The `(authority, subject)` the browser's session proves, namespaced
    /// as the tool-call adapter namespaces `installation_id`'s users.
    pub(super) async fn principal(
        &self,
        session: &Session,
        headers: &HeaderMap,
    ) -> Option<(String, String)> {
        let token = sole_cookie(headers, &session.cookie_name)?;
        let id = self.session_user(&session.user_endpoint, token).await?;
        Some(session_principal(&session.installation_id, &id))
    }

    async fn session_user(&self, endpoint: &str, token: &str) -> Option<String> {
        let mut response = self
            .client
            .get(endpoint)
            .bearer_auth(token)
            .send()
            .await
            .ok()?;
        if response.status() != reqwest::StatusCode::OK {
            return None;
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if body.len().saturating_add(chunk.len()) > BODY_MAX {
                return None;
            }
            body.extend_from_slice(&chunk);
        }
        let user: SessionUser = serde_json::from_slice(&body).ok()?;
        let unexpired = user.expires_at.is_none_or(|at| at >= unix_now());
        unexpired.then_some(user.id)
    }
}

/// Exactly one non-empty cookie named `name`, across every `Cookie` line
/// (HTTP/2 may split them). Missing, empty or duplicated is `None`.
fn sole_cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    let mut found = None;
    for line in headers.get_all(header::COOKIE) {
        for pair in line.to_str().ok()?.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key == name && found.replace(value).is_some() {
                return None;
            }
        }
    }
    found.filter(|value| !value.is_empty())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}
