// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7642.PR.B`: a legacy exchange dropped before its reply was read tells
//! the backend, by the id the backend received, to stop the work.
//!
//! A modern (2026-07-28) backend needs nothing: dropping the POST closes its
//! response stream, and that is its cancellation. A legacy backend keeps
//! running until it reads `notifications/cancelled`.

use std::time::Duration;

use reqwest::header::HeaderMap;
use tracing::debug;

use super::HTTP_TARGET;
use crate::protocol::era::Era;
use crate::protocol::{JsonRpcNotification, JsonRpcRequest};

/// Bound on the cancel POST; nothing waits for it, but it must not linger.
const CANCEL_POST_TIMEOUT: Duration = Duration::from_secs(5);

/// The one notification to send if the exchange is dropped while armed.
struct CancelPost {
    client: reqwest::Client,
    url: String,
    headers: HeaderMap,
    body: JsonRpcNotification,
}

/// Armed for one exchange; disarmed once its reply is read or it failed.
/// Owns clones only, never the transport, so it can send after the future
/// that held it is gone.
pub(super) struct CancelOnDrop(Option<CancelPost>);

impl CancelOnDrop {
    /// Armed for every legacy-shaped request except `initialize`, which is
    /// never cancelled (the protocol forbids it).
    pub(super) fn arm(
        client: &reqwest::Client,
        url: &str,
        headers: &HeaderMap,
        request: &JsonRpcRequest,
        era: Option<Era>,
    ) -> Self {
        if era == Some(Era::Modern) || request.method == "initialize" {
            return Self(None);
        }
        Self(Some(CancelPost {
            client: client.clone(),
            url: url.to_string(),
            headers: headers.clone(),
            body: JsonRpcNotification {
                jsonrpc: "2.0".to_string(),
                method: "notifications/cancelled".to_string(),
                params: Some(serde_json::json!({
                    "requestId": request.id,
                    "reason": "the gateway's caller abandoned the request",
                })),
            },
        }))
    }

    /// The exchange finished, answered or failed: nothing to cancel.
    pub(super) fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let Some(post) = self.0.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            debug!(target: HTTP_TARGET, "no runtime left to send a cancel; the backend finishes the call");
            return;
        };
        runtime.spawn(async move {
            let sent = post
                .client
                .post(&post.url)
                .headers(post.headers)
                .json(&post.body)
                .timeout(CANCEL_POST_TIMEOUT)
                .send()
                .await;
            if sent.is_err() {
                debug!(target: HTTP_TARGET, "cancel notification not delivered; best effort");
            }
        });
    }
}
