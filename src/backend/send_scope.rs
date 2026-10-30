// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every send runs inside its backend's notification scope.
//!
//! A notification raised anywhere in a send, a start's handshake included,
//! names this backend at the sink's ingress (`transport::notify_ingress`);
//! one raised outside any backend's scope is withheld there.

use serde_json::Value;

use super::Backend;
use super::ops::Attempts;
use crate::Result;
use crate::protocol::JsonRpcResponse;

impl Backend {
    pub(super) async fn send_in_scope(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: crate::transport::LentCredential,
        identity_key: Option<&str>,
        attempts: Attempts,
    ) -> Result<JsonRpcResponse> {
        crate::transport::notify_ingress::in_backend(
            std::sync::Arc::clone(&self.notify_origin),
            self.request_attempted(method, params, extra_headers, identity_key, attempts),
        )
        .await
    }
}
