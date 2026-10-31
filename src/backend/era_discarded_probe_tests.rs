// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A probe that meets a refused redirect hop drops its error, so the refusal
//! is not the answer of the call it runs inside: it records nothing there.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::probe;
use crate::protocol::JsonRpcResponse;
use crate::protocol::era::ProbeOutcome;

/// A backend whose every request meets a refused redirect hop after it was
/// sent: the hop raises `refused` on the open cell, as `refuse_hop` does.
struct RefusedHop;

#[async_trait]
impl crate::transport::Transport for RefusedHop {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let permission = crate::transport::ResendPermission::Permitted;
        self.request_with_headers(method, params, &[], None, permission)
            .await
    }

    async fn request_with_headers(
        &self,
        _method: &str,
        _params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        crate::gateway::delivery_facts::refused_while_vouched();
        Err(crate::Error::Protocol("SSRF blocked".to_owned()))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn a_probe_that_meets_a_refused_hop_records_nothing_on_the_call() {
    let transport: Arc<dyn crate::transport::Transport> = Arc::new(RefusedHop);
    let refused = crate::gateway::delivery_facts::scope(async {
        let outcome = probe(&transport, crate::test_wait::HANG_BOUND, &[]).await;
        assert!(
            matches!(outcome, ProbeOutcome::NoAnswer),
            "premise: the probe met the refusal and dropped it"
        );
        crate::gateway::delivery_facts::snapshot()
            .expect("a cell")
            .refused()
    })
    .await;
    assert!(
        !refused,
        "a dropped probe's refused hop recorded refused on the call"
    );
}
