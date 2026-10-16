// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use axum::body::Body;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::super::audience_ear::spawn_relay;
use super::{Ear, Events, World, asserted};

impl World {
    /// `POST /mcp` with `bearer`.
    pub(in crate::gateway::server::tools_changed) async fn post(
        &self,
        bearer: &str,
        method: &str,
        params: Value,
    ) -> Value {
        self.post_as(bearer, (None, None), method, params).await
    }

    /// `POST /mcp` with `bearer`, inside legacy session `id` (its minted id).
    pub(in crate::gateway::server::tools_changed) async fn post_in(
        &self,
        bearer: &str,
        id: &str,
        method: &str,
        params: Value,
    ) -> Value {
        let minted = self
            .minted
            .borrow()
            .get(id)
            .cloned()
            .expect("a legacy session");
        self.post_as(bearer, (Some(&minted), None), method, params)
            .await
    }

    /// `POST /mcp` with `bearer`, in a session and
    /// with an Open `WebUI` assertion, each when given.
    pub(super) async fn post_as(
        &self,
        bearer: &str,
        (session, assertion): (Option<&str>, Option<&str>),
        method: &str,
        params: Value,
    ) -> Value {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json");
        if let Some(session) = session {
            request = request.header("mcp-session-id", session);
        }
        let mut request = request
            .body(Body::from(
                json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
                    .to_string(),
            ))
            .expect("a request");
        asserted(&mut request, assertion);
        let response = self.router.clone().oneshot(request).await.expect("served");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        serde_json::from_slice(&body).expect("a JSON body")
    }

    /// The `tools/list` result's tools for `bearer`.
    pub(in crate::gateway::server::tools_changed) async fn served(
        &self,
        bearer: &str,
    ) -> Vec<Value> {
        let reply = self.post(bearer, "tools/list", json!({})).await;
        reply["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list failed: {reply}"))
            .clone()
    }

    /// The names `tools/list` serves `bearer`.
    pub(in crate::gateway::server::tools_changed) async fn served_names(
        &self,
        bearer: &str,
    ) -> Vec<String> {
        let mut names: Vec<String> = self
            .served(bearer)
            .await
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_owned))
            .collect();
        names.sort();
        names
    }

    /// The names `gateway_list_tools` shows `bearer` for `server`, which also
    /// warms the caller's own slot when `server` is per-user.
    pub(in crate::gateway::server::tools_changed) async fn discovered(
        &self,
        bearer: &str,
        server: &str,
    ) -> Vec<String> {
        self.discovered_as(bearer, None, server).await
    }

    /// As [`Self::discovered`], with an Open `WebUI` `assertion`.
    pub(in crate::gateway::server::tools_changed) async fn discovered_as(
        &self,
        bearer: &str,
        assertion: Option<&str>,
        server: &str,
    ) -> Vec<String> {
        let reply = self
            .post_as(
                bearer,
                (None, assertion),
                "tools/call",
                json!({ "name": "gateway_list_tools", "arguments": { "server": server } }),
            )
            .await;
        let text = reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("gateway_list_tools failed: {reply}"));
        let parsed: Value = serde_json::from_str(text).unwrap_or(Value::Null);
        let mut names: Vec<String> = parsed["tools"]
            .as_array()
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|t| t["name"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// A legacy GET session held by `bearer`, as the MCP handler opens one.
    pub(in crate::gateway::server::tools_changed) async fn legacy(
        &self,
        id: &str,
        bearer: &str,
    ) -> Ear {
        self.legacy_with(id, &[("authorization", format!("Bearer {bearer}"))])
            .await
    }

    /// Resume legacy session `id` under a new bearer, as a re-keyed request does.
    pub(in crate::gateway::server::tools_changed) fn rekey(&self, id: &str, bearer: &str) {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {bearer}").parse().expect("a header value"),
        );
        let held = crate::gateway::auth::live::held_credential(&headers);
        let owner = crate::gateway::session_id::SessionOwner::Credential(id.to_string());
        assert!(
            self.state
                .multiplexer
                .resume_session_id_scoped(
                    self.minted.borrow().get(id).map(String::as_str),
                    &owner,
                    held
                )
                .is_some(),
            "premise: the session resumes"
        );
    }

    /// A live dashboard-session cookie value, as the middleware would set.
    pub(in crate::gateway::server::tools_changed) fn dashboard_cookie(&self) -> String {
        let handle = self.state.dashboard_bootstrap.issue_session();
        format!("{}={handle}", crate::gateway::auth::SESSION_COOKIE)
    }

    /// A legacy GET stream held by `bearer`, opened through the real route
    /// (`mcp_sse_handler`), so the write path (`credential_at_write`, the write
    /// acknowledgement) runs for every frame it is sent. [`Self::legacy`] reads
    /// a bare receiver and never reaches it.
    pub(in crate::gateway::server::tools_changed) async fn sse(&self, bearer: &str) -> Ear {
        self.sse_as(bearer, None).await
    }

    /// As [`Self::sse`], with an Open `WebUI` `assertion`.
    pub(in crate::gateway::server::tools_changed) async fn sse_as(
        &self,
        bearer: &str,
        assertion: Option<&str>,
    ) -> Ear {
        self.sse_open(bearer, assertion, None).await
    }

    /// Reopen the GET stream of `session` under `bearer`: the same session,
    /// resumed by the credential that owns it.
    pub(in crate::gateway::server::tools_changed) async fn sse_resume(
        &self,
        bearer: &str,
        session: &str,
    ) -> Ear {
        self.sse_open(bearer, None, Some(session)).await
    }

    async fn sse_open(&self, bearer: &str, assertion: Option<&str>, resume: Option<&str>) -> Ear {
        self.sse_request(bearer, assertion, ("/mcp", resume), |_| {})
            .await
    }

    /// A GET stream at `uri`, resuming `resume` when given.
    pub(in crate::gateway::server::tools_changed) async fn sse_at(
        &self,
        bearer: &str,
        uri: &str,
        resume: Option<&str>,
    ) -> Ear {
        self.sse_request(bearer, None, (uri, resume), |_| {}).await
    }

    /// As [`Self::sse`], with `extend` applied to the request first: the
    /// request extensions the TLS layer or a proxy's connection would insert
    /// (a client certificate, its `notAfter`, the peer), for MIK-8377.
    pub(in crate::gateway::server::tools_changed) async fn sse_with(
        &self,
        bearer: &str,
        extend: impl FnOnce(&mut axum::http::Request<Body>),
    ) -> Ear {
        self.sse_request(bearer, None, ("/mcp", None), extend).await
    }

    async fn sse_request(
        &self,
        bearer: &str,
        assertion: Option<&str>,
        (uri, resume): (&str, Option<&str>),
        extend: impl FnOnce(&mut axum::http::Request<Body>),
    ) -> Ear {
        let mut builder = axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"))
            .header("accept", "text/event-stream");
        if let Some(session) = resume {
            builder = builder.header("mcp-session-id", session);
        }
        let mut request = builder.body(Body::empty()).expect("a request");
        asserted(&mut request, assertion);
        extend(&mut request);
        let response = self.router.clone().oneshot(request).await.expect("served");
        assert!(
            response.status().is_success(),
            "sse refused: {}",
            response.status()
        );
        let session = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .expect("the stream names its session")
            .to_string();
        let body = Events {
            stream: Box::pin(response.into_body().into_data_stream()),
            buffer: String::new(),
        };
        let relay = spawn_relay(body);
        Ear::Sse { relay, session }
    }
}
