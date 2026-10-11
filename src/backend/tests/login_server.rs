// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The loopback authorization server and MCP endpoint the login rows run
//! against (MIK-7982, MIK-8269, MIK-8339), split from `login_window` to keep
//! that file under the size ceiling.

use super::*;

/// How [`issuing_server_with`]'s MCP endpoint behaves after the handshake.
#[derive(Clone, Copy)]
pub(crate) enum Upstream {
    /// Lists no tools, at once.
    Plain,
    /// A first `tools/list` page after the delay, then one that never comes;
    /// `pages` counts each (MIK-8046, MIK-8269). One test owns each counter.
    ListStallsCounted(Duration, &'static super::token_lapse::Pages),
    /// Hands out a session at the handshake, and answers every later request,
    /// counted as it arrives, after the delay with "session not found".
    SessionExpires(Duration, &'static AtomicUsize),
    /// Hands out a session at the handshake, answers as `Plain` after it,
    /// and counts each session `DELETE` a close sends (MIK-8339).
    SessionHeld(&'static AtomicUsize),
    /// Answers as `Plain`; once `on` is set, every authorization-server
    /// metadata read is counted in `stalled` and never answers (MIK-8339).
    MetadataStalls(&'static AtomicBool, &'static AtomicUsize),
}

/// How [`issuing_server_with`]'s token endpoint answers (MIK-8339).
#[derive(Clone, Copy)]
pub(crate) enum TokenEndpoint {
    /// Every grant at once, with no refresh token.
    Plain,
    /// Issues a refresh token with each access token; a `refresh_token`
    /// grant never answers.
    RefreshStalls,
    /// The first `n` `authorization_code` grants answer at once; every later
    /// one never answers (a code exchange stalled after approval).
    ExchangeStallsAfter(usize, &'static AtomicUsize),
}

/// An authorization server that issues a token good for `expires_in` seconds
/// (a refresh token too under [`TokenEndpoint::RefreshStalls`]), and an MCP endpoint at `/mcp` that answers the
/// handshake and behaves as `upstream` says. Returns its origin.
pub(crate) async fn issuing_server_with(
    expires_in: u64,
    upstream: Upstream,
    token: TokenEndpoint,
) -> String {
    use axum::http::{HeaderMap, StatusCode};
    use axum::{Json, Router, routing::get, routing::post};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let metadata = json!({
        "issuer": origin,
        "authorization_endpoint": format!("{origin}/authorize"),
        "token_endpoint": format!("{origin}/token"),
    });
    let mcp = move |Json(request): Json<Value>| async move {
        let Some(id) = request.get("id").cloned() else {
            return (StatusCode::ACCEPTED, HeaderMap::new(), Json(Value::Null));
        };
        let mut headers = HeaderMap::new();
        let body = match (upstream, request["method"].as_str()) {
            (Upstream::SessionExpires(..) | Upstream::SessionHeld(_), Some("initialize")) => {
                headers.insert("mcp-session-id", "login-window-session".parse().unwrap());
                json!({"jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "login-window", "version": "1"},
                }})
            }
            (Upstream::SessionExpires(delay, seen), _) => {
                seen.fetch_add(1, Ordering::SeqCst);
                sleep(delay).await;
                json!({"jsonrpc": "2.0", "id": id,
                    "error": {"code": -32600, "message": "session not found"}})
            }
            (_, Some("initialize")) => json!({"jsonrpc": "2.0", "id": id, "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "login-window", "version": "1"},
            }}),
            (_, Some("tools/list")) => match (upstream, request["params"].get("cursor")) {
                (Upstream::ListStallsCounted(first, pages), None) => {
                    pages.first.fetch_add(1, Ordering::SeqCst);
                    sleep(first).await;
                    json!({"jsonrpc": "2.0", "id": id,
                        "result": {"tools": [], "nextCursor": "page-2"}})
                }
                (Upstream::ListStallsCounted(_, pages), Some(_)) => {
                    pages.second.fetch_add(1, Ordering::SeqCst);
                    std::future::pending().await
                }
                _ => json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}}),
            },
            _ => json!({"jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": "method not found"}}),
        };
        (StatusCode::OK, headers, Json(body))
    };
    let app = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(move || {
                let body = metadata.clone();
                async move {
                    if let Upstream::MetadataStalls(on, stalled) = upstream
                        && on.load(Ordering::SeqCst)
                    {
                        stalled.fetch_add(1, Ordering::SeqCst);
                        std::future::pending::<()>().await;
                    }
                    Json(body)
                }
            }),
        )
        .route(
            "/token",
            post(move |body: String| token_answer(token, expires_in, body)),
        )
        .route(
            "/mcp",
            post(mcp).delete(move || async move {
                if let Upstream::SessionHeld(deletes) = upstream {
                    deletes.fetch_add(1, Ordering::SeqCst);
                }
                StatusCode::OK
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await });
    origin
}

/// The token endpoint's answer to one grant, as `token` says (MIK-8339).
async fn token_answer(token: TokenEndpoint, expires_in: u64, body: String) -> axum::Json<Value> {
    let grant = url::form_urlencoded::parse(body.as_bytes())
        .find(|(key, _)| key == "grant_type")
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    match (token, grant.as_str()) {
        (TokenEndpoint::RefreshStalls, "refresh_token") => {
            std::future::pending::<()>().await;
        }
        (TokenEndpoint::ExchangeStallsAfter(n, seen), "authorization_code")
            if seen.fetch_add(1, Ordering::SeqCst) >= n =>
        {
            std::future::pending::<()>().await;
        }
        _ => {}
    }
    let mut issued = json!({
        "access_token": "login-window-token",
        "token_type": "Bearer",
        "expires_in": expires_in,
    });
    if matches!(token, TokenEndpoint::RefreshStalls) {
        issued["refresh_token"] = json!("login-window-refresh");
    }
    axum::Json(issued)
}
