// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! OAuth Callback Server
//!
//! A minimal HTTP server to receive the OAuth authorization code
//! after user authorization in the browser.
//!
//! When `callback_host` is `None` or `"localhost"` the server dual-binds
//! 127.0.0.1 **and** `[::1]` on the same port so that browsers which resolve
//! `localhost` to either address family work without extra configuration.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::{
    Router,
    extract::{Query, State},
    response::{Html, IntoResponse},
    routing::get,
};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::{Error, Result};

/// OAuth callback query parameters
#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    /// Authorization code
    pub code: Option<String>,

    /// State parameter (for CSRF protection)
    pub state: Option<String>,

    /// Error code
    pub error: Option<String>,

    /// Error description
    pub error_description: Option<String>,

    /// The issuer the authorization response came from (RFC 9207).
    ///
    /// Carried rather than checked here: the specification requires the
    /// comparison to happen before the code is redeemed, and the recorded
    /// issuer belongs to the client that started the flow, not to this server.
    pub iss: Option<String>,
}

/// OAuth callback result
#[derive(Debug)]
pub struct CallbackResult {
    /// Authorization code
    pub code: String,

    /// State parameter (validated but kept for debugging)
    #[allow(dead_code)]
    pub state: String,

    /// The issuer the authorization server named, when it named one.
    pub iss: Option<String>,
}

/// State shared with the callback handler
struct CallbackState {
    expected_state: String,
    tx: Option<oneshot::Sender<Result<CallbackResult>>>,
}

/// A running callback server
pub struct CallbackServer {
    /// The URL where the callback server is listening
    pub callback_url: String,
    /// Receiver for the callback result
    receiver: oneshot::Receiver<Result<CallbackResult>>,
    /// Server task handles (one per bound address)
    server_handles: Vec<tokio::task::JoinHandle<Result<()>>>,
    /// Dropped only once every listener has let go of its socket (MIK-7982).
    closed: Option<tokio_util::sync::DropGuard>,
}

impl CallbackServer {
    /// Hold `guard` until the listeners are closed, however this server ends.
    pub(crate) fn hold_until_closed(&mut self, guard: tokio_util::sync::DropGuard) {
        self.closed = Some(guard);
    }

    /// Stop listening without waiting for a callback, for an authorization
    /// abandoned before the browser was sent anywhere. Returns once the
    /// listeners have let go of their sockets.
    pub(crate) async fn stop(self) {
        self.shutdown().await;
    }
    /// Tests only: every login waits through [`Self::wait_within`] (MIK-7982).
    #[cfg(test)]
    pub async fn wait_for_callback(mut self) -> Result<(String, CallbackResult)> {
        let result = (&mut self.receiver)
            .await
            .map_err(|_| Error::OAuth("Callback channel closed unexpectedly".to_string()))?;

        // The listeners have done their job; dropping `self` aborts them.
        result.map(|r| (std::mem::take(&mut self.callback_url), r))
    }

    /// Wait for the callback to be received, ended without an answer when `window`
    /// passes or `cancel` fires (MIK-7982). On those ends the listeners are
    /// closed before this returns, so the port is free for the next login.
    pub(crate) async fn wait_within(
        mut self,
        window: std::time::Duration,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> std::result::Result<Result<(String, CallbackResult)>, Unanswered> {
        let unanswered = tokio::select! {
            answer = &mut self.receiver => {
                let result = answer
                    .map_err(|_| Error::OAuth("Callback channel closed unexpectedly".to_string()))
                    .and_then(|r| r);
                let callback_url = std::mem::take(&mut self.callback_url);
                // Closed before the login reports its end, so a restart or a
                // new login can bind a fixed callback port at once.
                self.shutdown().await;
                return Ok(result.map(|r| (callback_url, r)));
            }
            () = tokio::time::sleep(window) => Unanswered::Window,
            () = cancel.cancelled() => Unanswered::Cancelled,
        };
        self.shutdown().await;
        Err(unanswered)
    }

    /// Abort every listener and wait until each has let go of its socket.
    /// Dropping alone frees a port only on the listener's next poll.
    async fn shutdown(mut self) {
        for handle in &self.server_handles {
            handle.abort();
        }
        // Each handle leaves `self` only once joined: a shutdown interrupted
        // mid-way leaves the rest to `Drop`, which keeps the guard until then.
        while let Some(handle) = self.server_handles.last_mut() {
            let _ = handle.await;
            self.server_handles.pop();
        }
    }
}

/// How a bounded callback wait ended without an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unanswered {
    /// The authorization window passed.
    Window,
    /// The login was cancelled (restart or shutdown of its backend).
    Cancelled,
}

impl Drop for CallbackServer {
    /// Every way a server ends closes its listeners, a wait dropped mid-way
    /// (a cancelled or timed-out caller) included: dropping a `JoinHandle`
    /// alone would detach the listener and keep its port (MIK-7982 F2).
    fn drop(&mut self) {
        for handle in &self.server_handles {
            handle.abort();
        }
        // An aborted listener frees its port only when next polled: the
        // guard is dropped once each one has actually ended.
        let handles = std::mem::take(&mut self.server_handles);
        if let Some(guard) = self.closed.take()
            && !handles.is_empty()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            runtime.spawn(async move {
                for handle in handles {
                    let _ = handle.await;
                }
                drop(guard);
            });
        }
    }
}

/// The configured host as a loopback IP literal, if it is one (brackets
/// allowed). Such a host is bound and named exactly as configured, so the
/// address the redirect URI names is the address that answers (#2578).
/// Anything else keeps today's behaviour: bound on 127.0.0.1, named
/// `localhost`, and the callback never listens beyond loopback.
fn loopback_literal(host: &str, dual_bind: bool) -> Option<IpAddr> {
    let ip = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok()
        .filter(IpAddr::is_loopback);
    if !dual_bind && ip.is_none() {
        warn!(
            event = "oauth.callback_server.host_not_loopback",
            host,
            "callback_host is neither localhost nor a loopback IP: the callback listens on \
             127.0.0.1 and the redirect URI names localhost"
        );
    }
    ip
}

/// The host as the redirect URI names it: a loopback IP literal as
/// configured, IPv6 in brackets as a URI authority requires; otherwise
/// `localhost`, where the callback listens.
fn url_host(loopback_ip: Option<IpAddr>) -> String {
    match loopback_ip {
        Some(IpAddr::V6(v6)) => format!("[{v6}]"),
        Some(IpAddr::V4(v4)) => v4.to_string(),
        None => "localhost".to_string(),
    }
}

/// Start a callback server and return it immediately
///
/// When `host` is `None` or `"localhost"`, the server binds both
/// `127.0.0.1:<port>` and `[::1]:<port>` so that browsers which resolve
/// `localhost` to the IPv6 loopback address still reach the callback.  The
/// IPv6 bind is attempted on a best-effort basis; if the system has no IPv6
/// loopback the port is still reachable over IPv4.
///
/// `path` defaults to `/oauth/callback`.
///
/// This allows the caller to get the callback URL before waiting for the
/// callback, which is necessary to build the authorization URL correctly.
pub async fn start_callback_server(
    expected_state: String,
    host: Option<&str>,
    port: Option<u16>,
    path: Option<&str>,
) -> Result<CallbackServer> {
    let effective_host = host.unwrap_or("localhost");
    let callback_path = path.unwrap_or("/oauth/callback");
    let dual_bind = effective_host == "localhost";
    let loopback_ip = loopback_literal(effective_host, dual_bind);

    // Bind the primary address first so we can learn the kernel-assigned
    // port when `port` is `None`.
    let primary_addr = SocketAddr::new(
        loopback_ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port.unwrap_or(0),
    );
    let primary_listener = TcpListener::bind(primary_addr).await.map_err(|e| {
        Error::OAuth(format!(
            "Failed to bind callback server on {primary_addr}: {e}"
        ))
    })?;

    let actual_port = primary_listener
        .local_addr()
        .map_err(|e| Error::OAuth(format!("Failed to get callback server address: {e}")))?
        .port();

    // #144: when using localhost, also try to bind the IPv6 loopback so
    // browsers that resolve localhost → ::1 can reach the server.
    let ipv6_listener: Option<TcpListener> = if dual_bind {
        let ipv6_addr: SocketAddr = format!("[::1]:{actual_port}").parse().unwrap();
        match TcpListener::bind(ipv6_addr).await {
            Ok(l) => {
                info!(
                    event = "oauth.callback_server.bind",
                    host = "[::1]",
                    port = actual_port,
                    "OAuth callback server also bound on IPv6 loopback"
                );
                Some(l)
            }
            Err(e) => {
                debug!(
                    event = "oauth.callback_server.ipv6_unavailable",
                    port = actual_port,
                    error = %e,
                    "IPv6 loopback unavailable; callback server is IPv4-only"
                );
                None
            }
        }
    } else {
        None
    };

    let callback_url = format!(
        "http://{}:{actual_port}{callback_path}",
        url_host(loopback_ip)
    );

    // #143 — structured telemetry: server bind event.
    info!(
        event = "oauth.callback_server.bind",
        host = effective_host,
        port = actual_port,
        path = callback_path,
        dual_bind,
        url = %callback_url,
        "OAuth callback server listening"
    );

    // Create oneshot channel for the result
    let (tx, rx) = oneshot::channel();

    let state = Arc::new(tokio::sync::Mutex::new(CallbackState {
        expected_state,
        tx: Some(tx),
    }));

    // Build router (shared between both listeners)
    let app = Router::new()
        .route(callback_path, get(handle_callback))
        .with_state(state.clone());

    let mut handles: Vec<tokio::task::JoinHandle<Result<()>>> = Vec::with_capacity(2);

    // Spawn IPv4 listener task
    handles.push(tokio::spawn({
        let app = app.clone();
        async move {
            axum::serve(primary_listener, app)
                .await
                .map_err(|e| Error::OAuth(format!("Callback server error: {e}")))
        }
    }));

    // Spawn IPv6 listener task if available
    if let Some(l6) = ipv6_listener {
        handles.push(tokio::spawn(async move {
            axum::serve(l6, app)
                .await
                .map_err(|e| Error::OAuth(format!("Callback server (IPv6) error: {e}")))
        }));
    }

    Ok(CallbackServer {
        callback_url,
        receiver: rx,
        server_handles: handles,
        closed: None,
    })
}

/// Handle the OAuth callback
async fn handle_callback(
    State(state): State<Arc<tokio::sync::Mutex<CallbackState>>>,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    // #143 — structured telemetry: callback received event.
    // Fields computed before the macro: tracing compiles its arguments twice,
    // and the coverage instrument reads the copy that never runs (MIK-7324).
    let has_code = params.code.is_some();
    let has_state = params.state.is_some();
    let has_error = params.error.is_some();
    debug!(
        event = "oauth.callback.received",
        has_code, has_state, has_error, "OAuth callback received"
    );

    let mut state = state.lock().await;

    // Check for errors
    if let Some(ref error) = params.error {
        let description = params.error_description.as_deref().unwrap_or_default();
        // #143 — structured telemetry: provider error event.
        warn!(
            event = "oauth.callback.provider_error",
            error = %error,
            description = %description,
            "OAuth provider returned an error"
        );
        let result = Err(Error::OAuth(format!(
            "OAuth error: {error} - {description}"
        )));
        if let Some(tx) = state.tx.take() {
            let _ = tx.send(result);
        }
        let escaped_error = escape_html(error);
        let escaped_description = escape_html(description);
        return Html(format!(
            "<html><body><h1>Authorization Failed</h1><p>{escaped_error}: {escaped_description}</p></body></html>"
        ));
    }

    // Validate state
    if params.state.as_deref() != Some(&state.expected_state) {
        // #143 — structured telemetry: CSRF / state-mismatch event.
        let received = params.state.as_deref().unwrap_or("<none>");
        warn!(
            event = "oauth.callback.state_mismatch",
            received, "OAuth state mismatch — possible CSRF attempt"
        );
        let result = Err(Error::OAuth(
            "State mismatch - possible CSRF attack".to_string(),
        ));
        if let Some(tx) = state.tx.take() {
            let _ = tx.send(result);
        }
        return Html(
            "<html><body><h1>Authorization Failed</h1><p>State mismatch</p></body></html>"
                .to_string(),
        );
    }

    // Extract code
    let Some(code) = params.code else {
        warn!(
            event = "oauth.callback.missing_code",
            "OAuth callback arrived with no authorization code"
        );
        let result = Err(Error::OAuth("No authorization code received".to_string()));
        if let Some(tx) = state.tx.take() {
            let _ = tx.send(result);
        }
        return Html(
            "<html><body><h1>Authorization Failed</h1><p>No code received</p></body></html>"
                .to_string(),
        );
    };

    // #143 — structured telemetry: successful callback event.
    let code_len = code.len();
    info!(
        event = "oauth.callback.success",
        code_len, "OAuth authorization code received successfully"
    );

    // Send success
    let result = Ok(CallbackResult {
        code,
        state: params.state.unwrap_or_default(),
        iss: params.iss,
    });
    if let Some(tx) = state.tx.take() {
        let _ = tx.send(result);
    }

    Html(
        "<html><body><h1>Authorization Successful!</h1><p>You can close this window.</p></body></html>".to_string()
    )
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
#[path = "callback_tests.rs"]
pub(in crate::oauth) mod tests;
