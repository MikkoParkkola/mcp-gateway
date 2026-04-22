//! OAuth Callback Server
//!
//! A minimal HTTP server to receive the OAuth authorization code
//! after user authorization in the browser.
//!
//! When `callback_host` is `None` or `"localhost"` the server dual-binds
//! 127.0.0.1 **and** `[::1]` on the same port so that browsers which resolve
//! `localhost` to either address family work without extra configuration.

use std::net::SocketAddr;
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
}

/// OAuth callback result
#[derive(Debug)]
pub struct CallbackResult {
    /// Authorization code
    pub code: String,

    /// State parameter (validated but kept for debugging)
    #[allow(dead_code)]
    pub state: String,
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
}

impl CallbackServer {
    /// Wait for the callback to be received
    pub async fn wait_for_callback(self) -> Result<(String, CallbackResult)> {
        let result = self
            .receiver
            .await
            .map_err(|_| Error::OAuth("Callback channel closed unexpectedly".to_string()))?;

        // Abort all listener tasks — they have all done their job.
        for handle in self.server_handles {
            handle.abort();
        }

        result.map(|r| (self.callback_url, r))
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

    // Always bind the primary IPv4 loopback address first so we can
    // learn the kernel-assigned port when `port` is `None`.
    let ipv4_addr: SocketAddr = format!("127.0.0.1:{}", port.unwrap_or(0)).parse().unwrap();
    let ipv4_listener = TcpListener::bind(ipv4_addr)
        .await
        .map_err(|e| Error::OAuth(format!("Failed to bind callback server: {e}")))?;

    let actual_port = ipv4_listener
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

    let callback_url = format!("http://localhost:{actual_port}{callback_path}");

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
            axum::serve(ipv4_listener, app)
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
    })
}

/// Handle the OAuth callback
async fn handle_callback(
    State(state): State<Arc<tokio::sync::Mutex<CallbackState>>>,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    // #143 — structured telemetry: callback received event.
    debug!(
        event = "oauth.callback.received",
        has_code = params.code.is_some(),
        has_state = params.state.is_some(),
        has_error = params.error.is_some(),
        "OAuth callback received"
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
        return Html(format!(
            "<html><body><h1>Authorization Failed</h1><p>{error}: {description}</p></body></html>"
        ));
    }

    // Validate state
    if params.state.as_deref() != Some(&state.expected_state) {
        // #143 — structured telemetry: CSRF / state-mismatch event.
        warn!(
            event = "oauth.callback.state_mismatch",
            received = params.state.as_deref().unwrap_or("<none>"),
            "OAuth state mismatch — possible CSRF attempt"
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
    info!(
        event = "oauth.callback.success",
        code_len = code.len(),
        "OAuth authorization code received successfully"
    );

    // Send success
    let result = Ok(CallbackResult {
        code,
        state: params.state.unwrap_or_default(),
    });
    if let Some(tx) = state.tx.take() {
        let _ = tx.send(result);
    }

    Html(
        "<html><body><h1>Authorization Successful!</h1><p>You can close this window.</p></body></html>".to_string()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // CallbackParams deserialization
    // =========================================================================

    #[test]
    fn callback_params_success_case() {
        let params: CallbackParams =
            serde_urlencoded::from_str("code=auth_code_123&state=random_state_456").unwrap();
        assert_eq!(params.code.as_deref(), Some("auth_code_123"));
        assert_eq!(params.state.as_deref(), Some("random_state_456"));
        assert!(params.error.is_none());
        assert!(params.error_description.is_none());
    }

    #[test]
    fn callback_params_error_case() {
        let params: CallbackParams =
            serde_urlencoded::from_str("error=access_denied&error_description=User+denied+access")
                .unwrap();
        assert_eq!(params.error.as_deref(), Some("access_denied"));
        assert_eq!(
            params.error_description.as_deref(),
            Some("User denied access")
        );
        assert!(params.code.is_none());
    }

    #[test]
    fn callback_params_empty_query() {
        let params: CallbackParams = serde_urlencoded::from_str("").unwrap();
        assert!(params.code.is_none());
        assert!(params.state.is_none());
        assert!(params.error.is_none());
    }

    // =========================================================================
    // start_callback_server - binds and provides URL
    // =========================================================================

    #[tokio::test]
    async fn callback_server_binds_to_random_port() {
        let server = start_callback_server("test_state".to_string(), None, None, None)
            .await
            .unwrap();
        assert!(server.callback_url.starts_with("http://localhost:"));
        assert!(server.callback_url.ends_with("/oauth/callback"));
        // Clean up
        for h in server.server_handles {
            h.abort();
        }
    }

    #[tokio::test]
    async fn callback_server_binds_to_specified_port() {
        // Use port 0 as fallback since specific ports might be taken
        let server = start_callback_server("test_state".to_string(), None, Some(0), None)
            .await
            .unwrap();
        assert!(server.callback_url.starts_with("http://localhost:"));
        for h in server.server_handles {
            h.abort();
        }
    }

    #[tokio::test]
    async fn callback_server_custom_path() {
        let server =
            start_callback_server("st".to_string(), None, None, Some("/auth/cb"))
                .await
                .unwrap();
        assert!(server.callback_url.ends_with("/auth/cb"));
        for h in server.server_handles {
            h.abort();
        }
    }

    // =========================================================================
    // Full callback flow (server + HTTP request)
    // =========================================================================

    #[tokio::test]
    async fn callback_flow_success() {
        let state = "csrf_state_123".to_string();
        let server = start_callback_server(state.clone(), None, None, None)
            .await
            .unwrap();
        let callback_url = server.callback_url.clone();

        // Simulate the OAuth provider redirecting back
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{callback_url}?code=auth_code_xyz&state={state}"))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());

        // The callback should have delivered the result
        let (url, result) = server.wait_for_callback().await.unwrap();
        assert_eq!(result.code, "auth_code_xyz");
        assert_eq!(url, callback_url);
    }

    #[tokio::test]
    async fn callback_flow_state_mismatch() {
        let server = start_callback_server("expected_state".to_string(), None, None, None)
            .await
            .unwrap();
        let callback_url = server.callback_url.clone();

        let client = reqwest::Client::new();
        let _resp = client
            .get(format!("{callback_url}?code=code123&state=wrong_state"))
            .send()
            .await
            .unwrap();

        let result = server.wait_for_callback().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn callback_flow_error_from_provider() {
        let server = start_callback_server("some_state".to_string(), None, None, None)
            .await
            .unwrap();
        let callback_url = server.callback_url.clone();

        let client = reqwest::Client::new();
        let _resp = client
            .get(format!(
                "{callback_url}?error=access_denied&error_description=User+denied"
            ))
            .send()
            .await
            .unwrap();

        let result = server.wait_for_callback().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn callback_flow_missing_code() {
        let server = start_callback_server("state123".to_string(), None, None, None)
            .await
            .unwrap();
        let callback_url = server.callback_url.clone();

        let client = reqwest::Client::new();
        let _resp = client
            .get(format!("{callback_url}?state=state123"))
            .send()
            .await
            .unwrap();

        let result = server.wait_for_callback().await;
        assert!(result.is_err());
    }
}
