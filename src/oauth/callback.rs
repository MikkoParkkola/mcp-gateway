//! OAuth Callback Server
//!
//! A minimal HTTP server to receive the OAuth authorization code
//! after user authorization in the browser.

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
use tracing::{debug, info};

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
    /// Server task handle
    server_handle: tokio::task::JoinHandle<Result<()>>,
}

impl CallbackServer {
    /// Wait for the callback to be received
    pub async fn wait_for_callback(self) -> Result<(String, CallbackResult)> {
        let result = self
            .receiver
            .await
            .map_err(|_| Error::Internal("Callback channel closed unexpectedly".to_string()))?;

        // Abort the server (it's done its job)
        self.server_handle.abort();

        result.map(|r| (self.callback_url, r))
    }
}

/// Start a callback server and return it immediately
///
/// This allows the caller to get the callback URL before waiting for the callback,
/// which is necessary to build the authorization URL correctly.
pub async fn start_callback_server(
    expected_state: String,
    port: Option<u16>,
) -> Result<CallbackServer> {
    // Find an available port
    let addr: SocketAddr = format!("127.0.0.1:{}", port.unwrap_or(0)).parse().unwrap();
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Internal(format!("Failed to bind callback server: {e}")))?;

    let actual_addr = listener
        .local_addr()
        .map_err(|e| Error::Internal(format!("Failed to get callback server address: {e}")))?;

    let callback_url = format!("http://127.0.0.1:{}/oauth/callback", actual_addr.port());
    info!(url = %callback_url, "OAuth callback server listening");

    // Create oneshot channel for the result
    let (tx, rx) = oneshot::channel();

    let state = Arc::new(tokio::sync::Mutex::new(CallbackState {
        expected_state,
        tx: Some(tx),
    }));

    // Build router
    let app = Router::new()
        .route("/oauth/callback", get(handle_callback))
        .with_state(state);

    // Spawn server task
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .map_err(|e| Error::Internal(format!("Callback server error: {e}")))
    });

    Ok(CallbackServer {
        callback_url,
        receiver: rx,
        server_handle: server,
    })
}

/// Handle the OAuth callback
async fn handle_callback(
    State(state): State<Arc<tokio::sync::Mutex<CallbackState>>>,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    debug!(?params, "Received OAuth callback");

    let mut state = state.lock().await;

    // Check for errors
    if let Some(error) = params.error {
        let description = params.error_description.unwrap_or_default();
        let result = Err(Error::Internal(format!(
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
        let result = Err(Error::Internal(
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
    let code = if let Some(c) = params.code {
        c
    } else {
        let result = Err(Error::Internal(
            "No authorization code received".to_string(),
        ));
        if let Some(tx) = state.tx.take() {
            let _ = tx.send(result);
        }
        return Html(
            "<html><body><h1>Authorization Failed</h1><p>No code received</p></body></html>"
                .to_string(),
        );
    };

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
