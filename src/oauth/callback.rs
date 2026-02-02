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

/// Start a callback server and wait for the authorization code
pub async fn wait_for_callback(expected_state: String, port: Option<u16>) -> Result<(String, CallbackResult)> {
    // Find an available port
    let addr: SocketAddr = format!("127.0.0.1:{}", port.unwrap_or(0)).parse().unwrap();
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Internal(format!("Failed to bind callback server: {e}")))?;

    let actual_addr = listener.local_addr()
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

    // Wait for the callback
    let result = rx
        .await
        .map_err(|_| Error::Internal("Callback channel closed unexpectedly".to_string()))?;

    // Abort the server (it's done its job)
    server.abort();

    result.map(|r| (callback_url, r))
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
        let description = params.error_description.unwrap_or_else(|| "Unknown error".to_string());
        let result = Err(Error::Internal(format!("OAuth error: {error} - {description}")));

        if let Some(tx) = state.tx.take() {
            let _ = tx.send(result);
        }

        return Html(error_page(&error, &description));
    }

    // Validate required parameters
    let code = match params.code {
        Some(c) => c,
        None => {
            let result = Err(Error::Internal("Missing authorization code".to_string()));
            if let Some(tx) = state.tx.take() {
                let _ = tx.send(result);
            }
            return Html(error_page("missing_code", "Authorization code not provided"));
        }
    };

    let callback_state = match params.state {
        Some(s) => s,
        None => {
            let result = Err(Error::Internal("Missing state parameter".to_string()));
            if let Some(tx) = state.tx.take() {
                let _ = tx.send(result);
            }
            return Html(error_page("missing_state", "State parameter not provided"));
        }
    };

    // Validate state matches
    if callback_state != state.expected_state {
        let result = Err(Error::Internal("State mismatch - possible CSRF attack".to_string()));
        if let Some(tx) = state.tx.take() {
            let _ = tx.send(result);
        }
        return Html(error_page("state_mismatch", "Invalid state parameter"));
    }

    // Success!
    let result = Ok(CallbackResult {
        code,
        state: callback_state,
    });

    if let Some(tx) = state.tx.take() {
        let _ = tx.send(result);
    }

    Html(success_page())
}

fn success_page() -> String {
    r#"<!DOCTYPE html>
<html>
<head>
    <title>Authorization Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .container {
            text-align: center;
            padding: 2rem;
            background: rgba(255,255,255,0.1);
            border-radius: 16px;
            backdrop-filter: blur(10px);
        }
        .checkmark {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        h1 { margin: 0 0 0.5rem 0; }
        p { margin: 0; opacity: 0.9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">✓</div>
        <h1>Authorization Successful</h1>
        <p>You can close this window and return to MCP Gateway.</p>
    </div>
    <script>setTimeout(() => window.close(), 3000);</script>
</body>
</html>"#.to_string()
}

fn error_page(error: &str, description: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>Authorization Failed</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
        }}
        .container {{
            text-align: center;
            padding: 2rem;
            background: rgba(255,255,255,0.1);
            border-radius: 16px;
            backdrop-filter: blur(10px);
            max-width: 400px;
        }}
        .error-icon {{
            font-size: 4rem;
            margin-bottom: 1rem;
        }}
        h1 {{ margin: 0 0 0.5rem 0; }}
        p {{ margin: 0; opacity: 0.9; }}
        .error-code {{ font-family: monospace; margin-top: 1rem; opacity: 0.7; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">✗</div>
        <h1>Authorization Failed</h1>
        <p>{description}</p>
        <p class="error-code">Error: {error}</p>
    </div>
</body>
</html>"#)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callback_params_deserialize() {
        let params: CallbackParams = serde_urlencoded::from_str(
            "code=abc123&state=xyz789"
        ).unwrap();

        assert_eq!(params.code, Some("abc123".to_string()));
        assert_eq!(params.state, Some("xyz789".to_string()));
    }
}
