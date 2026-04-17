//! A2A HTTP client.
//!
//! Wraps `reqwest` to talk the A2A JSON-RPC 2.0 wire protocol.
//! All operations are async, cancel-safe, and respect the backend
//! timeout configured in [`BackendConfig`].
//!
//! # Usage
//!
//! ```rust,ignore
//! use mcp_gateway::a2a::client::A2aClient;
//!
//! let client = A2aClient::new("https://agent.example.com".to_string(), None);
//! let card = client.fetch_agent_card().await?;
//! let task = client.send_message("Plan a trip to Helsinki", None).await?;
//! ```

use std::collections::HashMap;
use std::time::Duration;

use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{Error, Result};

use super::types::{
    A2aError, A2aMessage, A2aRequest, A2aResponse, A2aTask, AgentCard, CancelTaskParams,
    GetTaskParams, MessageConfiguration, MessageRole, Part, SendMessageParams,
};

/// Default well-known path for the Agent Card.
const DEFAULT_AGENT_CARD_PATH: &str = "/.well-known/agent.json";

/// Default accepted output modes sent in every `message/send` request.
const DEFAULT_OUTPUT_MODES: &[&str] = &["text/plain", "application/json"];

// ── Client ────────────────────────────────────────────────────────────────────

/// HTTP client for the A2A protocol.
///
/// Holds a shared `reqwest::Client` (connection-pool reuse) with pre-injected
/// auth headers.  All JSON-RPC calls go through [`A2aClient::rpc`] to keep
/// error handling consistent.
pub struct A2aClient {
    http: reqwest::Client,
    base_url: String,
    agent_card_path: String,
}

impl A2aClient {
    /// Create a new client targeting `base_url`.
    ///
    /// `headers` are injected into every request (auth tokens, API keys, etc.).
    /// Pass `None` or an empty map for unauthenticated agents.
    ///
    /// # Panics
    ///
    /// Panics if `reqwest::Client` construction fails, which only occurs when
    /// TLS initialization fails (extremely rare, indicates system misconfiguration).
    #[must_use]
    pub fn new(
        base_url: &str,
        headers: Option<HashMap<String, String>>,
        agent_card_path: Option<String>,
        timeout: Option<Duration>,
    ) -> Self {
        let mut default_headers = HeaderMap::new();
        default_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        if let Some(extra) = headers {
            for (k, v) in extra {
                if let (Ok(name), Ok(value)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(&v),
                ) {
                    default_headers.insert(name, value);
                }
            }
        }

        let mut builder = reqwest::Client::builder()
            .default_headers(default_headers)
            .use_rustls_tls();

        if let Some(t) = timeout {
            builder = builder.timeout(t);
        }

        Self {
            http: builder.build().expect("reqwest client build failed"),
            base_url: base_url.trim_end_matches('/').to_string(),
            agent_card_path: agent_card_path.unwrap_or_else(|| DEFAULT_AGENT_CARD_PATH.to_string()),
        }
    }

    /// Fetch and parse the Agent Card from the well-known URL.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if the HTTP request fails or the response
    /// body is not a valid `AgentCard`.
    pub async fn fetch_agent_card(&self) -> Result<AgentCard> {
        let url = format!("{}{}", self.base_url, self.agent_card_path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Protocol(format!("Agent Card fetch failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::Protocol(format!(
                "Agent Card returned HTTP {}: {}",
                resp.status(),
                url
            )));
        }

        resp.json::<AgentCard>()
            .await
            .map_err(|e| Error::Protocol(format!("Agent Card parse error: {e}")))
    }

    /// Send a text message to the agent and return the resulting task.
    ///
    /// Uses blocking mode (`configuration.blocking = true`) so the HTTP
    /// connection is held until the task reaches a terminal state or
    /// `input-required`.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP call fails or the agent responds with a
    /// JSON-RPC error.
    pub async fn send_message(&self, text: &str, context_id: Option<&str>) -> Result<A2aTask> {
        let message = A2aMessage {
            role: MessageRole::User,
            parts: vec![Part::Text {
                text: text.to_string(),
                mime_type: None,
            }],
            context_id: context_id.map(str::to_string),
            metadata: None,
        };

        let params = SendMessageParams {
            message,
            configuration: Some(MessageConfiguration {
                accepted_output_modes: DEFAULT_OUTPUT_MODES
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
                blocking: Some(true),
                timeout_seconds: None,
            }),
            metadata: None,
        };

        let params_value =
            serde_json::to_value(params).map_err(|e| Error::Protocol(e.to_string()))?;

        let response = self.rpc("message/send", Some(params_value)).await?;
        extract_task(response)
    }

    /// Retrieve a task by its identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP call fails or the agent returns an error.
    pub async fn get_task(&self, task_id: &str) -> Result<A2aTask> {
        let params = serde_json::to_value(GetTaskParams {
            id: task_id.to_string(),
            history_length: None,
        })
        .map_err(|e| Error::Protocol(e.to_string()))?;

        let response = self.rpc("tasks/get", Some(params)).await?;
        extract_task(response)
    }

    /// Cancel a running task.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP call fails or the agent returns an error.
    pub async fn cancel_task(&self, task_id: &str) -> Result<A2aTask> {
        let params = serde_json::to_value(CancelTaskParams {
            id: task_id.to_string(),
            metadata: None,
        })
        .map_err(|e| Error::Protocol(e.to_string()))?;

        let response = self.rpc("tasks/cancel", Some(params)).await?;
        extract_task(response)
    }

    /// Send a raw JSON-RPC request to the agent's base URL.
    ///
    /// All public methods delegate here to unify error handling.
    async fn rpc(&self, method: &str, params: Option<Value>) -> Result<A2aResponse> {
        let id = Uuid::new_v4().to_string();
        let request = A2aRequest::new(json!(id), method, params);

        let resp = self
            .http
            .post(&self.base_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::Protocol(format!("A2A RPC '{method}' failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::Protocol(format!(
                "A2A RPC '{method}' returned HTTP {}",
                resp.status()
            )));
        }

        resp.json::<A2aResponse>()
            .await
            .map_err(|e| Error::Protocol(format!("A2A response parse error for '{method}': {e}")))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract an [`A2aTask`] from the `result` field of an [`A2aResponse`].
fn extract_task(response: A2aResponse) -> Result<A2aTask> {
    if let Some(ref err) = response.error {
        return Err(a2a_error_to_gateway(err));
    }

    let result = response
        .result
        .ok_or_else(|| Error::Protocol("A2A response had neither result nor error".to_string()))?;

    serde_json::from_value(result)
        .map_err(|e| Error::Protocol(format!("A2A task deserialization failed: {e}")))
}

/// Map an [`A2aError`] into the gateway's [`Error`] type.
fn a2a_error_to_gateway(err: &A2aError) -> Error {
    Error::Protocol(format!("A2A error {}: {}", err.code, err.message))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::a2a::types::{A2aTask, TaskState, TaskStatus};

    fn make_completed_task() -> A2aTask {
        A2aTask {
            id: "task-1".to_string(),
            context_id: None,
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: None,
            },
            artifacts: vec![],
            metadata: None,
        }
    }

    #[test]
    fn a2a_client_new_builds_without_panic() {
        // GIVEN: valid base URL, no headers, no path override
        // WHEN: constructing client
        // THEN: does not panic
        let _client = A2aClient::new(
            "https://agent.example.com",
            None,
            None,
            Some(Duration::from_secs(30)),
        );
    }

    #[test]
    fn a2a_client_strips_trailing_slash_from_base_url() {
        // GIVEN: base URL with trailing slash
        // WHEN: constructing client
        // THEN: trailing slash is removed
        let client = A2aClient::new("https://agent.example.com/", None, None, None);
        assert_eq!(client.base_url, "https://agent.example.com");
    }

    #[test]
    fn a2a_client_uses_custom_agent_card_path() {
        // GIVEN: explicit agent card path
        // WHEN: constructing client
        // THEN: path is stored
        let client = A2aClient::new(
            "https://agent.example.com",
            None,
            Some("/custom/agent.json".to_string()),
            None,
        );
        assert_eq!(client.agent_card_path, "/custom/agent.json");
    }

    #[test]
    fn a2a_client_uses_default_agent_card_path_when_none() {
        // GIVEN: no agent card path override
        // WHEN: constructing client
        // THEN: default well-known path is used
        let client = A2aClient::new("https://agent.example.com", None, None, None);
        assert_eq!(client.agent_card_path, DEFAULT_AGENT_CARD_PATH);
    }

    #[test]
    fn extract_task_succeeds_with_valid_result() {
        // GIVEN: A2aResponse with a valid task in result
        let task = make_completed_task();
        let response = A2aResponse {
            jsonrpc: "2.0".to_string(),
            id: json!(1),
            result: Some(serde_json::to_value(&task).unwrap()),
            error: None,
        };
        // WHEN: extracting
        // THEN: task matches
        let extracted = extract_task(response).unwrap();
        assert_eq!(extracted.id, "task-1");
        assert_eq!(extracted.status.state, TaskState::Completed);
    }

    #[test]
    fn extract_task_fails_on_rpc_error() {
        // GIVEN: A2aResponse carrying an error
        let response = A2aResponse {
            jsonrpc: "2.0".to_string(),
            id: json!(1),
            result: None,
            error: Some(A2aError {
                code: -32600,
                message: "Invalid Request".to_string(),
                data: None,
            }),
        };
        // WHEN: extracting
        // THEN: returns Err with the error code
        let err = extract_task(response).unwrap_err();
        assert!(matches!(err, Error::Protocol(ref msg) if msg.contains("-32600")));
    }

    #[test]
    fn extract_task_fails_when_neither_result_nor_error() {
        // GIVEN: A2aResponse with both fields absent (malformed)
        let response = A2aResponse {
            jsonrpc: "2.0".to_string(),
            id: json!(1),
            result: None,
            error: None,
        };
        // WHEN: extracting
        // THEN: returns Err
        let err = extract_task(response).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn a2a_error_to_gateway_formats_code_and_message() {
        // GIVEN: A2aError with code and message
        let a2a_err = A2aError {
            code: -32000,
            message: "Server error".to_string(),
            data: None,
        };
        // WHEN: converting
        // THEN: gateway Error contains both
        let gw_err = a2a_error_to_gateway(&a2a_err);
        assert!(
            matches!(&gw_err, Error::Protocol(msg) if msg.contains("-32000") && msg.contains("Server error"))
        );
    }
}
