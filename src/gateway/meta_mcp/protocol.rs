//! MCP protocol handlers for prompts and logging.
//!
//! Implements `prompts/list`, `prompts/get`, `logging/setLevel`, and
//! `current_log_level`.
//!
//! Gateway-owned meta-prompts (names prefixed `gateway/`) are served inline
//! without forwarding to any backend, prepended to every `prompts/list`
//! response so clients always find them first.

use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::protocol::{
    Content, JsonRpcResponse, LoggingLevel, LoggingSetLevelParams, Prompt, PromptArgument,
    PromptMessage, PromptsListResult, RequestId,
};

use super::super::meta_mcp_helpers::{extract_nested_optional_str, missing_parameter_response};
use super::MetaMcp;

// ============================================================================
// Gateway-owned meta-prompts (served inline — no backend required)
// ============================================================================

/// Metadata for all gateway-owned static meta-prompts.
///
/// Names use a bare `gateway/` prefix (no backend component) so the
/// routing logic in `handle_prompts_get` can distinguish them without
/// splitting on `/` in a way that would conflict with backend names.
fn gateway_prompts() -> [Prompt; 2] {
    [
        Prompt {
            name: "gateway/gateway-discover".to_string(),
            title: Some("Discover Gateway Tools".to_string()),
            description: Some(
                "Walk through finding the right tool for a task using the search-first pattern."
                    .to_string(),
            ),
            arguments: vec![PromptArgument {
                name: "task".to_string(),
                description: Some("What you are trying to accomplish".to_string()),
                required: true,
            }],
        },
        Prompt {
            name: "gateway/gateway-compose".to_string(),
            title: Some("Compose a Gateway Workflow".to_string()),
            description: Some(
                "Build a multi-step workflow using composition chains and gateway tools."
                    .to_string(),
            ),
            arguments: vec![PromptArgument {
                name: "goal".to_string(),
                description: Some("The end-to-end outcome you want to achieve".to_string()),
                required: true,
            }],
        },
    ]
}

/// Prefix used to identify gateway-owned prompts in routing.
const GATEWAY_PROMPT_PREFIX: &str = "gateway/";

/// Serve the `gateway-discover` prompt for a given task.
fn discover_prompt_messages(task: &str) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: "user".to_string(),
        content: Content::Text {
            text: format!(
                "I want to: {task}\n\n\
                     Please use gateway_search_tools to find relevant tools, \
                     then call gateway_invoke with the best match.\n\n\
                     Steps:\n\
                     1. Call gateway_search_tools(query=\"<keyword from the task>\")\n\
                     2. Pick the best match from the results\n\
                     3. Call gateway_invoke(server=\"<server>\", tool=\"<tool>\", arguments={{...}})\n\
                     4. Report the result"
            ),
            annotations: None,
        },
    }]
}

/// Serve the `gateway-compose` prompt for a given goal.
fn compose_prompt_messages(goal: &str) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: "user".to_string(),
        content: Content::Text {
            text: format!(
                "Build a multi-step workflow to: {goal}\n\n\
                     Use gateway tools as building blocks:\n\
                     1. Call gateway_search_tools to find candidate tools for each step\n\
                     2. Check \"chains_with\" hints in results to find pre-defined composition paths\n\
                     3. Execute each step via gateway_invoke, feeding outputs into subsequent steps\n\
                     4. Use gateway_cost_report() at the end to summarise spend\n\n\
                     Prefer composition chains over ad-hoc sequences when they are available."
            ),
            annotations: None,
        },
    }]
}

/// Try to serve a gateway-owned meta-prompt by name.
///
/// Returns `Some(JsonRpcResponse)` when the name matches a known prompt;
/// `None` when the name refers to a backend prompt and should be routed normally.
fn try_serve_gateway_prompt(
    id: RequestId,
    name: &str,
    arguments: Option<&Value>,
) -> Option<JsonRpcResponse> {
    let messages = match name {
        "gateway/gateway-discover" => {
            let task =
                extract_nested_optional_str(arguments, "task").unwrap_or("complete the task");
            discover_prompt_messages(task)
        }
        "gateway/gateway-compose" => {
            let goal =
                extract_nested_optional_str(arguments, "goal").unwrap_or("accomplish the goal");
            compose_prompt_messages(goal)
        }
        _ => return None,
    };
    Some(JsonRpcResponse::success(
        id,
        json!({ "messages": messages }),
    ))
}

impl MetaMcp {
    /// Handle `prompts/list` — gateway meta-prompts + aggregated backend prompts.
    ///
    /// Gateway-owned meta-prompts (names prefixed `gateway/`) are prepended so
    /// clients always discover them first.  Backend prompts are namespaced as
    /// `"backend_name/original_name"` so `prompts/get` can route them correctly.
    ///
    /// # Panics
    ///
    /// Panics if `PromptsListResult` fails to serialize to JSON, which cannot
    /// occur in practice as the type derives `Serialize` with no fallible fields.
    pub async fn handle_prompts_list(
        &self,
        id: RequestId,
        _params: Option<&Value>,
    ) -> JsonRpcResponse {
        // Prepend gateway-owned meta-prompts (served inline, no backend required).
        let mut all_prompts: Vec<Prompt> = gateway_prompts().into();

        for backend in self.backends.all() {
            match backend.get_prompts_shared().await {
                Ok(prompts) => {
                    for prompt in prompts.iter() {
                        let mut prompt = prompt.clone();
                        prompt.name = format!("{}/{}", backend.name, prompt.name);
                        all_prompts.push(prompt);
                    }
                }
                Err(e) => {
                    warn!(
                        backend = %backend.name,
                        error = %e,
                        "Failed to fetch prompts from backend"
                    );
                }
            }
        }

        let result = PromptsListResult {
            prompts: all_prompts,
            next_cursor: None,
        };
        JsonRpcResponse::success_serialized(id, result)
    }

    /// Handle `prompts/get` — gateway meta-prompts take priority, then backend routing.
    ///
    /// Names prefixed `gateway/` are served inline without a backend round-trip.
    /// All other names are routed using the `"backend_name/original_name"` convention.
    pub async fn handle_prompts_get(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let Some(name) = extract_nested_optional_str(params, "name") else {
            return missing_parameter_response(&id, "name");
        };

        // Gateway-owned meta-prompts are served inline — no backend round-trip.
        if name.starts_with(GATEWAY_PROMPT_PREFIX) {
            let arguments = params.and_then(|p| p.get("arguments"));
            if let Some(response) = try_serve_gateway_prompt(id.clone(), name, arguments) {
                return response;
            }
            return JsonRpcResponse::error(
                Some(id),
                -32002,
                format!("Unknown gateway prompt: '{name}'"),
            );
        }

        let Some((backend_name, original_name)) = name.split_once('/') else {
            return JsonRpcResponse::error(
                Some(id),
                -32602,
                format!(
                    "Invalid prompt name format: '{name}'. Expected 'backend_name/prompt_name'"
                ),
            );
        };

        let Some(backend) = self.backends.get(backend_name) else {
            return JsonRpcResponse::error(
                Some(id),
                -32001,
                format!("Backend not found: {backend_name}"),
            );
        };

        let mut forward_params = json!({ "name": original_name });
        if let Some(arguments) = params.and_then(|p| p.get("arguments")) {
            forward_params["arguments"] = arguments.clone();
        }

        match backend.request("prompts/get", Some(forward_params)).await {
            Ok(resp) => {
                if let Some(error) = resp.error {
                    JsonRpcResponse::error(Some(id), error.code, error.message)
                } else {
                    JsonRpcResponse::success(id, resp.result.unwrap_or(json!({"messages": []})))
                }
            }
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }

    /// Handle `logging/setLevel` — store level and broadcast to all backends.
    ///
    /// Updates the gateway-wide log level and forwards the request to every
    /// running backend.  Backends that fail to accept the level are logged
    /// but do not cause the overall request to fail.
    pub async fn handle_logging_set_level(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let level_params: LoggingSetLevelParams =
            match params.map(|p| serde_json::from_value::<LoggingSetLevelParams>(p.clone())) {
                Some(Ok(p)) => p,
                Some(Err(e)) => {
                    return JsonRpcResponse::error(
                        Some(id),
                        -32602,
                        format!("Invalid logging/setLevel params: {e}"),
                    );
                }
                None => {
                    return JsonRpcResponse::error(
                        Some(id),
                        -32602,
                        "Missing params for logging/setLevel",
                    );
                }
            };

        *self.log_level.write() = level_params.level;
        debug!(level = ?level_params.level, "Logging level updated");

        let forward_params = serde_json::to_value(&level_params).unwrap_or_else(|err| {
            warn!(error = %err, "failed to serialize logging/setLevel params for backend forwarding");
            json!({})
        });
        for backend in self.backends.all() {
            if let Err(e) = backend
                .request("logging/setLevel", Some(forward_params.clone()))
                .await
            {
                warn!(
                    backend = %backend.name,
                    error = %e,
                    "Failed to forward logging/setLevel to backend"
                );
            }
        }

        JsonRpcResponse::success(id, json!({}))
    }

    /// Get the current gateway-wide logging level.
    #[must_use]
    #[allow(dead_code)]
    pub fn current_log_level(&self) -> LoggingLevel {
        *self.log_level.read()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RequestId;
    use serde_json::json;

    #[test]
    fn gateway_prompts_returns_exactly_two_entries() {
        // GIVEN/WHEN: calling gateway_prompts()
        // THEN: exactly 2 prompts are returned
        let prompts = gateway_prompts();
        assert_eq!(prompts.len(), 2);
    }

    #[test]
    fn gateway_prompts_names_use_gateway_prefix() {
        // GIVEN/WHEN: calling gateway_prompts()
        // THEN: all names start with "gateway/"
        for prompt in gateway_prompts() {
            assert!(
                prompt.name.starts_with(GATEWAY_PROMPT_PREFIX),
                "prompt '{}' must start with '{GATEWAY_PROMPT_PREFIX}'",
                prompt.name
            );
        }
    }

    #[test]
    fn gateway_prompts_have_required_arguments() {
        // GIVEN/WHEN: calling gateway_prompts()
        // THEN: each prompt declares at least one required argument
        for prompt in gateway_prompts() {
            assert!(
                !prompt.arguments.is_empty(),
                "prompt '{}' must have at least one argument",
                prompt.name
            );
            assert!(
                prompt.arguments.iter().any(|a| a.required),
                "prompt '{}' must have a required argument",
                prompt.name
            );
        }
    }

    #[test]
    fn try_serve_gateway_prompt_returns_some_for_discover() {
        // GIVEN: discover prompt name with task argument
        let id = RequestId::Number(1);
        let args = json!({ "task": "search the web" });
        // WHEN: serving the prompt
        let resp = try_serve_gateway_prompt(id, "gateway/gateway-discover", Some(&args));
        // THEN: Some response returned
        assert!(resp.is_some());
    }

    #[test]
    fn try_serve_gateway_prompt_returns_some_for_compose() {
        // GIVEN: compose prompt name with goal argument
        let id = RequestId::Number(2);
        let args = json!({ "goal": "analyse a company" });
        // WHEN: serving the prompt
        let resp = try_serve_gateway_prompt(id, "gateway/gateway-compose", Some(&args));
        // THEN: Some response returned
        assert!(resp.is_some());
    }

    #[test]
    fn try_serve_gateway_prompt_returns_none_for_unknown_name() {
        // GIVEN: an unknown gateway prompt name
        let id = RequestId::Number(3);
        // WHEN: calling try_serve_gateway_prompt
        // THEN: None — falls through to backend routing
        let resp = try_serve_gateway_prompt(id, "gateway/unknown-prompt", None);
        assert!(resp.is_none());
    }

    #[test]
    fn try_serve_gateway_prompt_response_contains_messages_array() {
        // GIVEN: discover prompt with task argument
        let id = RequestId::Number(4);
        let args = json!({ "task": "find weather data" });
        // WHEN: serving the prompt
        let resp = try_serve_gateway_prompt(id, "gateway/gateway-discover", Some(&args)).unwrap();
        // THEN: result contains a non-empty messages array
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let messages = result["messages"].as_array().unwrap();
        assert!(!messages.is_empty());
    }

    #[test]
    fn discover_prompt_messages_embed_the_task() {
        // GIVEN: a specific task string
        // WHEN: generating discover prompt messages
        // THEN: the task appears in the first message text
        let messages = discover_prompt_messages("debug a Rust compiler error");
        assert!(!messages.is_empty());
        if let Content::Text { text, .. } = &messages[0].content {
            assert!(text.contains("debug a Rust compiler error"));
        } else {
            panic!("Expected text content in discover prompt");
        }
    }

    #[test]
    fn compose_prompt_messages_embed_the_goal() {
        // GIVEN: a specific goal string
        // WHEN: generating compose prompt messages
        // THEN: the goal appears in the first message text
        let messages = compose_prompt_messages("publish a release to GitHub");
        assert!(!messages.is_empty());
        if let Content::Text { text, .. } = &messages[0].content {
            assert!(text.contains("publish a release to GitHub"));
        } else {
            panic!("Expected text content in compose prompt");
        }
    }

    #[test]
    fn try_serve_gateway_prompt_uses_default_when_arguments_missing() {
        // GIVEN: discover prompt with no arguments
        let id = RequestId::Number(5);
        // WHEN: serving without arguments
        // THEN: response is still Some (uses fallback task text)
        let resp = try_serve_gateway_prompt(id, "gateway/gateway-discover", None);
        assert!(resp.is_some());
    }
}
