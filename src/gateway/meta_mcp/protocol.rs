//! MCP protocol handlers for prompts and logging.
//!
//! Implements `prompts/list`, `prompts/get`, `logging/setLevel`, and
//! `current_log_level`.

use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::protocol::{
    JsonRpcResponse, LoggingLevel, LoggingSetLevelParams, Prompt, PromptsListResult, RequestId,
};

use super::MetaMcp;

impl MetaMcp {
    /// Handle `prompts/list` — aggregate prompts from all backends.
    ///
    /// Prefixes each prompt name with `"backend_name/"` so that `prompts/get`
    /// can route back to the correct backend.
    pub async fn handle_prompts_list(
        &self,
        id: RequestId,
        _params: Option<&Value>,
    ) -> JsonRpcResponse {
        let mut all_prompts: Vec<Prompt> = Vec::new();

        for backend in self.backends.all() {
            match backend.get_prompts().await {
                Ok(prompts) => {
                    for mut prompt in prompts {
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
        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Handle `prompts/get` — route to the correct backend based on name prefix.
    ///
    /// Prompt names are namespaced as `"backend_name/original_prompt_name"`.
    /// Splits on the first `/` to recover the backend name and original name.
    pub async fn handle_prompts_get(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let Some(name) = params.and_then(|p| p.get("name")).and_then(Value::as_str) else {
            return JsonRpcResponse::error(Some(id), -32602, "Missing 'name' parameter");
        };

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

        let forward_params = serde_json::to_value(&level_params).unwrap_or(json!({}));
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
