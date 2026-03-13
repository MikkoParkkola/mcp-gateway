//! Playbook execution engine.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use serde_json::Value;
use tracing::{debug, warn};

use super::{
    ErrorStrategy, PlaybookContext, PlaybookDefinition, PlaybookResult, ToolInvoker,
    evaluate_condition,
};
#[cfg(test)]
use super::{OutputMapping, PlaybookOutput, PlaybookStep, extract_var_refs, is_truthy};

/// Engine that loads and executes playbooks.
pub struct PlaybookEngine {
    definitions: HashMap<String, PlaybookDefinition>,
}

impl PlaybookEngine {
    /// Create an empty engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            definitions: HashMap::new(),
        }
    }

    /// Load playbooks from a directory (reads all `*.yaml` files).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read.
    pub fn load_from_directory(&mut self, dir: &str) -> crate::Result<usize> {
        let path = Path::new(dir);
        if !path.is_dir() {
            return Ok(0);
        }

        let mut count = 0;
        for entry in std::fs::read_dir(path).map_err(|e| {
            crate::Error::Config(format!("Failed to read playbooks directory '{dir}': {e}"))
        })? {
            let entry = entry.map_err(|e| {
                crate::Error::Config(format!("Failed to read directory entry: {e}"))
            })?;

            let file_path = entry.path();
            if file_path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                match std::fs::read_to_string(&file_path) {
                    Ok(content) => match serde_yaml::from_str::<PlaybookDefinition>(&content) {
                        Ok(def) => {
                            debug!(name = %def.name, path = %file_path.display(), "Loaded playbook");
                            self.definitions.insert(def.name.clone(), def);
                            count += 1;
                        }
                        Err(e) => {
                            warn!(path = %file_path.display(), error = %e, "Failed to parse playbook");
                        }
                    },
                    Err(e) => {
                        warn!(path = %file_path.display(), error = %e, "Failed to read playbook file");
                    }
                }
            }
        }

        Ok(count)
    }

    /// Register a playbook definition directly.
    pub fn register(&mut self, definition: PlaybookDefinition) {
        self.definitions.insert(definition.name.clone(), definition);
    }

    /// Get a playbook definition by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PlaybookDefinition> {
        self.definitions.get(name)
    }

    /// List all playbook names.
    pub fn list(&self) -> Vec<&str> {
        self.definitions.keys().map(String::as_str).collect()
    }

    /// Get the number of loaded playbooks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.definitions.len()
    }

    /// Check if there are no loaded playbooks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }

    /// Execute a playbook by name.
    ///
    /// # Errors
    ///
    /// Returns an error if the playbook is not found, a step fails (with abort strategy),
    /// or the total timeout is exceeded.
    pub async fn execute(
        &self,
        name: &str,
        inputs: Value,
        invoker: &dyn ToolInvoker,
    ) -> crate::Result<PlaybookResult> {
        let definition = self
            .get(name)
            .ok_or_else(|| crate::Error::Config(format!("Playbook not found: {name}")))?;

        self.execute_definition(definition, inputs, invoker).await
    }

    /// Execute a playbook from its definition.
    async fn execute_definition(
        &self,
        definition: &PlaybookDefinition,
        inputs: Value,
        invoker: &dyn ToolInvoker,
    ) -> crate::Result<PlaybookResult> {
        let start = Instant::now();
        let timeout = std::time::Duration::from_secs(definition.timeout);
        let mut ctx = PlaybookContext::new(inputs);

        let mut steps_completed = Vec::new();
        let mut steps_skipped = Vec::new();
        let mut steps_failed = Vec::new();

        for step in &definition.steps {
            // Check timeout
            if start.elapsed() > timeout {
                return Err(crate::Error::Internal(format!(
                    "Playbook '{}' exceeded timeout of {}s",
                    definition.name, definition.timeout
                )));
            }

            // Evaluate condition
            if let Some(ref condition) = step.condition
                && !evaluate_condition(condition, &ctx)
            {
                debug!(step = %step.name, "Step skipped (condition false)");
                steps_skipped.push(step.name.clone());
                continue;
            }

            // Interpolate arguments
            let arguments = ctx.interpolate(&Value::Object(
                step.arguments
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ));

            // Execute with retry
            let mut last_error = None;
            let max_attempts = if definition.on_error == ErrorStrategy::Retry {
                definition.max_retries.max(1)
            } else {
                1
            };

            let mut succeeded = false;
            for attempt in 0..max_attempts {
                if attempt > 0 {
                    debug!(step = %step.name, attempt, "Retrying step");
                }

                match invoker
                    .invoke(&step.server, &step.tool, arguments.clone())
                    .await
                {
                    Ok(result) => {
                        debug!(step = %step.name, "Step completed");
                        ctx.step_results.insert(step.name.clone(), result);
                        steps_completed.push(step.name.clone());
                        succeeded = true;
                        break;
                    }
                    Err(e) => {
                        warn!(step = %step.name, error = %e, "Step failed");
                        last_error = Some(e);
                    }
                }
            }

            if !succeeded {
                steps_failed.push(step.name.clone());
                match definition.on_error {
                    ErrorStrategy::Abort => {
                        return Err(last_error.unwrap_or_else(|| {
                            crate::Error::Internal(format!(
                                "Step '{}' failed in playbook '{}'",
                                step.name, definition.name
                            ))
                        }));
                    }
                    ErrorStrategy::Continue | ErrorStrategy::Retry => {
                        // Already retried if Retry; continue to next step.
                        ctx.step_results.insert(step.name.clone(), Value::Null);
                    }
                }
            }
        }

        // Build output
        let output = build_output(definition, &ctx);
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(PlaybookResult {
            output,
            steps_completed,
            steps_skipped,
            steps_failed,
            duration_ms,
        })
    }
}

impl Default for PlaybookEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the final output from output mappings or raw step results.
fn build_output(definition: &PlaybookDefinition, ctx: &PlaybookContext) -> Value {
    let Some(ref output_def) = definition.output else {
        // No output mapping: return all step results.
        return Value::Object(
            ctx.step_results
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        );
    };

    let mut result = serde_json::Map::new();
    for (prop_name, mapping) in &output_def.properties {
        let resolved = ctx.resolve_var(&mapping.path);
        if resolved.is_null() {
            if let Some(ref fallback) = mapping.fallback {
                result.insert(prop_name.clone(), fallback.clone());
            } else {
                result.insert(prop_name.clone(), Value::Null);
            }
        } else {
            result.insert(prop_name.clone(), resolved);
        }
    }
    Value::Object(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;
