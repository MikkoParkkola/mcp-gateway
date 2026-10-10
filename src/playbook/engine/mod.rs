// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Playbook execution engine.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use serde_json::Value;
use tracing::{debug, warn};

use super::{
    ErrorStrategy, PlaybookContext, PlaybookDefinition, PlaybookResult, PlaybookStep, ToolInvoker,
    evaluate_condition, var_refs_in,
};
#[cfg(test)]
use super::{OutputMapping, PlaybookOutput, extract_var_refs, is_truthy};
use crate::protocol::continuation::{PROBE_OPENS_PER_STEP, ProbeBudget, ProbeRefusal};

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
                        Ok(def) if !def.sealed_state_references().is_empty() => {
                            for (step, reference) in def.sealed_state_references() {
                                warn!(path = %file_path.display(), step = %step, reference = %reference,
                                    "Skipped playbook: a step argument names a sealed requestState");
                            }
                        }
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
        // Refused whole, before any step runs: the playbook was written to
        // hand the gateway's envelope to a backend (MIK-8323).
        if let Some((step, reference)) = definition.sealed_state_references().into_iter().next() {
            return Err(crate::Error::Forbidden {
                code: -32003,
                status: 403,
                message: format!(
                    "playbook '{}' refused: step '{step}' argument {reference} names a sealed requestState",
                    definition.name
                ),
            });
        }
        let start = Instant::now();
        let timeout = std::time::Duration::from_secs(definition.timeout);
        let mut ctx = PlaybookContext::new(inputs);

        let mut steps_completed = Vec::new();
        let mut steps_skipped = Vec::new();
        let mut steps_failed = Vec::new();
        // Why each failed step failed. Populated for the strategies that carry
        // on past a failure, so a partial result explains itself.
        let mut step_errors = std::collections::BTreeMap::new();

        // Each completed step's label, its index in `steps` (MIK-8113).
        let mut labels: HashMap<String, u32> = HashMap::new();
        for (index, step) in definition.steps.iter().enumerate() {
            let label = u32::try_from(index).unwrap_or(u32::MAX);
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

            let max_attempts = if definition.on_error == ErrorStrategy::Retry {
                definition.max_retries.max(1)
            } else {
                1
            };
            // Checked and interpolated once, outside the retry loop: a retry
            // re-sends the same arguments and must not refill the probe budget.
            let outcome = match checked_arguments(&ctx, step, invoker) {
                Ok(arguments) => dispatch(step, label, arguments, max_attempts, invoker).await,
                Err(refusal) => {
                    warn!(step = %step.name, error = %refusal, refused = true, "Step failed");
                    Err(refusal)
                }
            };

            match outcome {
                Ok(result) => {
                    debug!(step = %step.name, "Step completed");
                    labels.insert(step.name.clone(), label);
                    ctx.step_results.insert(step.name.clone(), result);
                    steps_completed.push(step.name.clone());
                }
                Err(e) => {
                    steps_failed.push(step.name.clone());
                    match definition.on_error {
                        ErrorStrategy::Abort => return Err(e),
                        ErrorStrategy::Continue | ErrorStrategy::Retry => {
                            // Both arms null-fill and carry on, so both must say
                            // why: a null with no reason is how a caller ends up
                            // with a partial result that reads like a success.
                            step_errors.insert(step.name.clone(), e.to_string());
                            // Already retried if Retry; continue to next step.
                            ctx.step_results.insert(step.name.clone(), Value::Null);
                        }
                    }
                }
            }
        }

        // Build output
        let (output, provenance) = build_output(definition, &ctx, &labels);
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(PlaybookResult {
            output,
            steps_completed,
            steps_skipped,
            steps_failed,
            step_errors,
            duration_ms,
            provenance,
        })
    }
}

/// `step`'s arguments, interpolated, or a refusal when a value a reference
/// resolves to carries the gateway's envelope (MIK-8323). Each resolved value
/// is checked BEFORE substitution: text glued around it could hide it from a
/// scan of the rendered string. One probe budget covers the whole step.
fn checked_arguments(
    ctx: &PlaybookContext,
    step: &PlaybookStep,
    invoker: &dyn ToolInvoker,
) -> crate::Result<Value> {
    let raw = Value::Object(
        step.arguments
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    );
    let mut refs = Vec::new();
    var_refs_in(&raw, &mut refs);
    let mut budget = ProbeBudget::new(PROBE_OPENS_PER_STEP);
    for reference in &refs {
        let why = match invoker.sealed_state_in(&ctx.resolve_var(reference), &mut budget) {
            Ok(false) => continue,
            Ok(true) => "carries a sealed continuation state",
            Err(ProbeRefusal::TooManyCandidates) => {
                "has too many continuation-shaped values to check"
            }
            Err(ProbeRefusal::ClockUnreadable) => "cannot be checked while the clock is unreadable",
        };
        return Err(crate::Error::Forbidden {
            code: -32003,
            status: 403,
            message: format!("step '{}' refused: {reference} {why}", step.name),
        });
    }
    Ok(ctx.interpolate(&raw))
}

/// Invoke `step` up to `max_attempts` times; the last error when none succeeds.
async fn dispatch(
    step: &PlaybookStep,
    label: u32,
    arguments: Value,
    max_attempts: u32,
    invoker: &dyn ToolInvoker,
) -> crate::Result<Value> {
    let mut last_error = None;
    for attempt in 0..max_attempts.max(1) {
        if attempt > 0 {
            debug!(step = %step.name, attempt, "Retrying step");
        }
        match STEP
            .scope(
                label,
                invoker.invoke(&step.server, &step.tool, arguments.clone()),
            )
            .await
        {
            Ok(result) => return Ok(result),
            Err(e) => {
                // A refusal is not a flaky backend. Retrying it cannot change
                // the answer, and `max_retries` would turn one denial into N
                // identical ones — waste that reads like a brute-force attempt
                // in the audit log. Ordinary errors keep retrying: that
                // distinction is the whole reason the refusal carries its own
                // variant instead of arriving as an opaque error.
                let refused = matches!(e, crate::Error::Forbidden { .. });
                warn!(step = %step.name, error = %e, refused, "Step failed");
                if refused {
                    return Err(e);
                }
                last_error = Some(e);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        crate::Error::Internal(format!("Step '{}' was never attempted", step.name))
    }))
}

impl Default for PlaybookEngine {
    fn default() -> Self {
        Self::new()
    }
}

tokio::task_local! {
    /// The label of the step being invoked: its index in `steps`.
    static STEP: u32;
}

/// The label of the playbook step whose invocation this task runs, if any:
/// its index in the definition's `steps` (MIK-8113).
pub(crate) fn current_step() -> Option<u32> {
    STEP.try_with(|label| *label).ok()
}

/// Build the final output from output mappings or raw step results, and
/// which output member each completed step produced, by its label: only a
/// member resolved from that step's own result, never a fallback or an
/// input (MIK-8113).
fn build_output(
    definition: &PlaybookDefinition,
    ctx: &PlaybookContext,
    labels: &HashMap<String, u32>,
) -> (Value, Vec<(String, u32)>) {
    let mut provenance = Vec::new();
    let Some(ref output_def) = definition.output else {
        // No output mapping: return all step results.
        for (name, label) in labels {
            provenance.push((name.clone(), *label));
        }
        let all = ctx
            .step_results
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        return (Value::Object(all), provenance);
    };

    let mut result = serde_json::Map::new();
    for (prop_name, mapping) in &output_def.properties {
        let resolved = ctx.resolve_var(&mapping.path);
        let step = mapping
            .path
            .trim_start_matches('$')
            .split('.')
            .next()
            .filter(|name| *name != "inputs")
            .and_then(|name| labels.get(name));
        if let (Some(label), false) = (step, resolved.is_null()) {
            provenance.push((prop_name.clone(), *label));
        }
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
    (Value::Object(result), provenance)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod envelope_tests;
#[cfg(test)]
mod tests;
