// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Playbook execution engine.

use crate::error::rpc_codes::INTERNAL_ERROR;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use serde_json::{Value, json};
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
                    Ok(content) => match crate::yaml::from_str::<PlaybookDefinition>(&content) {
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
        // Whether any attempt so far had an outcome other than a busy custody,
        // so may have reached a backend (MIK-8429 C1b). Conservative: a
        // refusal before its send counts too.
        let mut attempted = false;
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
            let (outcome, sent) =
                run_step(&ctx, step, label, max_attempts, invoker, &mut attempted).await;

            match outcome {
                Ok(result) => {
                    debug!(step = %step.name, "Step completed");
                    labels.insert(step.name.clone(), label);
                    ctx.step_results.insert(step.name.clone(), result);
                    steps_completed.push(step.name.clone());
                }
                // A busy custody refused the step before its send: the plan
                // ends here under every policy, no null fill and no successor
                // (MIK-8429 STEP.1). Retryable only while nothing in the plan
                // may have reached a backend; after that, a retry label would
                // invite a re-run of what already ran.
                Err(e) if is_busy(&e) => {
                    warn!(step = %step.name, error = %e, "Step met a busy custody; plan ends");
                    if attempted {
                        return Err(crate::Error::Transport(format!(
                            "after an earlier step ran: {e}"
                        )));
                    }
                    return Err(e);
                }
                Err(e) => {
                    steps_failed.push(step.name.clone());
                    match definition.on_error {
                        ErrorStrategy::Abort if sent => return Err(e.with_may_have_run()),
                        ErrorStrategy::Abort => return Err(e),
                        ErrorStrategy::Continue | ErrorStrategy::Retry => {
                            // Carried on past: this step no longer ends the plan.
                            crate::gateway::delivery_facts::step_absorbed();
                            // Both arms null-fill and carry on, so both must say
                            // why: a null with no reason is how a caller ends up
                            // with a partial result that reads like a success.
                            step_errors.insert(step.name.clone(), step_reason(&e));
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

/// One step's outcome, and whether it came from dispatching the step
/// (`true`) rather than from refusing its arguments before any send. The
/// arguments are checked and interpolated once, outside the retry loop: a
/// retry re-sends the same arguments and must not refill the probe budget.
async fn run_step(
    ctx: &PlaybookContext,
    step: &PlaybookStep,
    label: u32,
    max_attempts: u32,
    invoker: &dyn ToolInvoker,
    attempted: &mut bool,
) -> (crate::Result<Value>, bool) {
    match checked_arguments(ctx, step, invoker) {
        Ok(arguments) => (
            dispatch(step, label, arguments, max_attempts, invoker, attempted).await,
            true,
        ),
        Err(refusal) => {
            warn!(step = %step.name, error = %refusal, refused = true, "Step failed");
            (Err(refusal), false)
        }
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
/// A result whose tool reported failure (`isError: true`) fails the step
/// (MIK-8429 PBERR.1) and is never re-sent: the tool ran and answered, so its
/// side effect may be done (the hold, D1). `attempted` is set by every outcome
/// that is not a busy custody.
async fn dispatch(
    step: &PlaybookStep,
    label: u32,
    arguments: Value,
    max_attempts: u32,
    invoker: &dyn ToolInvoker,
    attempted: &mut bool,
) -> crate::Result<Value> {
    let mut last_error = None;
    for attempt in 0..max_attempts.max(1) {
        if attempt > 0 {
            debug!(step = %step.name, attempt, "Retrying step");
        }
        let outcome = STEP
            .scope(
                label,
                invoker.invoke(&step.server, &step.tool, arguments.clone()),
            )
            .await;
        if !matches!(&outcome, Err(e) if is_busy(e)) {
            *attempted = true;
        }
        match outcome {
            // Final under every policy, keyed or not: a retry cannot be told
            // apart from a second send of whatever the first one did (D1).
            Ok(result) if is_tool_error(&result) => {
                warn!(step = %step.name, "Step failed: the tool reported an error");
                return Err(tool_error(step, &result));
            }
            Ok(result) => return Ok(result),
            // Nothing was sent, and an immediate re-send meets the same held
            // custody: the plan ends at the caller (STEP.1).
            Err(e) if is_busy(&e) => return Err(e),
            Err(e) => {
                // A refusal is not a flaky backend. Retrying it cannot change
                // the answer, and `max_retries` would turn one denial into N
                // identical ones — waste that reads like a brute-force attempt
                // in the audit log. Ordinary errors keep retrying: that
                // distinction is the whole reason the refusal carries its own
                // variant instead of arriving as an opaque error. A firewall
                // refusal is as final as a denial (MIK-8325): the gate's verdict
                // on the same answer will not change, and a retry calls the
                // backend again.
                let refused = matches!(
                    e,
                    crate::Error::Forbidden { .. } | crate::Error::ResponseFirewallRefused
                );
                warn!(step = %step.name, error = %e, refused, "Step failed");
                // Re-sent only when the error was raised before the request
                // was sent: anything later may have acted, and a second send
                // would repeat it.
                if refused || !e.is_pre_dispatch() {
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

/// Whether a tool reported failure in the success channel: `isError` is the
/// JSON boolean `true` (the rule `gateway_execute` chains apply,
/// `chain_exec::chain_step_result`).
pub(crate) fn is_tool_error(result: &Value) -> bool {
    result.get("isError").and_then(Value::as_bool) == Some(true)
}

/// The most of a tool's text a step failure carries (the hold, D3). The
/// JSON-RPC renderer forwards [`TOOL_TEXT_DATA_KEY`] only within it.
pub(crate) const TOOL_TEXT_CAP: usize = 256;

/// The error `data` key a step failure carries the tool's capped text under.
pub(crate) const TOOL_TEXT_DATA_KEY: &str = "tool_text";

/// The step failure for a tool error: -32603 with a fixed message, so the
/// tool's text never reaches a log line that prints the error (the hold,
/// D3). The caller still gets the tool's first text, at most
/// [`TOOL_TEXT_CAP`] characters and marked when cut, as `data.tool_text`.
fn tool_error(step: &PlaybookStep, result: &Value) -> crate::Error {
    let text = result["content"][0]["text"]
        .as_str()
        .map_or_else(|| result.to_string(), str::to_owned);
    let capped = crate::truncate::truncate(
        &text,
        crate::truncate::Budget::Chars(TOOL_TEXT_CAP),
        "…",
        crate::truncate::Suffix::After,
    );
    crate::Error::JsonRpc {
        code: INTERNAL_ERROR,
        message: format!("step '{}' failed: the tool reported an error", step.name),
        data: Some(json!({ TOOL_TEXT_DATA_KEY: capped })),
    }
}

/// A failed step's entry in `step_errors`, caller output, not a log: the
/// error and, for a tool error, its capped text.
fn step_reason(error: &crate::Error) -> String {
    let reason = match error {
        crate::Error::JsonRpc {
            data: Some(data), ..
        } if data[TOOL_TEXT_DATA_KEY].is_string() => {
            format!(
                "{error}: {}",
                data[TOOL_TEXT_DATA_KEY].as_str().unwrap_or_default()
            )
        }
        _ => error.to_string(),
    };
    // A null-filled step returns success, so no outer settlement sees this
    // error: the reason itself says the step may have run.
    crate::error::step_failure_text(error, reason)
}

/// The gateway-sealed transient a busy custody raises before any send,
/// recognised by its seal, never by its text (MIK-8429 STEP.3).
fn is_busy(error: &crate::Error) -> bool {
    crate::personal_accounts::refusal::transient_data(error).is_some()
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

/// Run `future` as playbook step `label` (tests that read `current_step`).
#[cfg(test)]
pub(crate) async fn in_step<F: std::future::Future>(label: u32, future: F) -> F::Output {
    STEP.scope(label, future).await
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
mod busy_tests;
#[cfg(test)]
mod envelope_tests;
#[cfg(test)]
mod step_retry_tests;
#[cfg(test)]
mod tests;
