// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `service: mcp` execution (MIK-7782).
//!
//! No second MCP client: each (capability, caller) gets its own
//! [`crate::backend::Backend`] over a stdio child, built from the pinned
//! command, so one caller never sees another's open documents, projects or
//! imports. The child runs in a private directory tree that lives exactly as
//! long as it does. These backends are never registered as public servers.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use super::CapabilityExecutor;
use super::cli_argv::render_json;
use super::cli_run::{Workdir, child_env, is_reserved};
use crate::backend::Backend;
use crate::capability::definition::{McpConfig, ToolCall};
use crate::capability::{CapabilityDefinition, CapabilityExecutionContext};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::error::rpc_codes::INVALID_PARAMS;
use crate::protocol::JsonRpcResponse;
use crate::{Error, Result};

#[path = "mcp_children.rs"]
mod children;
use children::IDLE_STOP;
#[cfg(test)]
use children::MAX_CHILDREN_PER_CAPABILITY;
pub(crate) use children::McpChildren;

/// Which child a call belongs to: the dispatch binding, else the verified
/// OIDC subject, else the caller's grant subject, else, on a multi-user
/// gateway, an authenticated caller's credential owner key. A caller none of
/// these names
/// shares the one child of a single-user gateway and is refused on a
/// multi-user one, where sharing would hand it another caller's state.
pub(crate) fn principal(
    capability: &CapabilityDefinition,
    context: &CapabilityExecutionContext,
    multi_user: bool,
) -> Result<String> {
    if let Some(binding) = context.cache_binding.as_deref() {
        return Ok(format!("idp:{}:{binding}", binding.len()));
    }
    if let Some(identity) = context.verified_identity.as_deref() {
        return Ok(identity.stable_actor_id());
    }
    if let Some(subject) = context.caller_identity.as_ref() {
        return Ok(format!(
            "grant:{}:{}:{}:{}",
            subject.authority().len(),
            subject.authority(),
            subject.subject().len(),
            subject.subject()
        ));
    }
    // An API-key caller named by nothing above: its credential owner key
    // (MIK-7825), the same string for a live call and the task it starts.
    // Multi-user only: a single-user gateway keeps serving every key the one
    // operator child, as before.
    if multi_user
        && let Some(owner) = context
            .credential_principal
            .as_deref()
            .filter(|owner| !owner.is_empty())
    {
        return Ok(format!("cred:{}:{owner}", owner.len()));
    }
    if multi_user {
        return Err(Error::Config(format!(
            "capability '{}' keeps per-caller state, so on a multi-user gateway it needs an \
             identified caller",
            capability.name
        )));
    }
    Ok("operator".to_owned())
}

/// What `select` resolves for one call.
struct Selected<'a> {
    tool: &'a str,
    template: Option<&'a Value>,
    prepare: Option<&'a crate::capability::definition::PrepareCall>,
    wait: Option<&'a crate::capability::definition::WaitStep>,
}

/// The tool, its argument template and any prepare step for this call.
fn select<'a>(config: &'a McpConfig, params: &Value) -> Result<Selected<'a>> {
    if let Some(selector) = &config.tool_selector {
        let op = params
            .get(&selector.param)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::json_rpc(
                    INVALID_PARAMS,
                    format!("missing parameter '{}'", selector.param),
                )
            })?;
        let ToolCall {
            tool,
            arguments,
            prepare,
            requires,
            wait,
        } = selector.tools.get(op).ok_or_else(|| {
            Error::json_rpc(INVALID_PARAMS, format!("unknown {} '{op}'", selector.param))
        })?;
        // Before a child is acquired: a call that cannot work spends no process.
        if let Some(missing) = requires
            .iter()
            .find(|name| params.get(name.as_str()).is_none_or(Value::is_null))
        {
            return Err(Error::json_rpc(
                INVALID_PARAMS,
                format!("operation '{op}' needs parameter '{missing}'"),
            ));
        }
        return Ok(Selected {
            tool,
            template: arguments.as_ref(),
            prepare: prepare.as_ref(),
            wait: wait.as_ref(),
        });
    }
    match &config.tool {
        Some(tool) => Ok(Selected {
            tool,
            template: config.arguments.as_ref(),
            prepare: None,
            wait: None,
        }),
        None => Err(Error::Config(
            "not executable: this mcp capability declares no tool mapping (`tool` or `tool_selector`)".into(),
        )),
    }
}

/// `deadline` from now. MIK-8207: the parser bounds a provider timeout, and a
/// deadline no clock can hold is still refused rather than added unchecked.
fn ends_after(deadline: Duration) -> Result<Instant> {
    Instant::now().checked_add(deadline).ok_or_else(|| {
        Error::Config(crate::duration_bound::too_long(
            "the capability's provider timeout",
        ))
    })
}

/// Poll `wait.tool` until `until` holds, `max_wait_s` passes, or the call's
/// own deadline cuts in. A tool error or an answer that does not match yet is
/// "not ready": the server answers an absent or unfinished item with an
/// error. A dead transport or a stopped backend ends the wait at once.
/// Running out of time says so and leaves the child alone, since a busy
/// server is not a wedged one.
async fn wait_ready(
    backend: &Backend,
    wait: &crate::capability::definition::WaitStep,
    params: &Value,
    call_ends: Instant,
) -> Result<Value> {
    let args = arguments(wait.arguments.as_ref(), params)?;
    let mut wanted = Vec::with_capacity(wait.until.matches.len());
    for (field, template) in &wait.until.matches {
        let value = render_json(&Value::String(template.clone()), params)?.ok_or_else(|| {
            Error::json_rpc(
                INVALID_PARAMS,
                format!("wait needs a value for '{template}'"),
            )
        })?;
        wanted.push((field.as_str(), value));
    }
    // Absolute: the configured wait, cut short by what is left of the call's own
    // deadline (less a second), so running out here is the non-evicting wait
    // timeout and never the outer timeout that discards the child.
    let cap = call_ends
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let ends = Instant::now()
        .checked_add(Duration::from_secs(wait.max_wait_s))
        .map_or(cap, |wait_ends| wait_ends.min(cap));
    let interval = Duration::from_millis(wait.interval_ms);
    loop {
        let poll = tokio::time::timeout_at(
            tokio::time::Instant::from_std(ends),
            call_tool(backend, &wait.tool, args.clone()),
        )
        .await;
        // A dead or broken transport ends the wait now, and so does a stopped
        // one (every `BackendNotFound` a start returns is a stop or a retire,
        // never a start still on its way); only the server's own "not there
        // yet" answers (tool errors) count as not ready.
        let stopped =
            mutant!("M8", false, matches!(&poll, Ok(Err(Error::BackendNotFound(_)))));
        if let Ok(Err(e @ (Error::Transport(_) | Error::TransportPermanent(_)))) = &poll {
            return Err(Error::Transport(format!("wait aborted: {e}")));
        }
        if let Ok(Err(e)) = &poll
            && stopped
        {
            return Err(Error::Transport(format!("wait aborted: {e}")));
        }
        if let Ok(Ok(result)) = poll
            && let Some(found) = result
                .get(&wait.until.array)
                .and_then(Value::as_array)
                .and_then(|items| {
                    items.iter().find(|item| {
                        wanted.iter().all(|(f, v)| item.get(*f) == Some(v))
                            && item.get(&wait.until.field) == Some(&wait.until.equals)
                    })
                })
        {
            return Ok(found.clone());
        }
        if Instant::now()
            .checked_add(interval)
            .is_none_or(|next| next >= ends)
        {
            return Err(Error::BackendTimeout(
                "not finished within the wait; poll again to keep waiting".to_string(),
            ));
        }
        tokio::time::sleep(interval).await;
    }
}

fn arguments(template: Option<&Value>, params: &Value) -> Result<Map<String, Value>> {
    match template {
        None => Ok(Map::new()),
        Some(template) => match render_json(template, params)? {
            Some(Value::Object(map)) => Ok(map),
            None => Ok(Map::new()),
            Some(_) => Err(Error::Config("mcp `arguments` must be a mapping".into())),
        },
    }
}

/// One `tools/call`; a JSON-RPC error or `isError` is an error.
async fn call_tool(backend: &Backend, tool: &str, args: Map<String, Value>) -> Result<Value> {
    // Type-erased on purpose: left generic, this future's auto-trait proof
    // runs through every transport (WebSocket's mio types on Windows) on top of
    // the whole invoke chain and overflows rustc's recursion limit.
    let request: Pin<Box<dyn Future<Output = Result<JsonRpcResponse>> + Send + '_>> =
        Box::pin(backend.request(
            "tools/call",
            Some(json!({ "name": tool, "arguments": args })),
        ));
    let response = request.await?;
    if let Some(error) = response.error {
        return Err(Error::Protocol(format!(
            "tool '{tool}' failed: {}",
            error.message
        )));
    }
    let result = response.result.unwrap_or(Value::Null);
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        let text: Vec<&str> = result
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|c| c.get("text").and_then(Value::as_str))
            .collect();
        return Err(Error::Protocol(format!(
            "tool '{tool}' reported an error: {}",
            text.join(" ")
        )));
    }
    Ok(result
        .get("structuredContent")
        .cloned()
        .or_else(|| result.get("content").cloned())
        .unwrap_or(result))
}

impl CapabilityExecutor {
    pub(super) async fn execute_mcp(
        &self,
        capability: &CapabilityDefinition,
        config: &McpConfig,
        params: &Value,
        context: &CapabilityExecutionContext,
    ) -> Result<Value> {
        super::cli::refuse_egress(capability)
            .inspect_err(|_| crate::gateway::delivery_facts::refused_while_vouched())?;
        let params = super::cli::confine_paths(capability, params, &self.process_policy.files)?;
        let Selected {
            tool,
            template,
            prepare,
            wait,
        } = select(config, &params)?;
        let principal = principal(capability, context, self.multi_user.load(Ordering::Acquire))?;
        self.mcp_children.ensure_sweeper();
        let lookup = self.env_lookup();
        let declared: Vec<(&String, String)> = config
            .env
            .iter()
            .filter_map(|name| lookup(name).map(|v| (name, v.to_string_lossy().into_owned())))
            .collect();
        // As `child_env`: the gateway sets a reserved name itself, never from
        // this list, so its value is no injected secret. The fingerprint below
        // still hashes every declared pair: the child's PATH is the gateway's
        // own, so a changed declared PATH must restart the child.
        let env_values: Vec<String> = declared
            .iter()
            .filter(|(name, _)| !is_reserved(name))
            .map(|(_, value)| value.clone())
            .collect();
        // A root is no secret, so it stays out of `env_values` (which results
        // are scrubbed of), but a changed one restarts the child.
        let roots = bound_roots(config, &self.process_policy.files);
        let env_fp = {
            use std::hash::{Hash as _, Hasher as _};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            declared.hash(&mut hasher);
            roots.hash(&mut hasher);
            hasher.finish()
        };
        // One deadline for the whole call, writes included: a server that stops
        // reading its stdin must not hold its slot (and so its eviction) forever.
        let deadline = Duration::from_secs(capability.primary_provider().map_or(30, |p| p.timeout));
        let generation = context.mcp_generation;
        let lease = self.mcp_children.acquire(
            capability,
            config,
            &principal,
            (env_fp, deadline),
            |current| generation.is_none_or(|g| g == current),
            || Self::start_mcp(capability, config, &lookup, &roots),
        )?;
        let backend = lease.backend;
        let _busy = lease.busy;
        let child_id = lease.id;
        let call_ends = ends_after(deadline)?;
        let outcome = tokio::time::timeout(deadline, async {
            let mut args = arguments(template, &params)?;
            // Once any round has reached the backend, a later round's refusal
            // is never "nothing was sent" (MIK-7923, design M9).
            let mut dispatched = false;
            if let Some(prepare) = prepare {
                run_prepare(&backend, prepare, &params, &mut args).await?;
                dispatched = true;
            }
            let result = call_tool(&backend, tool, args)
                .await
                .map_err(|error| after_dispatch(error, dispatched))?;
            match wait {
                Some(wait) => {
                    let ready = wait_ready(&backend, wait, &params, call_ends)
                        .await
                        .map_err(|error| after_dispatch(error, true))?;
                    Ok(json!({ "result": result, "ready": ready }))
                }
                None => Ok(result),
            }
        })
        .await;
        match outcome {
            // A server that did not answer in time may be wedged: stop it so the
            // next call starts a fresh one instead of timing out on the same.
            Err(_) => {
                self.mcp_children
                    .discard(&capability.name, &principal, child_id);
                Err(Error::BackendTimeout("MCP call timed out".to_string()))
            }
            Ok(result) => result
                // A successful result may carry an injected credential the
                // server echoed (MIK-7882): the same removal as an error, whole.
                .map(|mut value| {
                    super::cli::redact_value(&mut value, &env_values);
                    value
                })
                .map_err(|error| match error {
                    // The server's own error text may echo a credential it was
                    // given or a value the caller sent.
                    Error::Protocol(text) => Error::Protocol(super::cli::redact(
                        &text,
                        &env_values,
                        &super::cli::caller_values(&params),
                    )),
                    other => other,
                }),
        }
    }

    /// Environment lookup for a child: the config overlay, then the process.
    fn env_lookup(&self) -> impl Fn(&str) -> Option<std::ffi::OsString> + use<> {
        let overlay = self.env.get();
        move |name: &str| {
            overlay
                .resolve(name)
                .map(std::ffi::OsString::from)
                .or_else(|| std::env::var_os(name))
        }
    }

    /// A new backend for one caller's child, in its own directory tree.
    ///
    /// `lookup` is the environment snapshot the call already redacts against:
    /// the child must receive exactly the values the result is scrubbed of, so
    /// a reload that lands between the two cannot leave one uncovered.
    fn start_mcp(
        capability: &CapabilityDefinition,
        config: &McpConfig,
        lookup: &dyn Fn(&str) -> Option<std::ffi::OsString>,
        roots: &[(String, String)],
    ) -> Result<(Arc<Backend>, Workdir)> {
        let workdir = Workdir::create()
            .map_err(|e| Error::Protocol(format!("no private work directory: {}", e.kind())))?;
        let program = super::cli_run::resolve_command(
            &config.command,
            lookup("PATH").as_deref(),
            lookup("PATHEXT").as_deref(),
        )?;
        let argv: Vec<String> = std::iter::once(program.display().to_string())
            .chain(config.args.iter().cloned())
            .collect();
        let command = crate::transport::join_command(&argv).ok_or_else(|| {
            Error::Config(format!(
                "capability '{}': command cannot be quoted",
                capability.name
            ))
        })?;
        let env = child_env(workdir.path(), &config.env, lookup, None)
            .into_iter()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .chain(roots.iter().cloned())
            .collect();
        let backend_config = BackendConfig {
            transport: TransportConfig::Stdio {
                command,
                cwd: Some(workdir.path().display().to_string()),
                protocol_version: None,
            },
            timeout: Duration::from_secs(capability.primary_provider().map_or(30, |p| p.timeout)),
            env,
            stop_when_idle_for: Some(IDLE_STOP),
            max_frame_bytes: None,
            ..BackendConfig::default()
        };
        let name = format!("capability:{}", capability.name);
        let backend = Backend::new(
            &name,
            backend_config,
            &FailsafeConfig::default(),
            Duration::ZERO,
        );
        Ok((Arc::new(backend), workdir))
    }
}

/// `root_env` as the child sees it: each root canonical, the form `confine`
/// gives a `path_root` parameter, so the server's own prefix check agrees
/// with the gateway's. An unset or missing root, or a reserved name, is left
/// out and the server keeps its private directory.
fn bound_roots(config: &McpConfig, files: &crate::config::FileRoots) -> Vec<(String, String)> {
    config
        .root_env
        .iter()
        .filter(|(name, _)| !is_reserved(name))
        .filter_map(|(name, root)| {
            let dir = super::cli::canonical(files.get(root.as_str())?).ok()?;
            Some((name.clone(), dir.display().to_string()))
        })
        .collect()
}

#[path = "mcp_rounds.rs"]
mod rounds;
use rounds::{after_dispatch, run_prepare};

#[cfg(tp4)]
#[cfg(test)]
#[path = "mcp_tests.rs"]
mod tests;

#[cfg(tp4)]
#[cfg(all(test, unix))]
#[path = "mcp_stop_tests.rs"]
mod stop_tests;

#[cfg(tp4)]
#[cfg(test)]
#[path = "shipped_capability_tests.rs"]
mod shipped_capability_tests;

#[cfg(tp4)]
#[cfg(test)]
#[path = "mcp_principal_tests.rs"]
mod principal_tests;

impl super::CapabilityExecutor {
    /// Stop every MCP child of one capability, mid-call included (its
    /// definition was replaced; MIK-7814).
    pub(crate) fn stop_mcp(&self, capability: &str) {
        self.mcp_children
            .evict(Duration::MAX, &|name| name != capability);
    }
}

#[cfg(tp4)]
#[cfg(test)]
#[path = "mcp_presend_tests.rs"]
mod presend_tests;
