// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `service: mcp` execution (MIK-7782).
//!
//! No second MCP client: each (capability, caller) gets its own
//! [`crate::backend::Backend`] over a stdio child, built from the pinned
//! command, so one caller never sees another's open documents, projects or
//! imports. The child runs in a private directory tree that lives exactly as
//! long as it does. These backends are never registered as public servers.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use super::CapabilityExecutor;
use super::cli_argv::render_json;
use super::cli_run::{Workdir, child_env};
use crate::backend::Backend;
use crate::capability::definition::{McpConfig, ToolCall};
use crate::capability::{CapabilityDefinition, CapabilityExecutionContext};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::error::rpc_codes::INVALID_PARAMS;
use crate::protocol::JsonRpcResponse;
use crate::{Error, Result};

/// Most live children one capability may have (one per caller).
pub(crate) const MAX_CHILDREN_PER_CAPABILITY: usize = 16;
/// An unused child is stopped after this long.
pub(crate) const IDLE_STOP: Duration = Duration::from_secs(300);

/// One caller's server for one capability.
struct Child {
    backend: Arc<Backend>,
    /// The definition it was started from; a changed one restarts it.
    config: McpConfig,
    /// Fingerprint of the env values it was started with; a rotated one restarts it.
    env_fp: u64,
    in_flight: Arc<AtomicUsize>,
    last_used: Instant,
    /// Dropped after the backend is stopped, removing the tree.
    _workdir: Workdir,
}

/// The executor's private MCP children, keyed by (capability, caller).
#[derive(Default)]
pub(crate) struct McpChildren {
    map: Mutex<HashMap<(String, String), Child>>,
    sweeping: AtomicBool,
}

/// Decrements a child's in-flight count when a call ends, however it ends.
pub(crate) struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl McpChildren {
    /// The caller's child for `capability`, started if needed, marked busy.
    fn acquire(
        &self,
        capability: &CapabilityDefinition,
        config: &McpConfig,
        principal: &str,
        env_fp: u64,
        start: impl FnOnce() -> Result<(Arc<Backend>, Workdir)>,
    ) -> Result<(Arc<Backend>, InFlight)> {
        let key = (capability.name.clone(), principal.to_owned());
        let mut stale = Vec::new();
        let mut map = self.map.lock();
        if map
            .get(&key)
            .is_some_and(|child| child.config != *config || child.env_fp != env_fp)
            && let Some(old) = map.remove(&key)
        {
            stale.push(old);
        }
        if !map.contains_key(&key) {
            let live = map
                .keys()
                .filter(|(cap, _)| *cap == capability.name)
                .count();
            if live >= MAX_CHILDREN_PER_CAPABILITY {
                // Evict the least recently used IDLE child; never a busy one.
                let victim = map
                    .iter()
                    .filter(|((cap, _), child)| {
                        *cap == capability.name && child.in_flight.load(Ordering::Acquire) == 0
                    })
                    .min_by_key(|(_, child)| child.last_used)
                    .map(|(k, _)| k.clone());
                let Some(victim) = victim else {
                    return Err(Error::RateLimited(format!(
                        "capability '{}' already serves {MAX_CHILDREN_PER_CAPABILITY} busy callers; \
                         retry shortly",
                        capability.name
                    )));
                };
                stale.extend(map.remove(&victim));
            }
            let (backend, workdir) = start()?;
            map.insert(
                key.clone(),
                Child {
                    backend,
                    config: config.clone(),
                    env_fp,
                    in_flight: Arc::new(AtomicUsize::new(0)),
                    last_used: Instant::now(),
                    _workdir: workdir,
                },
            );
        }
        let child = map.get_mut(&key).expect("present: inserted above");
        child.last_used = Instant::now();
        child.in_flight.fetch_add(1, Ordering::AcqRel);
        let lease = (
            Arc::clone(&child.backend),
            InFlight(Arc::clone(&child.in_flight)),
        );
        drop(map);
        stop_all(stale);
        Ok(lease)
    }

    /// Stop children idle for at least `idle`, and every child of a
    /// capability not in `loaded` (unloaded or rug-pulled).
    pub(crate) fn evict(&self, idle: Duration, loaded: &dyn Fn(&str) -> bool) {
        let now = Instant::now();
        let mut map = self.map.lock();
        let gone: Vec<_> = map
            .iter()
            .filter(|((cap, _), child)| {
                // An unloaded capability's child goes even mid-call; an idle one
                // only when it has no call in flight.
                !loaded(cap)
                    || (child.in_flight.load(Ordering::Acquire) == 0
                        && now.duration_since(child.last_used) >= idle)
            })
            .map(|(k, _)| k.clone())
            .collect();
        let stale: Vec<Child> = gone.iter().filter_map(|k| map.remove(k)).collect();
        drop(map);
        stop_all(stale);
    }

    /// Start the once-a-minute idle sweep. It holds only a `Weak`, so it
    /// ends with the executor. (Registered backends are swept by the gateway;
    /// these are deliberately not registered.)
    fn ensure_sweeper(self: &Arc<Self>) {
        if self.sweeping.swap(true, Ordering::AcqRel) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let weak = Arc::downgrade(self);
        handle.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let Some(children) = weak.upgrade() else {
                    break;
                };
                children.evict(IDLE_STOP, &|_| true);
            }
        });
    }

    /// Stop one caller's child (a call on it timed out, so it may be wedged).
    fn discard(&self, capability: &str, principal: &str) {
        let gone = self
            .map
            .lock()
            .remove(&(capability.to_owned(), principal.to_owned()));
        stop_all(gone.into_iter().collect());
    }

    /// Mark the caller's child busy, as a call in flight would.
    #[cfg(test)]
    pub(crate) fn hold_for_test(&self, _caller: &str) -> Vec<InFlight> {
        self.map
            .lock()
            .values()
            .map(|child| {
                child.in_flight.fetch_add(1, Ordering::AcqRel);
                InFlight(Arc::clone(&child.in_flight))
            })
            .collect()
    }

    /// Live children, for tests.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.lock().len()
    }
}

/// Stop each child's backend (which kills its process tree), then drop its
/// directory. Runs off the caller's path.
fn stop_all(children: Vec<Child>) {
    if children.is_empty() {
        return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        for child in children {
            let _ = child.backend.stop().await;
            drop(child);
        }
    });
}

/// Which child a call belongs to: the dispatch binding, else the verified
/// OIDC subject, else the caller's grant subject. A caller none of these names
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
            subject.authority.len(),
            subject.authority,
            subject.subject.len(),
            subject.subject
        ));
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

type Selected<'a> = (
    &'a str,
    Option<&'a Value>,
    Option<&'a crate::capability::definition::PrepareCall>,
);

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
        } = selector.tools.get(op).ok_or_else(|| {
            Error::json_rpc(INVALID_PARAMS, format!("unknown {} '{op}'", selector.param))
        })?;
        return Ok((tool, arguments.as_ref(), prepare.as_ref()));
    }
    match &config.tool {
        Some(tool) => Ok((tool, config.arguments.as_ref(), None)),
        None => Err(Error::Config(
            "not executable: this mcp capability declares no tool mapping (`tool` or `tool_selector`)".into(),
        )),
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

/// A prepare result as an object: `structuredContent` as is, or the first
/// text content block parsed as JSON.
fn prepare_object(result: Value) -> Option<Map<String, Value>> {
    match result {
        Value::Object(map) => Some(map),
        Value::Array(blocks) => blocks
            .first()
            .and_then(|b| b.get("text"))
            .and_then(Value::as_str)
            .and_then(|t| serde_json::from_str::<Value>(t).ok())
            .and_then(|v| match v {
                Value::Object(map) => Some(map),
                _ => None,
            }),
        _ => None,
    }
}

impl CapabilityExecutor {
    pub(super) async fn execute_mcp(
        &self,
        capability: &CapabilityDefinition,
        config: &McpConfig,
        params: &Value,
        context: &CapabilityExecutionContext,
    ) -> Result<Value> {
        super::cli::refuse_egress(capability)?;
        let params = super::cli::confine_paths(capability, params, &self.process_policy.files)?;
        let (tool, template, prepare) = select(config, &params)?;
        let principal = principal(capability, context, self.multi_user.load(Ordering::Acquire))?;
        self.mcp_children.ensure_sweeper();
        let lookup = self.env_lookup();
        let env_values: Vec<String> = config
            .env
            .iter()
            .filter_map(|name| lookup(name))
            .map(|v| v.to_string_lossy().into_owned())
            .collect();
        let env_fp = {
            use std::hash::{Hash as _, Hasher as _};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            env_values.hash(&mut hasher);
            hasher.finish()
        };
        let (backend, _busy) =
            self.mcp_children
                .acquire(capability, config, &principal, env_fp, || {
                    self.start_mcp(capability, config)
                })?;

        // One deadline for the whole call, writes included: a server that stops
        // reading its stdin must not hold its slot (and so its eviction) forever.
        let deadline = Duration::from_secs(capability.primary_provider().map_or(30, |p| p.timeout));
        let outcome = tokio::time::timeout(deadline, async {
            let mut args = arguments(template, &params)?;
            if let Some(prepare) = prepare {
                let first = call_tool(
                    &backend,
                    &prepare.tool,
                    arguments(prepare.arguments.as_ref(), &params)?,
                )
                .await?;
                let object = prepare_object(first).ok_or_else(|| {
                    Error::Protocol(format!(
                        "prepare tool '{}' returned no object",
                        prepare.tool
                    ))
                })?;
                for (arg, field) in &prepare.bind {
                    let value = object.get(field).cloned().ok_or_else(|| {
                        Error::Protocol(format!(
                            "prepare tool '{}' returned no '{field}'",
                            prepare.tool
                        ))
                    })?;
                    args.insert(arg.clone(), value);
                }
            }
            call_tool(&backend, tool, args).await
        })
        .await;
        match outcome {
            // A server that did not answer in time may be wedged: stop it so the
            // next call starts a fresh one instead of timing out on the same.
            Err(_) => {
                self.mcp_children.discard(&capability.name, &principal);
                Err(Error::BackendTimeout("MCP call timed out".to_string()))
            }
            Ok(result) => result.map_err(|error| match error {
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
    fn start_mcp(
        &self,
        capability: &CapabilityDefinition,
        config: &McpConfig,
    ) -> Result<(Arc<Backend>, Workdir)> {
        let workdir = Workdir::create()
            .map_err(|e| Error::Protocol(format!("no private work directory: {}", e.kind())))?;
        let lookup = self.env_lookup();
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
        let env = child_env(workdir.path(), &config.env, &lookup, None)
            .into_iter()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
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

#[cfg(test)]
#[path = "mcp_tests.rs"]
mod tests;
