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
use super::cli_run::{Workdir, child_env, is_reserved};
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
    /// The provider timeout it runs under; a changed one restarts it.
    timeout: Duration,
    /// Which start this is, so a late `discard` cannot remove a newer child.
    id: u64,
    in_flight: Arc<AtomicUsize>,
    /// Set at acquire and again when a call ends, so a long call is not idle.
    last_used: Arc<Mutex<Instant>>,
    /// The runtime it was started on, so a stop from a thread without one
    /// (a replacement registered by an embedder) still reaches it (MIK-7814).
    runtime: Option<tokio::runtime::Handle>,
    /// Dropped after the backend is stopped, removing the tree.
    _workdir: Workdir,
}

/// The executor's private MCP children, keyed by (capability, caller).
#[derive(Default)]
pub(crate) struct McpChildren {
    map: Mutex<HashMap<(String, String), Child>>,
    sweeping: AtomicBool,
    next_id: std::sync::atomic::AtomicU64,
    /// Bumped on every unload, reload and quarantine; see
    /// `CapabilityExecutionContext::mcp_generation`.
    generations: Mutex<HashMap<String, u64>>,
}

/// Decrements a child's in-flight count when a call ends, however it ends.
pub(crate) struct InFlight(Arc<AtomicUsize>, Arc<Mutex<Instant>>);

impl Drop for InFlight {
    fn drop(&mut self) {
        *self.1.lock() = Instant::now();
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A child leased for one call.
struct Lease {
    backend: Arc<Backend>,
    busy: InFlight,
    id: u64,
}

impl McpChildren {
    /// The caller's child for `capability`, started if needed, marked busy.
    fn acquire(
        &self,
        capability: &CapabilityDefinition,
        config: &McpConfig,
        principal: &str,
        (env_fp, timeout): (u64, Duration),
        epoch_current: impl Fn(u64) -> bool,
        start: impl FnOnce() -> Result<(Arc<Backend>, Workdir)>,
    ) -> Result<Lease> {
        let key = (capability.name.clone(), principal.to_owned());
        let mut stale = Vec::new();
        let mut map = self.map.lock();
        // Under the map lock: an unload bumps the epoch and then evicts under
        // this same lock, so a call from before the unload either gets its child
        // evicted or is refused here; none starts one that outlives the unload.
        if !epoch_current(self.generation(&capability.name)) {
            return Err(Error::Config(format!(
                "capability '{}' changed while this call was starting; retry",
                capability.name
            )));
        }
        if map.get(&key).is_some_and(|child| {
            child.config != *config || child.env_fp != env_fp || child.timeout != timeout
        }) && let Some(old) = map.remove(&key)
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
                    .min_by_key(|(_, child)| *child.last_used.lock())
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
                    timeout,
                    id: self.next_id.fetch_add(1, Ordering::Relaxed),
                    in_flight: Arc::new(AtomicUsize::new(0)),
                    last_used: Arc::new(Mutex::new(Instant::now())),
                    runtime: tokio::runtime::Handle::try_current().ok(),
                    _workdir: workdir,
                },
            );
        }
        let child = map.get_mut(&key).expect("present: inserted above");
        *child.last_used.lock() = Instant::now();
        child.in_flight.fetch_add(1, Ordering::AcqRel);
        let lease = Lease {
            backend: Arc::clone(&child.backend),
            busy: InFlight(Arc::clone(&child.in_flight), Arc::clone(&child.last_used)),
            id: child.id,
        };
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
                        && now.duration_since(*child.last_used.lock()) >= idle)
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

    /// The current revocation generation of one capability.
    pub(crate) fn generation(&self, capability: &str) -> u64 {
        self.generations
            .lock()
            .get(capability)
            .copied()
            .unwrap_or(0)
    }

    /// Revoke the calls of one capability that read an earlier generation.
    pub(crate) fn bump_generation(&self, capability: &str) {
        // Under the map lock `acquire` holds from its epoch check to the
        // lease, so a reload cannot land between the two (MIK-7889). Same
        // order as `acquire`: map, then generations.
        let _admission = self.map.lock();
        *self
            .generations
            .lock()
            .entry(capability.to_owned())
            .or_insert(0) += 1;
    }

    /// Stop one caller's child (a call on it timed out, so it may be wedged).
    fn discard(&self, capability: &str, principal: &str, id: u64) {
        let key = (capability.to_owned(), principal.to_owned());
        let mut map = self.map.lock();
        // Only the child that timed out: a newer one under the same key stays.
        let gone = if map.get(&key).is_some_and(|child| child.id == id) {
            map.remove(&key)
        } else {
            None
        };
        drop(map);
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
                InFlight(Arc::clone(&child.in_flight), Arc::clone(&child.last_used))
            })
            .collect()
    }

    /// Clone every child's backend, as a call's lease does, so a test can
    /// keep a "call in flight" past the child's eviction.
    #[cfg(all(test, unix))]
    pub(crate) fn lease_backends_for_test(&self) -> Vec<Arc<Backend>> {
        self.map
            .lock()
            .values()
            .map(|child| Arc::clone(&child.backend))
            .collect()
    }

    /// The id of the one child of `capability`, for tests.
    #[cfg(test)]
    pub(crate) fn id_for_test(&self, capability: &str) -> u64 {
        let map = self.map.lock();
        let (_, child) = map
            .iter()
            .find(|((cap, _), _)| cap == capability)
            .expect("a child exists");
        child.id
    }

    /// `discard` for the only caller used in tests.
    #[cfg(test)]
    pub(crate) fn discard_for_test(&self, capability: &str, id: u64) {
        let principal = {
            let map = self.map.lock();
            map.keys()
                .find(|(cap, _)| cap == capability)
                .map(|(_, p)| p.clone())
                .expect("a child exists")
        };
        self.discard(capability, &principal, id);
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
    // Each child stops on the runtime that drives it: the current one may be
    // entered but never driven, and a stop spawned there would never run.
    let current = tokio::runtime::Handle::try_current().ok();
    for child in children {
        // First, synchronously and without any runtime: end every process tree
        // the child's backend owns, pooled or held by a busy caller. The async
        // stop below may never run on an idle or dropped runtime (MIK-7923).
        child.backend.retire_now();
        let Some(handle) = child.runtime.clone().or_else(|| current.clone()) else {
            continue;
        };
        handle.spawn(async move {
            let _ = child.backend.stop().await;
            drop(child);
        });
    }
}

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
            subject.authority.len(),
            subject.authority,
            subject.subject.len(),
            subject.subject
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

/// Poll `wait.tool` until `until` holds, `max_wait_s` passes, or the call's
/// own deadline cuts in. A poll that errors or does not match yet is "not
/// ready", never fatal: the server answers an absent or unfinished item with
/// an error. Running out of time says so and leaves the child alone, since a
/// busy server is not a wedged one.
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
    let ends = (Instant::now() + Duration::from_secs(wait.max_wait_s)).min(
        call_ends
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now),
    );
    let interval = Duration::from_millis(wait.interval_ms);
    loop {
        let poll = tokio::time::timeout_at(
            tokio::time::Instant::from_std(ends),
            call_tool(backend, &wait.tool, args.clone()),
        )
        .await;
        // A dead or broken transport ends the wait now; only the server's own
        // "not there yet" answers (tool errors) count as not ready.
        if let Ok(Err(e @ (Error::Transport(_) | Error::TransportPermanent(_)))) = &poll {
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
        if Instant::now() + interval >= ends {
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
        let call_ends = Instant::now() + deadline;
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
            let result = call_tool(&backend, tool, args).await?;
            match wait {
                Some(wait) => {
                    let ready = wait_ready(&backend, wait, &params, call_ends).await?;
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

#[cfg(test)]
#[path = "mcp_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "shipped_capability_tests.rs"]
mod shipped_capability_tests;

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
