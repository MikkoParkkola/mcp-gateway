// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend warm-start orchestration shared by HTTP and stdio server modes.

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use tracing::{debug, info, warn};

use crate::Error;
use crate::backend::tools_nudge::NudgeKind;
use crate::backend::{Backend, BackendRegistry};
use crate::config::Config;
use crate::config_reload::{OnRegistered, RegisteredChange};
#[cfg(test)]
use crate::jitter::full_jitter;

mod retry;
#[cfg(test)]
use retry::{
    ATTEMPT_REQUEST_BUDGET, DORMANT_YIELDS_BEFORE_RETRY, EMPTY_TOOL_LISTS_BEFORE_ACCEPTING,
    gap_before_attempt, is_readiness_error,
};
use retry::{
    DormantAction, WarmStartPolicy, dormant_action, effective_attempt_timeout,
    retry_warm_start_attempts,
};

#[derive(Clone, Copy)]
pub(super) enum WarmStartMode {
    Http,
    Stdio,
}

pub(super) fn build_warm_start_list(
    backends: &BackendRegistry,
    configured: &[String],
    announce_selection: bool,
) -> Vec<String> {
    #[allow(
        clippy::disallowed_methods,
        reason = "Background: background work over the registered backends; no caller request"
    )]
    resolve_warm_start_names(
        configured,
        backends
            .all()
            .iter()
            .map(|backend| backend.name.clone())
            .collect(),
        announce_selection,
    )
}

/// Whether a successful warm-start should immediately prefetch (and cache) the
/// backend's tool list.
///
/// Tool discovery (`gateway_search` / `tools/list`) only surfaces backends with
/// a populated tool cache; an empty cache is skipped. Subprocess backends
/// (codex, other stdio command servers) therefore stay invisible unless their
/// tools are prefetched here. This must happen in **both** transport modes —
/// the gateway is commonly run via `serve --stdio` (how Claude Code / Codex
/// connect), and gating prefetch on HTTP-only left every stdio-mode subprocess
/// backend with zero discoverable tools (MIK-4649).
const fn warm_start_prefetches_tools(mode: WarmStartMode) -> bool {
    // Both modes prefetch: stdio-mode subprocess backends were previously left
    // with empty tool caches and zero discoverable tools (MIK-4649).
    matches!(mode, WarmStartMode::Http | WarmStartMode::Stdio)
}

/// The one owner of every warm-start task, boot and hot reload alike
/// (`MIK-8054`): at most one warmer per backend name, each bound to the
/// instance it was scheduled for.
///
/// Held through [`WarmerGuard`]; reload hooks hold only a `Weak`, so dropping
/// the guard cancels every warmer on any exit path. Warm-start retries
/// indefinitely while a cache is empty, so a task that outlived the gateway
/// would keep contacting backends after it was gone.
pub(super) struct ReloadWarmer {
    backends: Arc<BackendRegistry>,
    mode: WarmStartMode,
    shutdown: Option<tokio::sync::broadcast::Sender<()>>,
    policy: Arc<WarmStartPolicy>,
    inner: std::sync::Mutex<WarmerInner>,
}

#[derive(Default)]
struct WarmerInner {
    /// Set by `cancel`, by dropping the guard, or by the first admission after
    /// the shutdown broadcast; nothing is scheduled once shutdown has begun.
    sealed: bool,
    /// Taken when the warmer is built, before anything can be sent, so it holds
    /// every shutdown broadcast. Read under this lock by every admission: a
    /// reload past its last stop check can still call the hook after the
    /// broadcast, and a task subscribed then would never hear it (`MIK-8128`).
    shutdown_seen: Option<tokio::sync::broadcast::Receiver<()>>,
    tasks: HashMap<String, tokio::task::JoinHandle<()>>,
}

impl WarmerInner {
    /// Whether admission is closed: sealed, or shutdown already broadcast.
    fn closed(&mut self) -> bool {
        if !self.sealed
            && let Some(seen) = self.shutdown_seen.as_mut()
            && !matches!(
                seen.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            )
        {
            // A message, a lag or a closed channel all mean shutdown has begun.
            self.sealed = true;
        }
        self.sealed
    }
}

impl ReloadWarmer {
    fn lock(&self) -> std::sync::MutexGuard<'_, WarmerInner> {
        // A panic while scheduling leaves a map of handles, still usable.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Warm `names` now, replacing any earlier warmer per name. Returns the
    /// names scheduled.
    fn warm_locked(&self, inner: &mut WarmerInner, names: Vec<String>) -> Vec<String> {
        // Each task's receiver is taken BEFORE the check: a broadcast sent
        // earlier is seen by `closed`, and one sent later reaches the task. The
        // other order leaves a window where neither does.
        let receivers: Vec<_> = names
            .iter()
            .map(|_| {
                self.shutdown
                    .as_ref()
                    .map(tokio::sync::broadcast::Sender::subscribe)
            })
            .collect();
        if inner.closed() {
            return Vec::new();
        }
        let mut scheduled = Vec::new();
        for (name, shutdown) in names.into_iter().zip(receivers) {
            #[allow(
                clippy::disallowed_methods,
                reason = "Background: background work over the registered backends; no caller request"
            )]
            let Some(instance) = self.backends.get(&name) else {
                if matches!(self.mode, WarmStartMode::Http) {
                    warn!(backend = %name, "Backend not found for warm-start");
                }
                continue;
            };
            let task = self.spawn(name.clone(), Arc::downgrade(&instance), shutdown);
            if let Some(old) = inner.tasks.insert(name.clone(), task) {
                old.abort();
            }
            scheduled.push(name);
        }
        scheduled
    }

    /// A fully applied reload: stop the warmer of every replaced or removed
    /// backend FIRST, then warm the registered ones the published config
    /// selects. An excluded replacement is left with no warmer at all.
    fn apply(&self, change: &RegisteredChange, config: &Config) -> Vec<String> {
        let mut inner = self.lock();
        if inner.closed() {
            return Vec::new();
        }
        for name in change.registered.iter().chain(&change.removed) {
            if let Some(old) = inner.tasks.remove(name) {
                old.abort();
            }
        }
        let wanted = &config.meta_mcp.warm_start;
        let selected = change
            .registered
            .iter()
            .filter(|name| wanted.is_empty() || wanted.contains(name))
            .cloned()
            .collect();
        self.warm_locked(&mut inner, selected)
    }

    /// Seal, then abort every task, without waiting for them to unwind.
    fn seal_and_abort(&self) {
        let mut inner = self.lock();
        inner.sealed = true;
        for (_, task) in inner.tasks.drain() {
            task.abort();
        }
    }

    /// `shutdown` is this task's own receiver, taken by the caller before its
    /// admission check; stdio mode has no channel at all and is cancelled by
    /// aborting these handles instead.
    fn spawn(
        &self,
        name: String,
        instance: Weak<Backend>,
        mut shutdown: Option<tokio::sync::broadcast::Receiver<()>>,
    ) -> tokio::task::JoinHandle<()> {
        let backends = Arc::clone(&self.backends);
        let policy = Arc::clone(&self.policy);
        let mode = self.mode;
        tokio::spawn(async move {
            let work = warm_start_until_cached(&backends, &name, &policy, mode, &instance);
            match shutdown.as_mut() {
                Some(rx) => {
                    tokio::select! {
                        () = work => {}
                        _ = rx.recv() => {
                            debug!(backend = %name, "Warm-start cancelled by shutdown");
                        }
                    }
                }
                None => work.await,
            }
        })
    }
}

/// Owns the [`ReloadWarmer`]; dropping it seals the warmer and aborts every
/// task, whatever still holds a reload hook.
#[must_use = "dropping the guard aborts warm-start immediately"]
pub(super) struct WarmerGuard(Arc<ReloadWarmer>);

impl WarmerGuard {
    pub(super) fn new(
        backends: &Arc<BackendRegistry>,
        mode: WarmStartMode,
        shutdown: Option<&tokio::sync::broadcast::Sender<()>>,
    ) -> Self {
        Self(Arc::new(ReloadWarmer {
            backends: Arc::clone(backends),
            mode,
            shutdown: shutdown.cloned(),
            policy: Arc::new(WarmStartPolicy::default()),
            inner: std::sync::Mutex::new(WarmerInner {
                shutdown_seen: shutdown.map(tokio::sync::broadcast::Sender::subscribe),
                ..WarmerInner::default()
            }),
        }))
    }

    /// Warm `names` (boot). Returns the names scheduled.
    pub(super) fn warm(&self, names: Vec<String>) -> Vec<String> {
        let mut inner = self.0.lock();
        self.0.warm_locked(&mut inner, names)
    }

    /// The hook a reload context reports to. Holds the warmer weakly: once the
    /// guard is gone the hook does nothing.
    pub(super) fn hook(&self) -> OnRegistered {
        let warmer = Arc::downgrade(&self.0);
        Arc::new(move |change: &RegisteredChange, config: &Config| {
            warmer
                .upgrade()
                .map(|warmer| warmer.apply(change, config))
                .unwrap_or_default()
        })
    }

    /// Seal, abort every task, and wait for them to finish unwinding.
    ///
    /// Callers about to stop the backends use this rather than the `Drop`
    /// impl: an abort is asynchronous, so a task mid-`ensure_started` would
    /// otherwise still be starting a backend while shutdown drains it.
    pub(super) async fn cancel(self) {
        let tasks: Vec<_> = {
            let mut inner = self.0.lock();
            inner.sealed = true;
            inner.tasks.drain().map(|(_, task)| task).collect()
        };
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            // A cancelled task reports `JoinError::Cancelled`; expected here.
            let _ = task.await;
        }
    }

    #[cfg(test)]
    pub(super) fn abort_handles(&self) -> Vec<tokio::task::AbortHandle> {
        self.0
            .lock()
            .tasks
            .values()
            .map(tokio::task::JoinHandle::abort_handle)
            .collect()
    }
}

impl Drop for WarmerGuard {
    fn drop(&mut self) {
        self.0.seal_and_abort();
    }
}

/// Retry until this backend's tools are cached, or until retrying is pointless.
///
/// The exit condition is **cache presence**, not process liveness, because that
/// is what discovery reads: `backend_tools_for_discovery` returns a backend's
/// tools only if the cache is non-empty, and a plain semantic query fills an
/// empty one only in the background, after it has answered.
async fn warm_start_until_cached(
    backends: &Arc<BackendRegistry>,
    name: &str,
    policy: &WarmStartPolicy,
    mode: WarmStartMode,
    instance: &Weak<Backend>,
) {
    // A backend with per-user sessions only has no shared session to warm;
    // each user's own slot starts on that user's first call. Settled with no
    // shared list, as an attempt that stored none settles it: listeners told
    // of a predecessor's tools hear now that this instance shows none.
    if let Some(backend) = instance.upgrade()
        && backend.shared_slot_refused()
    {
        debug!(backend = %name, "Warm-start skipped: per-user sessions only");
        backend.nudge_tools(NudgeKind::Resolved);
        return;
    }
    // Prefetch is what fills the cache, so without it there is nothing for this
    // loop to wait for. Handled before the loop rather than inside it: an
    // attempt that cannot produce tools would otherwise retry forever against a
    // condition it can never satisfy.
    if !warm_start_prefetches_tools(mode) {
        #[allow(
            clippy::disallowed_methods,
            reason = "Background: background work over the registered backends; no caller request"
        )]
        if let Some(backend) = backends.get(name)
            && let Err(e) = backend.ensure_started().await
        {
            warn!(backend = %name, error = %e, "Warm-start failed");
        }
        return;
    }

    // Shared rather than borrowed: each attempt is an async block that outlives
    // the closure call, so a plain `&mut` counter cannot escape into it.
    let dormant_yields = Arc::new(std::sync::atomic::AtomicU32::new(0));
    // Set when an attempt came back with no tools, so the NEXT attempt knows to
    // discard the cached emptiness and actually re-ask.
    let saw_empty_list = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let outcome = retry_warm_start_attempts(
        name,
        policy,
        // Recomputed per attempt against whichever instance is registered now,
        // so a reload that raises a backend's timeout raises this ceiling too.
        || {
            #[allow(clippy::disallowed_methods, reason = "Background: background work over the registered backends; no caller request")]
            backends.get(name).map_or(policy.attempt_timeout, |backend| {
                effective_attempt_timeout(policy.attempt_timeout, backend.request_timeout())
            })
        },
        || {
            let dormant_yields = Arc::clone(&dormant_yields);
            let saw_empty_list = Arc::clone(&saw_empty_list);
            let settle = SettleOnExit(instance.clone());
            async move {
            let _settle = settle;
            // Resolved per attempt, never captured: a config reload can replace
            // the instance under us, and a task holding the old `Arc` would keep
            // reviving a discarded object while the live one stayed empty.
            #[allow(clippy::disallowed_methods, reason = "Background: background work over the registered backends; no caller request")]
            let backend = backends
                .get(name)
                .ok_or_else(|| Error::BackendUnavailable(name.to_string()))?;
            // Bound to the instance it was scheduled for (`MIK-8054`): a newer
            // one has its own warmer, or none if the reload excluded it, so this
            // task must never act on it. The `Weak` keeps the allocation, so the
            // address cannot be reused by another instance.
            if !std::ptr::eq(instance.as_ptr(), Arc::as_ptr(&backend)) {
                debug!(backend = %name, "Warm-start superseded by a newer instance");
                return Err(Error::Shutdown);
            }

            // Deference to the idle reaper, bounded. Restarting a backend it
            // deliberately stopped fights it; deferring forever leaves the
            // backend invisible, since a cache nobody fetches is a cache
            // discovery skips.
            let ordering = std::sync::atomic::Ordering::SeqCst;
            if backend.lifecycle() == crate::backend::BackendLifecycle::Dormant {
                match dormant_action(backend.cached_tools_count(), dormant_yields.load(ordering)) {
                    DormantAction::Done(tools) => return Ok(tools),
                    DormantAction::Yield => {
                        dormant_yields.fetch_add(1, ordering);
                        return Err(Error::BackendUnavailable(format!(
                            "{name} is dormant; yielding to the idle reaper"
                        )));
                    }
                    DormantAction::FetchAnyway => {
                        dormant_yields.store(0, ordering);
                        debug!(
                            backend = %name,
                            "Dormant with an empty tool cache; fetching once rather than staying invisible"
                        );
                    }
                }
            } else {
                dormant_yields.store(0, ordering);
            }

            // `ensure_started`, never `start`: the latter builds a fresh
            // transport unconditionally, so a retry could replace a transport
            // that ordinary traffic established between attempts and spawn a
            // duplicate subprocess.
            backend.ensure_started().await?;

            // Reconfirming an empty list means ASKING again. Without this the
            // cached empty answer is served straight back, and the bounded retry
            // above observes nothing it has not already seen.
            if saw_empty_list.swap(false, ordering) {
                backend.invalidate_tools_cache();
            }
            let count = backend.warm_tools().await.map(|tools| tools.len())?;
            if count == 0 {
                saw_empty_list.store(true, ordering);
            }
            Ok(count)
            }
        },
    )
    .await;

    if let Some(tools) = outcome {
        info!(backend = %name, tools, "Warm-started + tools cached");
    }
}

/// Sends `Resolved` for its instance when an attempt ends, however it ends:
/// returned, failed, or dropped by the attempt timeout. An attempt that stored
/// a list has already nudged `Changed` ahead of this, and the drain then
/// ignores it; one that did not leaves the instance showing nothing, which
/// listeners told of its predecessor's tools must hear now (`MIK-8127`).
struct SettleOnExit(Weak<Backend>);

impl Drop for SettleOnExit {
    fn drop(&mut self) {
        if let Some(backend) = self.0.upgrade() {
            backend.nudge_tools(NudgeKind::Resolved);
        }
    }
}

fn resolve_warm_start_names(
    configured: &[String],
    all_names: Vec<String>,
    announce_selection: bool,
) -> Vec<String> {
    if configured.is_empty() {
        if announce_selection {
            info!(
                "Warm-starting ALL {} backends (tool prefetch)",
                all_names.len()
            );
        }
        all_names
    } else {
        if announce_selection {
            info!("Warm-starting backends: {:?}", configured);
        }
        configured.to_vec()
    }
}

#[cfg(test)]
mod hot_reload_tests;
#[cfg(test)]
mod login_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod warmer_tests;
