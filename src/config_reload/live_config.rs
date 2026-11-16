// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The live config snapshot: the published generation and its revision, what
//! the process applied at startup, and the publish path every reload takes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;

use super::Generation;
use super::diff::pending_restart_fields;
use super::revision::{self, AppliedInputs, RawInputs};
use super::with_env_restart;
use crate::config::Config;
use crate::config_reload::history::Source;

/// A published generation and the revision naming it.
struct Published {
    generation: Arc<Generation>,
    applied: Option<Arc<Applied>>,
}

/// The keyed digests a published config was built from, its revision, and
/// what it asks for that only a restart applies (computed once per publish,
/// never per call).
pub(crate) struct Applied {
    inputs: AppliedInputs,
    pub(crate) revision: String,
    pub(crate) pending_restart: Vec<&'static str>,
}

/// Live, atomically-swappable config snapshot shared across the gateway.
///
/// Readers take a read-lock and clone the inner `Arc`; writers swap the whole
/// `Arc` under a write-lock, so readers are never blocked for more than a
/// pointer-width CAS.
pub struct LiveConfig {
    /// The published generation and the revision naming it, swapped as one
    /// so a reader never pairs a config with another config's revision.
    inner: RwLock<Published>,
    /// Derived from the record key; `None` publishes no revision at all.
    revision_key: Option<[u8; 32]>,
    /// The revision of what this process applied at startup.
    running_revision: Option<String>,
    /// What the running process actually applied, fixed at startup.
    ///
    /// Kept apart from `inner` because the diff compares the file against the
    /// published snapshot: publishing a restart-only edit into that snapshot
    /// makes the next reload see no difference, so the warning fires once and
    /// never again. Comparing against what is RUNNING keeps it true until a
    /// restart makes the two agree.
    running: Arc<Config>,
    /// Shared authorization-policy generation. `None` in isolated tests.
    policy_epoch: Option<Arc<AtomicU64>>,
    /// Held exclusively while a reload publishes and shared while an event
    /// send is admitted, so once `set` returns no send is admitted against
    /// the old config. Always taken before `inner`.
    admission: RwLock<()>,
    /// Told the incoming generation before each publication, with no lock
    /// held: cost governance takes the starting figures of names it starts
    /// budgeting there, before any request can judge with them.
    published: crate::observer::Observer<Arc<Generation>>,
    /// The configuration history each applied publish is recorded into.
    history: Option<Arc<crate::config_reload::history::HistoryHook>>,
    /// G5: how many generations this holder has published.
    #[cfg(test)]
    publishes: std::sync::atomic::AtomicU64,
    /// Test seam: runs inside [`Self::run_record`], after the published
    /// bytes are captured and before they are handed to the history hook.
    #[cfg(test)]
    record_pause: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl LiveConfig {
    /// A `LiveConfig` for `config` whose key table is resolved with no env
    /// overlay and a throwaway record key. For tests and tools that judge no
    /// production request; production starts through [`Self::from_prepared`]
    /// with the auth it resolved at startup (a source pin holds this).
    ///
    /// # Panics
    ///
    /// When `config.auth` holds a secret reference the process environment
    /// cannot resolve.
    #[must_use]
    pub fn new(config: Config) -> Self {
        use rand::RngExt;
        let key: [u8; 32] = rand::rng().random();
        let key = hex::encode(key);
        let auth = crate::gateway::auth::ResolvedAuthConfig::from_config(&config.auth, &key);
        Self::from_prepared(Generation::prepare_startup(config, Arc::new(auth)))
    }

    /// The startup `LiveConfig`, seeded with a prepared generation, so the
    /// startup keys authenticate from the first request.
    #[must_use]
    pub(crate) fn from_prepared(seed: Generation) -> Self {
        let running = Arc::clone(seed.config());
        Self {
            inner: RwLock::new(Published {
                generation: Arc::new(seed),
                applied: None,
            }),
            revision_key: None,
            running_revision: None,
            running,
            policy_epoch: None,
            admission: RwLock::new(()),
            published: crate::observer::Observer::default(),
            history: None,
            #[cfg(test)]
            publishes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            record_pause: None,
        }
    }

    /// Record every applied publish from here on into `hook`'s store; `None`
    /// (a gateway with no config file) records nothing.
    #[must_use]
    pub(crate) fn with_history(
        mut self,
        hook: impl Into<Option<crate::config_reload::history::HistoryHook>>,
    ) -> Self {
        self.history = hook.into().map(Arc::new);
        self
    }

    /// Install the pause [`Self::run_record`] runs before the history hook.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_record_pause(mut self, pause: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.record_pause = Some(pause);
        self
    }

    /// The record of the publish just made from `raw`, for the record task to
    /// run once every lock is released. `previous` and `published` were both
    /// read under the write lock that swapped them, so a grants publish
    /// landing before the record runs cannot relabel these bytes with its own
    /// revision.
    fn pending_publish(
        &self,
        raw: Option<RawInputs>,
        previous: Option<&str>,
        published: Option<Arc<Applied>>,
        source: Source,
    ) -> Option<crate::config_reload::history::PendingRecord> {
        let (Some(_), Some(raw), Some(applied)) = (self.history.as_ref(), raw, published) else {
            return None;
        };
        Some(crate::config_reload::history::PendingRecord::Publish {
            raw,
            revision: applied.revision.clone(),
            pending_restart: applied.pending_restart.clone(),
            previous: previous.map(str::to_string),
            source,
        })
    }

    /// Run `pending` on this thread: the test pause first, then the hook.
    pub(crate) fn run_record(&self, pending: crate::config_reload::history::PendingRecord) {
        let Some(hook) = &self.history else {
            return;
        };
        #[cfg(test)]
        if let Some(pause) = &self.record_pause {
            pause();
        }
        hook.run(pending, crate::clock::unix_secs().unwrap_or(0));
    }

    /// The history hook, for the record task.
    pub(crate) fn history_hook(&self) -> Option<Arc<crate::config_reload::history::HistoryHook>> {
        self.history.clone()
    }

    /// Test seam: log an overlay publication against the published revision.
    #[cfg(test)]
    pub(crate) fn observe_overlay(&self) {
        let revision = self
            .applied_now()
            .map(|applied| applied.revision.clone())
            .unwrap_or_default();
        self.observe(crate::config_reload::history::seams::Observed::Overlay { revision });
    }

    /// Test seam: append to the ordered log of the seams installed for this
    /// holder's history directory.
    #[cfg(test)]
    fn observe(&self, entry: crate::config_reload::history::seams::Observed) {
        if let Some(seams) = self
            .history
            .as_ref()
            .and_then(|hook| crate::config_reload::history::seams::for_file(&hook.store.file()))
        {
            seams.observe(entry);
        }
    }

    /// Record a refused reload into the history hook, when one is set.
    /// `line` is the parser line of a file refusal.
    pub(crate) fn refused_record(
        &self,
        source: Source,
        line: Option<u32>,
    ) -> Option<crate::config_reload::history::PendingRecord> {
        self.history.as_ref()?;
        #[cfg(test)]
        self.observe(crate::config_reload::history::seams::Observed::Refusal);
        let served = self.applied_now().map(|applied| applied.revision.clone());
        Some(crate::config_reload::history::PendingRecord::Refused {
            source,
            served,
            line,
        })
    }

    /// [`Self::from_prepared`] for `config` with `auth`, for unit-test
    /// fixtures whose auth differs from `config.auth`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_auth(
        config: Config,
        auth: Arc<crate::gateway::auth::ResolvedAuthConfig>,
    ) -> Self {
        Self::from_prepared(Generation::prepare_startup(config, auth))
    }

    /// Share the gateway policy epoch so a published reload can bump it.
    #[must_use]
    pub fn with_policy_epoch(mut self, epoch: Arc<AtomicU64>) -> Self {
        self.policy_epoch = Some(epoch);
        self
    }

    /// The configuration this process is actually running.
    #[must_use]
    pub fn running(&self) -> &Config {
        &self.running
    }

    /// `true` when the file asks for something only a restart can apply.
    ///
    /// Fail-closed: every tracked field counts unless it is on the allow-list of
    /// fields proven to be re-read on the request path. A field wrongly counted
    /// tells an operator to restart when they need not, which is the safe
    /// direction; the reverse tells them a change took effect when it did not.
    ///
    /// Fail-closed direction: restart-required over applied-live. Grep finds
    /// that phrase here and nowhere else: the fix is a subtraction in
    /// `pending_restart_fields`, so there is no added symbol carrying it, and
    /// it is otherwise findable only by reading the comparison.
    #[must_use]
    pub fn restart_required(&self) -> bool {
        !pending_restart_fields(&self.running, &self.get()).is_empty()
    }

    /// Which fields the file asks for that the running process has not applied.
    #[must_use]
    pub fn pending_restart_fields(&self) -> Vec<&'static str> {
        pending_restart_fields(&self.running, &self.get())
    }

    /// Clone the current active configuration snapshot.
    #[must_use]
    pub fn get(&self) -> Arc<Config> {
        Arc::clone(self.inner.read().generation.config())
    }

    /// The current generation. A request takes it once, on arrival, and its
    /// request-side checks are judged by that one alone. An answer-side scan
    /// reads it again when the scan starts and judges the answer under both
    /// (ADR-029, amended, item 5); nothing else reads it mid-request.
    #[must_use]
    pub fn generation(&self) -> Arc<Generation> {
        Arc::clone(&self.inner.read().generation)
    }

    /// Key revisions with `key` (derived from the record key).
    #[must_use]
    pub(crate) fn with_revision_key(mut self, key: [u8; 32]) -> Self {
        self.revision_key = Some(key);
        self
    }

    /// Record the inputs the startup config was built from: its revision is
    /// both the running and the published one.
    #[must_use]
    pub(crate) fn with_applied(mut self, raw: RawInputs) -> Self {
        let applied = self
            .digest_over(raw, None)
            .and_then(|inputs| self.applied(inputs, Vec::new()));
        self.running_revision = applied.as_ref().map(|a| a.revision.clone());
        self.inner.get_mut().applied = applied;
        self
    }

    /// Key revisions by `record_key` and publish what the startup load read;
    /// without inputs (a config built in memory) no revision is published.
    #[must_use]
    pub(crate) fn with_startup_revision(
        self,
        record_key: &crate::gateway::record_principal::RecordPrincipalKey,
        raw: Option<RawInputs>,
    ) -> Self {
        let live = self.with_revision_key(record_key.config_revision_key());
        match raw {
            Some(raw) => {
                // Cloned only when a hook will record it; `with_applied` takes the original.
                let recorded = live.history.as_ref().map(|_| raw.clone());
                let live = live.with_applied(raw);
                let published = live.applied_now();
                // Startup records on this thread, before the holder is shared.
                if let Some(pending) =
                    live.pending_publish(recorded, None, published, Source::Start)
                {
                    live.run_record(pending);
                }
                live
            }
            None => live,
        }
    }

    /// The revision this process applied at startup.
    #[must_use]
    pub(crate) fn running_revision(&self) -> Option<&str> {
        self.running_revision.as_deref()
    }

    fn applied(
        &self,
        inputs: AppliedInputs,
        pending_restart: Vec<&'static str>,
    ) -> Option<Arc<Applied>> {
        let key = self.revision_key?;
        let revision = revision::config_revision(&key, &inputs);
        Some(Arc::new(Applied {
            inputs,
            revision,
            pending_restart,
        }))
    }

    /// The published revision and its restart state, for a record: one read
    /// lock and one `Arc` clone.
    #[must_use]
    pub(crate) fn applied_now(&self) -> Option<Arc<Applied>> {
        self.inner.read().applied.clone()
    }

    /// `raw` digested, with the grants and capability digests their own sinks
    /// last published carried over from `current`: a config reload reads
    /// neither.
    fn digest_over(&self, raw: RawInputs, current: Option<&Applied>) -> Option<AppliedInputs> {
        let key = self.revision_key?;
        let mut inputs = AppliedInputs::digest(&key, raw);
        if let Some(current) = current {
            inputs.grants = current.inputs.grants;
            inputs.capabilities.clone_from(&current.inputs.capabilities);
        }
        Some(inputs)
    }

    /// Atomically replace the current config with one built from `raw`; the
    /// raw bytes are reduced to digests here and dropped.
    /// `env_restart` names the startup environment values changed since
    /// start, which only a restart applies.
    pub(crate) fn set_applied(
        &self,
        generation: Arc<Generation>,
        raw: RawInputs,
        env_restart: &[String],
        source: Source,
    ) -> Option<crate::config_reload::history::PendingRecord> {
        let recorded = self.history.as_ref().map(|_| raw.clone());
        #[cfg(test)]
        let mut observed = self.history.as_ref().map(|hook| hook.observed_files(&raw));
        // Both read inside the swap, under its write lock.
        let mut swapped = (None, None);
        self.publish_with(generation, |current, pending| {
            let applied = self
                .digest_over(raw, current)
                .and_then(|inputs| self.applied(inputs, with_env_restart(pending, env_restart)));
            #[cfg(test)]
            if let (Some(files), Some(applied)) = (observed.take(), applied.as_ref()) {
                self.observe(crate::config_reload::history::seams::Observed::Swap {
                    revision: applied.revision.clone(),
                    files,
                });
            }
            swapped = (current.map(|a| a.revision.clone()), applied.clone());
            applied
        });
        let (previous, published) = swapped;
        self.pending_publish(recorded, previous.as_deref(), published, source)
    }

    /// The env files changed under an unchanged config file: same config,
    /// new inputs, new revision. Recorded as a file reload.
    #[cfg(test)]
    pub(crate) fn set_inputs(&self, raw: RawInputs, env_restart: &[String]) {
        if let Some(pending) = self.set_inputs_from(raw, env_restart, Source::File) {
            self.run_record(pending);
        }
    }

    /// [`Self::set_inputs`] recording `source`. The replaced and the new
    /// revision are both read under this write lock.
    pub(crate) fn set_inputs_from(
        &self,
        raw: RawInputs,
        env_restart: &[String],
        source: Source,
    ) -> Option<crate::config_reload::history::PendingRecord> {
        let recorded = self.history.as_ref().map(|_| raw.clone());
        #[cfg(test)]
        let observed = self.history.as_ref().map(|hook| hook.observed_files(&raw));
        let (previous, published) = {
            let _gate = self.admission.write();
            let mut inner = self.inner.write();
            let current = inner.applied.as_deref();
            let previous = current.map(|applied| applied.revision.clone());
            let pending = current
                .map(|applied| applied.pending_restart.clone())
                .unwrap_or_default();
            let inputs = self.digest_over(raw, current);
            let pending = with_env_restart(pending, env_restart);
            inner.applied = inputs.and_then(|inputs| self.applied(inputs, pending));
            #[cfg(test)]
            if let (Some(files), Some(applied)) = (observed, inner.applied.as_ref()) {
                self.observe(crate::config_reload::history::seams::Observed::Swap {
                    revision: applied.revision.clone(),
                    files,
                });
            }
            (previous, inner.applied.clone())
        };
        self.pending_publish(recorded, previous.as_deref(), published, source)
    }

    /// New grants over the published config: only the grants part changes,
    /// and the revision is recomputed under the same gate as a reload.
    /// The replaced and the new revision are both read under that write
    /// lock; the history hook runs after the locks drop.
    pub(crate) fn set_grants(&self, grants: Option<&[u8]>) {
        let Some((replaced, published)) = self.replace_part(|key, inputs| {
            inputs.grants = grants.map(|g| revision::part_digest(key, g));
        }) else {
            return;
        };
        let Some(hook) = &self.history else {
            return;
        };
        hook.on_grants(
            grants,
            &published.revision,
            published.pending_restart.as_slice(),
            Some(replaced.revision.as_str()),
            crate::clock::unix_secs().unwrap_or(0),
        );
    }

    /// Apply `change` to the published inputs and return the replaced and
    /// the new [`Applied`], both captured under the write lock. `None` when
    /// this holder publishes no revision.
    fn replace_part(
        &self,
        change: impl FnOnce(&[u8; 32], &mut AppliedInputs),
    ) -> Option<(Arc<Applied>, Arc<Applied>)> {
        let _gate = self.admission.write();
        let mut inner = self.inner.write();
        let key = self.revision_key?;
        let replaced = Arc::clone(inner.applied.as_ref()?);
        let mut inputs = replaced.inputs.clone();
        let pending = replaced.pending_restart.clone();
        change(&key, &mut inputs);
        let published = self.applied(inputs, pending)?;
        inner.applied = Some(Arc::clone(&published));
        Some((replaced, published))
    }

    /// Test fixtures only: replaces the config and erases the revision.
    ///
    /// Prepares `config` against the published generation, with no env
    /// overlay, and publishes it with no revision. A reload prepares a
    /// [`Generation`] itself and calls [`Self::set_applied`]. Hidden from
    /// the documented API: integration-test
    /// fixtures call it, and nothing in the gateway does (design delta,
    /// 2026-11-16).
    ///
    /// # Panics
    ///
    /// When the preparation refuses `config`.
    #[doc(hidden)]
    pub fn set(&self, config: Config) {
        let published = self.generation();
        // An edit that leaves `auth` as published keeps the published key
        // table: a fixture seeded with an auth of its own, then reloading an
        // unrelated section, keeps its keys.
        let same_auth = serde_json::to_value(&config.auth).ok()
            == serde_json::to_value(&published.config().auth).ok();
        let prepared = if same_auth {
            Generation::following(config, Arc::clone(published.auth()), &published)
        } else {
            // A test-only path: a source pin keeps production off it.
            // invariant: a config a test cannot prepare is a broken fixture.
            self.prepare(config, &crate::config::EnvOverlay::none())
                .expect("the config prepares")
        };
        self.publish_with(Arc::new(prepared), |_, _| None);
    }

    /// Build the generation for `config` against what this process runs:
    /// its startup config and the published key table's running settings.
    /// The one way to a generation after startup (a source pin holds this).
    ///
    /// # Errors
    ///
    /// The reason `config` cannot be published, naming the setting.
    pub fn prepare(
        &self,
        config: Config,
        overlay: &crate::config::EnvOverlay,
    ) -> Result<Generation, String> {
        let published = self.generation();
        Generation::prepare(config, overlay, (&*self.running, &published))
    }

    /// Publish a prepared generation in one swap, with no revision; a reload
    /// that knows its inputs calls [`LiveConfig::set_applied`] instead.
    /// Test-only: it erases the revision config history records under.
    #[cfg(test)]
    pub(crate) fn publish(&self, generation: Arc<Generation>) {
        self.publish_with(generation, |_, _| None);
    }

    /// Swap in `generation` with the revision `applied` builds from the
    /// current one, both under the admission gate and the one write lock.
    fn publish_with(
        &self,
        generation: Arc<Generation>,
        applied: impl FnOnce(Option<&Applied>, Vec<&'static str>) -> Option<Arc<Applied>>,
    ) {
        self.published.call(Arc::clone(&generation));
        let gate = self.admission.write();
        let old = {
            let mut inner = self.inner.write();
            let pending = pending_restart_fields(&self.running, generation.config());
            let applied = applied(inner.applied.as_deref(), pending);
            std::mem::replace(
                &mut *inner,
                Published {
                    generation,
                    applied,
                },
            )
        };
        #[cfg(test)]
        self.publishes.fetch_add(1, Ordering::SeqCst);
        if let Some(epoch) = &self.policy_epoch {
            let prev = epoch.fetch_add(1, Ordering::Release);
            debug_assert!(
                epoch.load(Ordering::Relaxed) > prev,
                "policy epoch must be monotonic"
            );
        }
        drop(gate);
        // An API key or identity provider may have gone with it.
        crate::events::credentials_changed();
        // A large config is freed after the gate opens, never while a send
        // waits on it.
        drop(old);
    }

    /// G5: generations published since construction.
    #[cfg(test)]
    pub(crate) fn seq(&self) -> u64 {
        self.publishes.load(Ordering::SeqCst)
    }

    /// Publish the current config with `edit` applied, as a reload of an
    /// edited file would.
    #[cfg(test)]
    pub(crate) fn edit(&self, edit: impl FnOnce(&mut Config)) {
        let mut config = (*self.get()).clone();
        edit(&mut config);
        self.set(config);
    }

    /// Attach the observer told the incoming generation before each
    /// publication. Cost governance is its one observer.
    #[cfg(feature = "cost-governance")]
    pub(crate) fn on_publish(&self, observer: crate::observer::ObserverFn<Arc<Generation>>) {
        self.published.set(observer);
    }

    /// Run `admit` under the admission gate: a reload's `set` waits for it,
    /// and it sees the config the last returned `set` published. `admit` must
    /// not block; it may read this config (`get` takes another lock).
    pub(crate) fn admit<R>(&self, admit: impl FnOnce() -> R) -> R {
        let _gate = self.admission.read();
        admit()
    }
}
