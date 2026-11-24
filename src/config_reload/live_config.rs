// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The live config snapshot: the published generation and its revision, what
//! the process applied at startup, and the publish path every reload takes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;

use super::Generation;
use super::diff::pending_restart_fields;
use super::revision::{self, AppliedInputs, CapabilityPart, PartDigest, RawInputs};
use super::with_env_restart;
use crate::config::Config;
use crate::config_reload::history::Source;

/// A published generation and the revision naming it, with the running
/// revision beside it so one read cannot tear the pair.
struct Published {
    generation: Arc<Generation>,
    applied: Option<Arc<Applied>>,
    /// Startup revision, then the startup inputs with the first published
    /// capability part. Later publishes leave it.
    running_revision: Option<String>,
    /// Inputs `with_applied` published. The first capability publish names
    /// these with only the capability part replaced. A gateway.yaml or grants
    /// reload changes `applied` and leaves this baseline.
    startup_inputs: Option<Arc<AppliedInputs>>,
    /// The first capability publish has written `running_revision` from the
    /// baseline. Later publishes do not.
    capability_running_set: bool,
    /// The served version's id in the config history: the revision of the
    /// newest version a full publish stored (`records_a_version`). An
    /// unchanged full publish and the part-only publishes (grants,
    /// capabilities) leave it, so it always names a version the history was
    /// handed, while `applied` may name a revision it never stored.
    recorded_revision: Option<String>,
}

/// `applied`'s revision, for [`super::history::recorded_after`].
fn revision_of(applied: Option<&Applied>) -> Option<&str> {
    applied.map(|applied| applied.revision.as_str())
}

/// The keyed digests a published config was built from, its revision, and
/// what it asks for that only a restart applies (computed once per publish,
/// never per call).
pub(crate) struct Applied {
    inputs: AppliedInputs,
    pub(crate) revision: String,
    pub(crate) pending_restart: Vec<&'static str>,
}

impl Applied {
    /// The capability part this revision names. The record's coverage is this
    /// part, so the two cannot drift.
    pub(crate) fn capability_part(&self) -> &CapabilityPart<PartDigest> {
        &self.inputs.capabilities
    }
}

/// The published revision and the running revision, taken in one read.
///
/// `published` is the applied snapshot a record reads. `running` is the
/// startup revision, or after the first capability publish the startup inputs
/// with that part. One read, so a record never pairs one moment's published
/// revision with another moment's running revision.
pub(crate) struct AppliedNow {
    pub(crate) published: Option<Arc<Applied>>,
    pub(crate) running: Option<String>,
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
    /// A first-key file's wait: the most recent file-reading reload's
    /// verdict, set and cleared by the reload alone.
    first_key: RwLock<Option<FirstKeyWait>>,
    /// G5: how many generations this holder has published.
    #[cfg(test)]
    publishes: std::sync::atomic::AtomicU64,
    /// Test seam: runs inside [`Self::run_record`], after the published
    /// bytes are captured and before they are handed to the history hook.
    #[cfg(test)]
    record_pause: Option<Arc<dyn Fn() + Send + Sync>>,
}

#[path = "live_config_pending.rs"]
mod pending;
pub(crate) use pending::FirstKeyWait;

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
        #[allow(
            clippy::disallowed_methods,
            reason = "record key: a throwaway record key for tests and tools that judge no production request"
        )]
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
                running_revision: None,
                startup_inputs: None,
                capability_running_set: false,
                recorded_revision: None,
            }),
            revision_key: None,
            running,
            policy_epoch: None,
            admission: RwLock::new(()),
            published: crate::observer::Observer::default(),
            history: None,
            first_key: RwLock::new(None),
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
        recorded: Option<String>,
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
            // Read under the write lock that published `applied`; set
            // whenever a revision is, so the fallback never runs in practice.
            pin: recorded.unwrap_or_else(|| applied.revision.clone()),
            source,
        })
    }

    /// Run `pending` on this thread: the test pause first, then the hook.
    #[cfg(test)]
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

    /// The test pause, for the record task.
    #[cfg(test)]
    pub(crate) fn record_pause(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        self.record_pause.clone()
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
            .published
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
        // The version still served, as the history names it: after a
        // part-only publish the published revision names none.
        let served = self.served_revision();
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
        let inputs = self.digest_over(raw, None);
        let applied = inputs
            .clone()
            .and_then(|inputs| self.applied(inputs, Vec::new()));
        let inner = self.inner.get_mut();
        inner.running_revision = applied.as_ref().map(|a| a.revision.clone());
        inner.startup_inputs = inputs.map(Arc::new);
        inner.capability_running_set = false;
        // The startup revision: its record stores that version, or finds it
        // already the newest kept (a restart on the same files).
        inner.recorded_revision =
            super::history::recorded_after(None, revision_of(applied.as_deref()), None);
        inner.applied = applied;
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
                let published = live.applied_now().published;
                // Startup: open and this record on one worker, bounded by one
                // deadline, before the holder is shared (design D-1, gpt G1).
                if let (Some(hook), Some(pending)) = (
                    live.history.clone(),
                    live.pending_publish(
                        recorded,
                        None,
                        published,
                        live.served_revision(),
                        Source::Start,
                    ),
                ) {
                    #[cfg(test)]
                    if let Some(pause) = &live.record_pause {
                        pause();
                    }
                    let record = hook.build(pending, crate::clock::unix_secs().unwrap_or(0));
                    hook.store.start(record);
                }
                live
            }
            None => live,
        }
    }

    /// The revision this process applied at startup, then, after the first
    /// capability publish, the startup inputs with that publish's part.
    ///
    /// Owned: the value lives beside the published revision, behind the same
    /// lock, so a borrow cannot outlive the read.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn running_revision(&self) -> Option<String> {
        self.inner.read().running_revision.clone()
    }

    /// The served version's id in the config history (`recorded_revision`):
    /// what the history pins, marks running and restores compare against.
    /// Not the published revision, which a grants or capability publish
    /// moves with no version stored, and not `running_revision`, the startup
    /// one, which a reload never moves.
    #[must_use]
    pub(crate) fn served_revision(&self) -> Option<String> {
        self.inner.read().recorded_revision.clone()
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

    /// The published revision and the running revision, from one read.
    #[must_use]
    pub(crate) fn applied_now(&self) -> AppliedNow {
        let inner = self.inner.read();
        AppliedNow {
            published: inner.applied.clone(),
            running: inner.running_revision.clone(),
        }
    }

    /// `raw` digested, with the grants and capability digests their own sinks
    /// last published carried over from `current`: a config reload reads
    /// neither. The capability sequence is copied with the part. It is not an
    /// input, and a reload must not look like sequence zero.
    fn digest_over(&self, raw: RawInputs, current: Option<&Applied>) -> Option<AppliedInputs> {
        let key = self.revision_key?;
        let mut inputs = AppliedInputs::digest(&key, raw);
        if let Some(current) = current {
            inputs.grants = current.inputs.grants;
            inputs.capabilities.clone_from(&current.inputs.capabilities);
            inputs.capability_seq = current.inputs.capability_seq;
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
        let served = self.publish_with(generation, |current, pending| {
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
        self.pending_publish(recorded, previous.as_deref(), published, served, source)
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
        let (previous, published, served) = {
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
            inner.recorded_revision = super::history::recorded_after(
                previous.as_deref(),
                revision_of(inner.applied.as_deref()),
                inner.recorded_revision.as_deref(),
            );
            #[cfg(test)]
            if let (Some(files), Some(applied)) = (observed, inner.applied.as_ref()) {
                self.observe(crate::config_reload::history::seams::Observed::Swap {
                    revision: applied.revision.clone(),
                    files,
                });
            }
            (
                previous,
                inner.applied.clone(),
                inner.recorded_revision.clone(),
            )
        };
        self.pending_publish(recorded, previous.as_deref(), published, served, source)
    }

    /// New grants over the published config: only the grants part changes,
    /// and the revision is recomputed under the same gate as a reload. Nothing
    /// is recorded in the config history: grants versions are recorded separately.
    pub(crate) fn set_grants(&self, grants: Option<&[u8]>) {
        let _ = self.replace_part(|key, inputs| {
            inputs.grants = grants.map(|g| revision::part_digest(key, g));
        });
    }

    /// Publish `part` at load sequence `seq`, under the same locks as the
    /// other applied inputs.
    ///
    /// A seq at or below the stored one is a stale or repeated handoff: the
    /// stored part stays, and the applied snapshot is not replaced. `<=`,
    /// not `<`, because the same seq delivered twice must change nothing,
    /// including which snapshot is published. The first publish sets the
    /// running revision to the startup inputs with this part. A later one
    /// leaves it, so a gateway.yaml reload during the scan stays visible as
    /// published versus running.
    pub(crate) fn set_capabilities(&self, seq: u64, part: CapabilityPart<PartDigest>) {
        let _gate = self.admission.write();
        let mut inner = self.inner.write();
        let Some(key) = self.revision_key else {
            return;
        };
        let (pending, mut inputs) = {
            let Some(current) = inner.applied.as_deref() else {
                return;
            };
            if seq <= current.inputs.capability_seq {
                return;
            }
            (current.pending_restart.clone(), current.inputs.clone())
        };
        inputs.capabilities = part.clone();
        inputs.capability_seq = seq;
        if !inner.capability_running_set {
            if let Some(startup) = inner.startup_inputs.clone() {
                let mut baseline = (*startup).clone();
                baseline.capabilities = part;
                inner.running_revision = Some(revision::config_revision(&key, &baseline));
            }
            inner.capability_running_set = true;
        }
        inner.applied = self.applied(inputs, pending);
    }

    /// The capability load sequence the last publish recorded.
    ///
    /// Zero when nothing has published a part. A gateway.yaml reload keeps
    /// the sequence `digest_over` copied onto the new inputs.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "production call sites are a later slice; the tests are the caller until then"
        )
    )]
    pub(crate) fn capability_seq(&self) -> u64 {
        self.inner
            .read()
            .applied
            .as_ref()
            .map_or(0, |applied| applied.inputs.capability_seq)
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
    ) -> Option<String> {
        self.published.call(Arc::clone(&generation));
        let gate = self.admission.write();
        let (old, served) = {
            let mut inner = self.inner.write();
            let pending = pending_restart_fields(&self.running, generation.config());
            let applied = applied(inner.applied.as_deref(), pending);
            let running_revision = inner.running_revision.clone();
            let startup_inputs = inner.startup_inputs.clone();
            let capability_running_set = inner.capability_running_set;
            let recorded_revision = super::history::recorded_after(
                revision_of(inner.applied.as_deref()),
                revision_of(applied.as_deref()),
                inner.recorded_revision.as_deref(),
            );
            let served = recorded_revision.clone();
            let replaced = std::mem::replace(
                &mut *inner,
                Published {
                    generation,
                    applied,
                    running_revision,
                    startup_inputs,
                    capability_running_set,
                    recorded_revision,
                },
            );
            (replaced, served)
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
        served
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

#[cfg(tp3)]
#[cfg(test)]
#[path = "live_config_capability_tests.rs"]
mod capability_tests;
