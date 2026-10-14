// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: what each session was last told of each backend, and the
//! fan-out that tells a session of a `tools/list_changed` only when its own
//! view of that backend moved.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use serde_json::Value;

use super::copy::CopyAudience;
use super::{ClientSession, NotificationMultiplexer, TaggedNotification};
use crate::gateway::auth::AuthState;
use crate::gateway::auth::live::{Audience, Delivery, HeldCredential, delivery};

/// What one caller is shown of one backend: the served `tools/list` result,
/// which is the caller's own and shared by every backend, and the backend's
/// own listing as discovery shows it. The two are kept apart so a change
/// the caller cannot see on one backend never reads as a change on another
/// (MIK-8350).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ViewDigest {
    pub(crate) served: String,
    /// Empty when the caller is shown nothing of the backend.
    pub(crate) shown: String,
}

/// What a caller was last told: its one served-list digest and, per backend,
/// what it was shown of it. Every write carries the stamp it was read under
/// and is applied only if that stamp is newer than the one the record holds,
/// so a slow reader, a refresh and a rekey cannot move the record backward
/// (MIK-8350 D17b). Shared by the legacy GET stream and the listen stream.
#[derive(Debug, Default)]
pub(crate) struct ToldState {
    baselined: bool,
    stamp: u64,
    served: Option<String>,
    /// Per backend, the `shown` digest the caller was last told.
    backends: HashMap<String, String>,
}

/// The verdict on a view against a [`ToldState`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Peek {
    /// Nothing the caller does not already hold.
    Quiet,
    /// The caller is owed a hint.
    Owed,
}

impl ToldState {
    /// Forget everything and refuse every write read before `floor`: the next
    /// attach takes a fresh baseline for the new caller.
    pub(crate) fn clear(&mut self, floor: u64) {
        *self = Self {
            stamp: floor,
            ..Self::default()
        };
    }

    /// Record `view` for the backends this state has no record of, read under
    /// `stamp`; what it already holds is kept, so a change withheld at write
    /// stays owed after a resumed stream reopens (MIK-8350 B1, B2'). Refused
    /// when `stamp` is older than the record.
    pub(crate) fn baseline(&mut self, stamp: u64, view: HashMap<String, ViewDigest>) -> bool {
        if stamp < self.stamp {
            return false;
        }
        self.stamp = stamp;
        self.baselined = true;
        for (backend, digest) in view {
            self.served.get_or_insert(digest.served);
            self.backends.entry(backend).or_insert(digest.shown);
        }
        true
    }

    /// The caller was just shown `view`, read under `stamp`: record it for
    /// every backend (MIK-8350 B9). Refused when `stamp` is older than the
    /// record.
    pub(crate) fn refresh(&mut self, stamp: u64, view: HashMap<String, ViewDigest>) -> bool {
        if stamp <= self.stamp {
            return false;
        }
        self.stamp = stamp;
        self.baselined = true;
        for (backend, digest) in view {
            self.served = Some(digest.served);
            self.backends.insert(backend, digest.shown);
        }
        true
    }

    /// Whether `digest` is a view of `backend` the caller was not told. A
    /// state that never took a baseline records this one and is owed nothing
    /// (a stream is never told of a change it never saw); once one is taken, a
    /// backend it has no record of is new, and owed when it shows anything.
    pub(crate) fn peek(&mut self, stamp: u64, backend: &str, digest: &ViewDigest) -> Peek {
        if !self.baselined {
            self.baseline(stamp, HashMap::from([(backend.to_owned(), digest.clone())]));
            return Peek::Quiet;
        }
        let served_moved = self.served.as_deref() != Some(digest.served.as_str());
        match self.backends.get(backend) {
            Some(shown) if !served_moved && *shown == digest.shown => Peek::Quiet,
            Some(_) => Peek::Owed,
            None if served_moved || !digest.shown.is_empty() => Peek::Owed,
            None => {
                self.backends.insert(backend.to_owned(), String::new());
                Peek::Quiet
            }
        }
    }

    /// Record that `digest` of `backend`, read under `stamp`, was told, once
    /// its frame is written. `false` when there is nothing to record and so
    /// nothing to write: the state was cleared, a newer write got there
    /// first, or the caller already holds this view.
    pub(crate) fn commit(&mut self, stamp: u64, backend: &str, digest: &ViewDigest) -> bool {
        if !self.baselined || stamp <= self.stamp {
            return false;
        }
        let served_moved = self.served.as_deref() != Some(digest.served.as_str());
        let owed = self
            .backends
            .get(backend)
            .is_none_or(|shown| served_moved || *shown != digest.shown);
        if owed {
            self.stamp = stamp;
            self.served = Some(digest.served.clone());
            self.backends
                .insert(backend.to_owned(), digest.shown.clone());
        }
        owed
    }
}

#[path = "streaming_told_custody.rs"]
mod custody;
use custody::{ActiveView, CloseLease};

#[path = "streaming_told_cf.rs"]
mod cf;
pub(crate) use cf::{CfGrace, HeldSource};
#[cfg(test)]
pub(super) use cf::{CfVerdict, cf_verdict};

/// The identities and request surface a stream was opened under, besides its
/// credential: part of what its caller is shown, so the judge builds the scope
/// a POST of that caller would (MIK-8350 D11, D16). Owned by the stream.
#[derive(Clone, Default)]
pub(crate) struct ViewSubject {
    pub(crate) grant_subject: Option<crate::identity_grants::GrantSubject>,
    pub(crate) oauth_agent: Option<crate::gateway::oauth::AgentIdentity>,
    pub(crate) cert: Option<crate::mtls::CertIdentity>,
    /// The URL asked for Code Mode (`?codemode=search_and_execute`).
    pub(crate) code_mode_url: bool,
    /// The verified identity the request carried (the Open `WebUI` adapter's,
    /// a key-server token's), which selects a per-user catalogue slot.
    pub(crate) verified_identity: Option<crate::key_server::oidc::VerifiedIdentity>,
    /// The Open `WebUI` assertion this stream was admitted under, when it was.
    pub(crate) adapter: Option<crate::gateway::openwebui_adapter::AdapterAssertion>,
    /// The certificate's `notAfter`, in unix seconds. Captured here and
    /// checked per decision by MIK-8377.
    #[expect(dead_code, reason = "read by MIK-8377's live() clause")]
    pub(crate) cert_not_after: Option<u64>,
    /// The header identity this stream was admitted under, when one was:
    /// the verified Cloudflare assertion (re-verified per decision by
    /// MIK-8377 and dropped with the stream; re-verifying needs the token
    /// itself) or the trusted proxy's peer address.
    pub(crate) identity_source: HeldSource,
    /// Grace for transient Cloudflare re-verification failures.
    pub(crate) cf_grace: Arc<parking_lot::Mutex<CfGrace>>,
}

impl std::fmt::Debug for ViewSubject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewSubject").finish_non_exhaustive()
    }
}

impl ViewSubject {
    /// What two requests must share to be one view: the identities and the
    /// surface, not the secrets or the clock-bound parts. Only used as a map
    /// key in process.
    pub(crate) fn key(&self) -> String {
        crate::hashing::sha256_hex(
            format!(
                "{:?}|{:?}|{:?}|{}|{:?}",
                // Authority and subject only: a display label is not identity,
                // and a changing one must not mint a new view per request.
                self.grant_subject
                    .as_ref()
                    .map(|g| (g.authority.as_str(), g.subject.as_str())),
                self.oauth_agent,
                self.cert,
                self.code_mode_url,
                self.verified_identity
                    .as_ref()
                    .map(crate::key_server::oidc::VerifiedIdentity::stable_actor_id)
            )
            .as_bytes(),
        )
    }

    /// Whether the identity the stream was admitted under is still good, or
    /// why not. The adapter assertion's window is judged here; MIK-8377 adds
    /// its clauses, which need the live handles in [`LiveCtx`].
    pub(crate) fn live(&self, _ctx: &LiveCtx<'_>) -> Result<(), DeadReason> {
        match &self.adapter {
            Some(adapter) if !adapter.live() => Err(DeadReason::Adapter),
            _ => Ok(()),
        }
    }
}

/// What a liveness check may consult besides the subject: the caller the
/// credential resolved to and the live handles an identity source is
/// re-verified with, read from the current state, never captured at attach.
#[derive(Clone, Copy)]
pub(crate) struct LiveCtx<'a> {
    #[expect(dead_code, reason = "read by MIK-8377's live() clauses")]
    pub(crate) agent: Option<&'a crate::gateway::oauth::ValidatedToken>,
    #[expect(dead_code, reason = "read by MIK-8377's live() clauses")]
    pub(crate) caller_identity: &'a crate::security::caller_identity::CallerIdentityConfig,
    pub(crate) cf_verifier: Option<&'a crate::key_server::OidcVerifier>,
}

/// What a caller found dead when its stream opens gets.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AtAttach {
    /// No stream: the caller is answered as an invalid credential is.
    Refuse,
    /// A caller that presented nothing: a public path admits it anonymously, so
    /// its bearer "death" is only the absence of a credential. Its stream opens
    /// with no view, and no hint is ever judged live for it.
    OpenAnonymous,
}

pub(crate) fn dead_at_attach(
    credential: Option<&HeldCredential>,
    reason: DeadReason,
    subject: &ViewSubject,
) -> AtAttach {
    match (credential, reason, subject) {
        (
            None,
            DeadReason::Bearer,
            ViewSubject {
                identity_source: HeldSource::None,
                cert: None,
                adapter: None,
                oauth_agent: None,
                verified_identity: None,
                ..
            },
        ) => AtAttach::OpenAnonymous,
        _ => AtAttach::Refuse,
    }
}

/// What the judge made of a caller: a view, or a caller that no longer
/// resolves (MIK-8350 D17i). Every consumer closes its stream on `Dead`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Judged<T> {
    Live(T),
    Dead(DeadReason),
}

/// Why a stream's caller no longer resolves: the closed label of
/// `mcp_view_liveness_dead_total`, set by whichever check failed (MIK-8350
/// D17i; MIK-8377 adds the labels for its clauses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeadReason {
    /// The held credential no longer authenticates.
    Bearer,
    /// The Open `WebUI` assertion the stream was admitted under has expired. An
    /// unreadable clock is folded in here: `jwt_window` answers Expired for
    /// it, and a broken host clock alerts elsewhere.
    Adapter,
    /// The Cloudflare Access assertion the stream was admitted under no longer
    /// verifies (a rotated or revoked key, or no verifier to ask).
    Cf,
}

impl DeadReason {
    /// Count one held stream's death under its label, where the stream
    /// closes (`mcp_view_liveness_dead_total`).
    pub(crate) fn count(self) {
        telemetry_metrics::counter!(
            "mcp_view_liveness_dead_total",
            "reason" => self.label()
        )
        .increment(1);
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::Adapter => "adapter",
            Self::Cf => "cf",
        }
    }
}

/// The caller a stream's credential resolves to, found outside the record's
/// gate: resolving can reach an identity provider, the digest never does.
pub(crate) struct ResolvedCaller {
    pub(crate) client: crate::gateway::auth::AuthenticatedClient,
    pub(crate) identity: Option<crate::key_server::oidc::VerifiedIdentity>,
}

/// Decides what a stream's caller is shown, for the per-stream
/// `list_changed` filter (MIK-8350). Installed by the router, which owns the
/// visibility state the multiplexer does not. `resolve` may await (the
/// credential's validation can fetch keys); `digest` and `baseline` read
/// caches only: they never mint a credential and never fill a slot.
pub(crate) trait ViewJudge: Send + Sync {
    /// The caller the held credential resolves to, or why it does not.
    fn resolve<'a>(
        &'a self,
        auth: &'a AuthState,
        caller: (Option<&'a HeldCredential>, &'a ViewSubject),
    ) -> futures::future::BoxFuture<'a, Judged<ResolvedCaller>>;

    /// What the resolved caller is shown of `backend` now.
    fn digest(
        &self,
        caller: &ResolvedCaller,
        subject: &ViewSubject,
        session_id: &str,
        backend: &str,
    ) -> ViewDigest;

    /// Every backend's view for the resolved caller, taken when a stream opens
    /// so the first change after attach is judged against what it saw.
    fn baseline(
        &self,
        caller: &ResolvedCaller,
        subject: &ViewSubject,
        session_id: &str,
    ) -> HashMap<String, ViewDigest>;
}

/// One view held on a session: the key of its subject, its durable record
/// and the weak registrations of the streams currently open on it. No raw
/// subject is retained here (MIK-8350): a registration is only a weak
/// subject plus that attachment's close receiver.
#[derive(Debug)]
pub(super) struct ViewEntry {
    key: String,
    pub(super) record: Arc<ViewRecord>,
    active: Vec<ActiveView>,
    /// Session history: a stream has opened on this session, on this entry
    /// or on one since pruned idle, carried across that pruning by
    /// `record_for`. It is not this entry's own current admission.
    opened: bool,
}

/// One view's record: what its caller was last told, the stamps writes are
/// ordered by, and the gate that makes stamp order equal data order.
#[derive(Debug, Default)]
pub(crate) struct ViewRecord {
    state: parking_lot::Mutex<ToldState>,
    stamps: std::sync::atomic::AtomicU64,
    /// Bumped each time the caller changes: a read made under an earlier
    /// epoch describes the old caller and is never recorded (rekey).
    epoch: std::sync::atomic::AtomicU64,
    gate: tokio::sync::Mutex<()>,
}

impl ViewRecord {
    /// Run `read` and give it a stamp. The stamp is taken and the read made
    /// under one gate, so a read that took a later stamp never captured older
    /// data (MIK-8350 D17b). The gate covers cache reads only.
    pub(crate) async fn read<T>(&self, read: impl std::future::Future<Output = T>) -> (u64, T) {
        let _gate = self.gate.lock().await;
        let stamp = self.stamps.fetch_add(1, Ordering::AcqRel) + 1;
        (stamp, read.await)
    }

    pub(crate) fn state(&self) -> parking_lot::MutexGuard<'_, ToldState> {
        self.state.lock()
    }

    /// How many times the caller has changed under this record.
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// The caller changed: forget what it was told and refuse every write read
    /// before now.
    pub(crate) fn clear(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        let floor = self.stamps.fetch_add(1, Ordering::AcqRel) + 1;
        self.state.lock().clear(floor);
    }
}

/// What one open stream judges with: its own subject, the record of its view,
/// and the judge.
#[derive(Clone)]
pub(crate) struct StreamView {
    pub(crate) subject: Arc<ViewSubject>,
    pub(crate) record: Arc<ViewRecord>,
    pub(crate) judge: Arc<dyn ViewJudge>,
    /// This attachment's close lease, shared by its clones only: the last
    /// clone dropping signals closure to the session's registration.
    close_lease: Arc<CloseLease>,
}

impl std::fmt::Debug for StreamView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamView").finish_non_exhaustive()
    }
}

/// What a stream does with a view hint at write.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Its view did not move, or a newer write already told it.
    Skip,
    /// Its caller no longer resolves: close.
    Close,
    /// Write it; the record is made.
    Write,
}

/// Whether `notification` is the `tools/list_changed` hint.
fn is_tools_list_changed(notification: &TaggedNotification) -> bool {
    notification.data.get("method").and_then(Value::as_str)
        == Some("notifications/tools/list_changed")
}

/// A refresh read before an answer was built, held until the answer is known
/// to have been delivered.
#[derive(Default)]
pub(crate) struct PendingRefresh(Option<HeldRefresh>);

/// A refresh read: the record, its epoch and stamp, and the view read.
type HeldRefresh = (Arc<ViewRecord>, u64, u64, HashMap<String, ViewDigest>);

impl PendingRefresh {
    /// Record the view as told when the answer was `delivered`; a withheld
    /// answer leaves the record alone, so the change is still owed.
    pub(crate) fn settle(self, delivered: bool) {
        if let (true, Some((record, epoch, stamp, view))) = (delivered, self.0)
            && record.epoch() == epoch
        {
            record.state().refresh(stamp, view);
        }
    }
}

impl ClientSession {
    /// The record of the view `subject` opens, made on first use.
    fn record_for(&self, subject: &ViewSubject) -> Arc<ViewRecord> {
        let key = subject.key();
        if let Some(entry) = self.records.read().iter().find(|entry| entry.key == key) {
            return Arc::clone(&entry.record);
        }
        let mut records = self.records.write();
        if let Some(entry) = records.iter().find(|entry| entry.key == key) {
            return Arc::clone(&entry.record);
        }
        // Session history is captured before any pruning, so dropping the
        // last opened record idle cannot make the session read never-opened.
        let opened = records.iter().any(|entry| entry.opened);
        // Bounded: a record no stream holds is dropped to make room. Records
        // still held by an open stream stay, so growth is bounded by the
        // streams a client can hold open, not by the subjects it presents.
        if records.len() >= MAX_IDLE_RECORDS {
            records.retain(|entry| Arc::strong_count(&entry.record) > 1);
        }
        let record = Arc::new(ViewRecord::default());
        records.push(ViewEntry {
            key,
            record: Arc::clone(&record),
            active: Vec::new(),
            opened,
        });
        record
    }

    /// The record of the view `subject` opens, if a stream opened it.
    fn existing_record(&self, subject: &ViewSubject) -> Option<Arc<ViewRecord>> {
        let key = subject.key();
        self.records
            .read()
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| Arc::clone(&entry.record))
    }

    /// Register one admitted attachment on its view's entry, as its own
    /// weak registration beside any concurrent same-key attachments.
    fn register_view(&self, view: &StreamView) {
        let key = view.subject.key();
        let mut records = self.records.write();
        let Some(entry) = records.iter_mut().find(|entry| entry.key == key) else {
            records.push(ViewEntry {
                key,
                record: Arc::clone(&view.record),
                active: vec![ActiveView::new(
                    Arc::downgrade(&view.subject),
                    view.close_receiver(),
                )],
                opened: true,
            });
            return;
        };
        entry.active.retain(|active| !active.is_dead());
        entry.active.push(ActiveView::new(
            Arc::downgrade(&view.subject),
            view.close_receiver(),
        ));
        entry.opened = true;
    }

    /// Whether no stream has ever opened a view on this session.
    fn never_opened(&self) -> bool {
        self.records.read().iter().all(|entry| !entry.opened)
    }

    /// Every active attachment held on this session, as a weak subject, its
    /// record and its close receiver. Dead registrations are pruned.
    fn views(
        &self,
    ) -> Vec<(
        Weak<ViewSubject>,
        Arc<ViewRecord>,
        tokio::sync::watch::Receiver<bool>,
    )> {
        let mut records = self.records.write();
        let mut views = Vec::new();
        for entry in &mut *records {
            entry.active.retain(|active| !active.is_dead());
            for active in &entry.active {
                views.push((
                    active.subject_weak(),
                    Arc::clone(&entry.record),
                    active.close_receiver(),
                ));
            }
        }
        views
    }
}

/// The record a written view hint makes.
pub(crate) struct Owed {
    backend: String,
    digest: ViewDigest,
    stamp: u64,
    /// The record's epoch when the view was read.
    epoch: u64,
}

impl StreamView {
    /// One attachment's view, with the close lease it alone owns.
    pub(crate) fn new(
        subject: Arc<ViewSubject>,
        record: Arc<ViewRecord>,
        judge: Arc<dyn ViewJudge>,
    ) -> Self {
        Self {
            subject,
            record,
            judge,
            close_lease: Arc::new(CloseLease::new()),
        }
    }

    /// A receiver for this attachment's closure, retained by its session
    /// registration without owning the lease.
    fn close_receiver(&self) -> tokio::sync::watch::Receiver<bool> {
        self.close_lease.subscribe()
    }

    /// What `backend` shows this stream's caller now, against what it was
    /// told: the record to make if the hint is written, or `None` when its
    /// view did not move. Nothing is recorded yet (MIK-8350 B2').
    pub(crate) async fn owed(
        &self,
        auth: &AuthState,
        credential: Option<&HeldCredential>,
        session_id: &str,
        backend: &str,
    ) -> Judged<Option<Owed>> {
        // The epoch is read before anything else: a caller change after this
        // point makes the read stale, and `commit` refuses it.
        let epoch = self.record.epoch();
        // Resolved before the gate: the credential's validation can reach an
        // identity provider, and the gate covers cache reads only.
        let caller = match self.judge.resolve(auth, (credential, &self.subject)).await {
            Judged::Live(caller) => caller,
            // An anonymous stream's `Bearer` death is silence, not a close.
            Judged::Dead(reason) => {
                if let (None, DeadReason::Bearer) = (credential, reason) {
                    return Judged::Live(None);
                }
                reason.count();
                return Judged::Dead(reason);
            }
        };
        let (stamp, digest) = self
            .record
            .read(async {
                self.judge
                    .digest(&caller, &self.subject, session_id, backend)
            })
            .await;
        let moved = self.record.state().peek(stamp, backend, &digest) == Peek::Owed;
        Judged::Live(moved.then(|| Owed {
            backend: backend.to_owned(),
            digest,
            stamp,
            epoch,
        }))
    }

    /// Make the record for a hint that has been written. `false` when a newer
    /// write already told the caller (the frame is then not written).
    pub(crate) fn commit(&self, owed: &Owed) -> bool {
        if self.record.epoch() != owed.epoch {
            return false;
        }
        self.record
            .state()
            .commit(owed.stamp, &owed.backend, &owed.digest)
    }

    /// Judge the hint a stream is about to write, under its own subject and
    /// record. The frame has passed every write gate, so the record is made
    /// here.
    pub(crate) async fn decide(
        &self,
        auth: &AuthState,
        credential: Option<&HeldCredential>,
        session_id: &str,
        backend: &str,
    ) -> Decision {
        match self.owed(auth, credential, session_id, backend).await {
            Judged::Dead(_) => Decision::Close,
            Judged::Live(Some(owed)) if self.commit(&owed) => Decision::Write,
            Judged::Live(_) => Decision::Skip,
        }
    }
}

#[path = "streaming_told_multiplexer.rs"]
mod multiplexer;

/// How many view records a session keeps before it drops the idle ones.
const MAX_IDLE_RECORDS: usize = 16;

#[cfg(test)]
#[path = "streaming_told_bounds_tests.rs"]
mod bounds_tests;

#[cfg(test)]
#[path = "streaming_told_state_tests.rs"]
mod state_tests;

#[cfg(test)]
#[path = "streaming_told_decision_tests.rs"]
mod decision_tests;

#[cfg(test)]
#[path = "streaming_told_gap_tests.rs"]
mod gap_tests;

#[cfg(test)]
#[path = "streaming_told_custody_tests.rs"]
pub(super) mod custody_tests;
