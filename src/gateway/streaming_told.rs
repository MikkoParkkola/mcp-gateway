// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: what each session was last told of each backend, and the
//! fan-out that tells a session of a `tools/list_changed` only when its own
//! view of that backend moved.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

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

/// A secret carried only so it can be checked again: its `Debug` and `Display`
/// never show a byte of it.
#[derive(Clone)]
pub(crate) struct Redacted(String);

impl Redacted {
    pub(crate) fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The secret, for the check that needs it.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl std::fmt::Display for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

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
    /// The raw Cloudflare Access assertion, when that is the identity source;
    /// re-verified per decision by MIK-8377 and dropped with the stream.
    pub(crate) cf_assertion: Option<Redacted>,
    /// The trusted proxy's peer address, when that is the identity source.
    #[expect(dead_code, reason = "read by MIK-8377's live() clause")]
    pub(crate) proxy_peer: Option<std::net::SocketAddr>,
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
                self.grant_subject,
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

    /// Re-verify the held Cloudflare Access assertion against the verifier's
    /// current keys, as admission did, so a rotated or revoked key ends the
    /// stream. Nothing to check for a stream that holds no assertion; a
    /// missing verifier refuses, as admission does.
    pub(crate) async fn verify_held_cf(&self, ctx: &LiveCtx<'_>) -> Result<(), DeadReason> {
        let Some(assertion) = &self.cf_assertion else {
            return Ok(());
        };
        let Some(verifier) = ctx.cf_verifier else {
            return Err(DeadReason::Cf);
        };
        let age = crate::config::KeyServerOidcConfig {
            token_age: crate::key_server::TokenAgeCap::ExpOnly,
        };
        verifier
            .verify(assertion.expose(), &age)
            .await
            .map(drop)
            .map_err(|_| DeadReason::Cf)
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
    #[expect(dead_code, reason = "read by MIK-8377's live() clauses")]
    pub(crate) cf_verifier: Option<&'a crate::key_server::OidcVerifier>,
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

/// One view held on a session: the key of its subject, the subject and its
/// record.
pub(super) type ViewEntry = (String, Arc<ViewSubject>, Arc<ViewRecord>);

/// One view's record: what its caller was last told, the stamps writes are
/// ordered by, and the gate that makes stamp order equal data order.
#[derive(Debug, Default)]
pub(crate) struct ViewRecord {
    state: parking_lot::Mutex<ToldState>,
    stamps: std::sync::atomic::AtomicU64,
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

    /// The caller changed: forget what it was told and refuse every write read
    /// before now.
    pub(crate) fn clear(&self) {
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
pub(crate) struct PendingRefresh(Option<(Arc<ViewRecord>, u64, HashMap<String, ViewDigest>)>);

impl PendingRefresh {
    /// Record the view as told when the answer was `delivered`; a withheld
    /// answer leaves the record alone, so the change is still owed.
    pub(crate) fn settle(self, delivered: bool) {
        if let (true, Some((record, stamp, view))) = (delivered, self.0) {
            record.state().refresh(stamp, view);
        }
    }
}

impl ClientSession {
    /// The record of the view `subject` opens, made on first use.
    fn record_for(&self, subject: &ViewSubject) -> Arc<ViewRecord> {
        let key = subject.key();
        if let Some((_, _, record)) = self.records.read().iter().find(|(k, ..)| *k == key) {
            return Arc::clone(record);
        }
        let mut records = self.records.write();
        if let Some((_, _, record)) = records.iter().find(|(k, ..)| *k == key) {
            return Arc::clone(record);
        }
        let record = Arc::new(ViewRecord::default());
        records.push((key, Arc::new(subject.clone()), Arc::clone(&record)));
        record
    }

    /// The record of the view `subject` opens, if a stream opened it.
    fn existing_record(
        &self,
        subject: &ViewSubject,
    ) -> Option<(Arc<ViewSubject>, Arc<ViewRecord>)> {
        let key = subject.key();
        self.records
            .read()
            .iter()
            .find(|(k, ..)| *k == key)
            .map(|(_, held, record)| (Arc::clone(held), Arc::clone(record)))
    }

    /// Every view held on this session.
    fn views(&self) -> Vec<(Arc<ViewSubject>, Arc<ViewRecord>)> {
        self.records
            .read()
            .iter()
            .map(|(_, subject, record)| (Arc::clone(subject), Arc::clone(record)))
            .collect()
    }
}

/// The record a written view hint makes.
pub(crate) struct Owed {
    backend: String,
    digest: ViewDigest,
    stamp: u64,
}

impl StreamView {
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
        // Resolved before the gate: the credential's validation can reach an
        // identity provider, and the gate covers cache reads only.
        let caller = match self.judge.resolve(auth, (credential, &self.subject)).await {
            Judged::Live(caller) => caller,
            Judged::Dead(reason) => {
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
        }))
    }

    /// Make the record for a hint that has been written. `false` when a newer
    /// write already told the caller (the frame is then not written).
    pub(crate) fn commit(&self, owed: &Owed) -> bool {
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

impl NotificationMultiplexer {
    /// The view `session_id`'s stream opens with: its own subject's record on
    /// the session, with a baseline of what each backend shows its caller now,
    /// so the first change after attach is judged against what it saw
    /// (MIK-8350). Streams of one session with different subjects get
    /// different records and never judge one another (D17e).
    pub(crate) async fn attach_view(
        &self,
        session_id: &str,
        subject: ViewSubject,
        judge: Arc<dyn ViewJudge>,
    ) -> Result<Option<StreamView>, DeadReason> {
        let Some(authorizer) = self.authorizer.read().clone() else {
            return Ok(None);
        };
        let Some(session) = self.sessions.read().get(session_id).map(Arc::clone) else {
            return Ok(None);
        };
        let subject = Arc::new(subject);
        let record = session.record_for(&subject);
        let credential = session.credential.read().clone();
        match judge
            .resolve(&authorizer, (credential.as_ref(), &subject))
            .await
        {
            Judged::Live(caller) => {
                let (stamp, view) = record
                    .read(async { judge.baseline(&caller, &subject, session_id) })
                    .await;
                record.state().baseline(stamp, view);
            }
            // A caller that does not resolve at attach gets no stream.
            Judged::Dead(reason) => {
                reason.count();
                return Err(reason);
            }
        }
        Ok(Some(StreamView {
            subject,
            record,
            judge,
        }))
    }

    /// Take `session_id`'s baseline for the default subject: for a session no
    /// stream has opened a view on (a bare receiver).
    #[cfg(test)]
    pub(crate) async fn take_baseline(&self, session_id: &str, judge: &Arc<dyn ViewJudge>) {
        let _ = self
            .attach_view(session_id, ViewSubject::default(), Arc::clone(judge))
            .await;
    }

    /// Read what `session_id`'s caller, under `subject`, is shown now, ahead
    /// of an answer that will show it (a `tools/list`, a profile switch). The
    /// result is applied by [`PendingRefresh::settle`] only once that answer
    /// has cleared every delivery gate (MIK-8350 B9, D17h). Empty when no
    /// stream holds a view for that subject.
    pub(crate) async fn read_refresh(
        &self,
        session_id: &str,
        subject: &ViewSubject,
        judge: &dyn ViewJudge,
    ) -> PendingRefresh {
        let Some(authorizer) = self.authorizer.read().clone() else {
            return PendingRefresh::default();
        };
        let Some(session) = self.sessions.read().get(session_id).map(Arc::clone) else {
            return PendingRefresh::default();
        };
        let Some((_, record)) = session.existing_record(subject) else {
            return PendingRefresh::default();
        };
        let credential = session.credential.read().clone();
        let Judged::Live(caller) = judge
            .resolve(&authorizer, (credential.as_ref(), subject))
            .await
        else {
            return PendingRefresh::default();
        };
        let (stamp, view) = record
            .read(async { judge.baseline(&caller, subject, session_id) })
            .await;
        PendingRefresh(Some((record, stamp, view)))
    }

    /// Deliver to every session whose caller may access `backend` now; returns the count.
    ///
    /// Each session's credential is re-validated at delivery, so a revoked or
    /// expired token receives nothing even on a stream opened while it was valid.
    pub(crate) async fn broadcast_to_backend(
        &self,
        notification: &TaggedNotification,
        backend: &str,
    ) -> usize {
        self.broadcast_to_backend_raw(notification, backend, None, None)
            .await
    }

    /// [`Self::broadcast_to_backend`] for a `tools/list_changed`, told only to
    /// the sessions `judge` finds a moved view for (MIK-8350).
    pub(crate) async fn broadcast_to_backend_judged(
        &self,
        notification: &TaggedNotification,
        backend: &str,
        judge: &dyn ViewJudge,
    ) -> usize {
        self.broadcast_to_backend_raw(notification, backend, None, Some(judge))
            .await
    }

    /// [`Self::broadcast_to_backend`] for an item transformed from a raw
    /// inbound value (a webhook body): each copy is also judged on what
    /// `raw` named before the transform dropped it (MIK-7116.MIN.2, §4.4).
    pub(crate) async fn broadcast_to_backend_raw(
        &self,
        notification: &TaggedNotification,
        backend: &str,
        raw: Option<&Value>,
        judge: Option<&dyn ViewJudge>,
    ) -> usize {
        let hidden = raw.and_then(|raw| self.reads.get().and_then(|judge| judge.raw(raw)));
        let Some(authorizer) = self.authorizer.read().clone() else {
            return 0;
        };
        // Copied out so no lock is held across the re-validation awaits. The
        // session itself is held, not its sender, so an unopened one stays
        // unopened and a stream that subscribes meanwhile is still reached.
        let targets: Vec<_> = self
            .sessions
            .read()
            .values()
            .map(|s| (Arc::clone(s), s.credential.read().clone()))
            .collect();
        // MIK-8350: a `tools/list_changed` judged by view is a constant hint
        // that carries nothing of the backend, so it is owed to a caller whose
        // view moved even when that move is losing the backend; only a dead
        // credential is refused, here and again at write. Each stream then
        // judges it again for itself when it writes (D17d).
        let judge = judge.filter(|_| is_tools_list_changed(notification));
        let audience = match judge {
            Some(_) => CopyAudience::Any,
            None => CopyAudience::Backend(Arc::from(backend)),
        };
        let mut reached = 0;
        for (session, credential) in targets {
            let verdict =
                delivery(&authorizer, credential.as_ref(), Audience::Backend(backend)).await;
            // A judged hint goes to a dead caller too: the write-time check
            // closes its stream (D17i).
            if judge.is_none() && verdict != Delivery::Deliver {
                continue;
            }
            if let Some(judge) = judge
                && !self
                    .view_moved(&session, &authorizer, credential.as_ref(), backend, judge)
                    .await
            {
                continue;
            }
            let judged = judge.map(|_| Arc::from(backend));
            if self
                .enqueue(
                    &session,
                    notification.clone(),
                    hidden.as_ref(),
                    None,
                    audience.clone(),
                    judged,
                )
                .is_ok()
            {
                reached += 1;
            }
        }
        reached
    }

    /// Whether any view held on `session` is owed a hint for `backend`. A
    /// session no stream opened a view on has none, so it is judged as the
    /// default subject would be.
    async fn view_moved(
        &self,
        session: &Arc<ClientSession>,
        authorizer: &AuthState,
        credential: Option<&HeldCredential>,
        backend: &str,
        judge: &dyn ViewJudge,
    ) -> bool {
        let mut views = session.views();
        if views.is_empty() {
            views.push((
                Arc::new(ViewSubject::default()),
                session.record_for(&ViewSubject::default()),
            ));
        }
        for (subject, record) in views {
            // A dead caller is closed by the write-time check; the copy still
            // goes so it can be.
            let Judged::Live(caller) = judge.resolve(authorizer, (credential, &subject)).await
            else {
                return true;
            };
            let (stamp, digest) = record
                .read(async {
                    judge.digest(&caller, &subject, session.id.expose_secret(), backend)
                })
                .await;
            if record.state().peek(stamp, backend, &digest) == Peek::Owed {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
#[path = "streaming_told_state_tests.rs"]
mod state_tests;

#[cfg(test)]
#[path = "streaming_told_decision_tests.rs"]
mod decision_tests;
