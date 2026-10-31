// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The per-request visibility memo (MIK-8340, MIK-8392): its maps, the one
//! way to read or write them, and every accessor the rest of the gateway uses.
//! A task worker's judgement ([`Judged`]) lives beside it.

use super::absent::absent_name;
use super::deferred::{DeferredReplay, DeferredReplayKey};
use super::{Visibility, Withholding};

/// One visibility judgement per request (MIK-8340, perflane MIK-8356 R3.1):
/// the first answer [`MetaMcp::tool_visible_to`](crate::gateway::meta_mcp::MetaMcp::tool_visible_to) gives for a `(server, tool)`
/// within a request, kept for the rest of that request.
///
/// It also carries the caller verdict's credential resolution to the
/// dispatch (MIK-8356 R5.2): one resolution per call, on the same backend
/// instance the verdict judged; and it keeps what intake judged the sanitize
/// exemption on ([`Judged`], MIK-8154).
#[derive(Default)]
struct VisibilityMemo {
    visibility: Keyed<TargetKey, Visibility>,
    /// Boxed: a [`Carried`] is hundreds of bytes, and the map's smallest
    /// table of them inline crosses the per-call allocation budget
    /// (`http_nonce_alloc` ALLOC.2).
    carried_credential: Keyed<TargetKey, Box<Carried>>,
    /// MIK-8361: the route stage's refusal code, for the call's one record.
    denial_code: Keyed<TargetKey, i32>,
    judged: parking_lot::Mutex<Judged>,
    /// MIK-8392: each target account's liveness, filled once per request by
    /// the async pre-pass and only read after it. Never a [`Visibility`]: an
    /// account outcome and a caller-view judgement are kept apart.
    offer_pending: Keyed<AccountSlot, AccountOutcome>,
    /// MIK-8392 d0 warm path: the binding the pre-pass's view read gave each
    /// account, so a warm read revalidates its indexed slot without a second
    /// vault read.
    account_binding: Keyed<AccountSlot, String>,
    /// MIK-8392 (lead ruling 2026-10-12): the live call's own refusal for an
    /// account that can never bind this caller, so a stored read answers what
    /// the live call answers instead of "retry" forever.
    account_refusal: Keyed<AccountSlot, crate::Error>,
    deferred_replay: Keyed<DeferredReplayKey, DeferredReplay>,
    /// MIK-8392 Busy parity: a transient busy custody met by this request's
    /// mint-free view read, carried to the dispatch and consumed once there,
    /// so nothing in the request reads custody a second time.
    account_transient: Keyed<TargetKey, String>,
    /// The route verdict's resolution error for a target (MIK-8392 G1a),
    /// carried to that target's dispatch so it answers without resolving
    /// (and auditing) a second time in one request.
    resolution_error: Keyed<TargetKey, crate::Error>,
    /// The surfaced state this request reads, taken at its first
    /// surfaced read, so a reload mid-request cannot split it across two maps.
    surfaced: parking_lot::Mutex<Option<std::sync::Arc<super::SurfacedState>>>,
    /// A task's recorded server for its surfaced name, which
    /// wins over the snapshot, so its dispatch runs where it was admitted.
    surfaced_pins: parking_lot::Mutex<std::collections::HashMap<String, &'static str>>,
}

/// A memo map's key for one `(server, tool)` target.
type TargetKey = (String, String);
/// A memo map's key for one `(server, account)` pair.
type AccountSlot = (String, DescriptorId);

fn target_key(server: &str, tool: &str) -> TargetKey {
    (server.to_owned(), tool.to_owned())
}

fn account_slot(server: &str, account: &DescriptorId) -> AccountSlot {
    (server.to_owned(), account.clone())
}

/// The borrowed form of a [`TargetKey`], for reads: no key is built.
fn target<'a>(server: &'a str, tool: &'a str) -> (&'a str, &'a str) {
    (server, tool)
}

/// The borrowed form of an [`AccountSlot`], for reads: no key is built.
fn slot<'a>(server: &'a str, account: &'a DescriptorId) -> (&'a str, &'a str) {
    (server, account.0.as_str())
}

/// A memo key seen as its two string halves, so a read can look an owned
/// key up by borrowed text through `Borrow<dyn Pair>` (MIK-8498.1b).
trait Pair {
    fn pair(&self) -> (&str, &str);
}

impl Pair for (String, String) {
    fn pair(&self) -> (&str, &str) {
        (self.0.as_str(), self.1.as_str())
    }
}

impl Pair for (String, DescriptorId) {
    fn pair(&self) -> (&str, &str) {
        (self.0.as_str(), self.1.0.as_str())
    }
}

impl Pair for (&str, &str) {
    fn pair(&self) -> (&str, &str) {
        (self.0, self.1)
    }
}

impl std::hash::Hash for dyn Pair + '_ {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.pair(), state);
    }
}

impl PartialEq for dyn Pair + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.pair() == other.pair()
    }
}

impl Eq for dyn Pair + '_ {}

impl<'a> std::borrow::Borrow<dyn Pair + 'a> for (String, String) {
    fn borrow(&self) -> &(dyn Pair + 'a) {
        self as &(dyn Pair + 'a)
    }
}

impl<'a> std::borrow::Borrow<dyn Pair + 'a> for (String, DescriptorId) {
    fn borrow(&self) -> &(dyn Pair + 'a) {
        self as &(dyn Pair + 'a)
    }
}

/// One map in the open request's memo (MIK-8498 VISIBLE.2). Every memo map
/// is this type, so each accessor states only which operation it uses:
/// first-wins, overwrite, read, take, or take the first that matches.
struct Keyed<K, V>(parking_lot::Mutex<std::collections::HashMap<K, V>>);

impl<K, V> Default for Keyed<K, V> {
    fn default() -> Self {
        Self(parking_lot::Mutex::new(std::collections::HashMap::new()))
    }
}

impl<K: std::hash::Hash + Eq, V> Keyed<K, V> {
    /// Keep `value` unless an answer is recorded; returns the recorded one.
    fn first(&self, key: K, value: V) -> V
    where
        V: Clone,
    {
        self.0.lock().entry(key).or_insert(value).clone()
    }

    /// Record `value`, replacing any earlier one.
    fn set(&self, key: K, value: V) {
        self.0.lock().insert(key, value);
    }

    // Reads are generic over the borrowed form of the key (`dyn Pair` for
    // the pair-keyed maps; the owned key itself, e.g. `DeferredReplayKey`,
    // for the rest), so a lookup need not build an owned key.
    fn get<Q>(&self, key: &Q) -> Option<V>
    where
        V: Clone,
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.0.lock().get(key).cloned()
    }

    /// Read the entry in place, without cloning or consuming it.
    fn with<Q, R>(&self, key: &Q, read: impl FnOnce(&V) -> R) -> Option<R>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.0.lock().get(key).map(read)
    }

    fn take<Q>(&self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.0.lock().remove(key)
    }

    fn contains<Q>(&self, key: &Q) -> bool
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.0.lock().contains_key(key)
    }

    /// Take the first entry, in the map's own iteration order, whose value
    /// matches; the rest stay.
    fn take_first_where(&self, matches: impl Fn(&V) -> bool) -> Option<V>
    where
        K: Clone,
    {
        let mut held = self.0.lock();
        let key = held
            .iter()
            .find(|(_, value)| matches(value))
            .map(|(key, _)| key.clone())?;
        held.remove(&key)
    }
}

impl Keyed<TargetKey, Visibility> {
    /// Record `key` absent unless it is already withheld (MIK-8387): an
    /// empty or `Visible` entry becomes `Absent`; any withholding keeps its
    /// reason. Nothing ever writes `Visible` over it, since `first` keeps it.
    fn upgrade_to_absent(&self, key: TargetKey) {
        let mut judged = self.0.lock();
        let entry = judged.entry(key).or_insert(Visibility::Visible);
        if *entry == Visibility::Visible {
            *entry = Visibility::Withheld(Withholding::Absent);
        }
    }
}

/// Run `read` on the open request's memo; `None` outside one. The one place
/// the memo's task-local is opened for a read or write.
fn in_memo<R>(read: impl FnOnce(&VisibilityMemo) -> R) -> Option<R> {
    VISIBILITY_MEMO.try_with(read).ok()
}

/// This request's surfaced snapshot, taken from `live` at the first read;
/// `None` outside a memo.
pub(crate) fn surfaced_snapshot(
    live: impl FnOnce() -> std::sync::Arc<super::SurfacedState>,
) -> Option<std::sync::Arc<super::SurfacedState>> {
    in_memo(|memo| std::sync::Arc::clone(memo.surfaced.lock().get_or_insert_with(live)))
}

/// The server a task pinned for its surfaced name in this request, if any.
pub(crate) fn surfaced_pin(tool_name: &str) -> Option<&'static str> {
    in_memo(|memo| memo.surfaced_pins.lock().get(tool_name).copied()).flatten()
}

/// A pin on one surfaced name; dropping it restores the name's earlier pin,
/// or its absence. A resume reuses its answering request's memo, so a pin
/// left behind would keep routing the rest of that request to the recorded
/// server after a reload moved the name.
#[must_use = "the pin is lifted when this is dropped"]
pub(crate) struct SurfacedPin {
    tool_name: String,
    prior: Option<&'static str>,
}

impl Drop for SurfacedPin {
    fn drop(&mut self) {
        in_memo(|memo| {
            let mut pins = memo.surfaced_pins.lock();
            match self.prior {
                Some(prior) => pins.insert(std::mem::take(&mut self.tool_name), prior),
                None => pins.remove(&self.tool_name),
            };
        });
    }
}

/// Pin `tool_name` to `server` in the active memo until the returned guard
/// drops. A resume runs inside its answering request's memo, and a nested
/// scope would reuse that one, so the pin is recorded into whichever memo is
/// active. `None` when no memo is: the caller opens one first.
pub(crate) fn pin_surfaced(tool_name: &str, server: &'static str) -> Option<SurfacedPin> {
    in_memo(|memo| SurfacedPin {
        tool_name: tool_name.to_owned(),
        prior: memo
            .surfaced_pins
            .lock()
            .insert(tool_name.to_owned(), server),
    })
}

/// Run `read` with `tool_name` pinned to `server`, in the active memo or in
/// one opened for the call. For the synchronous readers after a surfaced
/// task's dispatch (the settled result's inspection), which run once the
/// dispatch's own memo has ended.
pub(crate) fn with_surfaced_pin_sync<R>(
    tool_name: &str,
    server: &'static str,
    read: impl FnOnce() -> R,
) -> R {
    if let Some(_pin) = pin_surfaced(tool_name, server) {
        return read();
    }
    VISIBILITY_MEMO.sync_scope(VisibilityMemo::default(), || {
        let _pin = pin_surfaced(tool_name, server);
        read()
    })
}

/// The account a target's dispatch would use (MIK-8392): a managed
/// descriptor's id, from an identity-propagation backend's `account` or a
/// capability's `auth.account`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DescriptorId(pub(crate) String);

/// Whether a target's account is live for this caller, judged without a
/// mint (MIK-8392).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccountOutcome {
    /// The caller's grant yields a binding now.
    Live,
    /// No grant: absent, revoked, reconnect-required, or no principal.
    NoView,
    /// The account kind has no mint-free view (an external or token-exchange
    /// descriptor): visibility is judged on the catalogue only (stated
    /// residual).
    Unjudged,
    /// Custody could not be read (shutting down, store failure): not a
    /// finding about the grant, so a reader answers retryable.
    Unavailable,
    /// Custody is at its in-flight bound (MIK-8392 Busy parity): transient,
    /// audited once as such, and answered exactly as a live call answers it.
    Transient,
}

/// Record `outcome` for `(server, account)` in the open request's memo unless
/// one is recorded; outside a memo nothing is kept.
pub(crate) fn record_account_outcome(
    server: &str,
    account: &DescriptorId,
    outcome: AccountOutcome,
) {
    in_memo(|memo| {
        memo.offer_pending
            .first(account_slot(server, account), outcome)
    });
}

/// The outcome recorded for `(server, account)` in the open request. Reads
/// the memo only: outside an open memo, or before the pre-pass ran, it is
/// `None`, and the caller fails closed. It never judges afresh (unlike the
/// visibility fallback in [`MetaMcp::tool_visible_to`](crate::gateway::meta_mcp::MetaMcp::tool_visible_to)).
pub(crate) fn account_outcome(server: &str, account: &DescriptorId) -> Option<AccountOutcome> {
    in_memo(|memo| {
        memo.offer_pending
            .get(&slot(server, account) as &(dyn Pair + '_))
    })
    .flatten()
}

/// A caller verdict's resolution, waiting for the first invocation on its
/// server in the same request.
pub(crate) struct Carried {
    /// The backend instance the verdict judged; the dispatch uses it, never
    /// a second lookup by name (a reload in between keeps the old instance).
    pub(crate) backend: std::sync::Arc<crate::backend::Backend>,
    /// The credential the verdict resolved.
    pub(crate) resolved: super::super::invoke::ResolvedDispatch,
    /// The verdict's fill failed with this error (after any managed-401
    /// recovery): the dispatch answers it as a failed dispatch, unfilled.
    pub(crate) fill_error: Option<crate::Error>,
}

/// What intake judged a request's sanitize exemption on (MIK-8154): the digest
/// of the playbook definition (C2e), and, for an exempt call, the backend
/// instance each target was judged passthrough on (F2). A run or a send that
/// meets a different definition or instance (a reload since) is refused.
/// `Weak` keeps each judged allocation, so a new instance never shares its
/// address.
#[derive(Clone, Default)]
pub(crate) struct Judged {
    playbook: Option<String>,
    instances: Vec<(String, std::sync::Weak<crate::backend::Backend>)>,
}

impl Judged {
    /// Nothing was judged: intake found no exemption, which it only looks
    /// for while sanitising is on.
    pub(crate) fn is_empty(&self) -> bool {
        self.playbook.is_none() && self.instances.is_empty()
    }
}

impl VisibilityMemo {
    fn recorded(&self, server: &str, tool: &str) -> Option<Visibility> {
        self.visibility
            .get(&target(server, tool) as &(dyn Pair + '_))
    }

    /// Record `judged` unless an answer is already recorded; returns the
    /// recorded answer, so the first judgement wins.
    fn record(&self, server: &str, tool: &str, judged: Visibility) -> Visibility {
        self.visibility.first(target_key(server, tool), judged)
    }
}

tokio::task_local! {
    /// The open request's memo; see [`with_visibility_memo`].
    static VISIBILITY_MEMO: VisibilityMemo;
    /// A task worker's judgement; see [`with_judged`].
    static WORKER_JUDGED: Judged;
}

/// Record the digest of the playbook definition intake judged, in the open
/// request's memo. Outside a memo there is no request to bind it to.
pub(crate) fn record_judged_playbook(digest: String) {
    in_memo(|memo| memo.judged.lock().playbook = Some(digest));
}

/// Record the backend instances an exempt call's targets were judged on.
pub(crate) fn record_exempt_instances(instances: &[std::sync::Arc<crate::backend::Backend>]) {
    let judged: Vec<_> = instances
        .iter()
        .map(|backend| (backend.name.clone(), std::sync::Arc::downgrade(backend)))
        .collect();
    in_memo(|memo| memo.judged.lock().instances = judged);
}

/// What this request's intake judged, or what a task worker carries from its
/// submit ([`with_judged`]); empty outside both.
pub(crate) fn judged() -> Judged {
    // An empty memo (one a worker's dispatch opened) defers to the worker's.
    let memo = in_memo(|memo| memo.judged.lock().clone()).unwrap_or_default();
    if memo.playbook.is_some() || !memo.instances.is_empty() {
        return memo;
    }
    WORKER_JUDGED.try_with(Clone::clone).unwrap_or_default()
}

/// The playbook digest [`judged`] holds, if any.
pub(crate) fn judged_playbook() -> Option<String> {
    judged().playbook
}

/// The refusal of a `tools/call` sent by a backend instance other than the
/// one intake judged the call exempt on (MIK-8154 F2); `None` when the call
/// was not judged exempt on this backend's name, or on this very instance.
pub(crate) fn changed_instance(backend: &crate::backend::Backend) -> Option<String> {
    // Looked up in place: this runs on every send.
    let differs = |judged: &Judged| {
        judged
            .instances
            .iter()
            .find(|(name, _)| *name == backend.name)
            .map(|(_, instance)| !std::ptr::eq(instance.as_ptr(), backend))
    };
    let differs = in_memo(|memo| differs(&memo.judged.lock()))
        .flatten()
        .or_else(|| WORKER_JUDGED.try_with(differs).ok().flatten())?;
    differs.then(|| "The backend changed after this call was admitted; retry the call".to_owned())
}

/// Run a task's dispatch with what its submit judged (MIK-8154 C2e, F2), so
/// the run refuses a playbook or backend reloaded between submit and run. Not
/// a memo: a task's visibility is judged live, however long it runs.
///
/// An empty `judged` keeps the enclosing judgement, read when the returned
/// future first runs (not when this is called): a wrapper with nothing to add
/// must never switch off the guards an outer one holds. Only a wholly empty
/// judgement inherits; one that names a playbook or an instance replaces the
/// enclosing one whole.
pub(crate) async fn with_judged<F: std::future::Future>(judged: Judged, dispatch: F) -> F::Output {
    let judged = if judged.is_empty() {
        WORKER_JUDGED.try_with(Clone::clone).unwrap_or(judged)
    } else {
        judged
    };
    WORKER_JUDGED.scope(judged, dispatch).await
}

/// Record `judged` for `(server, tool)` in the open request's memo unless an
/// answer is already recorded; returns the recorded answer (first judgement
/// wins). Outside a request scope nothing is kept and `judged` is returned.
pub(crate) fn record_visibility(server: &str, tool: &str, judged: Visibility) -> Visibility {
    in_memo(|memo| memo.record(server, tool, judged)).unwrap_or(judged)
}

/// Hand `carried` to the next invocation of `tool` on `server` in the open
/// request; a later carry for the same `(server, tool)` replaces it.
/// Outside a request scope it is dropped, and the dispatch resolves itself.
pub(crate) fn carry_dispatch(server: &str, tool: &str, carried: Carried) {
    in_memo(|memo| {
        memo.carried_credential
            .set(target_key(server, tool), Box::new(carried));
    });
}

/// Read the resolution carried for `(server, tool)` without consuming it: the step
/// resume fingerprint derives from the same resolution its dispatch will
/// use (MIK-8356 fold F6).
pub(crate) fn with_carried<R>(
    server: &str,
    tool: &str,
    read: impl FnOnce(&Carried) -> R,
) -> Option<R> {
    in_memo(|memo| {
        memo.carried_credential
            .with(&target(server, tool) as &(dyn Pair + '_), |carried| {
                read(carried)
            })
    })
    .flatten()
}

/// Take the resolution carried for `(server, tool)`, consuming it: a later
/// invocation of the same `(server, tool)` resolves again.
pub(crate) fn take_carried(server: &str, tool: &str) -> Option<Carried> {
    in_memo(|memo| {
        memo.carried_credential
            .take(&target(server, tool) as &(dyn Pair + '_))
            .map(|carried| *carried)
    })
    .flatten()
}

/// MIK-8361: keep the route stage's refusal code for `(server, tool)`, so the
/// answer's one record names it; dropped outside a request scope.
pub(crate) fn note_denial_code(server: &str, tool: &str, code: i32) {
    in_memo(|memo| memo.denial_code.first(target_key(server, tool), code));
}

/// The code [`note_denial_code`] kept for `(server, tool)`, if any.
pub(crate) fn denial_code(server: &str, tool: &str) -> Option<i32> {
    in_memo(|memo| {
        memo.denial_code
            .get(&target(server, tool) as &(dyn Pair + '_))
    })
    .flatten()
}

/// The answer already recorded for `(server, tool)` in the open request, if
/// any.
pub(crate) fn recorded_visibility(server: &str, tool: &str) -> Option<Visibility> {
    in_memo(|memo| memo.recorded(server, tool)).flatten()
}

/// Run `request` with one visibility memo for its whole lifetime (the HTTP
/// `tools/call` handler and each stdio request). A request already inside
/// one keeps it, so nested entry points share the outer request's memo.
pub(crate) async fn with_visibility_memo<F: std::future::Future>(request: F) -> F::Output {
    if VISIBILITY_MEMO.try_with(|_| ()).is_ok() {
        return request.await;
    }
    VISIBILITY_MEMO
        .scope(VisibilityMemo::default(), request)
        .await
}

/// A name this request's caller verdict withheld answers as absent at every
/// layer that can serve a stored result for it: the invocation policy, and
/// the two layers that skip that policy for a target signing already prepared
/// (MIK-8356). On stdio, signing prepares before the route stage records the
/// verdict, so a check made only inside the policy would come too early.
///
/// # Errors
///
/// [`absent_name`] when the memo records `server`'s `tool` as withheld.
pub(crate) fn refuse_withheld(server: &str, tool: &str) -> crate::Result<()> {
    absent_if_withheld(recorded_visibility(server, tool), tool)
}

/// The absent answer for an already-judged [`Visibility`] (MIK-8392.STORED.3):
/// the one withheld-name guard, over the memo or over a judgement made where
/// no request memo is open. No second predicate.
///
/// # Errors
///
/// [`absent_name`] when `judged` is withheld.
pub(crate) fn absent_if_withheld(judged: Option<Visibility>, tool: &str) -> crate::Result<()> {
    match judged {
        Some(Visibility::Withheld(_)) => Err(absent_name(tool)),
        _ => Ok(()),
    }
}

/// Record that this request's account check of `(server, account)` did not
/// settle on a binding, overwriting any earlier read: an empty binding, which
/// no held slot's binding equals, so a held view of that account reads as
/// cold for the rest of this request. The one invalidation helper: a deadline
/// cut, a failed pre-pass read, a failed re-check read and a failed publish
/// read all write it.
pub(crate) fn record_account_unchecked(server: &str, account: &DescriptorId) {
    in_memo(|memo| {
        memo.account_binding
            .set(account_slot(server, account), String::new());
    });
}

/// How a caller's held binding compares with this request's account read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeldView {
    /// The request's read gave exactly the held binding.
    Current,
    /// The request's read gave another binding, or none (the unchecked marker).
    Stale,
    /// The request read no binding for the account: nothing to judge by.
    Unread,
}

/// The one rule for "is `held`, a caller's held binding on `server`, still the
/// binding this request's account read gave". Listings, the stored-read claim
/// and the re-check all decide through it.
pub(crate) fn held_view_current(server: &str, account: &DescriptorId, held: &str) -> HeldView {
    judge_held(account_binding(server, account).as_deref(), held)
}

/// [`held_view_current`] over a binding already in hand, for a reader that
/// holds its own read rather than the request memo's.
pub(crate) fn judge_held(read: Option<&str>, held: &str) -> HeldView {
    match read {
        Some(read) if read == held => HeldView::Current,
        Some(_) => HeldView::Stale,
        None => HeldView::Unread,
    }
}

/// Keep the binding the pre-pass's view read gave `(server, account)`.
pub(crate) fn record_account_binding(server: &str, account: &DescriptorId, binding: &str) {
    in_memo(|memo| {
        memo.account_binding
            .set(account_slot(server, account), binding.to_owned());
    });
}

/// The binding the pre-pass's view read gave `(server, account)`, if any.
pub(crate) fn account_binding(server: &str, account: &DescriptorId) -> Option<String> {
    in_memo(|memo| {
        memo.account_binding
            .get(&slot(server, account) as &(dyn Pair + '_))
    })
    .flatten()
}

/// Whether `held`, a caller's held slot binding on `server`, is still the
/// binding the pre-pass's read of `account` gave. A rotated grant's slot is
/// not current. With no account, or no read of it in this request, there is
/// nothing to judge it by and the held slot stands. The one rule for the
/// listings and the stored reads, so the two cannot drift.
pub(crate) fn held_binding_current(
    server: &str,
    account: Option<&DescriptorId>,
    held: &str,
) -> bool {
    account.is_none_or(|account| held_view_current(server, account, held) != HeldView::Stale)
}

/// Keep the live call's refusal for `(server, account)` in the open request;
/// outside one it is dropped.
pub(crate) fn record_account_refusal(server: &str, account: &DescriptorId, refusal: crate::Error) {
    in_memo(|memo| {
        memo.account_refusal
            .set(account_slot(server, account), refusal);
    });
}

/// Keep this request's transient busy custody for `(server, tool)`, with
/// the busy reason; outside a request nothing is kept.
pub(crate) fn record_account_transient(server: &str, tool: &str, reason: String) {
    in_memo(|memo| memo.account_transient.set(target_key(server, tool), reason));
}

/// The transient kept for `(server, tool)`, without consuming it.
pub(crate) fn account_transient(server: &str, tool: &str) -> Option<String> {
    in_memo(|memo| {
        memo.account_transient
            .get(&target(server, tool) as &(dyn Pair + '_))
    })
    .flatten()
}

/// Take any one transient this request holds, consuming it: the task
/// intake trigger, which answers for the whole call.
pub(crate) fn take_any_account_transient() -> Option<String> {
    in_memo(|memo| memo.account_transient.take_first_where(|_| true)).flatten()
}

/// Take any one sealed-transient resolution error this request holds (a
/// busy custody at the route stage's mint, MIK-8428 Case B), consuming it:
/// the task intake trigger beside [`take_any_account_transient`]. Any other
/// carried error is left for its own dispatch.
pub(crate) fn take_any_transient_resolution_error() -> Option<crate::Error> {
    in_memo(|memo| {
        memo.resolution_error.take_first_where(|error| {
            crate::personal_accounts::refusal::transient_data(error).is_some()
        })
    })
    .flatten()
}

/// Take the transient kept for `(server, tool)`, consuming it once.
pub(crate) fn take_account_transient(server: &str, tool: &str) -> Option<String> {
    in_memo(|memo| {
        memo.account_transient
            .take(&target(server, tool) as &(dyn Pair + '_))
    })
    .flatten()
}

/// Keep the route verdict's resolution error for `(server, tool)` in the
/// open request; outside one it is dropped.
pub(crate) fn record_resolution_error(server: &str, tool: &str, error: crate::Error) {
    in_memo(|memo| memo.resolution_error.set(target_key(server, tool), error));
}

/// Whether a resolution error is kept for `(server, tool)`, without
/// consuming it: a repeated verdict reads it as a memo hit (G1a twin).
pub(crate) fn has_resolution_error(server: &str, tool: &str) -> bool {
    in_memo(|memo| {
        memo.resolution_error
            .contains(&target(server, tool) as &(dyn Pair + '_))
    })
    .unwrap_or(false)
}

/// Take the resolution error kept for `(server, tool)`, consuming it once.
pub(crate) fn take_resolution_error(server: &str, tool: &str) -> Option<crate::Error> {
    in_memo(|memo| {
        memo.resolution_error
            .take(&target(server, tool) as &(dyn Pair + '_))
    })
    .flatten()
}

/// Take the refusal kept for `(server, account)`, if any.
pub(crate) fn take_account_refusal(server: &str, account: &DescriptorId) -> Option<crate::Error> {
    in_memo(|memo| {
        memo.account_refusal
            .take(&slot(server, account) as &(dyn Pair + '_))
    })
    .flatten()
}

/// Record `(server, tool)` absent for the rest of the request (MIK-8387).
/// Upgrade-only, unlike the first-judgement-wins record: an absence that lets
/// the call take the early path (past signing and admission) must hold even
/// over an earlier `Visible`, or a backend restored before the per-target
/// gate would be dispatched unadmitted. Nothing ever writes `Visible` over it.
pub(crate) fn record_absent(server: &str, tool: &str) {
    in_memo(|memo| memo.visibility.upgrade_to_absent(target_key(server, tool)));
}

/// Record `entry` for `key` in the open request's memo. `false` outside a
/// memo: nothing was recorded, so no lift can serve it, and the caller must
/// not proceed as though it were deferred.
pub(crate) fn record_deferred_replay(key: DeferredReplayKey, entry: DeferredReplay) -> bool {
    in_memo(|memo| memo.deferred_replay.set(key, entry)).is_some()
}

/// Take the entry recorded for `key`, consuming it: a second take returns
/// `None`, and a nested invocation's key never matches. `None` outside a memo.
pub(crate) fn take_deferred_replay(key: &DeferredReplayKey) -> Option<DeferredReplay> {
    in_memo(|memo| memo.deferred_replay.take(key)).flatten()
}

/// Whether a request memo is open, and what it holds there (MIK-8498): "no
/// memo" and "a memo with nothing recorded" are different answers.
pub(super) enum Scoped<T> {
    NoMemo,
    InMemo(T),
}

/// The visibility recorded for `(server, tool)` in the open request, told
/// apart from there being no open request at all.
pub(super) fn recorded_in_scope(server: &str, tool: &str) -> Scoped<Option<Visibility>> {
    in_memo(|memo| memo.recorded(server, tool)).map_or(Scoped::NoMemo, Scoped::InMemo)
}

#[cfg(test)]
mod account_tests;
#[cfg(test)]
mod alloc_tests;
#[cfg(test)]
mod key_tests;
#[cfg(test)]
mod memo_tests;
#[cfg(test)]
mod semantics_tests;
