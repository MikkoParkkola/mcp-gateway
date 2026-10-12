// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One answer to "may this caller see this tool?" (MIK-8340).
//!
//! A tool is withheld from a caller for any of three reasons: the caller may
//! not invoke it (profile, authorizer, admin rule, grants), its input schema
//! is structurally invalid, or its description failed the tool-poisoning
//! check. Every listing walk and every decision about a surfaced name asks
//! here, so a withheld tool answers exactly as an absent one everywhere.

use crate::capability::validator::input_schema_is_structurally_valid;
use crate::protocol::Tool;

use super::{InvokeScope, MetaMcp};

/// Why a tool is withheld from a caller. Read only by the audit owner; every
/// decision reader treats a withheld tool exactly as an absent one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Withholding {
    /// The caller may not invoke it.
    Refused,
    /// Its input schema is structurally invalid.
    Schema,
    /// Its description failed the tool-poisoning check.
    Descriptor,
    /// The caller's own complete catalogue on a per-user backend does not
    /// list it (MIK-8356).
    Lacked,
}

/// Whether a caller may be shown a tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Visibility {
    /// Shown, callable by its name.
    Visible,
    /// Withheld for this reason.
    Withheld(Withholding),
}

/// What a name the client called means for this caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Surfaced<'a> {
    /// A surfaced tool this caller may see, on this backend.
    Visible(&'a str),
    /// No surfaced tool has this name.
    Absent,
    /// A surfaced tool on this backend, withheld from this caller.
    Withheld(&'a str, Withholding),
}

impl<'a> Surfaced<'a> {
    /// The backend of a name this caller may see. `None` for an absent or a
    /// withheld name: every decision reader answers those the same way.
    pub(crate) fn visible_server(self) -> Option<&'a str> {
        match self {
            Self::Visible(server) => Some(server),
            Self::Absent | Self::Withheld(..) => None,
        }
    }
}

impl MetaMcp {
    /// Whether `caller` may be shown `tool`, the entry a listing walk holds
    /// from the caller's own catalogue slot (its schema is the one judged).
    pub(crate) fn visible_tool(
        &self,
        server: &str,
        tool: &Tool,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Visibility {
        if self.descriptor_blocked(server, &tool.name) {
            return Visibility::Withheld(Withholding::Descriptor);
        }
        // The schema reason is a backend's: a capability is validated when it
        // loads, and a webhook-only one carries a null schema by design, so
        // only a tool from a registry backend is judged here, as
        // `surfaced_schema_withheld` judges it.
        if self.backends.get(server).is_some()
            && !input_schema_is_structurally_valid(&tool.input_schema)
        {
            return Visibility::Withheld(Withholding::Schema);
        }
        self.invokable(server, &tool.name, scope, session_id)
    }

    /// Whether `caller` may be shown the tool named `tool` on `server`,
    /// judged from the shared catalogue. A cold cache is not a reason: a tool
    /// not yet listed is judged on the other two reasons only.
    ///
    /// Judged once per request: inside [`with_visibility_memo`] the first
    /// answer for `(server, tool)` is recorded and every later read in the
    /// same request gets it, so the route stage and the dispatch can never
    /// disagree (a catalogue refill between them cannot let a name withheld
    /// at the route stage dispatch past its checks). Outside a request scope
    /// (task workers, background paths) each read judges fresh.
    pub(crate) fn tool_visible_to(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Visibility {
        let judge = || self.judge_name(server, tool, scope, session_id);
        let recorded = VISIBILITY_MEMO.try_with(|memo| memo.recorded(server, tool));
        match recorded {
            Ok(Some(recorded)) => recorded,
            // A per-user backend's shared-slot verdict is never memoised
            // (MIK-8356 R5.4): the caller verdict records the first one.
            Ok(None) if self.keeps_per_user_catalogues(server) => judge(),
            Ok(None) => record_visibility(server, tool, judge()),
            Err(_) => judge(),
        }
    }

    /// Whether `server` keeps one catalogue per caller: its tools are judged
    /// by the caller's own slot, never the shared one (MIK-8356). The one
    /// predicate both the route filter and the caller verdict read.
    pub(crate) fn keeps_per_user_catalogues(&self, server: &str) -> bool {
        self.backends
            .get(server)
            .is_some_and(|backend| backend.keeps_per_user_catalogues())
    }

    fn judge_name(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Visibility {
        if self.descriptor_blocked(server, tool) {
            return Visibility::Withheld(Withholding::Descriptor);
        }
        // The schema reason of a per-user backend is the caller's slot's
        // alone (MIK-8356 R5.4): the shared slot's schema never filters it.
        if !self.keeps_per_user_catalogues(server) && self.surfaced_schema_withheld(server, tool) {
            return Visibility::Withheld(Withholding::Schema);
        }
        self.invokable(server, tool, scope, session_id)
    }

    /// Whether this caller can still see a STORED task's target, judged
    /// without a mint or a fill (MIK-8392.STORED.1), or `None` while its
    /// per-user view is cold (the caller answers retryable). The rules are
    /// the listing's: a descriptor block, a slot or account with no view, an
    /// entry withheld by [`Self::visible_tool`], or a catalogue that is
    /// populated, complete and lacks the tool, read from one snapshot. A
    /// truncated catalogue proves nothing about the tool, so it is judged
    /// on the other reasons only, as is a never-populated SHARED catalogue
    /// (T9c). A caller slot that is gone, replaced or not populated is
    /// retryable, never judged as never-populated (F3); a cleared cache
    /// (ever populated, no cached value) is retryable on every view, never
    /// complete-and-empty (F5).
    pub(crate) fn stored_target_view(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Option<Visibility> {
        if self.descriptor_blocked(server, tool) {
            return Some(Visibility::Withheld(Withholding::Descriptor));
        }
        let Some(backend) = self.backends.get(server) else {
            return Some(self.judge_name(server, tool, scope, session_id));
        };
        // A Passthrough backend is never indexed (`remember_caller_slot` skips
        // it), so its listing view is permanently Cold and no read could ever
        // warm it. The live path carries no per-caller binding for such a call,
        // so its verdict reads the shared slot; the stored read judges the
        // shared catalogue too, served when it offers the tool and -32601 when
        // it lacks it, never "retry" forever (MIK-8392).
        let passthrough = backend.identity_propagation_config().is_some_and(|idp| {
            matches!(
                idp.strategy,
                crate::identity_propagation::PropagationStrategyKind::Passthrough
            )
        });
        let binding = if passthrough {
            None
        } else {
            match self.listing_view(&backend, scope) {
                super::listing_view::ListingView::NoView => {
                    return Some(Visibility::Withheld(Withholding::Lacked));
                }
                super::listing_view::ListingView::Cold => return None,
                super::listing_view::ListingView::Shared => None,
                super::listing_view::ListingView::Caller(binding) => Some(binding),
            }
        };
        let (cached, truncated, populated) = backend.cached_tools_view(binding.as_deref());
        let Some(tools) = cached else {
            // No cached value. Cleared (ever populated) is retryable on
            // every view, never complete-and-empty and never served (F5).
            if populated {
                return None;
            }
            // Never populated. A Caller view reads only the pooled entry
            // that is still there and populated: gone, replaced or never
            // filled is retryable, never judged on the other reasons (F3),
            // so an eviction racing this read cannot serve a target the
            // caller's own catalogue had withheld.
            if binding.is_some() {
                return None;
            }
            return Some(self.invokable(server, tool, scope, session_id));
        };
        // A held catalogue past its TTL is stale, by the same rule the live
        // fill uses (F2). The pre-pass refreshes it — per-user through the
        // cold claim, shared through the shared fill — so still stale here
        // means the refresh failed or raced: retryable, never judged stale.
        // Fresh judges, including a withdrawn shared tool within its TTL
        // (the documented residual).
        if !backend.has_cached_tools_for(binding.as_deref()) {
            return None;
        }
        Some(match tools.iter().find(|entry| entry.name == tool) {
            Some(entry) => self.visible_tool(server, entry, scope, session_id),
            None if populated && !truncated => Visibility::Withheld(Withholding::Lacked),
            None => self.invokable(server, tool, scope, session_id),
        })
    }

    /// What the name `tool_name` means for this caller.
    pub(crate) fn surfaced_for<'s>(
        &'s self,
        tool_name: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Surfaced<'s> {
        let Some(server) = self.surfaced_tools_map.unscoped(tool_name) else {
            return Surfaced::Absent;
        };
        match self.tool_visible_to(server, tool_name, scope, session_id) {
            Visibility::Visible => Surfaced::Visible(server),
            Visibility::Withheld(reason) => Surfaced::Withheld(server, reason),
        }
    }

    /// Descriptor blocking applies whether or not the cache is warm (A6).
    fn descriptor_blocked(&self, server: &str, tool: &str) -> bool {
        self.backends
            .get(server)
            .is_some_and(|backend| backend.is_blocked_tool(tool))
    }

    fn invokable(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Visibility {
        if self.may_invoke(server, tool, scope, session_id).is_err() {
            Visibility::Withheld(Withholding::Refused)
        } else {
            Visibility::Visible
        }
    }
}

/// The surfaced-name table, encapsulated (MIK-8340 A4). A decision about a
/// caller's call reads it only through [`MetaMcp::surfaced_for`]; the raw
/// lookup is [`SurfacedMap::unscoped`], kept for readers that name the server
/// of a call already authorized and dispatched (receipts, relay records,
/// audit attribution, recovery of an admitted task).
#[derive(Debug, Default, Clone)]
pub(crate) struct SurfacedMap(std::collections::HashMap<String, String>);

impl SurfacedMap {
    pub(super) fn new(map: std::collections::HashMap<String, String>) -> Self {
        Self(map)
    }

    /// The backend a surfaced name routes to, for every caller alike. Not a
    /// visibility decision: use [`MetaMcp::surfaced_for`] for one.
    pub(crate) fn unscoped(&self, tool_name: &str) -> Option<&str> {
        self.0.get(tool_name).map(String::as_str)
    }

    #[cfg(test)]
    pub(super) fn contains(&self, tool_name: &str) -> bool {
        self.0.contains_key(tool_name)
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl MetaMcp {
    /// [`SurfacedMap::unscoped`] for readers outside this module that name the
    /// server of a call already authorized and dispatched. Never a decision.
    pub(crate) fn surfaced_server_unscoped(&self, tool_name: &str) -> Option<&str> {
        self.surfaced_tools_map.unscoped(tool_name)
    }
}

/// Whose view a call's backend targets are resolved in.
#[derive(Clone, Copy)]
pub(crate) enum TargetView<'s> {
    /// A decision about this caller's call: a surfaced name withheld from it
    /// resolves to no target, as an absent name does.
    Caller(InvokeScope<'s>, Option<&'s str>),
    /// Attribution of a call already dispatched (its response's security).
    Dispatched,
}

impl MetaMcp {
    /// Whether a listing walk shows `tool` (the caller's own catalogue entry)
    /// to this caller: [`Self::visible_tool`] as a filter.
    pub(crate) fn shows_tool(
        &self,
        server: &str,
        tool: &Tool,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> bool {
        self.visible_tool(server, tool, scope, session_id) == Visibility::Visible
    }

    /// Whether a name-only listing (the disabled list, predictions, counts over
    /// names, spec-preview names) shows the tool named `tool` to this caller.
    /// On a per-user backend it is judged by the caller's own catalogue slot,
    /// and withheld while that slot is cold (MIK-8356); elsewhere as
    /// [`Self::shows_shared_name`].
    pub(crate) fn shows_name(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> bool {
        self.listing_names(
            server,
            tool,
            scope,
            session_id,
            super::listing_view::ColdRule::Withhold,
        )
    }

    /// The shared-catalogue judgement of the tool named `tool`:
    /// [`Self::tool_visible_to`] as a filter.
    pub(crate) fn shows_shared_name(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> bool {
        self.tool_visible_to(server, tool, scope, session_id) == Visibility::Visible
    }
}

/// One visibility judgement per request (MIK-8340, perflane MIK-8356 R3.1):
/// the first answer [`MetaMcp::tool_visible_to`] gives for a `(server, tool)`
/// within a request, kept for the rest of that request.
///
/// It also carries the caller verdict's credential resolution to the
/// dispatch (MIK-8356 R5.2): one resolution per call, on the same backend
/// instance the verdict judged; and it keeps what intake judged the sanitize
/// exemption on ([`Judged`], MIK-8154).
#[derive(Default)]
pub(crate) struct VisibilityMemo {
    visibility: parking_lot::Mutex<std::collections::HashMap<(String, String), Visibility>>,
    carried_credential: parking_lot::Mutex<std::collections::HashMap<(String, String), Carried>>,
    judged: parking_lot::Mutex<Judged>,
    /// MIK-8392: each target account's liveness, filled once per request by
    /// the async pre-pass and only read after it. Never a [`Visibility`]: an
    /// account outcome and a caller-view judgement are kept apart.
    offer_pending:
        parking_lot::Mutex<std::collections::HashMap<(String, AccountKey), AccountOutcome>>,
    /// MIK-8392 d0 warm path: the binding the pre-pass's view read gave each
    /// account, so a warm read revalidates its indexed slot without a second
    /// vault read.
    account_binding: parking_lot::Mutex<std::collections::HashMap<(String, AccountKey), String>>,
    /// MIK-8392 (lead ruling 2026-10-12): the live call's own refusal for an
    /// account that can never bind this caller, so a stored read answers what
    /// the live call answers instead of "retry" forever.
    account_refusal:
        parking_lot::Mutex<std::collections::HashMap<(String, AccountKey), crate::Error>>,
}

/// The account a target's dispatch would use (MIK-8392): a managed
/// descriptor's id, from an identity-propagation backend's `account` or a
/// capability's `auth.account`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct AccountKey(pub(crate) String);

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
    /// Custody could not be read (busy, shutting down, store failure): not a
    /// finding about the grant, so a reader answers retryable.
    Unavailable,
}

/// Record `outcome` for `(server, account)` in the open request's memo unless
/// one is recorded; outside a memo nothing is kept.
pub(crate) fn record_account_outcome(server: &str, account: &AccountKey, outcome: AccountOutcome) {
    let _ = VISIBILITY_MEMO.try_with(|memo| {
        memo.offer_pending
            .lock()
            .entry((server.to_owned(), account.clone()))
            .or_insert(outcome);
    });
}

#[path = "visible_account_memo.rs"]
mod account_memo;
pub(crate) use account_memo::{
    account_binding, record_account_binding, record_account_refusal, take_account_refusal,
};

/// The outcome recorded for `(server, account)` in the open request. Reads
/// the memo only: outside an open memo, or before the pre-pass ran, it is
/// `None`, and the caller fails closed. It never judges afresh (unlike the
/// visibility fallback in [`MetaMcp::tool_visible_to`]).
pub(crate) fn account_outcome(server: &str, account: &AccountKey) -> Option<AccountOutcome> {
    VISIBILITY_MEMO
        .try_with(|memo| {
            memo.offer_pending
                .lock()
                .get(&(server.to_owned(), account.clone()))
                .copied()
        })
        .ok()
        .flatten()
}

/// A caller verdict's resolution, waiting for the first invocation on its
/// server in the same request.
pub(crate) struct Carried {
    /// The backend instance the verdict judged; the dispatch uses it, never
    /// a second lookup by name (a reload in between keeps the old instance).
    pub(crate) backend: std::sync::Arc<crate::backend::Backend>,
    /// The credential the verdict resolved.
    pub(crate) resolved: super::invoke::ResolvedDispatch,
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

impl VisibilityMemo {
    fn recorded(&self, server: &str, tool: &str) -> Option<Visibility> {
        self.visibility
            .lock()
            .get(&(server.to_owned(), tool.to_owned()))
            .copied()
    }

    /// Record `judged` unless an answer is already recorded; returns the
    /// recorded answer, so the first judgement wins.
    fn record(&self, server: &str, tool: &str, judged: Visibility) -> Visibility {
        *self
            .visibility
            .lock()
            .entry((server.to_owned(), tool.to_owned()))
            .or_insert(judged)
    }
}

/// Record the digest of the playbook definition intake judged, in the open
/// request's memo. Outside a memo there is no request to bind it to.
pub(crate) fn record_judged_playbook(digest: String) {
    let _ = VISIBILITY_MEMO.try_with(|memo| memo.judged.lock().playbook = Some(digest));
}

/// Record the backend instances an exempt call's targets were judged on.
pub(crate) fn record_exempt_instances(instances: &[std::sync::Arc<crate::backend::Backend>]) {
    let judged: Vec<_> = instances
        .iter()
        .map(|backend| (backend.name.clone(), std::sync::Arc::downgrade(backend)))
        .collect();
    let _ = VISIBILITY_MEMO.try_with(|memo| memo.judged.lock().instances = judged);
}

/// What this request's intake judged, or what a task worker carries from its
/// submit ([`with_judged`]); empty outside both.
pub(crate) fn judged() -> Judged {
    // An empty memo (one a worker's dispatch opened) defers to the worker's.
    let memo = VISIBILITY_MEMO
        .try_with(|memo| memo.judged.lock().clone())
        .unwrap_or_default();
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
    let request = VISIBILITY_MEMO.try_with(|memo| differs(&memo.judged.lock()));
    let differs = request
        .ok()
        .flatten()
        .or_else(|| WORKER_JUDGED.try_with(differs).ok().flatten())?;
    differs.then(|| "The backend changed after this call was admitted; retry the call".to_owned())
}

/// Run a task's dispatch with what its submit judged (MIK-8154 C2e, F2), so
/// the run refuses a playbook or backend reloaded between submit and run. Not
/// a memo: a task's visibility is judged live, however long it runs.
pub(crate) fn with_judged<F: std::future::Future>(
    judged: Judged,
    dispatch: F,
) -> impl std::future::Future<Output = F::Output> {
    WORKER_JUDGED.scope(judged, dispatch)
}

tokio::task_local! {
    /// The open request's memo; see [`with_visibility_memo`].
    static VISIBILITY_MEMO: VisibilityMemo;
    /// A task worker's judgement; see [`with_judged`].
    static WORKER_JUDGED: Judged;
}

/// Record `judged` for `(server, tool)` in the open request's memo unless an
/// answer is already recorded; returns the recorded answer (first judgement
/// wins). Outside a request scope nothing is kept and `judged` is returned.
pub(crate) fn record_visibility(server: &str, tool: &str, judged: Visibility) -> Visibility {
    VISIBILITY_MEMO
        .try_with(|memo| memo.record(server, tool, judged))
        .unwrap_or(judged)
}

/// Hand `carried` to the next invocation on `server` in the open request.
/// Outside a request scope it is dropped, and the dispatch resolves itself.
pub(crate) fn carry_dispatch(server: &str, tool: &str, carried: Carried) {
    let key = (server.to_owned(), tool.to_owned());
    let _ = VISIBILITY_MEMO.try_with(|memo| memo.carried_credential.lock().insert(key, carried));
}

/// Read the resolution carried for `server` without consuming it: the step
/// resume fingerprint derives from the same resolution its dispatch will
/// use (MIK-8356 fold F6).
pub(crate) fn with_carried<R>(
    server: &str,
    tool: &str,
    read: impl FnOnce(&Carried) -> R,
) -> Option<R> {
    let key = (server.to_owned(), tool.to_owned());
    VISIBILITY_MEMO
        .try_with(|memo| memo.carried_credential.lock().get(&key).map(read))
        .ok()
        .flatten()
}

/// Take the resolution carried for `server`, consuming it: a later
/// invocation on the same server resolves again.
pub(crate) fn take_carried(server: &str, tool: &str) -> Option<Carried> {
    let key = (server.to_owned(), tool.to_owned());
    VISIBILITY_MEMO
        .try_with(|memo| memo.carried_credential.lock().remove(&key))
        .ok()
        .flatten()
}

/// The answer already recorded for `(server, tool)` in the open request, if
/// any.
pub(crate) fn recorded_visibility(server: &str, tool: &str) -> Option<Visibility> {
    VISIBILITY_MEMO
        .try_with(|memo| memo.recorded(server, tool))
        .ok()
        .flatten()
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

/// The answer to a name that matches no tool (-32601). A tool withheld from
/// this caller answers with exactly this, so the two cannot be told apart.
pub(crate) fn absent_name(tool_name: &str) -> crate::Error {
    crate::Error::json_rpc(-32601, format!("Unknown tool: {tool_name}"))
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

/// Test-only hook between the route stage and the dispatch, for the row that
/// changes the catalogue in that window (MIK-8340 R3.1 row). Compiled out of
/// non-test builds.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::RefCell;

    thread_local! {
        static AFTER_ROUTE_STAGE: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static BEFORE_TASK_DISPATCH: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static AFTER_INTAKE: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    /// Run `hook` once, the next time `/mcp` or `/mcp/{name}` intake on this
    /// thread has made its sanitize decision (MIK-8154 NP3, F2).
    #[cfg(feature = "firewall")]
    pub(crate) fn after_intake(hook: impl FnOnce() + 'static) {
        AFTER_INTAKE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Called where `/mcp` or `/mcp/{name}` intake has made its sanitize
    /// decision.
    pub(crate) fn intake_judged() {
        if let Some(hook) = AFTER_INTAKE.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }

    /// Run `hook` once, the next time a task worker on this thread starts its
    /// dispatch: between the submit's intake and the run (MIK-8154 C2e2).
    #[cfg(feature = "firewall")]
    pub(crate) fn before_task_dispatch(hook: impl FnOnce() + 'static) {
        BEFORE_TASK_DISPATCH.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Called where a task worker starts its dispatch.
    pub(crate) fn task_dispatch_starts() {
        if let Some(hook) = BEFORE_TASK_DISPATCH.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }

    /// Run `hook` once, the next time a route stage on this thread finishes.
    /// Gated as its only caller, row 14 (router `withheld_parity_tests`), is.
    #[cfg(feature = "firewall")]
    pub(crate) fn after_route_stage(hook: impl FnOnce() + 'static) {
        AFTER_ROUTE_STAGE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Called where a route stage hands over to the dispatch.
    pub(crate) fn route_stage_done() {
        if let Some(hook) = AFTER_ROUTE_STAGE.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }
}

/// MIK-8340 memo semantics (seats gpt-20261011T084206Z-14299 and
/// kimi-20261011T084206Z-14300): first judgement wins within a scope, a
/// nested scope reuses the outer memo, and outside any scope every read
/// judges fresh.
#[cfg(test)]
mod memo_tests {
    use super::{VISIBILITY_MEMO, Visibility, VisibilityMemo, Withholding, with_visibility_memo};

    const WITHHELD: Visibility = Visibility::Withheld(Withholding::Schema);

    /// What the open scope's memo holds for `(server, tool)`; panics outside
    /// a scope (the rows below check that separately).
    fn recorded(server: &str, tool: &str) -> Option<Visibility> {
        VISIBILITY_MEMO
            .try_with(|memo| memo.recorded(server, tool))
            .expect("inside a visibility memo scope")
    }

    fn in_scope() -> bool {
        VISIBILITY_MEMO.try_with(|_| ()).is_ok()
    }

    #[test]
    fn the_first_judgement_wins() {
        let memo = VisibilityMemo::default();
        assert_eq!(memo.record("alpha", "read", WITHHELD), WITHHELD);
        assert_eq!(memo.record("alpha", "read", Visibility::Visible), WITHHELD);
        assert_eq!(memo.recorded("alpha", "read"), Some(WITHHELD));
        assert_eq!(memo.recorded("alpha", "note"), None);
    }

    #[tokio::test]
    async fn a_nested_scope_reuses_the_outer_memo() {
        with_visibility_memo(async {
            VISIBILITY_MEMO.with(|memo| memo.record("alpha", "read", WITHHELD));
            with_visibility_memo(async {
                assert_eq!(recorded("alpha", "read"), Some(WITHHELD));
            })
            .await;
        })
        .await;
    }

    #[tokio::test]
    async fn outside_a_scope_there_is_no_memo_and_scopes_do_not_leak() {
        assert!(!in_scope(), "a memo outside any request scope");
        with_visibility_memo(async {
            VISIBILITY_MEMO.with(|memo| memo.record("alpha", "read", WITHHELD));
        })
        .await;
        with_visibility_memo(async {
            assert_eq!(
                recorded("alpha", "read"),
                None,
                "a second request saw the first's memo"
            );
        })
        .await;
    }
}
