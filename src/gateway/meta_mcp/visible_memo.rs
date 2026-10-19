// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The open request's visibility memo, read and written: the free functions
//! over [`super::VisibilityMemo`] and a task worker's [`super::Judged`].

use super::{
    Carried, Judged, VISIBILITY_MEMO, Visibility, VisibilityMemo, WORKER_JUDGED, absent_name,
    in_memo, target_key,
};

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
pub(crate) fn with_judged<F: std::future::Future>(
    judged: Judged,
    dispatch: F,
) -> impl std::future::Future<Output = F::Output> {
    WORKER_JUDGED.scope(judged, dispatch)
}

/// Record `judged` for `(server, tool)` in the open request's memo unless an
/// answer is already recorded; returns the recorded answer (first judgement
/// wins). Outside a request scope nothing is kept and `judged` is returned.
pub(crate) fn record_visibility(server: &str, tool: &str, judged: Visibility) -> Visibility {
    in_memo(|memo| memo.record(server, tool, judged)).unwrap_or(judged)
}

/// Hand `carried` to the next invocation on `server` in the open request.
/// Outside a request scope it is dropped, and the dispatch resolves itself.
pub(crate) fn carry_dispatch(server: &str, tool: &str, carried: Carried) {
    in_memo(|memo| {
        memo.carried_credential
            .set(target_key(server, tool), carried);
    });
}

/// Read the resolution carried for `server` without consuming it: the step
/// resume fingerprint derives from the same resolution its dispatch will
/// use (MIK-8356 fold F6).
pub(crate) fn with_carried<R>(
    server: &str,
    tool: &str,
    read: impl FnOnce(&Carried) -> R,
) -> Option<R> {
    in_memo(|memo| {
        memo.carried_credential
            .with(&target_key(server, tool), read)
    })
    .flatten()
}

/// Take the resolution carried for `server`, consuming it: a later
/// invocation on the same server resolves again.
pub(crate) fn take_carried(server: &str, tool: &str) -> Option<Carried> {
    in_memo(|memo| memo.carried_credential.take(&target_key(server, tool))).flatten()
}

/// MIK-8361: keep the route stage's refusal code for `(server, tool)`, so the
/// answer's one record names it; dropped outside a request scope.
pub(crate) fn note_denial_code(server: &str, tool: &str, code: i32) {
    in_memo(|memo| memo.denial_code.first(target_key(server, tool), code));
}

/// The code [`note_denial_code`] kept for `(server, tool)`, if any.
pub(crate) fn denial_code(server: &str, tool: &str) -> Option<i32> {
    in_memo(|memo| memo.denial_code.get(&target_key(server, tool))).flatten()
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
