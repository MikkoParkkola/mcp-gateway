// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call the web UI's Try-a-tool route makes (U12), in scope while that
//! route runs the one MCP dispatch for it.
//!
//! The dispatch writes here the facts only it knows: the invocation's trace,
//! whether the call was sent to a backend, and whether it failed after the
//! send. The route reads them to answer "did not run" (4xx), "ran" (200) or
//! "may have run" (5xx) without reading any JSON-RPC code. The dispatch also
//! reads here what only the route knows: which one call it confirmed for.
//!
//! A task-local, so nothing on the wire can set or read it, and with no call
//! in scope every hook below is a no-op: the MCP path is unchanged. It does
//! not cross `tokio::spawn`; nothing between the MCP handler and the send
//! spawns (a source row pins that), and the one hand-off to another task, a
//! task-augmented call's worker, is refused for a UI call before it starts.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

/// Web UI tool calls that may run at once, per gateway. A constant: the
/// shell's contract leaves no status for "wait", so a full pool refuses.
pub(crate) const MAX_UI_CALLS: usize = 4;

/// What the route confirmed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Confirm {
    /// `confirm_write: true`: the caller confirmed this call, write or not.
    Confirmed,
    /// No confirmation: only a tool the server declared read-only may run.
    DeclaredReadOnlyOnly,
}

/// One UI call: its expected target and caller, and what the dispatch did.
#[derive(Debug)]
pub(crate) struct UiCall {
    server: String,
    tool: String,
    /// The admin the route checked, as `AuthenticatedClient::principal`'s
    /// storage form: the dispatch must run as this one caller.
    principal: String,
    confirm: Confirm,
    trace: OnceLock<Arc<str>>,
    dispatched: AtomicBool,
    failed_after_send: AtomicBool,
    confirm_refused: AtomicBool,
    /// The gate before the send admitted this call. A send the gate did not
    /// admit is refused at the send point (`admit_send`), so a path that
    /// skipped the gate cannot run a UI call.
    gated: AtomicBool,
    /// Who won the race between the send and the route's deadline: one atomic
    /// transition, so a call the deadline cancelled is never sent and a call
    /// already sending is never cancelled.
    race: AtomicU8,
}

/// `race` states.
const OPEN: u8 = 0;
const SENDING: u8 = 1;
const CANCELLED: u8 = 2;

/// What the dispatch recorded, read once it returns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) trace: Option<Arc<str>>,
    /// A send to the backend began: the tool may have acted.
    pub(crate) dispatched: bool,
    /// The send failed (timeout, transport, the backend's error): may have
    /// acted, though the answer may read as an `isError` result.
    pub(crate) failed_after_send: bool,
    /// Refused for want of `confirm_write`; never sent.
    pub(crate) confirm_refused: bool,
}

tokio::task_local! {
    static UI_CALL: Arc<UiCall>;
}

impl UiCall {
    pub(crate) fn new(server: &str, tool: &str, principal: &str, confirm: Confirm) -> Arc<Self> {
        Arc::new(Self {
            server: server.to_owned(),
            tool: tool.to_owned(),
            principal: principal.to_owned(),
            confirm,
            trace: OnceLock::new(),
            dispatched: AtomicBool::new(false),
            failed_after_send: AtomicBool::new(false),
            confirm_refused: AtomicBool::new(false),
            gated: AtomicBool::new(false),
            race: AtomicU8::new(OPEN),
        })
    }

    /// Run `call` with this UI call in scope.
    pub(crate) async fn scope<F: std::future::Future>(self: &Arc<Self>, call: F) -> F::Output {
        UI_CALL.scope(Arc::clone(self), call).await
    }

    pub(crate) fn outcome(&self) -> Outcome {
        Outcome {
            trace: self.trace.get().cloned(),
            dispatched: self.dispatched.load(Ordering::SeqCst),
            failed_after_send: self.failed_after_send.load(Ordering::SeqCst),
            confirm_refused: self.confirm_refused.load(Ordering::SeqCst),
        }
    }

    /// The deadline's claim: `true` when it won, so nothing will be sent.
    pub(crate) fn cancel(&self) -> bool {
        self.race
            .compare_exchange(OPEN, CANCELLED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    fn targets(&self, (server, tool): (&str, &str)) -> bool {
        self.server == server && self.tool == tool
    }
}

fn current() -> Option<Arc<UiCall>> {
    UI_CALL.try_with(Arc::clone).ok()
}

/// Whether a UI call is in scope: it bypasses the response cache, so a
/// result always comes from the tool itself.
pub(crate) fn in_scope() -> bool {
    UI_CALL.try_with(|_| ()).is_ok()
}

/// The invocation's trace, when `gateway_invoke` mints it (before any gate).
pub(crate) fn note_trace(trace: &str) {
    if let Some(call) = current() {
        let _ = call.trace.set(Arc::from(trace));
    }
}

/// The last check before a send: a UI call goes out only as the call its
/// gate admitted. `Err` refuses it; nothing is sent.
pub(crate) fn admit_send(step: (&str, &str)) -> crate::Result<()> {
    let Some(call) = current() else {
        return Ok(());
    };
    if !call.targets(step) || !call.gated.load(Ordering::SeqCst) {
        return Err(refused("this send is not the call the web UI checked"));
    }
    // The send's claim: it loses only to a deadline that cancelled first.
    match call
        .race
        .compare_exchange(OPEN, SENDING, Ordering::SeqCst, Ordering::SeqCst)
    {
        Ok(_) | Err(SENDING) => Ok(()),
        Err(_) => Err(refused("the web UI stopped waiting for this call")),
    }
}

/// A send to `step` begins. Set before the send, so every failure after it
/// reads as dispatched.
pub(crate) fn note_dispatched(_step: (&str, &str)) {
    if let Some(call) = current() {
        call.dispatched.store(true, Ordering::SeqCst);
    }
}

/// A sent call failed. `catalogue_miss`: the backend or tool was not found,
/// which the dispatch decides from its catalogue before any transport
/// attempt (a server that is not registered fails after the mark), so the
/// call did not run. Any other failure may follow an attempt that reached
/// the backend: a retry can end in a connect failure after a timeout, so the
/// broader "cannot have acted" list is not used here.
pub(crate) fn note_send_error(catalogue_miss: bool) {
    if let Some(call) = current() {
        if catalogue_miss && !call.failed_after_send.load(Ordering::SeqCst) {
            call.dispatched.store(false, Ordering::SeqCst);
        } else {
            call.failed_after_send.store(true, Ordering::SeqCst);
        }
    }
}

/// A task-augmented call under a UI call: its worker would run outside the
/// scope, so it is refused.
pub(crate) fn refuses_task() -> bool {
    in_scope()
}

/// The gate before the send, where the dispatched backend and the caller's
/// own binding are resolved: `declared_read_only` is that slot's declaration.
/// `Err` refuses the call; nothing is sent.
pub(crate) fn gate(
    step: (&str, &str),
    principal: Option<&str>,
    declared_read_only: bool,
) -> crate::Result<()> {
    let Some(call) = current() else {
        return Ok(());
    };
    // The principal is the one the route checked as an admin.
    if !call.targets(step) || principal != Some(call.principal.as_str()) {
        return Err(refused("this call is not the one the web UI checked"));
    }
    confirmed(&call, declared_read_only)?;
    call.gated.store(true, Ordering::SeqCst);
    Ok(())
}

/// The capability executor's arm: `read_only` is the definition it is about
/// to run, so a reload after the gate cannot turn the call into a write.
pub(crate) fn gate_capability(read_only: bool) -> crate::Result<()> {
    match current() {
        Some(call) => confirmed(&call, read_only),
        None => Ok(()),
    }
}

fn confirmed(call: &UiCall, read_only: bool) -> crate::Result<()> {
    if call.confirm == Confirm::DeclaredReadOnlyOnly && !read_only {
        call.confirm_refused.store(true, Ordering::SeqCst);
        return Err(refused(
            "this tool is not declared read-only; confirm_write is required",
        ));
    }
    Ok(())
}

fn refused(message: &str) -> crate::Error {
    crate::Error::Forbidden {
        code: crate::error::rpc_codes::INVALID_REQUEST,
        status: axum::http::StatusCode::FORBIDDEN.as_u16(),
        message: message.to_owned(),
    }
}
