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

use super::{InvokeScope, MetaMcp, scoped_backends::Unscoped};
pub(crate) mod absent;
pub(crate) mod deferred;
pub(crate) mod memo;

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
    /// Its backend's `allowed_tools` leaves it out.
    Unselected,
    /// The caller's own complete catalogue on a per-user backend does not
    /// list it (MIK-8356).
    Lacked,
    /// Its backend is outside a scoped key's grant, or not registered (MIK-8387).
    Absent,
}

impl Withholding {
    /// Withheld by the backend's own gate (its `allowed_tools`, or the
    /// descriptor check): answered at once, whatever the caller's slot holds.
    #[must_use]
    pub(crate) fn is_backend_gate(self) -> bool {
        matches!(self, Self::Descriptor | Self::Unselected)
    }

    /// Whether the gateway withholds for a policy reason (the caller may not
    /// invoke it, or its schema or description failed a check): answered
    /// absent, it is the gateway's refusal. A name the caller's catalogue
    /// lacks, or a backend it cannot reach, is not.
    pub(in crate::gateway::meta_mcp) fn is_policy(self) -> bool {
        matches!(self, Self::Refused | Self::Schema | Self::Descriptor)
    }
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
        if let Some(reason) = self.gate_withholding(server, &tool.name) {
            return Visibility::Withheld(reason);
        }
        // The schema reason is a backend's: a capability is validated when it
        // loads, and a webhook-only one carries a null schema by design, so
        // only a tool from a registry backend is judged here, as
        // `surfaced_schema_withheld` judges it.
        if self
            .backends
            .get_for(Unscoped::Visibility, server)
            .is_some()
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
    /// Judged once per request: inside [`with_visibility_memo`](memo::with_visibility_memo) the first
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
        match memo::recorded_in_scope(server, tool) {
            memo::Scoped::InMemo(Some(recorded)) => recorded,
            // A per-user backend's shared-slot verdict is never memoised
            // (MIK-8356 R5.4): the caller verdict records the first one.
            memo::Scoped::InMemo(None) if self.keeps_per_user_catalogues(server) => judge(),
            memo::Scoped::InMemo(None) => memo::record_visibility(server, tool, judge()),
            memo::Scoped::NoMemo => judge(),
        }
    }

    /// Whether `server` keeps one catalogue per caller: its tools are judged
    /// by the caller's own slot, never the shared one (MIK-8356). The one
    /// predicate both the route filter and the caller verdict read.
    pub(crate) fn keeps_per_user_catalogues(&self, server: &str) -> bool {
        self.backends
            .get_for(Unscoped::Visibility, server)
            .is_some_and(|backend| backend.keeps_per_user_catalogues())
    }

    fn judge_name(
        &self,
        server: &str,
        tool: &str,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Visibility {
        if let Some(reason) = self.gate_withholding(server, tool) {
            return Visibility::Withheld(reason);
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
        if let Some(reason) = self.gate_withholding(server, tool) {
            return Some(Visibility::Withheld(reason));
        }
        let Some(backend) = self.backends.get_for(Unscoped::Visibility, server) else {
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
        let (cached, truncated, populated, fresh) = backend.cached_tools_view(binding.as_deref());
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
        if !fresh {
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
        let Some(server) = self.surfaced_server_unscoped(tool_name) else {
            return Surfaced::Absent;
        };
        match self.tool_visible_to(server, tool_name, scope, session_id) {
            Visibility::Visible => Surfaced::Visible(server),
            Visibility::Withheld(reason) => Surfaced::Withheld(server, reason),
        }
    }

    /// Descriptor blocking applies whether or not the cache is warm (A6).
    /// The backend gate's reason to withhold `tool`: outside the backend's
    /// `allowed_tools`, or blocked by the descriptor gate.
    fn gate_withholding(&self, server: &str, tool: &str) -> Option<Withholding> {
        let backend = self.backends.get_for(Unscoped::Visibility, server)?;
        if backend.is_unselected(tool) {
            Some(Withholding::Unselected)
        } else {
            backend
                .is_blocked_tool(tool)
                .then_some(Withholding::Descriptor)
        }
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
pub(crate) struct SurfacedMap(std::collections::HashMap<String, &'static str>);

/// A backend name as a `&'static str`, leaked once per distinct name.
///
/// The surfaced map is swapped by a reload, but its readers hand
/// out a server name borrowed for the caller's own lifetime (`Surfaced<'s>`,
/// `Option<&str>`). An interned name outlives every snapshot, so those
/// signatures stay as they are.
// ponytail: one small leak per distinct backend name ever surfaced, bounded
// by what an operator configures; move to `Arc<str>` values if names churn.
pub(crate) fn intern(server: &str) -> &'static str {
    static NAMES: std::sync::LazyLock<parking_lot::Mutex<std::collections::HashSet<&'static str>>> =
        std::sync::LazyLock::new(Default::default);
    let mut names = NAMES.lock();
    if let Some(name) = names.get(server) {
        return name;
    }
    let name: &'static str = Box::leak(server.to_owned().into_boxed_str());
    names.insert(name);
    name
}

impl SurfacedMap {
    pub(super) fn new(map: std::collections::HashMap<String, String>) -> Self {
        Self(
            map.into_iter()
                .map(|(tool, server)| (tool, intern(&server)))
                .collect(),
        )
    }

    /// The backend a surfaced name routes to, for every caller alike. Not a
    /// visibility decision: use [`MetaMcp::surfaced_for`] for one.
    pub(crate) fn unscoped(&self, tool_name: &str) -> Option<&'static str> {
        self.0.get(tool_name).copied()
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

/// The validated surfaced tools and their name table: one unit, replaced
/// whole by a reload.
#[derive(Debug, Default)]
pub(crate) struct SurfacedState {
    pub(crate) tools: Vec<crate::config::SurfacedToolConfig>,
    pub(crate) map: SurfacedMap,
}

impl MetaMcp {
    /// The surfaced state this request reads. Inside a request's
    /// visibility memo the first read fixes it for the rest of the request, so
    /// admission, policy, dispatch and a deferred replay's lift all see one
    /// map even if a reload swaps it mid-request; a pinned name (a task's
    /// recorded server) wins over that snapshot. Outside a memo, the live
    /// state. The read guard is dropped before this returns.
    pub(crate) fn surfaced_state(&self) -> std::sync::Arc<SurfacedState> {
        memo::surfaced_snapshot(|| self.surfaced_state_live())
            .unwrap_or_else(|| self.surfaced_state_live())
    }

    /// The live surfaced state, ignoring any request snapshot: for the one
    /// check that must see a reload a snapshot would hide (a task's
    /// moved-target check) and for the reload itself.
    pub(crate) fn surfaced_state_live(&self) -> std::sync::Arc<SurfacedState> {
        std::sync::Arc::clone(&self.surfaced.read())
    }

    /// [`SurfacedMap::unscoped`] for readers outside this module that name the
    /// server of a call already authorized and dispatched. Never a decision.
    pub(crate) fn surfaced_server_unscoped(&self, tool_name: &str) -> Option<&'static str> {
        memo::surfaced_pin(tool_name).or_else(|| self.surfaced_state().map.unscoped(tool_name))
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

/// Test-only hook between the route stage and the dispatch, for the row that
/// changes the catalogue in that window (MIK-8340 R3.1 row). Compiled out of
/// non-test builds.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::RefCell;

    thread_local! {
        static AFTER_ROUTE_STAGE: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static BEFORE_TASK_DISPATCH: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static AFTER_READMIT: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static AFTER_INTAKE: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static AFTER_CALLER: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static AT_TASK_START: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static AFTER_LIST_SNAPSHOT: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static INSPECTED_SERVERS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    /// Record the servers a settled task result was inspected under.
    pub(crate) fn inspected_under(servers: Vec<String>) {
        INSPECTED_SERVERS.with(|slot| slot.borrow_mut().extend(servers));
    }

    /// The servers settled task results on this thread were inspected under.
    pub(crate) fn take_inspected() -> Vec<String> {
        INSPECTED_SERVERS.with(|slot| std::mem::take(&mut *slot.borrow_mut()))
    }

    /// Run `hook` once, the next time `served_tools_list` on this thread has
    /// taken its surfaced snapshot.
    pub(crate) fn after_list_snapshot(hook: impl FnOnce() + 'static) {
        AFTER_LIST_SNAPSHOT.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Called where `served_tools_list` has taken its surfaced snapshot.
    pub(crate) fn list_snapshot_taken() {
        if let Some(hook) = AFTER_LIST_SNAPSHOT.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }

    /// Run `hook` once, the next time a task worker on this thread starts,
    /// before its surfaced-target check.
    pub(crate) fn at_task_start(hook: impl FnOnce() + 'static) {
        AT_TASK_START.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Called where a task worker starts, before the surfaced-target check.
    pub(crate) fn task_starts() {
        if let Some(hook) = AT_TASK_START.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }

    /// Run `hook` once, the next time `/mcp/{name}` on this thread has
    /// resolved its caller and pinned its generation, before it reads the
    /// body (ADR-023: the window a reload lands in mid-request).
    #[cfg(feature = "firewall")]
    pub(crate) fn after_caller(hook: impl FnOnce() + 'static) {
        AFTER_CALLER.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Called where `/mcp/{name}` has resolved its caller.
    pub(crate) fn caller_resolved() {
        if let Some(hook) = AFTER_CALLER.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
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

    /// Run `hook` once, the next time a task worker on this thread has
    /// re-admitted its call: between the re-admission's judgement and the run
    /// (the C2e6 row).
    #[cfg(feature = "firewall")]
    pub(crate) fn after_readmit(hook: impl FnOnce() + 'static) {
        AFTER_READMIT.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Called where a task worker's re-admission has succeeded.
    pub(crate) fn readmitted() {
        if let Some(hook) = AFTER_READMIT.with(|slot| slot.borrow_mut().take()) {
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
