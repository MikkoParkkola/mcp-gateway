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
        match VISIBILITY_MEMO.try_with(|memo| memo.recorded(server, tool)) {
            Ok(Some(recorded)) => recorded,
            Ok(None) => {
                let judged = judge();
                VISIBILITY_MEMO
                    .try_with(|memo| memo.record(server, tool, judged))
                    .unwrap_or(judged)
            }
            Err(_) => judge(),
        }
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
        if self.surfaced_schema_withheld(server, tool) {
            return Visibility::Withheld(Withholding::Schema);
        }
        self.invokable(server, tool, scope, session_id)
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
#[derive(Default)]
pub(crate) struct VisibilityMemo(
    parking_lot::Mutex<std::collections::HashMap<(String, String), Visibility>>,
);

impl VisibilityMemo {
    fn recorded(&self, server: &str, tool: &str) -> Option<Visibility> {
        self.0
            .lock()
            .get(&(server.to_owned(), tool.to_owned()))
            .copied()
    }

    /// Record `judged` unless an answer is already recorded; returns the
    /// recorded answer, so the first judgement wins.
    fn record(&self, server: &str, tool: &str, judged: Visibility) -> Visibility {
        *self
            .0
            .lock()
            .entry((server.to_owned(), tool.to_owned()))
            .or_insert(judged)
    }
}

tokio::task_local! {
    /// The open request's memo; see [`with_visibility_memo`].
    static VISIBILITY_MEMO: VisibilityMemo;
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

/// Test-only hook between the route stage and the dispatch, for the row that
/// changes the catalogue in that window (MIK-8340 R3.1 row). Compiled out of
/// non-test builds.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::RefCell;

    thread_local! {
        static AFTER_ROUTE_STAGE: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
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

    /// What the open request's memo holds for `(server, tool)`, if anything
    /// (MIK-8356 row F2). `None` outside a request scope too.
    pub(crate) fn recorded(server: &str, tool: &str) -> Option<super::Visibility> {
        super::VISIBILITY_MEMO
            .try_with(|memo| memo.recorded(server, tool))
            .ok()
            .flatten()
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
