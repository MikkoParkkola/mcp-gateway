// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `tools/list_changed` axis of the route x check matrix (MIK-8350,
//! family route-check-parity).
//!
//! The parent table is typed by the `tools/call` routes and stages, so this
//! method family keeps its own routes, checks and wildcard-free `expect_notify`
//! beside it: a new notification route, or a new check, without a row here
//! does not compile, and a route that skips the view check fails the test
//! that reads its behaviour row's name below.

/// The routes a `tools/list_changed` hint can leave on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotifyRoute {
    /// The legacy `GET /mcp` SSE stream.
    GetStream,
    /// The 2026 `subscriptions/listen` stream.
    Listen,
    /// The stdio announcer.
    Stdio,
}

/// The checks a hint passes before it is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ViewCheck {
    /// A hint is sent only when the receiving caller's own view moved.
    OwnView,
    /// The identities the stream was opened under are part of that view.
    SubjectAtAttach,
    /// That identity is judged again at every decision, and a stream whose
    /// identity died is closed (MIK-8377).
    ///
    /// Carve-out of condition (3), ruled by the lead (Q1): the agent-mismatch
    /// and proxy-peer clauses are pinned by unit rows on `live()`
    /// (`r_agent_4`/`5`/`6`, `r_proxy_2_peer`), because no running gateway
    /// reaches them: agent auth and `trusted_proxies` are restart-only, and
    /// the session owner binds the agent's grant subject and the bearer's
    /// digest (`owner_of`), so another agent's bearer cannot resume a session
    /// to swap the agent under an open stream.
    IdentityLiveness,
}

/// What a route does about a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotifyExpect {
    /// The check applies; the named test pins it.
    Applies(&'static str),
    /// It cannot apply, and the shared reason why.
    NotApplicable(super::Na),
}

impl NotifyRoute {
    pub(crate) const ALL: [Self; 3] = [Self::GetStream, Self::Listen, Self::Stdio];
}

impl ViewCheck {
    pub(crate) const ALL: [Self; 3] =
        [Self::OwnView, Self::SubjectAtAttach, Self::IdentityLiveness];
}

/// Exhaustive: a new route or check without a row does not compile.
pub(crate) const fn expect_notify(route: NotifyRoute, check: ViewCheck) -> NotifyExpect {
    match (route, check) {
        (NotifyRoute::GetStream, ViewCheck::OwnView) => {
            NotifyExpect::Applies("audience_review_tests::r1_legacy_a_hidden_change")
        }
        (NotifyRoute::Listen, ViewCheck::OwnView) => {
            NotifyExpect::Applies("audience_review_tests::r1_listen_a_hidden_change")
        }
        (NotifyRoute::Stdio, ViewCheck::OwnView) => {
            NotifyExpect::Applies("stdio_list_changed::a5_c1_a_change_hidden_from_the_stdio_scope")
        }
        (NotifyRoute::GetStream, ViewCheck::SubjectAtAttach) => {
            NotifyExpect::Applies("audience_l2_tests::r3_legacy_grant_subject_two_adapter_users")
        }
        (NotifyRoute::Listen, ViewCheck::SubjectAtAttach) => {
            NotifyExpect::Applies("audience_l2_tests::l2_grant_subject_one_key_two_adapter_users")
        }
        // The stdio owner holds no stream identity to capture or judge.
        (NotifyRoute::Stdio, ViewCheck::SubjectAtAttach | ViewCheck::IdentityLiveness) => {
            NotifyExpect::NotApplicable(super::Na::AlwaysLocalOperator)
        }
        (NotifyRoute::GetStream, ViewCheck::IdentityLiveness) => {
            NotifyExpect::Applies("audience_liveness_tests::r_live_1_cert_get")
        }
        (NotifyRoute::Listen, ViewCheck::IdentityLiveness) => {
            NotifyExpect::Applies("audience_liveness_tests::r_live_1_cert_listen")
        }
    }
}

#[test]
fn every_notification_route_states_every_check() {
    for route in NotifyRoute::ALL {
        for check in ViewCheck::ALL {
            match expect_notify(route, check) {
                NotifyExpect::Applies(row) => {
                    assert!(!row.is_empty(), "{route:?} x {check:?} names no row");
                }
                NotifyExpect::NotApplicable(_) => {}
            }
        }
    }
}

#[test]
fn the_view_check_applies_on_every_route() {
    for route in NotifyRoute::ALL {
        assert!(
            matches!(
                expect_notify(route, ViewCheck::OwnView),
                NotifyExpect::Applies(_)
            ),
            "{route:?} sends a hint without judging the caller's own view"
        );
    }
}
