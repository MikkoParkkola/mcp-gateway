// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which pages and tabs a caller may open: the `access` member of
//! `GET /ui/api/status`.
//!
//! Decided row by row from [`super::access_table`], with the same verdicts the
//! routes enforce: the admin needs through [`super::guard::decide`], Activity
//! through its own resolver, the control plane through its actor and RBAC.
//! Each row reads the role mapping from the source its route reads.

use serde_json::{Value, json};

use super::access_table::{CpCheck, Need, PAGES, Page, ROWS, Row, TABS, Tab};
use super::guard;
use crate::config_reload::Generation;
use crate::control_plane::{ControlPlaneAction, ControlPlaneRbac};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::AppState;
use crate::key_server::oidc::VerifiedIdentity;

/// The caller, as the report judges it.
struct Caller<'a> {
    client: Option<&'a AuthenticatedClient>,
    identity: Option<&'a VerifiedIdentity>,
}

/// The `access` report for this caller, or `None` for an auth-on caller with
/// no credential (it reaches status only through a public path).
pub(super) fn report(
    state: &AppState,
    generation: &Generation,
    client: Option<&AuthenticatedClient>,
    identity: Option<&VerifiedIdentity>,
) -> Option<Value> {
    // The table that authenticated this request: its pinned generation.
    let auth_on = generation.auth().enabled;
    if auth_on && !client.is_some_and(|c| c.authenticated) {
        return None;
    }
    let caller = Caller { client, identity };
    let live = state.live_config.get();
    let admits = |row: &Row| admits(row, &caller, (&live, generation));
    let pages: Vec<Value> = PAGES
        .iter()
        .map(|&page| page_report(page, auth_on, &admits))
        .collect();
    Some(json!({ "pages": pages }))
}

fn page_report(page: Page, auth_on: bool, admits: &dyn Fn(&Row) -> bool) -> Value {
    let tabs: Vec<(Tab, bool)> = TABS
        .iter()
        .filter_map(|&tab| tab_open(page, tab, admits).map(|open| (tab, open)))
        .collect();
    let open = tabs.iter().any(|&(_, open)| open);
    let mut answer = json!({
        "id": page.id(),
        "open": open,
        "tabs": tabs
            .iter()
            .map(|&(tab, open)| json!({"id": tab.id(), "open": open}))
            .collect::<Vec<_>>(),
    });
    if !open {
        answer["reason"] = reason(page, auth_on, admits).into();
    }
    answer
}

/// Whether `tab` of `page` opens: every row it loads admits the caller, or,
/// with no load rows, any row does. `None`: no row backs the tab.
fn tab_open(page: Page, tab: Tab, admits: &dyn Fn(&Row) -> bool) -> Option<bool> {
    let rows: Vec<&Row> = ROWS
        .iter()
        .filter(|r| r.tabs.contains(&(page, tab)))
        .collect();
    if rows.is_empty() {
        return None;
    }
    let mut loads = rows.iter().filter(|r| r.load).peekable();
    Some(if loads.peek().is_some() {
        loads.all(|r| admits(r))
    } else {
        rows.iter().any(|r| admits(r))
    })
}

/// One short reason a page is hidden: fixed text of ours, from the first row
/// on the page that refuses the caller.
fn reason(page: Page, auth_on: bool, admits: &dyn Fn(&Row) -> bool) -> &'static str {
    let first = ROWS
        .iter()
        .find(|r| r.tabs.iter().any(|&(p, _)| p == page) && !admits(r));
    match first.map(|r| r.need) {
        None => "not in this build",
        Some(_) if !auth_on => "authentication is off; these pages need an admin key",
        Some(Need::ActivityReader) => "needs an admin key or a mapped role",
        Some(Need::ControlPlane(_)) => "needs a signed-in key",
        Some(_) => "needs an admin key",
    }
}

/// Whether `row` admits the caller, as its route decides it.
fn admits(
    row: &Row,
    caller: &Caller<'_>,
    (live, generation): (&crate::config::Config, &Generation),
) -> bool {
    match row.need {
        Need::ActivityReader => super::activity::access::resolve(
            caller.client,
            caller.identity,
            &live.control_plane.role_mapping,
        )
        .is_ok(),
        Need::ControlPlane(check) => {
            // The control plane's layer refuses an unauthenticated caller first.
            if !caller.client.is_some_and(|c| c.authenticated) {
                return false;
            }
            // The snapshot reads the pinned generation's mapping; the other
            // control-plane routes read the live config.
            let mapping = match check {
                CpCheck::Read => &generation.config().control_plane.role_mapping,
                CpCheck::Action(_) | CpCheck::FromBody(_) => &live.control_plane.role_mapping,
            };
            let actor = super::control_plane::mutations::actor_from_client(
                caller.client,
                caller.identity,
                mapping,
            );
            let allowed = |action| ControlPlaneRbac::authorize(&actor, action).allowed;
            match check {
                CpCheck::Read => {
                    allowed(ControlPlaneAction::ReadInventory)
                        && allowed(ControlPlaneAction::ReadEvidence)
                }
                CpCheck::Action(action) => allowed(action),
                CpCheck::FromBody(actions) => actions.iter().any(|&action| allowed(action)),
            }
        }
        need => guard::decide(need, caller.client).is_ok(),
    }
}
