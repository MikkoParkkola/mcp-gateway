// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What each web UI API route asks of its caller, in one table.
//!
//! The table is the one source two readers share: every `/ui/api` handler
//! admits its caller through [`Guard`], which reads the row for the matched
//! route, and `GET /ui/api/status` reports which pages and tabs the caller may
//! open from the same rows. A handler calls the guard where its own check
//! always stood (after its body is parsed, after a store check that answers
//! first), so every answer a caller sees is the one it saw before.
//!
//! Defaults stay where they are: Activity refuses an unmapped identity, the
//! control plane serves it as an Auditor. Each need calls the resolver that
//! already decides it; nothing here derives a role of its own.

use crate::control_plane::ControlPlaneAction;
use crate::gateway::routes;

/// The refusal a plain admin route has always answered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AdminShape {
    /// `admin_auth_required()`.
    AdminRequired,
    /// `auth_required(403)`.
    Forbidden,
    /// `auth_required(401)`.
    Unauthorized,
    /// The dashboard's HTML page.
    Html,
}

/// What a control-plane route checks once its actor is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CpCheck {
    /// The read view: `ReadInventory` and `ReadEvidence` (`read_only_view`).
    Read,
    /// One RBAC action, checked where the handler always checked it.
    Action(ControlPlaneAction),
    /// Authenticated only; the handler picks the action from the body.
    Authenticated,
}

/// What a route asks of its caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Need {
    /// An admin credential.
    Admin(AdminShape),
    /// History: no client is 401, a non-admin client the admin refusal.
    AdminSplit,
    /// Dashboard-link: an admin holding the static bearer or an API key.
    AdminKeyLink,
    /// Activity: `access::resolve` admits the caller, to all or its own rows.
    ActivityReader,
    /// The control plane, behind its authenticated layer.
    ControlPlane(CpCheck),
    /// No guard: the handler shapes its answer by caller.
    Open,
}

/// A sidebar page of the UI shell, in sidebar order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Page {
    Overview,
    ToDo,
    Servers,
    Tools,
    Activity,
    Costs,
    Access,
    Policies,
    Gateway,
}

/// A tab of a page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Tab {
    Status,
    Actions,
    Settings,
}

impl Page {
    /// The id the shell routes by.
    pub(super) const fn id(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::ToDo => concat!("to", "do"),
            Self::Servers => "servers",
            Self::Tools => "tools",
            Self::Activity => "activity",
            Self::Costs => "costs",
            Self::Access => "access",
            Self::Policies => "policies",
            Self::Gateway => "gateway",
        }
    }
}

impl Tab {
    pub(super) const fn id(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Actions => "actions",
            Self::Settings => "settings",
        }
    }
}

/// The shell's pages, in its sidebar order.
pub(super) const PAGES: [Page; 9] = [
    Page::Overview,
    Page::ToDo,
    Page::Servers,
    Page::Tools,
    Page::Activity,
    Page::Costs,
    Page::Access,
    Page::Policies,
    Page::Gateway,
];

/// The shell's tabs, in its order.
pub(super) const TABS: [Tab; 3] = [Tab::Status, Tab::Actions, Tab::Settings];

/// The methods a UI route registers. HEAD is served through GET.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verb {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Verb {
    /// The verb `method` is served by, if any (HEAD is served by GET).
    pub(super) fn of(method: &axum::http::Method) -> Option<Self> {
        use axum::http::Method;
        Some(match *method {
            Method::GET | Method::HEAD => Self::Get,
            Method::POST => Self::Post,
            Method::PUT => Self::Put,
            Method::PATCH => Self::Patch,
            Method::DELETE => Self::Delete,
            _ => return None,
        })
    }
}

/// One route and method: what it asks, and which tabs it backs.
#[derive(Debug)]
pub(super) struct Row {
    pub(super) path: &'static str,
    pub(super) method: Verb,
    pub(super) need: Need,
    /// The tabs this route backs. Empty: no tab (the shell, the classic page).
    pub(super) tabs: &'static [(Page, Tab)],
    /// A GET the tab fetches when it opens; it decides whether the tab opens.
    pub(super) load: bool,
}

const fn row(
    path: &'static str,
    method: Verb,
    need: Need,
    tabs: &'static [(Page, Tab)],
    load: bool,
) -> Row {
    Row {
        path,
        method,
        need,
        tabs,
        load,
    }
}

use AdminShape::{AdminRequired, Forbidden, Html};
use Need::{ActivityReader, Admin, AdminKeyLink, AdminSplit, ControlPlane, Open};
use Verb::{Delete, Get, Patch, Post, Put};

/// Every route the UI API router mounts, and the dashboard page.
pub(super) static ROWS: &[Row] = &[
    row(
        routes::UI_STATUS,
        Get,
        Open,
        &[(Page::Servers, Tab::Status)],
        true,
    ),
    row(
        routes::UI_OVERVIEW,
        Get,
        Admin(AdminRequired),
        &[(Page::Overview, Tab::Status)],
        true,
    ),
    row(
        routes::UI_METRICS_SERIES,
        Get,
        AdminSplit,
        &[(Page::Overview, Tab::Status)],
        true,
    ),
    row(
        routes::UI_MARKERS,
        Get,
        AdminSplit,
        &[(Page::Overview, Tab::Status)],
        true,
    ),
    row(
        routes::UI_REFUSALS,
        Get,
        Admin(Forbidden),
        &[(Page::ToDo, Tab::Status)],
        true,
    ),
    row(
        routes::UI_DEAD_LETTERS,
        Get,
        Admin(AdminRequired),
        &[(Page::ToDo, Tab::Status)],
        true,
    ),
    row(
        routes::UI_DEAD_LETTERS_REPLAY,
        Post,
        Admin(AdminRequired),
        &[(Page::ToDo, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_DEAD_LETTER_REPLAY,
        Post,
        Admin(AdminRequired),
        &[(Page::ToDo, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_EVENTS_HELD,
        Get,
        Admin(AdminRequired),
        &[(Page::Gateway, Tab::Status)],
        true,
    ),
    row(
        routes::UI_EVENTS_LEASES,
        Get,
        Admin(AdminRequired),
        &[(Page::Gateway, Tab::Status)],
        true,
    ),
    row(
        routes::UI_TOOLS,
        Get,
        Admin(Forbidden),
        &[(Page::Tools, Tab::Status)],
        true,
    ),
    row(
        routes::UI_CAPABILITIES,
        Get,
        Admin(AdminRequired),
        &[(Page::Tools, Tab::Settings)],
        true,
    ),
    row(
        routes::UI_CAPABILITIES,
        Post,
        Admin(AdminRequired),
        &[(Page::Tools, Tab::Settings)],
        false,
    ),
    row(
        routes::UI_CAPABILITY,
        Get,
        Admin(AdminRequired),
        &[(Page::Tools, Tab::Settings)],
        false,
    ),
    row(
        routes::UI_CAPABILITY,
        Put,
        Admin(AdminRequired),
        &[(Page::Tools, Tab::Settings)],
        false,
    ),
    row(
        routes::UI_CAPABILITY,
        Delete,
        Admin(AdminRequired),
        &[(Page::Tools, Tab::Settings)],
        false,
    ),
    row(
        routes::UI_CAPABILITY_VALIDATE,
        Post,
        Admin(AdminRequired),
        &[(Page::Tools, Tab::Settings)],
        false,
    ),
    row(
        routes::UI_BACKENDS,
        Post,
        Admin(AdminRequired),
        &[(Page::Servers, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_BACKEND,
        Delete,
        Admin(AdminRequired),
        &[(Page::Servers, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_BACKEND,
        Patch,
        Admin(AdminRequired),
        &[(Page::Servers, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_BACKEND_REVIVE,
        Post,
        Admin(AdminRequired),
        &[(Page::Servers, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_REGISTRY,
        Get,
        Admin(AdminRequired),
        &[(Page::Servers, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_REGISTRY_SEARCH,
        Get,
        Admin(AdminRequired),
        &[(Page::Servers, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_IMPORT_PREVIEW,
        Post,
        Admin(AdminRequired),
        &[(Page::Servers, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_IMPORT,
        Post,
        Admin(AdminRequired),
        &[(Page::Servers, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_PREVIEWS,
        Post,
        Admin(AdminRequired),
        &[(Page::Servers, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_ACTIVITY,
        Get,
        ActivityReader,
        &[(Page::Activity, Tab::Status)],
        true,
    ),
    row(
        routes::UI_ACTIVITY_EXPORT,
        Get,
        ActivityReader,
        &[(Page::Activity, Tab::Status)],
        false,
    ),
    row(
        routes::UI_ACTIVITY_RECEIPT,
        Get,
        ActivityReader,
        &[(Page::Activity, Tab::Status)],
        false,
    ),
    #[cfg(feature = "cost-governance")]
    row(
        routes::UI_COSTS,
        Get,
        Admin(AdminShape::Unauthorized),
        &[(Page::Costs, Tab::Status)],
        true,
    ),
    row(
        routes::UI_CONTROL_PLANE,
        Get,
        ControlPlane(CpCheck::Read),
        &[(Page::Policies, Tab::Status), (Page::Access, Tab::Status)],
        true,
    ),
    row(
        routes::UI_CONTROL_PLANE_GRANTS,
        Post,
        ControlPlane(CpCheck::Action(ControlPlaneAction::MutateGrant)),
        &[(Page::Access, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_CONTROL_PLANE_POLICIES,
        Post,
        ControlPlane(CpCheck::Action(ControlPlaneAction::MutatePolicy)),
        &[(Page::Policies, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_CONTROL_PLANE_DECISIONS,
        Post,
        ControlPlane(CpCheck::Authenticated),
        &[(Page::Policies, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_CONTROL_PLANE_EXPORT_STATUS,
        Get,
        ControlPlane(CpCheck::Action(ControlPlaneAction::ReadInventory)),
        &[(Page::Gateway, Tab::Status)],
        false,
    ),
    row(
        routes::UI_CONFIG,
        Get,
        Admin(Forbidden),
        &[(Page::Gateway, Tab::Settings)],
        true,
    ),
    row(
        routes::UI_RELOAD,
        Post,
        Admin(AdminRequired),
        &[(Page::Gateway, Tab::Actions)],
        false,
    ),
    row(
        routes::UI_DASHBOARD_LINK,
        Post,
        AdminKeyLink,
        &[(Page::Gateway, Tab::Actions)],
        false,
    ),
    row(routes::DASHBOARD, Get, Admin(Html), &[], false),
];

/// The row for `path` (a matched route template) and `method`.
pub(super) fn row_for(path: &str, method: &axum::http::Method) -> Option<&'static Row> {
    let verb = Verb::of(method)?;
    ROWS.iter().find(|r| r.path == path && r.method == verb)
}
