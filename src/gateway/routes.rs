// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every path the gateway HTTP listener registers, declared once.
//!
//! Each entry becomes a constant the router registers through, and [`OWNED`]
//! lists them all, so the owned set cannot drift from what the router mounts.
//! `webhooks.base_path` is refused when it overlaps any owned path
//! (MIK-8002). `routes_tests.rs` fails a listener registration that names
//! anything other than one of these constants.

macro_rules! owned_routes {
    ($($(#[$doc:meta])* $name:ident = $path:literal,)*) => {
        $($(#[$doc])* pub(crate) const $name: &str = $path;)*

        /// Every path the gateway listener can register, across all features.
        pub(crate) const OWNED: &[&str] = &[$($name),*];
    };
}

owned_routes! {
    HEALTH = "/health",
    LIVEZ = "/livez",
    READYZ = "/readyz",
    METRICS = "/metrics",
    API_COSTS = "/api/costs",
    MCP = "/mcp",
    MCP_BACKEND = "/mcp/{name}",
    SSE = "/sse",
    JWKS = "/.well-known/jwks.json",
    PROTECTED_RESOURCE = "/.well-known/oauth-protected-resource",
    AUTH_TOKEN = "/auth/token",
    AUTH_TOKEN_JTI = "/auth/token/{jti}",
    AUTH_TOKENS = "/auth/tokens",
    UI = "/ui",
    /// The classic page, kept for one release beside the new UI (MIK-8870).
    UI_CLASSIC = "/ui/classic",
    /// The new UI's content-hashed static files (MIK-8870).
    UI_ASSET = "/ui/assets/{file}",
    /// Every other `/ui` deep link: the new UI's shell document (MIK-8870).
    UI_SHELL = "/ui/{*path}",
    DASHBOARD = "/dashboard",
    DASHBOARD_HANDOFF = "/dashboard/handoff",
    DASHBOARD_LOGOUT = "/dashboard/logout",
    UI_STATUS = "/ui/api/status",
    UI_TOOLS = "/ui/api/tools",
    UI_TOOLS_CALL = "/ui/api/tools/call",
    UI_CONFIG = "/ui/api/config",
    UI_RELOAD = "/ui/api/reload",
    UI_DASHBOARD_LINK = "/ui/api/dashboard-link",
    UI_COSTS = "/ui/api/costs",
    UI_CAPABILITIES = "/ui/api/capabilities",
    UI_CAPABILITY = "/ui/api/capabilities/{name}",
    UI_CAPABILITY_VALIDATE = "/ui/api/capabilities/{name}/validate",
    UI_CONTROL_PLANE = "/ui/api/control-plane",
    UI_CONTROL_PLANE_GRANTS = "/ui/api/control-plane/grants",
    UI_CONTROL_PLANE_POLICIES = "/ui/api/control-plane/policies",
    UI_CONTROL_PLANE_DECISIONS = "/ui/api/control-plane/decisions",
    UI_CONTROL_PLANE_EXPORT_STATUS = "/ui/api/control-plane/export-status",
    /// The Activity list over both transparency logs.
    UI_ACTIVITY = "/ui/api/activity",
    /// The Activity export: signed NDJSON or CSV.
    UI_ACTIVITY_EXPORT = "/ui/api/activity/export",
    /// One Activity row's receipt.
    UI_ACTIVITY_RECEIPT = "/ui/api/activity/{id}",
    UI_BACKENDS = "/ui/api/backends",
    UI_BACKEND = "/ui/api/backends/{name}",
    UI_BACKEND_REVIVE = "/ui/api/backends/{name}/revive",
    UI_REGISTRY = "/ui/api/registry",
    UI_REGISTRY_SEARCH = "/ui/api/registry/search",
    UI_DEAD_LETTERS = "/ui/api/events/dead-letters",
    UI_DEAD_LETTERS_REPLAY = "/ui/api/events/dead-letters/replay",
    UI_DEAD_LETTER_REPLAY = "/ui/api/events/dead-letters/{id}/replay",
    UI_EVENTS_HELD = "/ui/api/events/held",
    UI_EVENTS_LEASES = "/ui/api/events/leases",
    UI_IMPORT_PREVIEW = "/ui/api/import/openapi/preview",
    UI_IMPORT = "/ui/api/import/openapi",
    /// Start-once preview of a server before it is added. Its own
    /// prefix, so it can never shadow a backend name under `/ui/api/backends`.
    UI_PREVIEWS = "/ui/api/previews",
    /// Servers named in other MCP clients' config files on this host.
    UI_DISCOVERY = "/ui/api/discovery",
    /// One of those servers made a disabled backend.
    UI_DISCOVERY_ADOPT = "/ui/api/discovery/adopt",
    /// The decisions an admin has open.
    UI_DECISIONS = "/ui/api/decisions",
    /// How many decisions an admin has open, and their revision.
    UI_DECISIONS_COUNT = "/ui/api/decisions/count",
    /// The web UI's windowed call counters.
    UI_METRICS_SERIES = "/ui/api/metrics/series",
    /// Restarts, upgrades, reloads, pauses and switch-offs.
    UI_MARKERS = "/ui/api/markers",
    /// The bare prefix, which the catch-all does not match; claimed so it
    /// never reaches the main router's full-URI trace span.
    ACCOUNTS_ROOT = "/accounts/v1",
    /// Every path under the prefix that no route claims.
    ACCOUNTS_UNROUTED = "/accounts/v1/{*rest}",
    ACCOUNTS_JOURNEYS = "/accounts/v1/journeys",
    ACCOUNTS_JOURNEY = "/accounts/v1/journeys/{id}",
    ACCOUNTS_JOURNEY_START = "/accounts/v1/journeys/{id}/start",
    ACCOUNTS_CONNECTION = "/accounts/v1/connections/{account_id}",
    ACCOUNTS_CALLBACK = "/accounts/v1/callback",
    ACCOUNTS_COMPLETE = "/accounts/v1/complete",
    ACCOUNTS_COMPLETE_SCRIPT = "/accounts/v1/assets/complete.js",
    UI_OVERVIEW = "/ui/api/overview",
    UI_REFUSALS = "/ui/api/refusals",
    /// The Gateway page's facts: process, reloads, TLS, upgrade, clients.
    UI_GATEWAY = "/ui/api/gateway",
    /// The UI's live event feed (server-sent events).
    UI_STREAM = "/ui/api/stream",
}
