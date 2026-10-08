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
    DASHBOARD = "/dashboard",
    DASHBOARD_HANDOFF = "/dashboard/handoff",
    DASHBOARD_LOGOUT = "/dashboard/logout",
    UI_STATUS = "/ui/api/status",
    UI_TOOLS = "/ui/api/tools",
    UI_CONFIG = "/ui/api/config",
    UI_RELOAD = "/ui/api/reload",
    UI_DASHBOARD_LINK = "/ui/api/dashboard-link",
    UI_COSTS = "/ui/api/costs",
    UI_CAPABILITIES = "/ui/api/capabilities",
    UI_CAPABILITY = "/ui/api/capabilities/{name}",
    UI_CONTROL_PLANE = "/ui/api/control-plane",
    UI_CONTROL_PLANE_GRANTS = "/ui/api/control-plane/grants",
    UI_CONTROL_PLANE_POLICIES = "/ui/api/control-plane/policies",
    UI_CONTROL_PLANE_DECISIONS = "/ui/api/control-plane/decisions",
    UI_CONTROL_PLANE_EXPORT_STATUS = "/ui/api/control-plane/export-status",
    UI_BACKENDS = "/ui/api/backends",
    UI_BACKEND = "/ui/api/backends/{name}",
    UI_BACKEND_REVIVE = "/ui/api/backends/{name}/revive",
    UI_REGISTRY = "/ui/api/registry",
    UI_REGISTRY_SEARCH = "/ui/api/registry/search",
    UI_DEAD_LETTERS = "/ui/api/events/dead-letters",
    UI_DEAD_LETTERS_REPLAY = "/ui/api/events/dead-letters/replay",
    UI_DEAD_LETTER_REPLAY = "/ui/api/events/dead-letters/{id}/replay",
    UI_EVENTS_HELD = "/ui/api/events/held",
    UI_IMPORT_PREVIEW = "/ui/api/import/openapi/preview",
    UI_IMPORT = "/ui/api/import/openapi",
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
}
