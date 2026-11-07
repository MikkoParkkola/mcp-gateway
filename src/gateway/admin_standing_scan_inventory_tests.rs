// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The admin-standing reader inventory, and the test that the crate's
//! production sources match it exactly.

use super::*;

/// (needle, file, count, the standing it reads).
const ADMIN_READERS: &[(&str, &str, usize, &str)] = &[
    (
        ".admin",
        "src/config/features/api_key.rs",
        1,
        "the key config Debug field",
    ),
    (
        "resolve_role(",
        "src/control_plane/role_mapping.rs",
        10,
        "the role mapping itself",
    ),
    (
        ".admin",
        "src/events/operational_source.rs",
        2,
        "Gateway: the key config through authz::admin_standing, and its result",
    ),
    (
        ".admin",
        "src/events/rpc.rs",
        1,
        "Gateway: set from CallerStanding::of_client",
    ),
    (
        ".admin",
        "src/gateway/auth_caller.rs",
        1,
        "the accessor: AuthenticatedClient::admin_standing",
    ),
    (
        ".admin",
        "src/gateway/auth_api_key.rs",
        1,
        "the resolved key Debug field",
    ),
    (
        ".admin",
        "src/gateway/auth_bootstrap.rs",
        1,
        "whether any admin credential is configured; no caller standing",
    ),
    (
        ".admin",
        "src/gateway/auth_live.rs",
        1,
        "sets a key-server client flag from the role mapping",
    ),
    (
        "grants_admin(",
        "src/gateway/auth_live.rs",
        1,
        "the key-server admission",
    ),
    (
        ".admin",
        "src/gateway/auth_resolved.rs",
        4,
        "key config into the client, the load warning, session liveness through authz::admin_standing",
    ),
    (".admin", "src/gateway/authz.rs", 1, "BackendGrant::for_ui"),
    (
        ".admin",
        "src/gateway/meta_mcp/call_dispatch.rs",
        4,
        "AdminStanding context reads: meta-tools, stats and profile are Gateway",
    ),
    (
        "CallerStanding::of(",
        "src/gateway/meta_mcp/call_dispatch.rs",
        1,
        "the meta-tool gate",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/caller_context.rs",
        2,
        "AdminStanding passed through",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/invoke/admin.rs",
        3,
        "Gateway: the cost report admin views",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/invoke/chokepoint.rs",
        1,
        "InScope: the admin-only capability rule, after the backend check",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/invoke/errors.rs",
        1,
        "Gateway: the revive hint",
    ),
    (
        "CallerStanding::of(",
        "src/gateway/meta_mcp/invoke/errors.rs",
        1,
        "the revive hint",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/invoke/gate.rs",
        1,
        "InScope: the admin-only capability rule, after the backend check",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/invoke/gate_as_undefined.rs",
        1,
        "InScope: the admin-only capability rule, after the backend check",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/invoke/policy.rs",
        1,
        "InScope: the admin-only capability rule, after the backend check",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/signing.rs",
        1,
        "Gateway: the signing admin bypass",
    ),
    (
        "CallerStanding::of(",
        "src/gateway/meta_mcp/signing.rs",
        1,
        "the signing admin bypass",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/visibility.rs",
        3,
        "InScope: the admin-only capability rule; Gateway: the CallerStanding conversion",
    ),
    (
        "CallerStanding::of_client(",
        "src/gateway/router/authorization.rs",
        2,
        "the tools/call and tools/list gates",
    ),
    (
        "grants_admin(",
        "src/gateway/router/authorization_owned.rs",
        1,
        "a key-server task re-judged under the current mapping",
    ),
    (
        ".admin",
        "src/gateway/router/handlers/tasks.rs",
        3,
        "AdminStanding passed through",
    ),
    (
        "CallerStanding::of_client(",
        "src/gateway/router/handlers.rs",
        2,
        "events listing and catalogue standing",
    ),
    (
        ".admin",
        "src/gateway/task_service/execution/context.rs",
        1,
        "AdminStanding passed through",
    ),
    (
        "resolve_role(",
        "src/gateway/ui/activity/access.rs",
        1,
        "Activity breadth by role, bounded by the scope",
    ),
    (
        "resolve_role(",
        "src/gateway/ui/control_plane/mutations.rs",
        1,
        "the control-plane actor, capped at Auditor when scoped",
    ),
    (
        ".admin",
        "src/gateway/ui/keys.rs",
        1,
        "the key listing shows the config flag",
    ),
    (
        ".admin",
        "src/gateway/ui/stream/sent.rs",
        3,
        "Gateway: set from ui::is_admin; full view only when the scope is unscoped",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/meta_mcp/handlers.rs",
        1,
        "the embedder's unscoped tools/list, no request caller",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/meta_mcp/list_paging_e2e.rs",
        3,
        "a cfg(test) module the file-name filter does not see",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/meta_mcp/search_disclosure_e2e_discovery.rs",
        4,
        "a cfg(test) module the file-name filter does not see",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/meta_mcp/search_disclosure_e2e_guide.rs",
        6,
        "a cfg(test) module the file-name filter does not see",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/meta_mcp/spec_preview.rs",
        7,
        "its cfg(test) rows",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/meta_mcp/visibility.rs",
        2,
        "InvokeScope::unscoped: the operator's view at a given standing",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/router/authorization.rs",
        1,
        "CallerStanding::of: Admin only from Gateway",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/router/handlers.rs",
        1,
        "events listing: of_client compared with Admin",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/server/mod.rs",
        1,
        "stdio: the spawning client is the operator",
    ),
    (
        "is_gateway_admin",
        "src/gateway/router/backend_handlers/costs.rs",
        1,
        "Gateway: /api/costs",
    ),
    (
        "is_gateway_admin",
        "src/gateway/router/handlers/health.rs",
        1,
        "Gateway: /health backend detail",
    ),
    (
        "is_gateway_admin",
        "src/gateway/ui/guard.rs",
        2,
        "Gateway: AdminSplit and the dashboard link mint",
    ),
    (
        "is_gateway_admin",
        "src/gateway/ui/mod.rs",
        1,
        "Gateway: ui::is_admin",
    ),
    (
        "admin_standing",
        "src/events/operational_source.rs",
        1,
        "Gateway: operator event standing from the key config",
    ),
    (
        "admin_standing",
        "src/gateway/auth_caller.rs",
        2,
        "the accessor and is_gateway_admin",
    ),
    (
        "admin_standing",
        "src/gateway/auth_resolved.rs",
        2,
        "InScope: the load warning; Gateway: session liveness",
    ),
    (
        "admin_standing",
        "src/gateway/router/authorization.rs",
        1,
        "CallerStanding::of_client",
    ),
    (
        "admin_standing",
        "src/gateway/router/authorization_owned.rs",
        4,
        "task re-judgement: any step down refuses",
    ),
    (
        "admin_standing",
        "src/gateway/router/backend_handlers/direct_permit.rs",
        1,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/handlers/dispatch_intake_run.rs",
        1,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/handlers/dispatch_tools_call/route_stage.rs",
        1,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/handlers/dispatch_tools_call.rs",
        1,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/handlers/tasks.rs",
        1,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/handlers.rs",
        3,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/view_judge.rs",
        1,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/watch_poll.rs",
        2,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/ui/activity/access.rs",
        1,
        "InScope: Activity breadth, bounded by within",
    ),
    (
        "admin_standing",
        "src/gateway/ui/control_plane/mutations.rs",
        1,
        "Gateway: Admin; InScope: Auditor",
    ),
    (
        "is_gateway()",
        "src/gateway/meta_mcp/call_dispatch.rs",
        3,
        "Gateway: stats and the profile tools",
    ),
    (
        "is_admin(",
        "src/gateway/ui/guard.rs",
        1,
        "Gateway: the Admin rows",
    ),
    (
        "is_admin(",
        "src/gateway/ui/mod.rs",
        1,
        "its definition and the auth facts",
    ),
    (
        "is_admin(",
        "src/gateway/ui/status.rs",
        1,
        "Gateway: the full status view",
    ),
    (
        "is_admin(",
        "src/gateway/ui/stream/mod.rs",
        2,
        "Gateway: the stream's reload kind and full view",
    ),
    (
        "::for_ui(",
        "src/gateway/ui/activity/access.rs",
        1,
        "the scope that bounds Activity breadth",
    ),
    (
        "::for_ui(",
        "src/gateway/ui/control_plane/mutations.rs",
        1,
        "the actor cap: a scoped Admin identity is Auditor",
    ),
    (
        "::for_ui(",
        "src/gateway/ui/control_plane/snapshot.rs",
        1,
        "the snapshot scope",
    ),
    (
        "::for_ui(",
        "src/gateway/ui/status.rs",
        1,
        "the status scope beside the Gateway check",
    ),
    (
        "::for_ui(",
        "src/gateway/ui/stream/conn.rs",
        1,
        "the stream's status scope, the status route's rule beside the Gateway check",
    ),
    (
        "{ admin, .. }",
        "src/gateway/meta_mcp/boundary_pins/key_field_rows.rs",
        1,
        "none: an exhaustive field list (no `..`) on ApiKeyConfig::default(), the value discarded",
    ),
];

#[test]
fn every_admin_standing_reader_is_inventoried() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    production_sources(root, &root.join("src"), &mut paths);
    let files: Vec<(String, String)> = paths
        .iter()
        .map(|path| {
            let name = path
                .strip_prefix(root)
                .expect("under the crate")
                .to_string_lossy()
                .replace('\\', "/");
            (
                name,
                std::fs::read_to_string(path).expect("a source file reads"),
            )
        })
        .collect();
    let listed: std::collections::BTreeMap<_, _> = ADMIN_READERS
        .iter()
        .map(|(needle, file, n, _)| ((*needle, (*file).to_owned()), *n))
        .collect();
    assert_eq!(
        found_in(&files),
        listed,
        "an admin standing reader changed: decide whether it reads Gateway or InScope, add a row that fails if it reads the other, then list it"
    );
}
