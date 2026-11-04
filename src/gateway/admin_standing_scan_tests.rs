// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every production reader of a caller's admin standing, inventoried: the
//! raw `admin` flag, the role mapping's admin answers and the
//! `CallerStanding` constructors. A gateway-wide power reads `Gateway`; admin
//! breadth inside a backend scope reads `InScope` too. A new reader fails the
//! scan until it is listed here with the standing it reads.

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
        11,
        "the role mapping itself",
    ),
    (
        "grants_admin(",
        "src/control_plane/role_mapping.rs",
        1,
        "its definition",
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
        2,
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
        "src/gateway/ui/stream/conn.rs",
        1,
        "Gateway: set from ui::is_admin",
    ),
    (
        ".admin",
        "src/gateway/ui/stream/sent.rs",
        2,
        "Gateway: set from ui::is_admin",
    ),
    (
        ".admin",
        "src/key_server/handler.rs",
        1,
        "a doc comment naming key_server.admin",
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
        "src/gateway/auth_caller.rs",
        1,
        "its definition: admin_standing() is Gateway",
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
        4,
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
        "src/gateway/authz.rs",
        1,
        "the rule itself",
    ),
    (
        "admin_standing",
        "src/gateway/mod.rs",
        1,
        "this scan's module name",
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
        2,
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
        "is_admin(",
        "src/security/data_flow.rs",
        2,
        "unrelated: data-flow classifier test names",
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
];

const NEEDLES: &[&str] = &[
    ".admin",
    "resolve_role(",
    "grants_admin(",
    "CallerStanding::of(",
    "CallerStanding::of_client(",
    "CallerStanding::Admin",
    DESTRUCTURED,
    "is_gateway_admin",
    "admin_standing",
    "is_gateway()",
    "is_admin(",
    "::for_ui(",
];

/// Not a literal needle: a struct pattern binding an `admin` field.
const DESTRUCTURED: &str = "{ admin, .. }";

/// Whether `path`, relative to the crate, is test-only source.
fn test_only(path: &std::path::Path) -> bool {
    path.components().any(|part| {
        let part = part.as_os_str().to_string_lossy();
        let stem = part.strip_suffix(".rs").unwrap_or(&part);
        stem == "tests"
            || stem.ends_with("_tests")
            || stem.starts_with("test_")
            || stem.ends_with("_test")
            || stem.contains("fixture")
    })
}

fn production_sources(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
) {
    for entry in std::fs::read_dir(dir).expect("src reads") {
        let path = entry.expect("a directory entry").path();
        if test_only(path.strip_prefix(root).expect("under the crate")) {
            continue;
        }
        if path.is_dir() {
            production_sources(root, &path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Occurrences of `needle` in `text`. `.admin` counts only the whole field
/// name, so `.admin_standing()` and `.admin_token` are not reads of the flag.
fn count(text: &str, needle: &str) -> usize {
    if needle == DESTRUCTURED {
        return destructured_admin(text);
    }
    if needle != ".admin" {
        return text.matches(needle).count();
    }
    text.match_indices(needle)
        .filter(|(at, _)| {
            text[at + needle.len()..]
                .chars()
                .next()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
        })
        .count()
}

/// Struct patterns that bind an `admin` field and end in a rest pattern:
/// `{ admin, .. }`, `{ admin: flag, .. }`, `{ admin: _, .. }`. A struct
/// literal with update syntax (`{ admin: true, ..base }`) is a write and does
/// not end in a bare `..`. A pattern naming every field without `..` is not
/// found: the clients have too many fields for that to be written by hand.
fn destructured_admin(text: &str) -> usize {
    let bytes = text.as_bytes();
    text.match_indices("admin")
        .filter(|(at, _)| {
            let before = text[..*at].chars().next_back();
            if before.is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '"')) {
                return false;
            }
            let after = text[at + "admin".len()..].trim_start();
            let field =
                after.starts_with(',') || (after.starts_with(':') && !after.starts_with("::"));
            field
                && enclosing_group(bytes, *at)
                    .is_some_and(|(open, close)| text[open + 1..close].trim_end().ends_with(".."))
        })
        .count()
}

/// The `{ .. }` group around byte `at`, by brace depth.
fn enclosing_group(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut depth = 0usize;
    let open = (0..at).rev().find(|&i| match bytes[i] {
        b'}' => {
            depth += 1;
            false
        }
        b'{' if depth == 0 => true,
        b'{' => {
            depth -= 1;
            false
        }
        _ => false,
    })?;
    let mut depth = 0usize;
    let close = (open + 1..bytes.len()).find(|&i| match bytes[i] {
        b'{' => {
            depth += 1;
            false
        }
        b'}' if depth == 0 => true,
        b'}' => {
            depth -= 1;
            false
        }
        _ => false,
    })?;
    Some((open, close))
}

fn found_in(
    files: &[(String, String)],
) -> std::collections::BTreeMap<(&'static str, String), usize> {
    let mut found = std::collections::BTreeMap::new();
    for (name, text) in files {
        for needle in NEEDLES {
            let n = count(text, needle);
            if n > 0 {
                found.insert((*needle, name.clone()), n);
            }
        }
    }
    found
}

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

/// The scan's own row: a new raw read of the flag is found, and a read of the
/// accessor is not.
#[test]
fn the_scan_finds_a_new_raw_admin_read() {
    let files = vec![(
        "src/new.rs".to_owned(),
        "let a = client.admin; let b = client.admin_standing();".to_owned(),
    )];
    assert_eq!(
        found_in(&files).get(&(".admin", "src/new.rs".to_owned())),
        Some(&1)
    );
}

/// The two reads a field-access needle cannot see: a struct pattern that
/// binds the flag (with or without a new name, or ignoring it) and a direct
/// `CallerStanding::Admin`. Struct update syntax is a write and is not found.
#[test]
fn the_scan_finds_a_destructured_read_and_a_direct_admin_standing() {
    let cells = [
        ("let AuthenticatedClient { admin, .. } = client;", 1),
        (
            "let AuthenticatedClient { name, admin: flag, .. } = client;",
            1,
        ),
        ("match c { Self { admin: _, .. } => {} }", 1),
        ("AuthenticatedClient { admin: true, ..base }", 0),
    ];
    for (text, want) in cells {
        let files = vec![("src/new.rs".to_owned(), text.to_owned())];
        assert_eq!(
            found_in(&files)
                .get(&("{ admin, .. }", "src/new.rs".to_owned()))
                .copied()
                .unwrap_or(0),
            want,
            "{text}"
        );
    }
    let files = vec![(
        "src/new.rs".to_owned(),
        "let s = CallerStanding::Admin;".to_owned(),
    )];
    assert_eq!(
        found_in(&files).get(&("CallerStanding::Admin", "src/new.rs".to_owned())),
        Some(&1)
    );
}

/// Every accessor that reads a standing is a reader too: each one picks
/// `Gateway` or `InScope`, so each call is inventoried with the one it reads.
#[test]
fn the_scan_finds_every_standing_accessor() {
    for (text, needle) in [
        ("if c.is_gateway_admin() {}", "is_gateway_admin"),
        ("let s = c.admin_standing();", "admin_standing"),
        (
            "client.map_or(None, AuthenticatedClient::admin_standing)",
            "admin_standing",
        ),
        ("if caller.admin.is_gateway() {}", "is_gateway()"),
        ("if is_admin(Some(c)) {}", "is_admin("),
        ("let g = BackendGrant::for_ui(Some(c));", "::for_ui("),
    ] {
        let files = vec![("src/new.rs".to_owned(), text.to_owned())];
        assert_eq!(
            found_in(&files).get(&(needle, "src/new.rs".to_owned())),
            Some(&1),
            "{text}"
        );
    }
}
