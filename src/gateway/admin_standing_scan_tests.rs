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
        "src/gateway/auth.rs",
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
];

const NEEDLES: &[&str] = &[
    ".admin",
    "resolve_role(",
    "grants_admin(",
    "CallerStanding::of(",
    "CallerStanding::of_client(",
];

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
