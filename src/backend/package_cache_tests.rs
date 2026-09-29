// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Classifying, owning and removing the package caches a stdio backend
//! installs into.

use super::{cache_shaped, owned_cache_dir, remove_now};
use crate::Error;
use std::path::Path;

// Verbatim texts Node and npm print when a package tree is missing, half
// unpacked, or refused. A fresh install repairs every one of them.
const CACHE_SHAPED: [&str; 6] = [
    "Error: Cannot find module 'zod'",
    "node:internal/modules/cjs/loader:1228\n  throw err;\n  ^\nError: Cannot find module 'zod'\nRequire stack:\n- /root/.npm/_npx/1c2d/node_modules/.bin/mcp-server-foo",
    "Error: Cannot find module '/root/.npm/_npx/1c2d/node_modules/@modelcontextprotocol/sdk/dist/esm/server/index.js'",
    "Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'zod' imported from /srv/foo/dist/index.js",
    "Error [ERR_MODULE_NOT_FOUND]: Cannot find module '/srv/foo/dist/index.js' imported from /srv/foo/dist/bin.js",
    "npm error code MODULE_NOT_FOUND",
];

// Failures a fresh install cannot repair. Clearing the cache on any of these
// deletes a directory that was never broken and retries against an unchanged
// cause, so each must be judged exactly `false`.
const NOT_CACHE_SHAPED: [&str; 9] = [
    "npm error code ENEEDAUTH\nnpm error need auth This command requires you to be logged in",
    "npm error code E401\nnpm error Incorrect or missing password",
    "Initialize failed for 'npx -y caldav-mcp': 401 Unauthorized: invalid_token",
    "connect ECONNREFUSED 127.0.0.1:8118",
    "Response channel closed",
    "npm error code E404\nnpm error 404 Not Found - GET https://registry.invalid/zod",
    "EACCES: permission denied, access '/root/.npm'",
    "spawn uvx EPERM",
    "npm error code EALLOWGIT\nnpm error Git dependencies are not supported when running in CI mode",
];

#[test]
fn cache_failure_recognises_what_a_torn_package_tree_prints() {
    for text in CACHE_SHAPED {
        assert!(
            cache_shaped(&Error::Transport(text.to_string()), ""),
            "a fresh install is the only repair, so this must classify as a cache failure: {text}"
        );
    }
}

#[test]
fn cache_failure_leaves_a_failure_an_install_cannot_fix_alone() {
    for text in NOT_CACHE_SHAPED {
        assert!(
            !cache_shaped(&Error::Transport(text.to_string()), ""),
            "clearing the cache repairs nothing here, and a false positive throws away a \
             directory that was fine: {text}"
        );
    }
}

#[test]
fn cache_failure_reads_the_rendered_error_whichever_variant_carries_it() {
    assert!(
        cache_shaped(
            &Error::Protocol(
                "Initialize failed for 'npx -y foo': Cannot find module 'zod'".to_string()
            ),
            ""
        ),
        "the classification is on the rendered text, so the variant it arrives in is irrelevant"
    );
    assert!(
        cache_shaped(
            &Error::TransportPermanent("Failed to spawn: Cannot find module 'zod'".to_string()),
            ""
        ),
        "and that holds for the permanent variant too"
    );
}

#[test]
fn cache_failure_reads_the_childs_stderr_not_only_the_errors_own_text() {
    // A package manager prints the reason to stderr and the child dies before
    // it can answer anything, so this is the route the failure actually takes.
    let timeout = Error::BackendTimeout("Request timed out".to_string());
    assert!(
        !cache_shaped(&timeout, ""),
        "a timeout on its own says nothing about the install"
    );
    assert!(
        cache_shaped(&timeout, "Error: Cannot find module 'zod'"),
        "the same timeout is a failed install once the child has said why"
    );
    assert!(
        !cache_shaped(&timeout, "Error: backend exploded during startup"),
        "stderr that names no install problem leaves the tree alone"
    );
}

#[test]
fn only_a_cache_the_gateway_created_is_its_to_remove() {
    let root = Path::new("/data/gateway/pkg-cache");
    assert!(
        owned_cache_dir(Path::new("/data/gateway/pkg-cache/calendar-work"), root),
        "a per-backend cache is exactly one component below the root"
    );
    assert!(
        !owned_cache_dir(root, root),
        "the root itself is the container, not a backend's cache"
    );
    assert!(
        !owned_cache_dir(Path::new("/data/gateway/pkg-cache/a/b"), root),
        "nothing deeper than one component was created by the gateway"
    );
    assert!(
        !owned_cache_dir(Path::new("/data/gateway/pkg-cache/../etc"), root),
        "a parent component escapes the directory the gateway owns"
    );
    assert!(
        !owned_cache_dir(Path::new("/data/gateway/pkg-cache-evil/x"), root),
        "a sibling whose name merely starts with the same text is not inside it"
    );
    assert!(
        !owned_cache_dir(Path::new("/data/gateway"), root),
        "a parent directory is not inside its own child"
    );
    assert!(
        !owned_cache_dir(Path::new("/root/.npm"), root),
        "a cache the gateway did not create is not its to delete"
    );
}

#[test]
fn cache_failure_judges_the_errors_the_start_path_returns() {
    let invalid_frame = Error::from(
        serde_json::from_str::<serde_json::Value>("not a JSON-RPC frame")
            .expect_err("the literal above is not valid JSON"),
    );
    for (error, why) in [
        (
            invalid_frame,
            "an unparsable frame from a live backend is a protocol problem, not a torn tree",
        ),
        (
            Error::BackendTimeout("Request timed out".to_string()),
            "a timeout is retried, and its tree is untouched",
        ),
        (
            Error::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            "a permission failure is not repaired by an install",
        ),
        (
            Error::TransportPermanent(
                "Failed to spawn: No such file or directory (os error 2)".to_string(),
            ),
            "a command path that does not exist is not a cache problem",
        ),
    ] {
        assert!(!cache_shaped(&error, ""), "{error} -- {why}");
    }
}

fn scratch_dir(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("stdio-cache-{}-{name}", std::process::id()))
}

fn cleanup(dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn remove_cache_dir_removes_a_populated_nested_tree() {
    let cache = scratch_dir("populated");
    let module = cache.join("_npx/1c2d/node_modules/zod");
    std::fs::create_dir_all(&module).expect("create a nested cache tree");
    std::fs::write(module.join("package.json"), "{\"name\":\"zod\"}").expect("seed a module");
    std::fs::write(cache.join("_update-notifier-last-checked"), "0").expect("seed a root file");
    let parent = cache
        .parent()
        .expect("the temp dir has a parent")
        .to_path_buf();

    assert!(remove_now(&cache), "a populated cache is removable");
    assert!(!cache.exists(), "the cache directory itself is gone");
    assert!(
        !module.exists(),
        "and so is everything the install had left in it"
    );
    assert!(
        parent.exists(),
        "removal must not reach above the directory it was handed"
    );
}

#[test]
fn remove_cache_dir_treats_an_absent_cache_as_already_gone() {
    let cache = scratch_dir("absent");
    assert!(!cache.exists());
    assert!(
        remove_now(&cache),
        "a cache the first spawn never created is not a failure to clear: reporting one would \
         block the retry for a backend whose install has not run yet"
    );
    assert!(
        remove_now(&cache.join("_npx/1c2d/node_modules")),
        "nor is a path whose parents never existed"
    );
}

#[test]
fn remove_cache_dir_reports_failure_when_it_was_handed_a_regular_file() {
    let root = scratch_dir("regular-file");
    std::fs::create_dir_all(&root).expect("create the scratch directory");
    let file = root.join("cache");
    std::fs::write(&file, "not a directory tree").expect("seed a regular file");

    assert!(
        !remove_now(&file),
        "a file is not a tree this removed: claiming success would let the caller retry against \
         a cache that is still there"
    );
    assert!(file.exists(), "a failed removal leaves the path as it was");
    assert_eq!(
        std::fs::read_to_string(&file).expect("the file is still readable"),
        "not a directory tree",
        "and it still holds what it held"
    );
    cleanup(&root);
}

#[cfg(unix)]
#[test]
fn remove_cache_dir_reports_failure_when_a_parent_is_not_a_directory() {
    let root = scratch_dir("blocked-parent");
    std::fs::create_dir_all(&root).expect("create the scratch directory");
    let file = root.join("cache");
    std::fs::write(&file, "x").expect("seed a regular file");

    assert!(
        !remove_now(&file.join("_npx")),
        "only NotFound means 'already gone'; a path below a regular file was never a cache"
    );
    assert!(
        file.exists(),
        "the file it has to walk through is untouched"
    );
    cleanup(&root);
}

#[cfg(unix)]
#[test]
fn remove_cache_dir_deletes_a_link_without_following_it() {
    use std::os::unix::fs::symlink;

    let cache = scratch_dir("symlink");
    let outside = scratch_dir("symlink-outside");
    std::fs::create_dir_all(outside.join("node_modules")).expect("create the operator's own tree");
    std::fs::write(outside.join("node_modules/zod.js"), "module").expect("seed it");
    std::fs::create_dir_all(cache.join("_npx")).expect("create the cache");
    symlink(&outside, cache.join("_npx/linked")).expect("link the cache at another tree");

    assert!(remove_now(&cache), "the cache is removable");
    assert!(!cache.exists());
    assert!(
        outside.join("node_modules/zod.js").exists(),
        "the link is removed, the tree it points at is not: a cache that links outside itself \
         must not let the recovery take the target with it"
    );
    cleanup(&outside);
}
