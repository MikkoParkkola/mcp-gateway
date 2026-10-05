// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Classifying, owning and removing the package caches a stdio backend
//! installs into.

use super::{install_failure_needle, is_a_tree_to_walk, remove_now};
use crate::Error;

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
        let error = Error::Transport(text.to_string());
        let needle = install_failure_needle(&error, "");
        assert!(
            needle.is_some_and(|needle| text.contains(needle)),
            "a fresh install is the only repair, and the match has to name itself: {text}"
        );
    }
}

#[test]
fn cache_failure_leaves_a_failure_an_install_cannot_fix_alone() {
    for text in NOT_CACHE_SHAPED {
        assert!(
            install_failure_needle(&Error::Transport(text.to_string()), "").is_none(),
            "clearing the cache repairs nothing here, and a false positive throws away a \
             directory that was fine: {text}"
        );
    }
}

#[test]
fn cache_failure_reads_the_rendered_error_whichever_variant_carries_it() {
    assert!(
        install_failure_needle(
            &Error::Protocol(
                "Initialize failed for 'npx -y foo': Cannot find module 'zod'".to_string()
            ),
            ""
        )
        .is_some(),
        "the classification is on the rendered text, so the variant it arrives in is irrelevant"
    );
    assert!(
        install_failure_needle(
            &Error::TransportPermanent("Failed to spawn: Cannot find module 'zod'".to_string()),
            ""
        )
        .is_some(),
        "and that holds for the permanent variant too"
    );
}

#[test]
fn cache_failure_reads_the_childs_stderr_not_only_the_errors_own_text() {
    // A package manager prints the reason to stderr and the child dies before
    // it can answer anything, so this is the route the failure actually takes.
    let timeout = Error::BackendTimeout("Request timed out".to_string());
    assert!(
        install_failure_needle(&timeout, "").is_none(),
        "a timeout on its own says nothing about the install"
    );
    assert!(
        install_failure_needle(&timeout, "Error: Cannot find module 'zod'").is_some(),
        "the same timeout is a failed install once the child has said why"
    );
    assert!(
        install_failure_needle(&timeout, "Error: backend exploded during startup").is_none(),
        "stderr that names no install problem leaves the tree alone"
    );
}

#[test]
fn the_walk_refuses_a_path_that_ends_in_a_separator() {
    let root = scratch_dir("trailing-separator");
    std::fs::create_dir_all(&root).expect("create the scratch directory");
    let plain = root.join("cache");
    std::fs::create_dir_all(&plain).expect("create the cache");

    assert!(
        is_a_tree_to_walk(&plain),
        "the path the gateway assigned is the shape this walks: {plain:?}"
    );
    assert!(
        !is_a_tree_to_walk(&root.join("cache/")),
        "a trailing separator makes the OS resolve the final component before the walk, so a \
         link there would be followed"
    );
    assert!(
        !remove_now(&root.join("cache/")),
        "and the removal refuses it too rather than clearing it"
    );
    assert!(
        plain.exists(),
        "the cache is untouched by the refused removal"
    );
    cleanup(&root);
}

#[cfg(unix)]
#[test]
fn the_walk_refuses_a_trailing_separator_that_reaches_through_a_link() {
    use std::os::unix::fs::symlink;

    let root = scratch_dir("trailing-separator-link");
    let outside = scratch_dir("trailing-separator-link-outside");
    std::fs::create_dir_all(&root).expect("create the scratch directory");
    std::fs::create_dir_all(outside.join("node_modules")).expect("create the operator's own tree");
    let sentinel = outside.join("node_modules/zod.js");
    std::fs::write(&sentinel, "module").expect("seed it");
    let leaf = root.join("cache");
    symlink(&outside, &leaf).expect("link the cache path at another tree");

    // The removal deletes the target's contents and then reports the error, so
    // a caller told "could not clear" has already lost a tree it was never
    // given. This is the shape the whole-path refusal exists for.
    let through_the_link = std::path::PathBuf::from(format!("{}/", leaf.display()));
    assert!(
        !remove_now(&through_the_link),
        "a separator-neutral path check reads this as one component below the root"
    );
    assert!(
        sentinel.exists(),
        "and nothing behind the link is deleted on the way to that answer"
    );
    cleanup(&root);
    cleanup(&outside);
}

#[cfg(unix)]
#[test]
fn the_walk_refuses_a_leaf_that_is_a_symlink() {
    use std::os::unix::fs::symlink;

    let root = scratch_dir("leaf-symlink");
    let outside = scratch_dir("leaf-symlink-outside");
    std::fs::create_dir_all(&root).expect("create the scratch directory");
    std::fs::create_dir_all(outside.join("node_modules")).expect("create the operator's own tree");
    let sentinel = outside.join("node_modules/zod.js");
    std::fs::write(&sentinel, "module").expect("seed it");
    let leaf = root.join("cache");
    symlink(&outside, &leaf).expect("link the cache path at another tree");

    assert!(
        !is_a_tree_to_walk(&leaf),
        "the gateway creates a directory here, so a link is not this cache"
    );
    assert!(
        !remove_now(&leaf),
        "only NotFound means 'already gone'; a link reported as removed would say the install \
         was cleared when nothing was"
    );
    assert!(
        sentinel.exists(),
        "and nothing outside the cache is deleted to reach it"
    );
    cleanup(&root);
    cleanup(&outside);
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
        assert!(
            install_failure_needle(&error, "").is_none(),
            "{error} -- {why}"
        );
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
