// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The retry contract's safety cases: a cache the operator chose is never
//! cleared, however its path is written, and an assigned cache that is a
//! symlink is not followed. A child of `package_cache_retry_tests.rs`, split
//! out to keep both under the file-size ceiling; `use super::*` reaches the
//! stubs and helpers there.

use super::*;

#[tokio::test]
async fn an_operators_cache_under_pkg_cache_is_never_cleared() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), DYING_STUB);
    // A path of the shape the gateway assigns, under the root it owns, set by
    // the backend's own `env:` — which is what makes it the operator's, not
    // the gateway's, however much it looks like the gateway's.
    let outside = temp_root(workspace.path()).join("the-operators-own");
    let marker = outside.join("_npx/1/marker");
    std::fs::create_dir_all(marker.parent().expect("marker parent"))
        .expect("create operator cache");
    std::fs::write(&marker, SEEDED).expect("seed marker");
    let log = workspace.path().join("spawns.log");

    let operator_env = HashMap::from([(
        CACHE_ENV.to_string(),
        outside.to_string_lossy().into_owned(),
    )]);
    let assigned = assigned_package_cache_dir(BACKEND, NPM_COMMAND, &operator_env);
    assert!(
        assigned.is_none(),
        "the gateway assigns nothing when the backend's environment already names a cache"
    );
    let mut env = stub_env(&log, "always-fail", CACHE_SHAPED);
    env.extend(isolated_package_manager_env(
        BACKEND,
        NPM_COMMAND,
        operator_env,
    ));

    let _ = start_with_repair(&transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        assigned.as_deref(),
    ))
    .await;

    assert_eq!(
        spawns(&log).len(),
        1,
        "a cache the gateway did not assign is not the gateway's to delete"
    );
    assert_eq!(
        std::fs::read_to_string(&marker).expect("the operator's cache is untouched"),
        SEEDED,
        "the gateway deletes only the caches it assigned"
    );
}

#[tokio::test]
async fn an_operator_cache_written_with_a_trailing_separator_is_never_cleared() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), DYING_STUB);
    // `…/pkg-cache/<backend>/` reads as one path component below the root, and
    // the trailing separator is exactly what makes the OS resolve the final
    // component: with a symlink there, a removal that followed it would delete
    // the contents of the link's target.
    let outside = workspace.path().join("operator-cache-target");
    let sentinel = outside.join("node_modules/zod.js");
    std::fs::create_dir_all(sentinel.parent().expect("sentinel parent"))
        .expect("create the operator's tree");
    std::fs::write(&sentinel, SEEDED).expect("seed the operator's tree");
    let leaf = temp_root(workspace.path()).join("the-operators-own");
    symlink(&outside, &leaf).expect("link the cache path at the operator's tree");
    let log = workspace.path().join("spawns.log");

    let operator_env = HashMap::from([(CACHE_ENV.to_string(), format!("{}/", leaf.display()))]);
    let assigned = assigned_package_cache_dir(BACKEND, NPM_COMMAND, &operator_env);
    assert!(
        assigned.is_none(),
        "a value the operator wrote is not one the gateway assigned, separator or not"
    );
    let mut env = stub_env(&log, "always-fail", CACHE_SHAPED);
    env.extend(isolated_package_manager_env(
        BACKEND,
        NPM_COMMAND,
        operator_env,
    ));

    let _ = start_with_repair(&transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        assigned.as_deref(),
    ))
    .await;

    assert_eq!(
        spawns(&log).len(),
        1,
        "no retry against a path this gateway never assigned"
    );
    assert_eq!(
        std::fs::read_to_string(&sentinel).expect("the link's target is untouched"),
        SEEDED,
        "and nothing behind the link is deleted"
    );
    assert!(
        std::fs::symlink_metadata(&leaf).is_ok(),
        "the link itself is left where the operator put it"
    );
}

#[tokio::test]
async fn an_assigned_cache_that_is_a_symlink_is_not_followed() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), DYING_STUB);
    // The gateway assigned this path, so provenance alone says it may be
    // cleared. A link at the leaf is what the removal has to refuse: following
    // it would delete a tree the gateway was never given.
    let outside = workspace.path().join("link-target");
    let sentinel = outside.join("node_modules/zod.js");
    std::fs::create_dir_all(sentinel.parent().expect("sentinel parent"))
        .expect("create the linked tree");
    std::fs::write(&sentinel, SEEDED).expect("seed the linked tree");
    let leaf = temp_root(workspace.path()).join(unique_leaf());
    symlink(&outside, &leaf).expect("link the cache path at another tree");
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "always-fail", CACHE_SHAPED, &leaf);

    let error = start_with_repair(&transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        Some(&leaf),
    ))
    .await
    .expect_err("the stub dies on every attempt");

    assert_eq!(
        spawns(&log).len(),
        1,
        "a cache that could not be cleared is not retried: {error}"
    );
    assert_eq!(
        std::fs::read_to_string(&sentinel).expect("the linked tree is untouched"),
        SEEDED,
        "the link is not a cache the gateway created, and its target is not deleted"
    );
    assert!(
        std::fs::symlink_metadata(&leaf).is_ok(),
        "and the link is still where it was"
    );
}
