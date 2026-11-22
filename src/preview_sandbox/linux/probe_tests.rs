// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the npm fetch's probe (T9, D7 floor, R-ip).

use std::os::unix::fs::symlink;
use std::path::Path;

use super::{check_npm, find_ip, npm_beside};

/// An executable shell script at `path`.
fn script(path: &Path, body: &str) {
    crate::test_stub::write_executable(path, &format!("#!/bin/sh\n{body}\n"));
}

/// An NVM-only node: npx, npm and node in one `bin` directory, npx and npm
/// symlinks into the npm package, as nvm installs them.
fn nvm_node(root: &Path) -> std::path::PathBuf {
    let bin = root.join(".nvm/versions/node/v20.0.0/bin");
    let npm_pkg = root.join(".nvm/versions/node/v20.0.0/lib/node_modules/npm/bin");
    std::fs::create_dir_all(&bin).expect("bin");
    std::fs::create_dir_all(&npm_pkg).expect("npm package");
    script(&npm_pkg.join("npm-cli.js"), "echo 10.2.0");
    script(&npm_pkg.join("npx-cli.js"), "true");
    script(&bin.join("node"), "true");
    symlink(npm_pkg.join("npm-cli.js"), bin.join("npm")).expect("npm link");
    symlink(npm_pkg.join("npx-cli.js"), bin.join("npx")).expect("npx link");
    bin
}

/// Kills "npm is looked up on PATH or beside npx's real file" (T9): under an
/// NVM-only node, npm and node are the siblings of the `npx` that was found.
#[test]
fn npm_and_node_are_found_beside_npx() {
    let root = tempfile::tempdir().expect("root");
    let bin = nvm_node(root.path());
    let (npm, node_dir) = npm_beside(&bin.join("npx")).expect("found");
    assert_eq!((npm, node_dir), (bin.join("npm"), bin.clone()));
}

/// Kills "the npm floor is not checked" and "the floor is off": npm 8 refuses
/// with its version named, npm 9 passes.
#[test]
fn an_npm_older_than_nine_refuses() {
    let dir = tempfile::tempdir().expect("dir");
    let old = dir.path().join("npm8");
    script(&old, "echo 8.19.4");
    let refused = check_npm(&old, dir.path()).expect_err("npm 8 refused");
    assert!(refused.to_string().contains("8.19.4"), "{refused}");
    let new = dir.path().join("npm9");
    script(&new, "echo 9.0.0");
    check_npm(&new, dir.path()).expect("npm 9 accepted");
}

/// Kills "npm runs with the gateway's environment": the probe's npm sees
/// only PATH, set to node's directory.
#[test]
fn the_npm_probe_runs_with_only_node_on_path() {
    let dir = tempfile::tempdir().expect("dir");
    let npm = dir.path().join("npm");
    let want = dir.path().display().to_string();
    script(
        &npm,
        &format!(
            "[ -z \"${{HOME+x}}\" ] && [ -z \"${{USER+x}}\" ] && [ \"$PATH\" = \"{want}\" ] && echo 9.1.0 || echo 0.0.0"
        ),
    );
    check_npm(&npm, dir.path()).expect("only PATH reached npm");
}

/// Kills "ip is taken from outside the bound trees" (R-ip): the first
/// existing candidate is used when its real file is bound; one outside every
/// bound tree refuses.
#[test]
fn ip_must_lie_inside_a_bound_tree() {
    let dir = tempfile::tempdir().expect("dir");
    let ip = dir.path().join("ip");
    script(&ip, "true");
    let ip = ip.to_str().expect("utf-8");
    let bound = |p: &Path| p.starts_with(dir.path());
    assert_eq!(
        find_ip(&["/nonexistent/ip", ip], &bound).expect("found"),
        ip
    );
    assert!(
        find_ip(&[ip], &|p: &Path| p.starts_with("/usr")).is_err(),
        "ip outside the binds"
    );
    assert!(find_ip(&["/nonexistent/ip"], &bound).is_err(), "no ip");
}
