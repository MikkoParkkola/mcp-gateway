// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the install checks: the npm lock holds only registry tarballs,
//! and the run argv comes from the installed package's own metadata.

use serde_json::{Value, json};

use super::*;

const TGZ: &str = "https://registry.npmjs.org/a/-/a-1.0.0.tgz";

/// A lock whose root asks for `a`, which needs `b` (optionally `c`).
fn lock() -> Value {
    json!({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": {
                "version": "1.0.0",
                "resolved": TGZ,
                "dependencies": {"b": "~2"},
                "optionalDependencies": {"c": "*"}
            },
            "node_modules/b": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz"},
            "node_modules/a/node_modules/c": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/c/-/c-1.0.0.tgz"
            }
        }
    })
}

fn lock_refusal(lock: &Value) -> String {
    match check_lock(lock) {
        Ok(()) => panic!("accepted: {lock}"),
        Err(e) => e.to_string(),
    }
}

/// T11: a lock of registry tarballs only, nested lookup included, passes.
#[test]
fn an_all_registry_lock_is_accepted() {
    check_lock(&lock()).expect("all-registry lock");
}

/// T11: a git edge, required or optional, refuses.
#[test]
fn a_git_edge_refuses() {
    for field in ["dependencies", "optionalDependencies"] {
        for spec in ["git+https://github.com/x/y.git", "github:x/y", "x/y"] {
            let mut l = lock();
            l["packages"]["node_modules/a"][field]["g"] = spec.into();
            let text = lock_refusal(&l);
            assert!(
                text.contains("not from the registry"),
                "{field} {spec}: {text}"
            );
        }
    }
}

/// T11: `file:`, `link:` and URL specs refuse, at the root too.
#[test]
fn file_link_and_url_specs_refuse() {
    for spec in ["file:../x", "link:../x", "https://x.example/y.tgz"] {
        let mut l = lock();
        l["packages"][""]["dependencies"]["z"] = spec.into();
        assert!(lock_refusal(&l).contains("not from the registry"), "{spec}");
    }
}

/// T11: a `resolved` that is a URL tarball off the registry, another host,
/// or missing, refuses.
#[test]
fn a_resolved_off_the_registry_refuses() {
    for resolved in [
        Some("https://x.example/a.tgz"),
        Some("https://registry.npmjs.org.evil.example/a/-/a-1.0.0.tgz"),
        Some("http://registry.npmjs.org/a/-/a-1.0.0.tgz"),
        Some("git+ssh://git@github.com/x/y.git"),
        Some("../local"),
        None,
    ] {
        let mut l = lock();
        let entry = l["packages"]["node_modules/b"]
            .as_object_mut()
            .expect("entry");
        match resolved {
            Some(r) => entry.insert("resolved".into(), r.into()),
            None => entry.remove("resolved"),
        };
        assert!(
            lock_refusal(&l).contains("not from the registry"),
            "{resolved:?}"
        );
    }
}

/// T11 (J4): a declared edge with no lock entry (a pruned optional subtree)
/// refuses, as does a required one.
#[test]
fn a_declared_edge_with_no_lock_entry_refuses() {
    let mut l = lock();
    l["packages"]
        .as_object_mut()
        .expect("packages")
        .remove("node_modules/a/node_modules/c");
    assert!(lock_refusal(&l).contains("no entry in the lock"));

    let mut l = lock();
    l["packages"]["node_modules/b"]["dependencies"] = json!({"missing": "1"});
    assert!(lock_refusal(&l).contains("no entry in the lock"));
}

/// T11: a `c` hoisted to the top satisfies `a`'s edge by node's lookup; one
/// nested under a sibling does not.
#[test]
fn edges_resolve_by_node_lookup() {
    let mut l = lock();
    let packages = l["packages"].as_object_mut().expect("packages");
    let c = packages.remove("node_modules/a/node_modules/c").expect("c");
    packages.insert("node_modules/c".into(), c.clone());
    check_lock(&l).expect("hoisted c");

    let packages = l["packages"].as_object_mut().expect("packages");
    packages.remove("node_modules/c");
    packages.insert("node_modules/b/node_modules/c".into(), c);
    assert!(lock_refusal(&l).contains("no entry in the lock"));
}

/// T11: a lock without `packages` (npm 6's format) or a linked entry refuses.
#[test]
fn an_old_lock_or_a_link_refuses() {
    assert!(lock_refusal(&json!({"lockfileVersion": 1, "dependencies": {}})).contains("lock"));
    let mut l = lock();
    l["packages"]["node_modules/b"] = json!({"resolved": "../b", "link": true});
    assert!(lock_refusal(&l).contains("not from the registry"));
}

/// A bundled dependency ships inside its parent's registry tarball and has
/// no `resolved` of its own.
#[test]
fn a_bundled_entry_needs_no_resolved() {
    let mut l = lock();
    l["packages"]["node_modules/b"] = json!({"version": "2.0.0", "inBundle": true});
    check_lock(&l).expect("bundled b");
}

/// `<root>/node_modules/<name>` with `package.json` holding `bin`, and each
/// file in `files` created under it.
fn npm_pkg(name: &str, bin: &Value, files: &[&str]) -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path().join("node_modules").join(name);
    std::fs::create_dir_all(&dir).expect("package dir");
    let manifest = json!({"name": name, "version": "1.0.0", "bin": bin});
    std::fs::write(dir.join("package.json"), manifest.to_string()).expect("manifest");
    for f in files {
        let path = dir.join(f);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("bin dir");
        std::fs::write(path, "#!/usr/bin/env node\n").expect("bin");
    }
    root
}

fn bin_of(root: &tempfile::TempDir, name: &str) -> Result<std::path::PathBuf, String> {
    npm_bin(root.path(), name).map_err(|e| e.to_string())
}

/// T5: `bin` as a string, a one-entry map, and a map with the entry named
/// after the package.
#[test]
fn npm_bin_forms_pick_one_file() {
    let r = npm_pkg("pkg", &json!("cli.js"), &["cli.js"]);
    assert!(
        bin_of(&r, "pkg")
            .expect("string bin")
            .ends_with("node_modules/pkg/cli.js")
    );

    let r = npm_pkg("pkg", &json!({"other": "bin/o.js"}), &["bin/o.js"]);
    assert!(
        bin_of(&r, "pkg")
            .expect("one entry")
            .ends_with("pkg/bin/o.js")
    );

    let r = npm_pkg(
        "pkg",
        &json!({"x": "x.js", "pkg": "p.js"}),
        &["x.js", "p.js"],
    );
    assert!(
        bin_of(&r, "pkg")
            .expect("named entry")
            .ends_with("pkg/p.js")
    );
}

/// T5 (K8): a scoped package with several bins takes the one named after the
/// package's own name.
#[test]
fn a_scoped_package_takes_the_bin_named_after_it() {
    let r = npm_pkg(
        "@s/pkg",
        &json!({"a": "a.js", "pkg": "p.js"}),
        &["a.js", "p.js"],
    );
    assert!(
        bin_of(&r, "@s/pkg")
            .expect("scoped")
            .ends_with("@s/pkg/p.js")
    );
}

/// T5: two unnamed entries, no `bin`, or a bin file that is missing refuse.
#[test]
fn no_single_npm_bin_refuses() {
    for (bin, files) in [
        (json!({"a": "a.js", "b": "b.js"}), &["a.js", "b.js"][..]),
        (Value::Null, &[]),
        (json!({}), &[]),
        (json!("gone.js"), &[]),
    ] {
        let r = npm_pkg("pkg", &bin, files);
        let text = bin_of(&r, "pkg").expect_err("refused");
        assert!(text.contains("no single entry point"), "{bin}: {text}");
    }
}

/// T5 (q14): a bin path escaping the package, by `..` or by a symlink, refuses.
#[cfg(unix)]
#[test]
fn an_npm_bin_outside_the_package_refuses() {
    let r = npm_pkg("pkg", &json!("../other/x.js"), &[]);
    let other = r.path().join("node_modules/other");
    std::fs::create_dir_all(&other).expect("other");
    std::fs::write(other.join("x.js"), "").expect("x");
    assert!(
        bin_of(&r, "pkg")
            .expect_err("dotdot")
            .contains("outside the package")
    );

    let r = npm_pkg("pkg", &json!("link.js"), &[]);
    let outside = r.path().join("outside.js");
    std::fs::write(&outside, "").expect("outside");
    std::os::unix::fs::symlink(&outside, r.path().join("node_modules/pkg/link.js"))
        .expect("symlink");
    assert!(
        bin_of(&r, "pkg")
            .expect_err("symlink")
            .contains("outside the package")
    );
}

/// A uv tool environment: one `site-packages` holding a `.dist-info` per
/// `(dir name, entry_points.txt)`, and a `bin/` file per name in `bins`.
fn uv_env(dists: &[(&str, &str)], bins: &[&str]) -> tempfile::TempDir {
    let env = tempfile::tempdir().expect("tempdir");
    let site = env.path().join("lib/python3.12/site-packages");
    for (dir, entry_points) in dists {
        let d = site.join(dir);
        std::fs::create_dir_all(&d).expect("dist-info");
        std::fs::write(d.join("METADATA"), "Metadata-Version: 2.1\n").expect("metadata");
        if !entry_points.is_empty() {
            std::fs::write(d.join("entry_points.txt"), entry_points).expect("entry points");
        }
    }
    std::fs::create_dir_all(env.path().join("bin")).expect("bin");
    for b in bins {
        std::fs::write(env.path().join("bin").join(b), "#!python\n").expect("script");
    }
    env
}

fn entry_of(env: &tempfile::TempDir, name: &str) -> Result<std::path::PathBuf, String> {
    uv_entry_point(env.path(), name).map_err(|e| e.to_string())
}

const ONE: &str = "[console_scripts]\nsrv = srv.main:run\n";

/// T5: the only console script, or the one named after the package.
#[test]
fn uv_entry_points_come_from_the_dist_info() {
    let env = uv_env(&[("srv-1.0.dist-info", ONE)], &["srv"]);
    assert!(entry_of(&env, "srv").expect("single").ends_with("bin/srv"));

    let named =
        "[console_scripts]\nhelper = srv.h:main\nsrv = srv.main:run\n\n[gui_scripts]\nx = y:z\n";
    let env = uv_env(&[("srv-1.0.dist-info", named)], &["helper", "srv", "x"]);
    assert!(entry_of(&env, "srv").expect("named").ends_with("bin/srv"));
}

/// T5 (q22): a dependency's script in `bin/` is never chosen; the package's
/// own metadata decides, so a package with no console script refuses.
#[test]
fn a_dependency_script_in_bin_is_not_the_entry_point() {
    let env = uv_env(
        &[
            ("srv-1.0.dist-info", ""),
            ("dep-2.0.dist-info", "[console_scripts]\ndep = dep:main\n"),
        ],
        &["dep"],
    );
    assert!(
        entry_of(&env, "srv")
            .expect_err("no own script")
            .contains("no single entry point")
    );
}

/// T5: two unnamed console scripts, or a script missing from `bin/`, refuse.
#[test]
fn no_single_uv_entry_point_refuses() {
    let two = "[console_scripts]\na = m:a\nb = m:b\n";
    let env = uv_env(&[("srv-1.0.dist-info", two)], &["a", "b"]);
    assert!(
        entry_of(&env, "srv")
            .expect_err("two")
            .contains("no single entry point")
    );

    let env = uv_env(&[("srv-1.0.dist-info", ONE)], &[]);
    assert!(
        entry_of(&env, "srv")
            .expect_err("missing")
            .contains("no single entry point")
    );
}

/// T12 (J1): the dist-info is found by its PEP 503-normalized name: an
/// uppercase or dotted directory matches; an unrelated one is ignored.
#[test]
fn dist_info_is_matched_by_normalized_name() {
    let env = uv_env(
        &[
            ("My_Srv-1.0.dist-info", ONE),
            ("other-1.0.dist-info", "[console_scripts]\no = o:m\n"),
        ],
        &["srv", "o"],
    );
    assert!(
        entry_of(&env, "my-srv")
            .expect("uppercase")
            .ends_with("bin/srv")
    );
    assert!(
        entry_of(&env, "My.Srv")
            .expect("dotted request")
            .ends_with("bin/srv")
    );

    let env = uv_env(&[("zope.interface-6.0.dist-info", ONE)], &["srv"]);
    assert!(
        entry_of(&env, "zope-interface")
            .expect("dotted dir")
            .ends_with("bin/srv")
    );
}

/// T12 (J1): two directories normalizing to the package's name, or none,
/// refuse.
#[test]
fn zero_or_two_matching_dist_infos_refuse() {
    let env = uv_env(
        &[("my_srv-1.0.dist-info", ONE), ("My.Srv-2.0.dist-info", ONE)],
        &["srv"],
    );
    assert!(
        entry_of(&env, "my-srv")
            .expect_err("two")
            .contains("installed metadata")
    );

    let env = uv_env(&[("other-1.0.dist-info", ONE)], &["srv"]);
    assert!(
        entry_of(&env, "my-srv")
            .expect_err("none")
            .contains("installed metadata")
    );
}

/// A console script whose name is a path, not one file in `bin/`, refuses.
#[test]
fn a_script_name_with_a_path_refuses() {
    for name in ["../x", "a/b", ".."] {
        let entry_points = format!("[console_scripts]\n{name} = m:main\n");
        let env = uv_env(&[("srv-1.0.dist-info", entry_points.as_str())], &[]);
        // Each name points at a real file, so only the name check refuses it.
        std::fs::write(env.path().join("x"), "").expect("outside bin");
        std::fs::create_dir_all(env.path().join("bin/a")).expect("bin/a");
        std::fs::write(env.path().join("bin/a/b"), "").expect("nested");
        let text = entry_of(&env, "srv").expect_err("path name");
        assert!(text.contains("no single entry point"), "{name}: {text}");
    }
}

/// The root has no required tarball, but must not opt into a local install.
#[test]
fn a_linked_root_refuses() {
    let mut l = lock();
    l["packages"][""]["link"] = true.into();
    assert!(lock_refusal(&l).contains("not from the registry"));
}

#[test]
fn a_root_resolved_outside_the_registry_refuses() {
    for resolved in ["file:../x", "git+https://github.com/x/y.git"] {
        let mut l = lock();
        l["packages"][""]["resolved"] = resolved.into();
        assert!(
            lock_refusal(&l).contains("not from the registry"),
            "{resolved}"
        );
    }
}

#[test]
fn a_root_without_resolved_or_link_is_accepted() {
    let l = lock();
    assert!(l["packages"][""].get("resolved").is_none());
    assert!(l["packages"][""].get("link").is_none());
    check_lock(&l).expect("root needs no tarball of its own");
}

/// Keep the dependency reachable so a missing entry cannot mask a bad spec.
#[test]
fn local_specs_in_dependency_maps_refuse() {
    for spec in [
        ".", "..", ".git", "./x", "a.tgz", "a.tar", "a.tar.gz", "A.TGZ", "a.Tar.Gz",
    ] {
        for range in [spec.to_owned(), format!("npm:@s/p@{spec}")] {
            let mut l = lock();
            l["packages"][""]["dependencies"]["a"] = range.as_str().into();
            assert!(
                lock_refusal(&l).contains("not from the registry"),
                "{range}"
            );
        }
    }
}

#[test]
fn registry_tags_ranges_and_aliases_are_accepted() {
    for range in [
        "latest",
        "^1.2.3",
        "npm:@s/p@^1",
        "1.x || >=2",
        // npm's default range, and an alias that omits its version.
        "",
        "npm:foo",
        "npm:@s/p",
        // A registry tag with an underscore, and ranges npm accepts with a
        // tab or a newline between their comparators.
        "beta_1",
        ">=1\t<2",
        ">=1\n<2",
    ] {
        let mut l = lock();
        l["packages"][""]["dependencies"]["a"] = range.into();
        check_lock(&l).expect(range);
    }
}

/// A normalized alias listed first must not shadow the exact script name.
#[test]
fn the_exact_console_script_wins_over_a_normalized_match() {
    let scripts = "[console_scripts]\nMY_SRV = m:alias\nmy-srv = m:main\n";
    let env = uv_env(&[("my_srv-1.0.dist-info", scripts)], &["MY_SRV", "my-srv"]);
    assert!(
        entry_of(&env, "my-srv")
            .expect("exact script")
            .ends_with("bin/my-srv")
    );
}

#[test]
fn a_unique_normalized_console_script_is_accepted() {
    let scripts = "[console_scripts]\nMY_SRV = m:main\nother = m:other\n";
    let env = uv_env(&[("my_srv-1.0.dist-info", scripts)], &["MY_SRV", "other"]);
    assert!(
        entry_of(&env, "my-srv")
            .expect("unique normalized script")
            .ends_with("bin/MY_SRV")
    );
}

/// Without an exact name, metadata order cannot resolve a collision.
#[test]
fn ambiguous_normalized_console_scripts_refuse() {
    let scripts = "[console_scripts]\nMY_SRV = m:first\nmy.srv = m:second\n";
    let env = uv_env(&[("my_srv-1.0.dist-info", scripts)], &["MY_SRV", "my.srv"]);
    assert!(
        entry_of(&env, "my-srv")
            .expect_err("ambiguous normalized scripts")
            .contains("no single entry point")
    );
}

/// The hyphen before the version separates the full distribution name.
#[test]
fn a_distribution_name_prefix_is_not_the_package() {
    let env = uv_env(&[("foo-bar-1.0.dist-info", ONE)], &["srv"]);
    assert!(
        entry_of(&env, "foo")
            .expect_err("prefix is not a distribution match")
            .contains("installed metadata")
    );
}

#[test]
fn a_hyphenated_distribution_name_is_matched_in_full() {
    let env = uv_env(&[("foo-bar-1.0.dist-info", ONE)], &["srv"]);
    assert!(
        entry_of(&env, "foo-bar")
            .expect("full distribution name")
            .ends_with("bin/srv")
    );
}

/// Containment applies to the package directory as well as its bin target.
#[cfg(unix)]
#[test]
fn an_npm_package_directory_outside_the_root_refuses() {
    let outside = npm_pkg("pkg", &json!("cli.js"), &["cli.js"]);
    let root = tempfile::tempdir().expect("root");
    std::fs::create_dir(root.path().join("node_modules")).expect("node_modules");
    std::os::unix::fs::symlink(
        outside.path().join("node_modules/pkg"),
        root.path().join("node_modules/pkg"),
    )
    .expect("package symlink");
    assert!(
        bin_of(&root, "pkg")
            .expect_err("package outside root")
            .contains("the package's entry point is outside the package")
    );
}

/// Valid metadata and a real bin isolate the read cap from parsing failures.
#[test]
fn an_oversized_npm_manifest_refuses() {
    let root = npm_pkg("pkg", &json!("cli.js"), &["cli.js"]);
    let mut manifest = json!({"bin": "cli.js"}).to_string();
    manifest.push_str(&" ".repeat(2 * 1024 * 1024 - manifest.len()));
    std::fs::write(root.path().join("node_modules/pkg/package.json"), manifest)
        .expect("oversized manifest");
    assert!(
        bin_of(&root, "pkg")
            .expect_err("oversized manifest")
            .contains("no single entry point")
    );
}

/// Comment padding keeps parsing valid without adding more console scripts.
#[test]
fn oversized_uv_entry_points_refuse() {
    let mut scripts = ONE.to_owned();
    scripts.push_str(&"#\n".repeat((2 * 1024 * 1024 - scripts.len()) / 2));
    scripts.push_str(&"\n".repeat(2 * 1024 * 1024 - scripts.len()));
    let env = uv_env(&[("srv-1.0.dist-info", &scripts)], &["srv"]);
    assert!(
        entry_of(&env, "srv")
            .expect_err("oversized entry points")
            .contains("no single entry point")
    );
}

/// An alias that names a version still must name a usable one.
#[test]
fn an_alias_with_an_empty_explicit_version_refuses() {
    let mut l = lock();
    l["packages"][""]["dependencies"]["a"] = "npm:@s/p@".into();
    assert!(lock_refusal(&l).contains("not from the registry"));
}

/// A peer is installed like a dependency: a non-registry peer spec refuses,
/// a registry range (or an optional peer with no entry) is accepted.
#[test]
fn a_peer_declaration_must_be_a_registry_range() {
    for spec in [
        "git+https://example.invalid/p.git",
        "file:../p",
        ".",
        "a.tgz",
    ] {
        let mut l = lock();
        l["packages"][""]["peerDependencies"] = serde_json::json!({ "peer": spec });
        assert!(lock_refusal(&l).contains("not from the registry"), "{spec}");
    }
    for range in ["", ">=16 <19 || ^1", "latest"] {
        let mut l = lock();
        l["packages"][""]["peerDependencies"] = serde_json::json!({ "absent": range });
        l["packages"][""]["peerDependenciesMeta"] =
            serde_json::json!({ "absent": { "optional": true } });
        check_lock(&l).expect(range);
    }
}

/// U-name (the uv fetch, design 4), kills "the raw spec names the tool env": a
/// spec with a version pin, dots, underscores, capitals or a run of
/// separators gives the PEP 503 name `foo-bar`, and the tool env, the
/// metadata lookup and the console script all sit under that one name.
#[test]
fn u_name_every_spelling_gives_one_tool_env() {
    let home = tempfile::tempdir().expect("home");
    let env = home.path().join("uv-tools/foo-bar");
    let site = env.join("lib/python3.12/site-packages/foo_bar-1.0.dist-info");
    std::fs::create_dir_all(&site).expect("site");
    std::fs::write(
        site.join("entry_points.txt"),
        "[console_scripts]\nfb = foo_bar:main\n",
    )
    .expect("entry points");
    std::fs::create_dir_all(env.join("bin")).expect("bin");
    std::fs::write(env.join("bin/fb"), "").expect("script");
    for spec in ["Foo_Bar==1.0", "foo.bar", "FOO--bar"] {
        assert_eq!(uv_name(spec), "foo-bar", "{spec}");
        assert_eq!(
            uv_tool_env(home.path(), spec),
            home.path().join("uv-tools/foo-bar"),
            "{spec}"
        );
        assert_eq!(
            uv_entry_point(&uv_tool_env(home.path(), spec), &uv_name(spec)).expect("entry point"),
            home.path().join("uv-tools/foo-bar/bin/fb"),
            "{spec}"
        );
    }
}

/// A uv tool env under `root` whose site-packages holds a `<stem>.dist-info`
/// directory (METADATA and RECORD inside) for each of `stems`.
fn tool_env(root: &std::path::Path, stems: &[String]) -> std::path::PathBuf {
    let env = root.join("uv-tools/probe-url");
    let site = env.join("lib/python3.12/site-packages");
    std::fs::create_dir_all(&site).expect("site");
    for stem in stems {
        let dir = site.join(format!("{stem}.dist-info"));
        std::fs::create_dir(&dir).expect("dist-info");
        std::fs::write(dir.join("METADATA"), "Metadata-Version: 2.1\n").expect("METADATA");
        std::fs::write(dir.join("RECORD"), "").expect("RECORD");
    }
    env
}

fn far() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(600)
}

fn direct_url_refusal() -> Refusal {
    Refusal::Command("the install holds a package from a direct URL".into())
}

/// U-direct (design 7), kills m-first-only and m-skip-one: with three named
/// dist-info dirs, tainting any ONE of them refuses, and a clean site passes
/// having checked all three.
#[test]
fn u_direct_every_dist_info_is_checked() {
    let stems: Vec<String> = ["a-1.0", "m-1.0", "z-1.0"].map(String::from).to_vec();
    for tainted in &stems {
        let root = tempfile::tempdir().expect("root");
        let env = tool_env(root.path(), &stems);
        std::fs::write(
            env.join(format!(
                "lib/python3.12/site-packages/{tainted}.dist-info/direct_url.json"
            )),
            "{\"url\": \"https://files.pythonhosted.org/direct/x.whl\"}",
        )
        .expect("taint");
        assert_eq!(
            check_direct_url(&env, far()),
            Err(direct_url_refusal()),
            "{tainted}"
        );
    }
    let root = tempfile::tempdir().expect("root");
    let env = tool_env(root.path(), &stems);
    let mut checked = check_direct_url(&env, far()).expect("a clean site passes");
    checked.sort();
    assert_eq!(checked, ["a-1.0", "m-1.0", "z-1.0"]);
}

/// U-direct, kills m-fail-open: a dist-info that cannot be read as a
/// directory (a regular file: ENOTDIR for any euid), no site-packages, two
/// site-packages, and a deadline already passed each refuse.
#[test]
fn u_direct_what_cannot_be_read_refuses() {
    let root = tempfile::tempdir().expect("root");
    let env = tool_env(root.path(), &["a-1.0".to_owned()]);
    std::fs::write(env.join("lib/python3.12/site-packages/x-1.0.dist-info"), "").expect("file");
    assert!(check_direct_url(&env, far()).is_err(), "a file dist-info");

    let root = tempfile::tempdir().expect("root");
    let env = root.path().join("uv-tools/probe-url");
    std::fs::create_dir_all(env.join("lib")).expect("lib");
    assert!(check_direct_url(&env, far()).is_err(), "no site-packages");

    let root = tempfile::tempdir().expect("root");
    let env = tool_env(root.path(), &["a-1.0".to_owned()]);
    std::fs::create_dir_all(env.join("lib/python3.13/site-packages")).expect("second site");
    assert!(check_direct_url(&env, far()).is_err(), "two site-packages");

    let root = tempfile::tempdir().expect("root");
    let env = tool_env(root.path(), &["a-1.0".to_owned()]);
    let past = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(60))
        .expect("an instant a minute back");
    assert!(check_direct_url(&env, past).is_err(), "a passed deadline");
    assert!(
        check_direct_url(&env, far()).is_ok(),
        "the same site, in time"
    );
}

/// U-direct, the cap on both sides (kills m-no-cap and m-stop-early): 4097
/// entries refuse; 4096 clean ones pass; 4096 with only the one sorting last
/// tainted refuse.
#[test]
fn u_direct_reads_at_most_4096_entries_and_checks_them_all() {
    let stems = |n: usize| (0..n).map(|i| format!("p{i:04}-1.0")).collect::<Vec<_>>();
    let root = tempfile::tempdir().expect("root");
    let env = tool_env(root.path(), &stems(4097));
    assert!(check_direct_url(&env, far()).is_err(), "4097 entries");

    let root = tempfile::tempdir().expect("root");
    let env = tool_env(root.path(), &stems(4096));
    assert_eq!(
        check_direct_url(&env, far()).expect("4096 pass").len(),
        4096
    );

    let mut many = stems(4095);
    many.push("zzzz-1.0".to_owned());
    let root = tempfile::tempdir().expect("root");
    let env = tool_env(root.path(), &many);
    std::fs::write(
        env.join("lib/python3.12/site-packages/zzzz-1.0.dist-info/direct_url.json"),
        "{}",
    )
    .expect("taint");
    assert_eq!(check_direct_url(&env, far()), Err(direct_url_refusal()));
}

/// U-direct, a site with no dist-info at all passes the check, and D6's
/// lookup then refuses it.
#[test]
fn u_direct_an_empty_site_passes_and_the_lookup_refuses() {
    let root = tempfile::tempdir().expect("root");
    let env = tool_env(root.path(), &[]);
    assert_eq!(check_direct_url(&env, far()), Ok(Vec::new()));
    assert_eq!(
        uv_entry_point(&env, "probe-url"),
        Err(Refusal::Command(
            "the package's installed metadata was not found exactly once".into()
        ))
    );
}

/// U-direct (code review r1, muse HIGH), kills m-utf8-skip: a dist-info
/// whose name is not UTF-8 is checked like any other, so a tainted one
/// refuses. Linux only: macOS file systems refuse a non-UTF-8 name.
#[cfg(target_os = "linux")]
#[test]
fn u_direct_a_dist_info_named_in_raw_bytes_is_checked() {
    use std::os::unix::ffi::OsStrExt as _;
    let root = tempfile::tempdir().expect("root");
    let env = tool_env(root.path(), &["a-1.0".to_owned()]);
    let raw = env
        .join("lib/python3.12/site-packages")
        .join(std::ffi::OsStr::from_bytes(b"x\xff-1.0.dist-info"));
    std::fs::create_dir(&raw).expect("a raw-named dist-info");
    std::fs::write(raw.join("direct_url.json"), "{}").expect("taint");
    assert_eq!(check_direct_url(&env, far()), Err(direct_url_refusal()));
}

#[path = "install_lock_names_tests.rs"]
mod lock_names;

#[cfg(unix)]
#[path = "install_link_tests.rs"]
mod link_tests;
