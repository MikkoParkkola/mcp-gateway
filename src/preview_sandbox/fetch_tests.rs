// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the command plan: which typed commands fetch a registry package
//! before the run, and which refuse.

use std::path::PathBuf;

use super::*;

fn target(program: &str, args: &[&str]) -> Target {
    Target {
        program: PathBuf::from(program),
        args: args.iter().map(OsString::from).collect(),
    }
}

fn phases(program: &str, args: &[&str]) -> Phases {
    plan(&target(program, args)).unwrap_or_else(|e| panic!("{program} {args:?}: {e}"))
}

fn refusal(program: &str, args: &[&str]) -> String {
    match plan(&target(program, args)) {
        Ok(p) => panic!("{program} {args:?} was accepted: {p:?}"),
        Err(e) => e.to_string(),
    }
}

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

/// T1: the accepted forms fetch their spec and keep the rest as run args.
#[test]
fn npx_and_uvx_fetch_the_spec_and_keep_the_args() {
    let p = phases("npx", &["-y", "pkg"]);
    assert_eq!(p.fetch, Some(Fetch::Npm("pkg".into())));
    assert!(p.run_args.is_empty());

    let p = phases("/usr/local/bin/npx", &["--yes", "@s/pkg@1.2.3", "--flag"]);
    assert_eq!(p.fetch, Some(Fetch::Npm("@s/pkg@1.2.3".into())));
    assert_eq!(p.run_args, os(&["--flag"]));

    let p = phases("uvx", &["pkg==1.0", "a", "b"]);
    assert_eq!(p.fetch, Some(Fetch::Uv("pkg==1.0".into())));
    assert_eq!(p.run_args, os(&["a", "b"]));

    // An option after the spec is the server's own.
    let p = phases("npx", &["pkg", "--registry=x"]);
    assert_eq!(p.run_args, os(&["--registry=x"]));
}

/// T1: any other program has no fetch phase; its args pass through.
#[test]
fn another_program_has_no_fetch() {
    let p = phases("python", &["-m", "x"]);
    assert_eq!(p.fetch, None);
    assert_eq!(p.run_args, os(&["-m", "x"]));
}

/// T1: an option before the package refuses, for both tools.
#[test]
fn an_option_before_the_package_refuses() {
    for (program, args) in [
        ("npx", &["--registry=x", "pkg"][..]),
        ("npx", &["--node-options=--require=x", "pkg"]),
        ("npx", &["-y", "-p", "pkg"]),
        ("uvx", &["--index-url", "https://x", "pkg"]),
        ("uvx", &["--with", "x", "pkg"]),
        ("uvx", &["-y", "pkg"]),
    ] {
        let text = refusal(program, args);
        assert!(
            text.contains("an npx/uvx option before the package"),
            "{args:?}: {text}"
        );
    }
}

/// T1: no package at all refuses.
#[test]
fn no_package_refuses() {
    for (program, args) in [("npx", &[][..]), ("npx", &["-y"]), ("uvx", &[])] {
        let text = refusal(program, args);
        assert!(text.contains("no package"), "{program} {args:?}: {text}");
    }
}

/// T1: npm forms that are not a registry package refuse, naming the form.
#[test]
fn npm_non_registry_specs_refuse() {
    let long = "a".repeat(215);
    for spec in [
        "file:../x",
        "git+https://github.com/a/b",
        "github:a/b",
        "https://x/y.tgz",
        "./local",
        "/abs",
        "npm:alias@1",
        ".",
        "..",
        ".hidden",
        "_under",
        "@./x",
        "@s/.x",
        "@s",
        "@s/",
        "@/x",
        "pkg@",
        "pkg@1:2",
        "pkg@1/2",
        "pkg@1\\2",
        "Pkg",
        "a:b",
        // npm reads a dot-led version as a path and an archive name as a file.
        "pkg@..",
        "pkg@.hidden",
        "pkg.tgz",
        "pkg@foo.tgz",
        "pkg@x.tar",
        "pkg@x.TAR.GZ",
        "",
        long.as_str(),
    ] {
        let text = refusal("npx", &[spec]);
        assert!(text.contains("not a registry package"), "{spec}: {text}");
    }
}

/// T1: npm's length limit is inclusive and counts the scope.
#[test]
fn npm_name_length_is_capped_at_214() {
    let ok = "a".repeat(214);
    assert_eq!(phases("npx", &[ok.as_str()]).fetch, Some(Fetch::Npm(ok)));
    let scoped = format!("@s/{}", "a".repeat(212));
    assert!(refusal("npx", &[scoped.as_str()]).contains("not a registry package"));
    let scoped = format!("@s/{}", "a".repeat(211));
    assert_eq!(
        phases("npx", &[scoped.as_str()]).fetch,
        Some(Fetch::Npm(scoped))
    );
}

/// T1: npm version ranges keep their own characters.
#[test]
fn npm_version_ranges_are_accepted() {
    for spec in [
        "pkg@^1.2.3",
        "pkg@~1",
        "pkg@>=1 <2",
        "pkg@1 || 2",
        "pkg@latest",
        "pkg@1.x",
        "pkg@*",
    ] {
        assert_eq!(
            phases("npx", &[spec]).fetch,
            Some(Fetch::Npm(spec.into())),
            "{spec}"
        );
    }
    assert!(phases("npx", &["a-b.c_d~e"]).fetch.is_some());
}

/// T1: `PyPI` forms that are not a registry package refuse, naming the form.
#[test]
fn pypi_non_registry_specs_refuse() {
    for spec in [
        "https://x/y.whl",
        "./x",
        "/abs",
        ".",
        "..",
        ".x",
        "x-",
        "x@1",
        "x==",
        "x>=1",
        "x==1/2",
        "x==1 ",
        "a:b",
        "",
    ] {
        let text = refusal("uvx", &[spec]);
        assert!(text.contains("not a registry package"), "{spec}: {text}");
    }
}

/// T1: `PyPI` names keep case, dots and underscores; `==version` is the one
/// version form.
#[test]
fn pypi_names_and_pins_are_accepted() {
    for spec in [
        "Pkg",
        "a.b_c-d",
        "x",
        "pkg==1.0",
        "pkg==1.0rc1",
        "pkg==1!2.0+local.1",
        "pkg==1.*",
    ] {
        assert_eq!(
            phases("uvx", &[spec]).fetch,
            Some(Fetch::Uv(spec.into())),
            "{spec}"
        );
    }
}

/// T7 (N5): `PyPI` extras refuse with their own reason.
#[test]
fn pypi_extras_are_not_previewed() {
    for spec in ["pkg[extra]", "pkg[a,b]==1"] {
        let text = refusal("uvx", &[spec]);
        assert!(
            text.contains("PyPI extras are not previewed"),
            "{spec}: {text}"
        );
    }
}

/// A refusal keeps the shared tail every preview refusal ends with.
#[test]
fn a_plan_refusal_ends_with_the_shared_tail() {
    let text = refusal("npx", &["github:a/b"]);
    assert!(
        text.ends_with("the server can still be added without a preview"),
        "{text}"
    );
}

/// A non-UTF-8 spec refuses; non-UTF-8 server arguments after a valid spec
/// pass through unchanged.
#[cfg(unix)]
#[test]
fn non_utf8_specs_refuse_and_non_utf8_args_pass_through() {
    use std::os::unix::ffi::OsStringExt as _;
    let raw = OsString::from_vec(vec![b'p', 0xff, b'k']);
    let target = Target {
        program: PathBuf::from("npx"),
        args: vec![raw.clone()],
    };
    let text = plan(&target).expect_err("non-UTF-8 spec").to_string();
    assert!(text.contains("not a registry package"), "{text}");
    let target = Target {
        program: PathBuf::from("uvx"),
        args: vec![OsString::from("pkg"), raw.clone()],
    };
    assert_eq!(plan(&target).expect("valid spec").run_args, vec![raw]);
}
