// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Linux preview sandbox's unit tests: plan building, refusal
//! classification and the helper dispatch.

use super::*;

/// What util-linux 2.41 prints on Ubuntu 25.10 with the `AppArmor`
/// restriction on (seen on a build host).
const UID_MAP_DENIED: &str = "unshare: write failed /proc/self/uid_map: Operation not permitted";

#[test]
fn apparmor_restricted_host_names_the_profile_step() {
    let host = HostFacts {
        apparmor_restricts_userns: Some("1".into()),
        max_user_namespaces: Some("511768".into()),
        ..HostFacts::default()
    };
    let refusal = classify_with(UID_MAP_DENIED, &host);
    assert_eq!(refusal, Refusal::AppArmorRestricted);
    let text = refusal.to_string();
    assert!(
        text.contains("SECURITY.md") && text.contains("apparmor_parser -r"),
        "{text}"
    );
    assert!(
        text.ends_with("the server can still be added without a preview"),
        "{text}"
    );
}

#[test]
fn disabled_user_namespaces_win_over_apparmor() {
    let host = HostFacts {
        max_user_namespaces: Some("0".into()),
        apparmor_restricts_userns: Some("1".into()),
        in_container: true,
    };
    let refusal = classify_with("unshare: unshare failed: No space left on device", &host);
    assert_eq!(refusal, Refusal::UserNamespacesDisabled);
    assert!(refusal.to_string().contains("user.max_user_namespaces = 0"));
}

#[test]
fn a_container_says_it_cannot_nest() {
    let host = HostFacts {
        in_container: true,
        ..HostFacts::default()
    };
    let refusal = classify_with("unshare: unshare failed: Operation not permitted", &host);
    assert_eq!(refusal, Refusal::Container);
    assert!(refusal.to_string().contains("container"));
}

/// An Ubuntu 24.04 container reports the host's `AppArmor` sysctl; the fix
/// it needs is to preview from a host install, not the profile.
#[test]
fn a_container_on_an_apparmor_host_says_container() {
    let host = HostFacts {
        apparmor_restricts_userns: Some("1".into()),
        in_container: true,
        ..HostFacts::default()
    };
    assert_eq!(classify_with(UID_MAP_DENIED, &host), Refusal::Container);
}

#[test]
fn a_helper_refusal_names_its_step_on_any_host() {
    let host = HostFacts {
        apparmor_restricts_userns: Some("1".into()),
        ..HostFacts::default()
    };
    let stderr = "preview-sandbox: refused at checking descriptors (inherited: [5])\n";
    assert_eq!(
        classify_with(stderr, &host),
        Refusal::Step("checking descriptors (inherited: [5])".into())
    );
}

/// Namespaces created, mounts denied: the same one-time step.
#[test]
fn a_mount_denied_under_apparmor_names_the_profile_step() {
    let host = HostFacts {
        apparmor_restricts_userns: Some("1".into()),
        ..HostFacts::default()
    };
    let stderr = "preview-sandbox: refused at mounting the root tmpfs on /tmp \
                  (Permission denied (os error 13))\n";
    assert_eq!(classify_with(stderr, &host), Refusal::AppArmorRestricted);
    // The same step on a host without the restriction is the step itself.
    assert!(matches!(
        classify_with(stderr, &HostFacts::default()),
        Refusal::Step(step) if step.starts_with("mounting the root tmpfs")
    ));
}

#[test]
fn an_unrecognised_failure_keeps_what_unshare_said() {
    let refusal = classify_with("unshare: a new message\n", &HostFacts::default());
    assert_eq!(
        refusal,
        Refusal::Step("starting the namespaces (unshare: a new message)".into())
    );
}

fn system() -> Vec<String> {
    ["/usr", "/bin", "/lib", "/lib64"]
        .map(ToOwned::to_owned)
        .into()
}

/// A program anywhere outside the system roots and the known runtime
/// trees binds as the file alone: a home around it is never bound,
/// whatever account owns it and wherever it lives.
#[test]
fn a_program_outside_the_allowlist_binds_as_its_file_alone() {
    for program in [
        "/home/alice/server",
        "/srv/users/alice/bin/server",
        "/var/lib/ldap-user/tool",
        "/opt/vendor/bin/mcp-server",
    ] {
        assert_eq!(
            program_bind(Path::new(program), &system()),
            ProgramBind::File(PathBuf::from(program)),
            "{program}"
        );
    }
}

/// Only `/usr/local` is bound back; a program under a masked secret path
/// is refused rather than reopening it.
#[test]
fn only_usr_local_is_bound_back() {
    assert!(matches!(
        program_bind(Path::new("/usr/local/bin/node"), &system()),
        ProgramBind::UsrLocal(dirs) if dirs.first() == Some(&PathBuf::from("/usr/local/bin"))
    ));
    assert_eq!(
        program_bind(Path::new("/etc/ssl/private/tool"), &system()),
        ProgramBind::Refused
    );
}

#[test]
fn a_system_program_binds_nothing_more() {
    for program in ["/usr/bin/python3", "/bin/sh", "/lib/x86_64-linux-gnu/ld.so"] {
        assert_eq!(
            program_bind(Path::new(program), &system()),
            ProgramBind::System
        );
    }
}

/// A runtime binds its own install tree and nothing above it: the NVM
/// version, not `.nvm` or the home holding it.
#[test]
fn a_runtime_binds_its_own_tree_only() {
    let cases = [
        (
            "/home/ann/.nvm/versions/node/v22.1.0/bin/node",
            "/home/ann/.nvm/versions/node/v22.1.0",
        ),
        (
            "/srv/u/bo/.pyenv/versions/3.12.4/bin/python3.12",
            "/srv/u/bo/.pyenv/versions/3.12.4",
        ),
        (
            "/home/linuxbrew/.linuxbrew/Cellar/python@3.12/3.12.4/bin/python3.12",
            "/home/linuxbrew/.linuxbrew/Cellar/python@3.12/3.12.4",
        ),
    ];
    for (program, tree) in cases {
        assert_eq!(
            program_bind(Path::new(program), &system()),
            ProgramBind::Runtime(PathBuf::from(tree)),
            "{program}"
        );
    }
    // A path that only names the tree, with nothing inside it, is a file.
    assert_eq!(
        program_bind(Path::new("/home/ann/.nvm/versions/node/v22"), &system()),
        ProgramBind::File(PathBuf::from("/home/ann/.nvm/versions/node/v22"))
    );
}

fn target(program: &str) -> Target {
    Target {
        program: PathBuf::from(program),
        args: Vec::new(),
    }
}

fn system_path() -> Option<OsString> {
    std::env::var_os("PATH")
}

/// A scratch directory outside `/tmp`, which the plan refuses to bind.
fn scratch() -> tempfile::TempDir {
    tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("scratch dir")
}

#[test]
fn a_relative_program_is_refused() {
    for program in ["./sh", "bin/sh", "../sh"] {
        assert!(
            matches!(build_plan(&target(program), &[], system_path().as_deref()), Err(Refusal::Step(s)) if s.contains("bare name")),
            "{program}"
        );
    }
}

#[test]
fn a_bare_name_resolves_to_an_absolute_path() {
    let plan = build_plan(&target("sh"), &[], system_path().as_deref()).expect("sh on PATH");
    let found = Path::new(&plan.program);
    assert!(
        found.is_absolute() && found.is_file(),
        "{}",
        found.display()
    );
}

/// An alias whose real file is elsewhere (delta check 3): the drop execs
/// the real file, `argv[0]` is the name as asked for, bare or absolute,
/// and the run phase's PATH never names the alias's own directory, which
/// the sandbox does not show.
#[test]
fn a_symlinked_program_execs_its_real_file_under_its_name() {
    let dir = scratch();
    let sh = resolve_command("sh", system_path().as_deref(), None).expect("sh on PATH");
    let real = fs::canonicalize(sh).expect("canonical sh");
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).expect("symlink");
    // A chain of two aliases ends at the same real file.
    std::os::unix::fs::symlink(&alias, dir.path().join("chained")).expect("symlink");
    let alias = alias.to_str().expect("UTF-8 scratch path").to_owned();
    for (requested, path) in [
        ("alias", Some(dir.path().as_os_str())),
        ("chained", Some(dir.path().as_os_str())),
        (alias.as_str(), system_path().as_deref()),
    ] {
        let plan = build_plan(&target(requested), &[], path).expect("plan");
        assert_eq!(Path::new(&plan.program), real, "{requested}");
        assert_eq!(plan.target.first().map(String::as_str), Some(requested));
        let run_path = &plan.env.iter().find(|(k, _)| k == "PATH").expect("PATH").1;
        assert!(
            !run_path.split(':').any(|d| Path::new(d) == dir.path()),
            "{requested}: {run_path}"
        );
    }
}

/// The preview and the capability executor take the same program for
/// every name (the same file, once links are followed), or refuse it alike. `a\b` is a file on the injected PATH,
/// which only a one-component check would accept.
#[test]
fn the_preview_resolves_as_the_executor_does() {
    let dir = scratch();
    fs::write(dir.path().join("a\\b"), "").expect("odd name");
    let mut dirs = vec![dir.path().to_owned()];
    dirs.extend(std::env::split_paths(&system_path().unwrap_or_default()));
    let path = std::env::join_paths(dirs).expect("PATH");
    for name in [
        "sh",
        "/bin/sh",
        "./sh",
        "bin/sh",
        "a\\b",
        "sh/",
        "",
        "no-such-tool-8905",
    ] {
        let preview = build_plan(&target(name), &[], Some(&path))
            .map(|p| fs::canonicalize(p.program).expect("canonical"));
        let executor = resolve_command(name, Some(&path), None)
            .map(|p| fs::canonicalize(p).expect("canonical"));
        match (preview, executor) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "{name}"),
            (Err(_), Err(_)) => {}
            (a, b) => panic!("{name:?}: preview {a:?}, executor {b:?}"),
        }
    }
}

/// The root's visibility, row by row, and the same answer as the rule it
/// replaced: `(read_only || bound_back) && !(masked && !bound_back) &&
/// !hidden`.
#[test]
fn shown_inside_follows_hidden_then_bind_backs_then_masks() {
    let set = |paths: &[&str]| -> Vec<String> { paths.iter().map(|p| (*p).to_owned()).collect() };
    let read_only = set(&["/usr", "/bin", "/etc/ssl"]);
    let masked = set(&["/usr/local", "/etc/ssl/private"]);
    let bound_back = set(&["/usr/local/bin"]);
    let hidden = set(&["/usr/share/gateway", "/usr/local/bin/state"]);
    for (path, want) in [
        ("/usr/share/gateway/config", false),
        ("/usr/local/bin/state/token", false),
        ("/usr/local/bin/node", true),
        ("/usr/bin/sh", true),
        ("/usr/local/lib/libx.so", false),
        ("/etc/ssl/private/key.pem", false),
        ("/home/ann/tool", false),
    ] {
        let p = Path::new(path);
        let under = |s: &[String]| s.iter().any(|r| p.starts_with(r));
        let in_root = under(&read_only) || under(&bound_back);
        let masked_out = under(&masked) && !under(&bound_back);
        let replaced = in_root && !masked_out && !under(&hidden);
        let got = shown_inside(p, &read_only, &bound_back, &masked, &hidden);
        assert_eq!(got, want, "{path}");
        assert_eq!(got, replaced, "{path}: differs from the replaced rule");
    }
}

/// An alias is exec'd as itself only when it and every link after it
/// stay where the root shows them.
#[test]
fn an_alias_is_kept_only_while_every_link_is_shown() {
    let dir = scratch();
    let root = fs::canonicalize(dir.path())
        .expect("canonical scratch")
        .join("root");
    let out = root.with_file_name("out");
    fs::create_dir_all(&root).expect("root");
    fs::create_dir_all(&out).expect("out");
    fs::write(root.join("real"), "").expect("real");
    let link = |at: &str, to: &str| std::os::unix::fs::symlink(to, root.join(at)).expect("link");
    link("same-dir", "real");
    link("chained", "same-dir");
    link("dangling", "missing");
    link("outside", "../out/hop");
    // A later hop through a directory link the root does not show: the kernel
    // would walk `out/dir-hop`, which is absent inside, so nothing is kept.
    link("later-dir-link", "../out/dir-hop/real");
    // The same walk hidden by `..`: `out/twin` is a directory link the root
    // does not show, and the `..` after it cancels it in the text, so the
    // text alone reads as resolved while the kernel still walks `out/twin`.
    link("dotdot-through-link", "../out/twin/../../root/real");
    // Any climb on a later hop runs the real file, a link-free one included
    // (an nvm `npm -> ../lib/...` alias): only the spelling is lost.
    link("plain-climb", "../root/real");
    // Two links pointing at each other end at the hop ceiling, not a loop.
    link("loop-a", "loop-b");
    link("loop-b", "loop-a");
    std::os::unix::fs::symlink("../root/real", out.join("hop")).expect("hop");
    std::os::unix::fs::symlink(&root, out.join("dir-hop")).expect("dir hop");
    fs::create_dir_all(out.join("real-dir")).expect("real dir");
    // No dots at all, yet through the unshown `out/dir-hop`: rejected only
    // because the target as written differs from its resolved form.
    let absolute = out.join("dir-hop").join("real");
    link(
        "absolute-dir-link",
        absolute.to_str().expect("UTF-8 scratch path"),
    );
    std::os::unix::fs::symlink("real-dir", out.join("twin")).expect("twin");
    let shown = |p: &Path| p.starts_with(&root);
    // Reached through a directory link the root does not show: kept, but
    // spelled through the real directory, which the root does show.
    std::os::unix::fs::symlink(&root, out.join("dir-link")).expect("dir link");
    assert_eq!(
        reachable_inside(&out.join("dir-link").join("same-dir"), &shown),
        Some(root.join("same-dir"))
    );
    // Every row is checked before the test fails, so a red run names them all.
    let mut wrong = Vec::new();
    for (name, kept) in [
        ("real", true),
        ("same-dir", true),
        ("chained", true),
        ("dangling", false),
        ("outside", false),
        ("later-dir-link", false),
        ("dotdot-through-link", false),
        ("plain-climb", false),
        ("absolute-dir-link", false),
        ("loop-a", false),
    ] {
        let got = reachable_inside(&root.join(name), &shown);
        if got != kept.then(|| root.join(name)) {
            wrong.push(format!("{name}: {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "wrong rows: {wrong:?}");
}

/// The helper subcommands are recognised only as the first argument.
#[test]
fn dispatch_ignores_ordinary_commands() {
    let args: Vec<OsString> = ["mcp-gateway", "serve", SANDBOX].map(Into::into).into();
    assert!(dispatch(&args).is_none());
}
