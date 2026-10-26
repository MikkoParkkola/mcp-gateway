// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Linux sandbox (ADR-027): util-linux `unshare` makes the namespaces, so
//! the gateway itself makes no namespace syscall, and the gateway's own binary
//! runs inside them as `__preview-sandbox` and `__preview-drop`.

mod drop;
mod helper;
mod mounts;
pub(crate) mod plan;
pub(crate) mod seccomp;

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};

use plan::{HostNamespaces, Plan};

use super::{Refusal, Started, Target};
use crate::capability::resolve_command;

/// The helper subcommands, dispatched before the CLI parser and any runtime.
pub(crate) const SANDBOX: &str = "__preview-sandbox";
pub(crate) const DROP: &str = "__preview-drop";
/// The helper's exit status when it refuses; its stderr names the step.
pub(crate) const REFUSED: u8 = 97;

/// Where util-linux installs `unshare`; the first that exists is used.
const UNSHARE: [&str; 2] = ["/usr/bin/unshare", "/bin/unshare"];

/// System paths bound read-only at the same place inside, plus every
/// top-level `/lib*` the host has.
const READ_ONLY: [&str; 5] = [
    "/usr",
    "/bin",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/pki/tls",
];
/// System paths covered by an empty read-only tmpfs.
const MASKED: [&str; 3] = ["/usr/local", "/etc/ssl/private", "/etc/pki/tls/private"];

/// Run `args` as the helper when they name one; `None` for any other command.
pub(super) fn dispatch(args: &[OsString]) -> Option<ExitCode> {
    match args.get(1)?.to_str()? {
        SANDBOX => Some(match decode::<Plan>(args.get(2)) {
            Ok(plan) => helper::run(&plan),
            Err(e) => refuse(&e),
        }),
        DROP => Some(match (decode(args.get(2)), args.get(3), args.get(4)) {
            (Ok(limits), Some(program), Some(dashes)) if dashes == "--" => {
                drop::run(limits, program, &args[5..])
            }
            (Err(e), ..) => refuse(&e),
            _ => refuse("reading the drop arguments"),
        }),
        _ => None,
    }
}

fn decode<T: serde::de::DeserializeOwned>(arg: Option<&OsString>) -> Result<T, String> {
    let arg = arg
        .and_then(|a| a.to_str())
        .ok_or("a missing plan argument")?;
    serde_json::from_str(arg).map_err(|e| format!("reading the plan ({e})"))
}

fn refuse(step: &str) -> ExitCode {
    eprintln!("preview-sandbox: refused at {step}");
    ExitCode::from(REFUSED)
}

/// Start `target` inside a fresh namespace set and private root.
///
/// `protected` names the gateway's config paths beyond the ones the launcher
/// resolves itself (the data dir and the OS config dir's `mcp-gateway`).
pub(super) fn start(
    helper: &Path,
    target: &Target,
    protected: &[PathBuf],
) -> Result<Started, Refusal> {
    let unshare = UNSHARE
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .ok_or(Refusal::MissingTool("util-linux unshare"))?;
    let plan = build_plan(target, protected, std::env::var_os("PATH").as_deref())?;
    let encoded = serde_json::to_string(&plan)
        .map_err(|e| Refusal::Step(format!("encoding the plan ({e})")))?;

    let mut command = tokio::process::Command::new(unshare);
    command
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "--pid",
            "--fork",
            "--kill-child",
            "--mount-proc",
            "--net",
            "--ipc",
            "--uts",
        ])
        .arg(helper)
        .arg(SANDBOX)
        .arg(encoded)
        // Neither `unshare` nor the helper ever holds a gateway secret.
        .env_clear()
        .envs(plan.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Killing `unshare` makes `--kill-child` kill the helper, PID 1 of the
        // namespace, and with it every process inside.
        .kill_on_drop(true);
    let child = command
        .spawn()
        .map_err(|e| Refusal::Step(format!("starting unshare ({e})")))?;
    Ok(Started {
        child,
        isolation: super::Isolation::linux(&plan),
    })
}

/// Turn a target into the helper's plan, refusing what the root cannot hold.
/// A bare program name is looked up on `path`.
fn build_plan(
    target: &Target,
    protected: &[PathBuf],
    path: Option<&OsStr>,
) -> Result<Plan, Refusal> {
    // The name exactly as asked for: the program's `argv[0]`.
    let requested = target
        .program
        .to_str()
        .ok_or_else(|| Refusal::Step("finding the program (not UTF-8)".to_owned()))?;
    let program = resolve_command(requested, path, None)
        .map_err(|e| Refusal::Step(format!("finding {requested} ({e})")))?;
    let mut read_only: Vec<String> = READ_ONLY.iter().map(ToString::to_string).collect();
    read_only.extend(top_level_libs());
    let masked: Vec<String> = MASKED.iter().map(ToString::to_string).collect();
    let mut hidden = Vec::new();
    let mut bound_back = Vec::new();
    // The run phase's PATH: the program's own directory, then the system's.
    let mut path_dirs = Vec::new();
    let real = fs::canonicalize(&program).unwrap_or_else(|_| program.clone());
    if real.starts_with(mounts::STAGE) {
        return Err(Refusal::Step(format!(
            "placing {} (a program under /tmp cannot be bound)",
            real.display()
        )));
    }
    // Bound on an allowlist: what the program needs and nothing around it, so
    // a home or any other private directory is excluded without being found.
    // Every arm leaves the real file reachable. An alias to it is never bound:
    // it is exec'd only where the root already shows it (below).
    match program_bind(&real, &read_only) {
        ProgramBind::Refused => {
            return Err(Refusal::Step(format!(
                "placing {} (it lies under a masked secret path)",
                real.display()
            )));
        }
        ProgramBind::System => {}
        ProgramBind::UsrLocal(dirs) => {
            for dir in dirs {
                bound_back.push(utf8(&dir)?);
            }
        }
        ProgramBind::Runtime(prefix) => read_only.push(utf8(&prefix)?),
        ProgramBind::File(file) => read_only.push(utf8(&file)?),
    }
    let gateway_paths = [
        Some(crate::config_persistence::gateway_data_dir()),
        crate::home_dir::config_dir().map(|c| c.join("mcp-gateway")),
    ];
    for path in gateway_paths
        .into_iter()
        .flatten()
        .chain(protected.iter().cloned())
    {
        // Hidden where it is named and where it really is: a state directory
        // that is a symlink into a bound prefix (`/usr/...`) would otherwise
        // stay readable at its real path. Hidden paths never bind anything
        // back, so they cover any interpreter bind-back beneath them.
        if let Ok(real) = fs::canonicalize(&path)
            && real != path
        {
            hidden.push(utf8(&real)?);
        }
        hidden.push(utf8(&path)?);
    }

    // A kernel-started script sees the exec path as its `$0`, so an alias
    // the root shows is exec'd as itself (a launcher keeps dispatching on
    // it); one that crosses anything unshown is replaced by the real file.
    let shown = |p: &Path| {
        let under = |set: &[String]| set.iter().any(|r| p.starts_with(r));
        if under(&hidden) {
            return false;
        }
        under(&bound_back) || (under(&read_only) && !under(&masked))
    };
    let exec = reachable_inside(&program, &shown).unwrap_or(real);
    if let Some(dir) = exec.parent() {
        path_dirs.push(utf8(dir)?);
    }
    for system in ["/usr/bin", "/bin"] {
        if !path_dirs.iter().any(|d| d == system) {
            path_dirs.push(system.to_owned());
        }
    }
    let env = vec![
        ("PATH".to_owned(), path_dirs.join(":")),
        ("HOME".to_owned(), plan::HOME.to_owned()),
        ("TMPDIR".to_owned(), "/tmp".to_owned()),
    ];

    let mut argv = vec![requested.to_owned()];
    for arg in &target.args {
        argv.push(
            arg.to_str()
                .ok_or_else(|| Refusal::Step("reading an argument (not UTF-8)".to_owned()))?
                .to_owned(),
        );
    }
    Ok(Plan {
        host: host_namespaces()?,
        read_only,
        masked,
        hidden,
        bound_back,
        limits: plan::limits(user_process_count() + 256),
        env,
        program: utf8(&exec)?,
        target: argv,
    })
}

/// `path` with its directory links resolved, if it and every link on its way
/// to a file are `shown` inside the root, so that spelling still leads to the
/// program there (a raw spelling through an unshown directory link would not).
fn reachable_inside(path: &Path, shown: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    let mut at = path.to_path_buf();
    let mut first = None;
    // The kernel's own symlink-hop ceiling.
    for _ in 0..40 {
        // Directory links resolved, so `..` and a linked parent cannot lead
        // the check somewhere the exec does not go.
        let Some(here) = at
            .parent()
            .and_then(|dir| fs::canonicalize(dir).ok())
            .zip(at.file_name())
            .map(|(dir, name)| dir.join(name))
        else {
            return None;
        };
        if !shown(&here) {
            return None;
        }
        if first.is_none() {
            first = Some(here.clone());
        }
        match fs::read_link(&here) {
            Ok(next) => at = here.parent().unwrap_or(Path::new("/")).join(next),
            Err(_) => return if here.is_file() { first } else { None },
        }
    }
    None
}

/// What the sandbox binds for a program, by where its real file is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProgramBind {
    /// Under the read-only system roots, which are bound already.
    System,
    /// Under the masked `/usr/local`: its directory and a sibling `lib`,
    /// bound back.
    UsrLocal(Vec<PathBuf>),
    /// Under a masked secret path (`/etc/ssl/private`): never bound.
    Refused,
    /// Inside a runtime's own install tree (an NVM node version, a pyenv
    /// version, a Homebrew keg): that tree, which holds the runtime and its
    /// standard library and nothing of the user's.
    Runtime(PathBuf),
    /// Anywhere else: the file alone, never the directory around it. A static
    /// binary runs; one needing libraries outside the system roots fails
    /// visibly rather than exposing where it lives.
    File(PathBuf),
}

/// The runtime install trees the sandbox knows, as path components that
/// end at the tree's root: `.nvm/versions/node/<v>`, `.pyenv/versions/<v>`,
/// `.linuxbrew/Cellar/<formula>/<v>`.
const RUNTIME_TREES: [&[&str]; 3] = [
    &[".nvm", "versions", "node", "*"],
    &[".pyenv", "versions", "*"],
    &[".linuxbrew", "Cellar", "*", "*"],
];

fn program_bind(real: &Path, system: &[String]) -> ProgramBind {
    const USR_LOCAL: &str = "/usr/local";
    if real.starts_with(USR_LOCAL) {
        let dir = real.parent().map(Path::to_path_buf).unwrap_or_default();
        let lib = fs::canonicalize(dir.join("../lib")).ok();
        let dirs = std::iter::once(dir)
            .chain(lib)
            .filter(|d| d.starts_with(USR_LOCAL))
            .collect();
        return ProgramBind::UsrLocal(dirs);
    }
    if MASKED.iter().any(|m| real.starts_with(m)) {
        return ProgramBind::Refused;
    }
    if system.iter().any(|root| real.starts_with(root)) {
        return ProgramBind::System;
    }
    runtime_tree(real).map_or_else(|| ProgramBind::File(real.to_owned()), ProgramBind::Runtime)
}

/// The root of the runtime tree `real` lies in, if it lies in one.
fn runtime_tree(real: &Path) -> Option<PathBuf> {
    let parts: Vec<_> = real.components().collect();
    RUNTIME_TREES.iter().find_map(|tree| {
        (0..parts.len()).find_map(|start| {
            let window = parts.get(start..start + tree.len())?;
            let matches = window
                .iter()
                .zip(tree.iter())
                .all(|(part, want)| *want == "*" || part.as_os_str() == std::ffi::OsStr::new(want));
            // The tree must hold the program, not be it.
            (matches && parts.len() > start + tree.len())
                .then(|| parts[..start + tree.len()].iter().collect())
        })
    })
}

/// `/lib`, `/lib64`, `/lib32`, `/libx32`, whichever exist.
fn top_level_libs() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/") else {
        return Vec::new();
    };
    let mut libs: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| name.starts_with("lib"))
        .map(|name| format!("/{name}"))
        .collect();
    libs.sort();
    libs
}

fn utf8(path: &Path) -> Result<String, Refusal> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| Refusal::Step(format!("reading {} (not UTF-8)", path.display())))
}

fn host_namespaces() -> Result<HostNamespaces, Refusal> {
    let inode = |name: &str| {
        fs::metadata(format!("/proc/self/ns/{name}"))
            .map(|m| m.ino())
            .map_err(|e| Refusal::Step(format!("reading the gateway's {name} namespace ({e})")))
    };
    Ok(HostNamespaces {
        user: inode("user")?,
        mnt: inode("mnt")?,
        pid: inode("pid")?,
        net: inode("net")?,
        ipc: inode("ipc")?,
        uts: inode("uts")?,
    })
}

/// Processes the gateway's user owns host-wide, which `RLIMIT_NPROC` counts.
fn user_process_count() -> u64 {
    let uid = rustix::process::getuid().as_raw();
    fs::read_dir("/proc").map_or(0, |entries| {
        entries
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
            })
            .filter(|e| e.metadata().is_ok_and(|m| m.uid() == uid))
            .count() as u64
    })
}

/// The host settings that decide which refusal a failed start gets.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct HostFacts {
    max_user_namespaces: Option<String>,
    apparmor_restricts_userns: Option<String>,
    in_container: bool,
}

impl HostFacts {
    fn read() -> Self {
        let sysctl = |path: &str| fs::read_to_string(path).ok().map(|s| s.trim().to_owned());
        Self {
            max_user_namespaces: sysctl("/proc/sys/user/max_user_namespaces"),
            apparmor_restricts_userns: sysctl(
                "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            ),
            in_container: Path::new("/.dockerenv").exists()
                || Path::new("/run/.containerenv").exists(),
        }
    }
}

/// Name why `unshare` or the helper failed, from what it printed and the
/// host's own settings, so the refusal can say which one-time step fixes it.
pub(super) fn classify(stderr: &str) -> Refusal {
    classify_with(stderr, &HostFacts::read())
}

fn classify_with(stderr: &str, host: &HostFacts) -> Refusal {
    let apparmor = host.apparmor_restricts_userns.as_deref() == Some("1");
    // The helper's own refusal names its step. On an AppArmor-restricted host
    // the namespaces can be created and the mounts inside them still denied,
    // which the one-time profile fixes too.
    if let Some(step) = stderr
        .lines()
        .find_map(|line| line.strip_prefix("preview-sandbox: refused at "))
    {
        let denied = step.contains("Permission denied") || step.contains("Operation not permitted");
        let mounting = ["mounting", "binding", "masking", "remounting", "pivoting"]
            .iter()
            .any(|verb| step.starts_with(verb));
        if apparmor && denied && mounting {
            return Refusal::AppArmorRestricted;
        }
        return Refusal::Step(step.to_owned());
    }
    if host.max_user_namespaces.as_deref() == Some("0") {
        return Refusal::UserNamespacesDisabled;
    }
    // A container first: its sysctls are the host's, but its seccomp denial
    // is what refused, and no AppArmor profile lifts that.
    if host.in_container {
        return Refusal::Container;
    }
    if apparmor {
        return Refusal::AppArmorRestricted;
    }
    Refusal::Step(format!("starting the namespaces ({})", stderr.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What util-linux 2.41 prints on Ubuntu 25.10 with the `AppArmor`
    /// restriction on (seen on a build host).
    const UID_MAP_DENIED: &str =
        "unshare: write failed /proc/self/uid_map: Operation not permitted";

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
        let link =
            |at: &str, to: &str| std::os::unix::fs::symlink(to, root.join(at)).expect("link");
        link("same-dir", "real");
        link("chained", "same-dir");
        link("dangling", "missing");
        link("outside", "../out/hop");
        std::os::unix::fs::symlink("../root/real", out.join("hop")).expect("hop");
        let shown = |p: &Path| p.starts_with(&root);
        // Reached through a directory link the root does not show: kept, but
        // spelled through the real directory, which the root does show.
        std::os::unix::fs::symlink(&root, out.join("dir-link")).expect("dir link");
        assert_eq!(
            reachable_inside(&out.join("dir-link").join("same-dir"), &shown),
            Some(root.join("same-dir"))
        );
        for (name, kept) in [
            ("real", true),
            ("same-dir", true),
            ("chained", true),
            ("dangling", false),
            ("outside", false),
        ] {
            assert_eq!(
                reachable_inside(&root.join(name), &shown),
                kept.then(|| root.join(name)),
                "{name}"
            );
        }
    }

    /// The helper subcommands are recognised only as the first argument.
    #[test]
    fn dispatch_ignores_ordinary_commands() {
        let args: Vec<OsString> = ["mcp-gateway", "serve", SANDBOX].map(Into::into).into();
        assert!(dispatch(&args).is_none());
    }
}
