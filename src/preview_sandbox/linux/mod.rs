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

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};

use plan::{HostNamespaces, Plan};

use super::{Refusal, Started, Target};

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
        DROP => Some(match (decode(args.get(2)), args.get(3)) {
            (Ok(limits), Some(dashes)) if dashes == "--" => drop::run(limits, &args[4..]),
            (Err(e), _) => refuse(&e),
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
    let plan = build_plan(target, protected)?;
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
fn build_plan(target: &Target, protected: &[PathBuf]) -> Result<Plan, Refusal> {
    let program = resolve(&target.program)?;
    let mut read_only: Vec<String> = READ_ONLY.iter().map(ToString::to_string).collect();
    read_only.extend(top_level_libs());
    let masked: Vec<String> = MASKED.iter().map(ToString::to_string).collect();
    let mut hidden = Vec::new();
    let mut bound_back = Vec::new();
    let homes = home_roots();
    // The run phase's PATH: the interpreter's directories, then the system's.
    let mut path_dirs = Vec::new();
    for dir in interpreter_dirs(&program) {
        let dir = utf8(&dir)?;
        let under = |prefixes: &[String]| prefixes.iter().any(|p| Path::new(&dir).starts_with(p));
        if Path::new(&dir).starts_with(mounts::STAGE) {
            return Err(Refusal::Step(format!(
                "placing {dir} (a program under /tmp cannot be bound)"
            )));
        }
        if let Some(home) = covered_home(Path::new(&dir), &homes) {
            return Err(Refusal::Step(format!(
                "placing {dir} (binding it would expose {})",
                home.display()
            )));
        }
        let masked_system: Vec<String> = MASKED.iter().map(ToString::to_string).collect();
        if under(&masked_system) {
            bound_back.push(dir.clone());
        } else if !under(&read_only) {
            read_only.push(dir.clone());
        }
        if !dir.ends_with("/lib") {
            path_dirs.push(dir);
        }
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

    let mut argv = vec![utf8(&program)?];
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
        target: argv,
    })
}

/// An absolute program as given, or the first match on the gateway's `PATH`.
fn resolve(program: &Path) -> Result<PathBuf, Refusal> {
    let not_found = || Refusal::Step(format!("finding {}", program.display()));
    if program.is_absolute() {
        return program
            .is_file()
            .then(|| program.to_owned())
            .ok_or_else(not_found);
    }
    // A bare name only, as the capability executor's resolver takes: `./tool`
    // and `bin/tool` name the gateway's working directory, which the preview
    // never sees, and so does a match through a relative PATH entry.
    if program.components().count() != 1 {
        return Err(Refusal::Step(format!(
            "finding {} (a bare name or an absolute path)",
            program.display()
        )));
    }
    let path = std::env::var_os("PATH").ok_or_else(not_found)?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_absolute() && candidate.is_file())
        .ok_or_else(not_found)
}

/// The program's directory, its target's directory when it is a link, and a
/// sibling `lib` of each.
///
/// ponytail: `../lib` stands in for the interpreter's real library list; read
/// its ELF needs (or the interpreter's own prefix layout) if a runtime needs a
/// library from anywhere else.
fn interpreter_dirs(program: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let real = fs::canonicalize(program).unwrap_or_else(|_| program.to_owned());
    for file in [program, real.as_path()] {
        let Some(dir) = file.parent() else { continue };
        for candidate in [dir.to_owned(), dir.join("../lib")] {
            let Ok(candidate) = fs::canonicalize(&candidate) else {
                continue;
            };
            if !dirs.contains(&candidate) {
                dirs.push(candidate);
            }
        }
    }
    dirs
}

/// Where homes live: the system's home roots, every user's home directly
/// under `/home` (another user's, not only the gateway user's), and the
/// gateway user's own wherever it is. Each is canonical, so a symlinked home
/// is found at its real path.
///
/// Not `/etc/passwd`: service accounts name system directories as their home
/// (Debian's `sync` has `/bin`), which would forbid binding `/bin` itself.
fn home_roots() -> Vec<PathBuf> {
    let mut homes = vec![PathBuf::from("/home"), PathBuf::from("/root")];
    if let Ok(entries) = fs::read_dir("/home") {
        homes.extend(
            entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .map(|p| fs::canonicalize(&p).unwrap_or(p)),
        );
    }
    if let Some(home) = crate::home_dir::home_dir() {
        homes.push(fs::canonicalize(&home).unwrap_or(home));
    }
    homes
}

/// The home that binding `dir` would expose: `dir` is `/`, a home, or an
/// ancestor of one. An interpreter's own directory inside a home (an NVM
/// `bin`) is fine; the home around it is not.
fn covered_home<'a>(dir: &Path, homes: &'a [PathBuf]) -> Option<&'a Path> {
    homes
        .iter()
        .map(PathBuf::as_path)
        .find(|home| home.starts_with(dir))
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

    /// An Ubuntu 24.04 container reports the host's AppArmor sysctl; the fix
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

    #[test]
    fn a_directory_that_holds_a_home_is_never_bound() {
        let homes = [PathBuf::from("/home"), PathBuf::from("/srv/users/ann")];
        for dir in ["/", "/home", "/srv", "/srv/users", "/srv/users/ann"] {
            assert!(covered_home(Path::new(dir), &homes).is_some(), "{dir}");
        }
        // Another user's home is a home too, once it is listed.
        let with_alice = [PathBuf::from("/home"), PathBuf::from("/home/alice")];
        assert!(covered_home(Path::new("/home/alice"), &with_alice).is_some());
        // An interpreter directory inside a home, or beside one, is fine.
        for dir in [
            "/srv/users/ann/.nvm/versions/node/v22/bin",
            "/usr/bin",
            "/opt/node/bin",
        ] {
            assert!(covered_home(Path::new(dir), &homes).is_none(), "{dir}");
        }
    }

    /// Every user's home under `/home` is a home root, not only the gateway
    /// user's, so none of them can be bound whole.
    #[test]
    fn every_home_under_slash_home_is_a_home_root() {
        let roots = home_roots();
        for entry in fs::read_dir("/home")
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
        {
            let home = fs::canonicalize(entry.path()).unwrap_or_else(|_| entry.path());
            assert!(roots.contains(&home), "{} is missing", home.display());
            assert!(covered_home(&home, &roots).is_some(), "{}", home.display());
        }
    }

    #[test]
    fn a_relative_program_is_refused() {
        for program in ["./sh", "bin/sh", "../sh"] {
            assert!(
                matches!(resolve(Path::new(program)), Err(Refusal::Step(s)) if s.contains("bare name")),
                "{program}"
            );
        }
    }

    #[test]
    fn a_bare_name_resolves_to_an_absolute_path() {
        let found = resolve(Path::new("sh")).expect("sh on PATH");
        assert!(
            found.is_absolute() && found.is_file(),
            "{}",
            found.display()
        );
    }

    /// The helper subcommands are recognised only as the first argument.
    #[test]
    fn dispatch_ignores_ordinary_commands() {
        let args: Vec<OsString> = ["mcp-gateway", "serve", SANDBOX].map(Into::into).into();
        assert!(dispatch(&args).is_none());
    }
}
