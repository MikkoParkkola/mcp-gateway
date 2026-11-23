// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Linux sandbox (ADR-027): util-linux `unshare` makes the namespaces, so
//! the gateway itself makes no namespace syscall, and the gateway's own binary
//! runs inside them as `__preview-sandbox` and `__preview-drop`.

mod ca_bundle;
mod control_client;
mod drop;
mod fetch_step;
mod fetch_uv;
mod helper;
mod launcher;
mod mounts;
pub(crate) mod plan;
mod probe;
mod relay;
pub(crate) mod seccomp;
mod uv_probe;

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
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

/// Start `target` inside a fresh namespace set and private root, once its
/// helper has reported its setup by `deadline`. A process not reaped in
/// time after a refusal is dropped, which kills it.
///
/// `protected` names the gateway's config paths beyond the ones the launcher
/// resolves itself (the data dir and the OS config dir's `mcp-gateway`).
pub(super) async fn start(
    helper: &Path,
    target: &Target,
    protected: &[PathBuf],
    deadline: tokio::time::Instant,
    runtime_dir: Option<OsString>,
) -> Result<Started, Refusal> {
    let ambient = Ambient {
        ca_bundle: None,
        runtime_dir,
        path: std::env::var_os("PATH"),
    };
    let mut prepared = launcher::prepare(target, protected, ambient, launcher::Phase::Run)?;
    launcher::launch_prepared(&mut prepared, helper, deadline)
        .await
        .map_err(|failed| failed.refusal)
}

/// Whether this host runs the sandbox: the real setup once with `/bin/true`.
/// Here alone the sandbox's stderr is read, from the handle the launch hands
/// back, when `unshare` ended before any status or the target failed after
/// one: `/bin/true` runs no package, so the text is `unshare`'s and the
/// helper's.
pub(super) async fn probe(helper: &Path) -> Result<(), Refusal> {
    let spawn = |unshare: &Path, plan: &plan::Plan| launch(unshare, helper, plan);
    probe_with(spawn, &HostFacts::read()).await
}

/// [`probe`] with the spawn and the host's facts given, so a row can stand a
/// fake launcher in for `unshare` and name the host.
async fn probe_with(
    spawn: impl FnOnce(&'static Path, &plan::Plan) -> Result<tokio::process::Child, Refusal>,
    host: &HostFacts,
) -> Result<(), Refusal> {
    let target = Target {
        program: PathBuf::from("/bin/true"),
        args: Vec::new(),
    };
    let deadline = tokio::time::Instant::now() + super::PROBE_DEADLINE;
    let ambient = Ambient {
        ca_bundle: None,
        runtime_dir: None,
        path: std::env::var_os("PATH"),
    };
    let answer = async {
        let mut prepared = launcher::prepare(&target, &[], ambient, launcher::Phase::Run)?;
        let unshare = prepared.unshare;
        let spawn = |plan: &plan::Plan| spawn(unshare, plan);
        let bounds = super::control::CONTROL_BOUNDS;
        let (launched, ending) =
            launcher::launch_with(&mut prepared, spawn, deadline, bounds, launcher::reap_exit)
                .await;
        match (launched, ending) {
            (Ok(Started { mut child, .. }), _) => {
                drop(child.stdin.take());
                let stderr = child.stderr.take();
                match child.wait().await {
                    Ok(status) if status.success() => Ok(()),
                    Ok(_) => Err(classify_with(&super::probe_stderr(stderr).await, host)),
                    Err(e) => Err(Refusal::Step(format!("waiting for the probe ({e})"))),
                }
            }
            (
                Err(_),
                Some(launcher::Ending {
                    how: launcher::How::EndedSilently,
                    stderr,
                }),
            ) => Err(classify_with(&super::probe_stderr(stderr).await, host)),
            (Err(failed), _) => Err(failed.refusal),
        }
    };
    // Dropping the child at the deadline kills `unshare` and the namespace.
    tokio::time::timeout_at(deadline, answer)
        .await
        .unwrap_or_else(|_| Err(super::probe_unanswered()))
}

fn find_unshare() -> Result<&'static Path, Refusal> {
    UNSHARE
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .ok_or(Refusal::MissingTool("util-linux unshare"))
}

/// Start `unshare` with the helper and its plan.
fn launch(unshare: &Path, helper: &Path, plan: &Plan) -> Result<tokio::process::Child, Refusal> {
    let encoded = serde_json::to_string(plan)
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
    command
        .spawn()
        .map_err(|e| Refusal::Step(format!("starting unshare ({e})")))
}

/// [`start`] after the fetch step's handshake (`preview_sandbox::start_fetching`):
/// the preview's own proxy and control socket, then the helper's session to
/// `expired`, raced against `unshare` exiting. Any refusal after the spawn
/// kills `unshare` (and with it the namespace) and reaps it before returning.
pub(super) async fn start_fetching(
    helper: &Path,
    target: &Target,
    protected: &[PathBuf],
    deadline: tokio::time::Instant,
    ca_bundle: Option<OsString>,
    runtime_dir: Option<OsString>,
) -> Result<Started, Refusal> {
    use super::proxy::System;
    use std::sync::Arc;
    uv_probe::staged_dark(target)?;
    let ambient = Ambient {
        ca_bundle,
        runtime_dir,
        path: std::env::var_os("PATH"),
    };
    start_fetching_with(
        helper,
        target,
        protected,
        deadline,
        ambient,
        Arc::new(System),
        Arc::new(System),
    )
    .await
}

/// What `start_fetching` reads from the gateway's environment, passed in so
/// the rows never change the process environment.
struct Ambient {
    ca_bundle: Option<OsString>,
    runtime_dir: Option<OsString>,
    path: Option<OsString>,
}

/// [`start_fetching`] with the proxy's resolver and dialer given: production
/// passes `System` for both; only the rows' `cfg(test)` fakes pass others.
async fn start_fetching_with(
    helper: &Path,
    target: &Target,
    protected: &[PathBuf],
    deadline: tokio::time::Instant,
    ambient: Ambient,
    resolve: std::sync::Arc<dyn super::proxy::Resolve>,
    connect: std::sync::Arc<dyn super::proxy::Connect>,
) -> Result<Started, Refusal> {
    let phase = launcher::Phase::Fetch { resolve, connect };
    let mut prepared = launcher::prepare(target, protected, ambient, phase)?;
    launcher::launch_prepared(&mut prepared, helper, deadline)
        .await
        .map_err(|failed| failed.refusal)
}

/// The npm fetch a target needs, or `None` when it names no package (the
/// handshake alone). npm and node are the ones beside the target's `npx`, its
/// version floor checked; `ip` and both must lie in the plan's bound trees,
/// where the root shows them at the same paths.
fn npm_fetch(
    target: &Target,
    plan: &mut Plan,
    path: Option<&OsStr>,
    proxy: &Path,
) -> Result<Option<plan::NpmFetch>, Refusal> {
    use super::fetch::Fetch;
    let phases = super::fetch::plan(target)?;
    let spec = match phases.fetch {
        // A uvx target is planned by `uv_probe::package_fetch`.
        None | Some(Fetch::Uv(_)) => return Ok(None),
        Some(Fetch::Npm(spec)) => spec,
    };
    let requested = target.program.to_str().unwrap_or("npx");
    let npx = resolve_command(requested, path, None)
        .map_err(|e| Refusal::Step(format!("finding {requested} ({e})")))?;
    let (npm, node_dir) = probe::npm_beside(&npx)?;
    probe::check_npm(&npm, &node_dir)?;
    let (npm, node_dir) = place_npm(plan, &npx, &npm, &node_dir.join("node"))?;
    let ip = probe::find_ip(&probe::IP_CANDIDATES, &|p: &Path| placed(p, plan))?;
    let run_args = phases
        .run_args
        .iter()
        .map(|a| a.to_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Refusal::Step("reading an argument (not UTF-8)".to_owned()))?;
    Ok(Some(plan::NpmFetch {
        spec,
        run_args,
        npm: utf8(&npm)?,
        node_dir: utf8(&node_dir)?,
        ip,
        proxy: utf8(proxy)?,
    }))
}

/// A step refusal with the time it came after the fetch step began.
fn with_elapsed(refusal: Refusal, begun: tokio::time::Instant) -> Refusal {
    match refusal {
        Refusal::Step(why) => Refusal::Step(format!(
            "{why} ({} ms into the fetch step)",
            begun.elapsed().as_millis()
        )),
        other => other,
    }
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
    let shown = |p: &Path| shown_inside(p, &read_only, &bound_back, &masked, &hidden);
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
        // Set by `launcher::prepare` once its socket is bound.
        control: String::new(),
        fetch: None,
        #[cfg(debug_assertions)]
        fault: None,
    })
}

/// Make npm and node shown inside the root and return the path npm is
/// executed by there and the directory that holds `node` there (for PATH);
/// refuses by name when either is not shown.
///
/// In every layout the root shows the fetch only node's real file and npm's
/// package (`.../node_modules/npm`, which holds npm's own modules), never
/// the trees around them: an npx preview's run phase executes downloaded
/// code, and a whole tree shows every globally installed package and the
/// tree's own config. What was bound for npx as the program goes first, as
/// the fetch never runs npx. Under the masked `/usr/local` the two are bound
/// back; in a known runtime tree (NVM) they are bound read-only; a system
/// root already shows them. Anywhere else, or under a masked secret path or
/// a hidden one, refuses by name. npm's builtin `npmrc` is covered by an
/// empty file either way.
fn place_npm(
    plan: &mut Plan,
    npx: &Path,
    npm: &Path,
    node: &Path,
) -> Result<(PathBuf, PathBuf), Refusal> {
    let real = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_owned());
    let (program_real, npm_real, node_real) = (real(npx), real(npm), real(node));
    if node_real.is_dir() {
        return Err(Refusal::Step(format!(
            "placing node ({} is a directory)",
            node.display()
        )));
    }
    // npx's program bind: bind-backs under /usr/local, its runtime tree, or
    // its lone real file.
    plan.bound_back.clear();
    let program_tree = runtime_tree(&program_real);
    plan.read_only
        .retain(|r| Path::new(r) != program_real && program_tree.as_deref() != Some(Path::new(r)));
    // npm's cli is `<package>/bin/npm-cli.js`.
    let package = npm_real
        .parent()
        .and_then(Path::parent)
        .filter(|p| p.ends_with("node_modules/npm"))
        .map(Path::to_path_buf);
    for (file, bind) in [
        (&node_real, Some(node_real.clone())),
        (&npm_real, package.clone()),
    ] {
        // What must be shown: node's file, npm's whole package (its cli
        // can be shown while npm's own modules are not).
        let Some(bind) = bind.filter(|b| !placed(b, plan)) else {
            continue;
        };
        match program_bind(file, &plan.read_only) {
            ProgramBind::UsrLocal(_) => plan.bound_back.push(utf8(&bind)?),
            ProgramBind::Runtime(_) => plan.read_only.push(utf8(&bind)?),
            // Outside the known trees a directory named `node_modules/npm`
            // proves nothing about what it holds: refused by name below.
            ProgramBind::File(_) | ProgramBind::System | ProgramBind::Refused => {}
        }
    }
    let npm_needs = package.as_deref().unwrap_or(&npm_real);
    for (what, file) in [("npm", npm_needs), ("node", node_real.as_path())] {
        if !placed(file, plan) {
            return Err(Refusal::Step(format!(
                "placing {what} ({} is not shown inside the root)",
                file.display()
            )));
        }
    }
    // npm's builtin config may hold a registry token someone stored there;
    // the pinned environment outranks it, and the downloaded code never
    // reads it: an empty file covers it, whatever npm's directory is called
    // (Debian's `/usr/share/nodejs/npm`). Covering only ever hides.
    if let Some(root) = npm_real.parent().and_then(Path::parent) {
        plan.masked.push(utf8(&root.join("npmrc"))?);
    }
    // The alias npx sat beside (`<bin>/npm`) may be hidden now; each literal
    // step it takes must be shown, as for the program.
    let shown = |p: &Path| {
        shown_inside(
            p,
            &plan.read_only,
            &plan.bound_back,
            &plan.masked,
            &plan.hidden,
        )
    };
    let exec = reachable_inside(npm, &shown).unwrap_or(npm_real);
    // `env node` searches PATH by name: the alias's own directory when the
    // root shows the alias, else the real file's, which only works when the
    // real file is itself called `node`.
    let node_dir = if reachable_inside(node, &shown).is_some() {
        node.parent()
    } else if node_real.file_name() == Some(std::ffi::OsStr::new("node")) {
        node_real.parent()
    } else {
        None
    };
    let node_dir = node_dir.ok_or_else(|| {
        Refusal::Step(format!(
            "placing node ({} is reached through a link the root does not show)",
            node.display()
        ))
    })?;
    Ok((exec, node_dir.to_path_buf()))
}

/// Whether `plan`'s root shows `file`, its links followed first.
fn placed(file: &Path, plan: &Plan) -> bool {
    let real = fs::canonicalize(file).unwrap_or_else(|_| file.to_owned());
    shown_inside(
        &real,
        &plan.read_only,
        &plan.bound_back,
        &plan.masked,
        &plan.hidden,
    )
}

/// Whether the new root shows `p`: a hidden path never, a bind-back always,
/// anything else when a read-only root holds it and no mask covers it.
fn shown_inside(
    p: &Path,
    read_only: &[String],
    bound_back: &[String],
    masked: &[String],
    hidden: &[String],
) -> bool {
    let under = |set: &[String]| set.iter().any(|r| p.starts_with(r));
    if under(hidden) {
        return false;
    }
    under(bound_back) || (under(read_only) && !under(masked))
}

/// `path` with its directory links resolved, if it and every link on its way
/// to a file are `shown` inside the root, so that spelling still leads to the
/// program there (a raw spelling through an unshown directory link would not).
/// The spelling is for the exec inside the root only, never on the host.
fn reachable_inside(path: &Path, shown: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    // Directory links resolved, so `..` and a linked parent cannot lead the
    // check somewhere the exec does not go.
    let resolve = |at: &Path| {
        at.parent()
            .and_then(|dir| fs::canonicalize(dir).ok())
            .zip(at.file_name())
            .map(|(dir, name)| dir.join(name))
    };
    let spelling = resolve(path)?;
    let mut here = spelling.clone();
    // The kernel's own symlink-hop ceiling.
    for _ in 0..40 {
        if !shown(&here) {
            return None;
        }
        match fs::read_link(&here) {
            Ok(next) => {
                // The kernel walks a link's target as written: a directory link
                // on that walk must exist inside too, which is only certain
                // when there is none. A target with no `.` or `..` that already
                // equals its resolved form has none; a `..` could cancel one in
                // the text, so any climb runs the real file instead.
                let climbs = next
                    .components()
                    .any(|c| matches!(c, Component::CurDir | Component::ParentDir));
                let target = here.parent().unwrap_or(Path::new("/")).join(next);
                here = resolve(&target)?;
                if climbs || target != here {
                    return None;
                }
            }
            Err(_) => return here.is_file().then_some(spelling),
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

    /// Whether this host's `AppArmor` restricts unprivileged user namespaces,
    /// the fact a reported mount denial is judged by.
    fn restricts_userns(&self) -> bool {
        self.apparmor_restricts_userns.as_deref() == Some("1")
    }
}

/// Name why `unshare` or the helper failed, from what it printed and the
/// host's own settings, so the refusal can say which one-time step fixes it.
/// Production reads this through the probe, which passes its facts; the
/// fetch rows name a helper's refusal with it.
#[cfg(test)]
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
mod elf_fixture;
#[cfg(test)]
mod fetch_pypi;
#[cfg(test)]
mod fetch_registry;
#[cfg(test)]
mod fetch_rows;
#[cfg(test)]
mod fetch_shim_rows;
#[cfg(test)]
mod fetch_uv_real_fixture;
#[cfg(test)]
mod fetch_uv_real_rows;
#[cfg(test)]
mod fetch_uv_rows;
// The rows plant the plan's fault, which only a debug build has.
#[cfg(all(test, debug_assertions))]
mod status_rows;
#[cfg(tp4)]
#[cfg(test)]
mod tests;
