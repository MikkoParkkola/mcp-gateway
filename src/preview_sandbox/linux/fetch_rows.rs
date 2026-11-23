// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The npm fetch through the real launcher, helper and proxy, against the
//! fake registry (L rows). The gateway binary the helper runs as is named by
//! `PREVIEW_SANDBOX_GATEWAY_BIN`; where `PREVIEW_SANDBOX_REQUIRED` is set, a
//! missing binary, npx or sandbox fails the row instead of skipping it.

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncReadExt as _;

use super::fetch_registry::{Package, Registry};
use super::{Ambient, start_fetching_with};
use crate::preview_sandbox::proxy::{Connect, Resolve};
use crate::preview_sandbox::{Refusal, Target};

/// The address the rows' resolver gives every registry name: public in form,
/// so every production address check runs on it; never dialled for real.
const SYNTHETIC: IpAddr = IpAddr::V4(Ipv4Addr::new(104, 16, 0, 10));
/// Hang guard for one preview, fetch and run together.
pub(super) const GUARD: Duration = Duration::from_secs(120);

/// Answers the three registry names with [`SYNTHETIC`], anything else fails.
pub(super) struct TestResolve;

#[async_trait]
impl Resolve for TestResolve {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        match host {
            "registry.npmjs.org" | "pypi.org" | "files.pythonhosted.org" => Ok(vec![SYNTHETIC]),
            _ => Err(std::io::Error::other("not a registry")),
        }
    }
}

/// After every check passed, sends [`SYNTHETIC`]:443 to the fake registry.
pub(super) struct TestDialer(pub(super) u16);

#[async_trait]
impl Connect for TestDialer {
    async fn connect(&self, addr: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
        if addr != SocketAddr::new(SYNTHETIC, 443) {
            return Err(std::io::Error::other(
                "the rows dial only the fake registry",
            ));
        }
        tokio::net::TcpStream::connect(("127.0.0.1", self.0)).await
    }
}

fn required() -> bool {
    std::env::var_os("PREVIEW_SANDBOX_REQUIRED").is_some()
}

/// `None` (skip) where this host cannot run the rows and they are not required.
fn skip(why: &str) -> Option<std::convert::Infallible> {
    assert!(!required(), "the fetch rows are required here but {why}");
    eprintln!("skipped: {why}");
    None
}

/// The gateway binary the helper runs as, or `None` to skip.
pub(super) fn gateway_bin() -> Option<PathBuf> {
    match std::env::var_os("PREVIEW_SANDBOX_GATEWAY_BIN") {
        Some(path) if PathBuf::from(&path).is_file() => Some(path.into()),
        _ => skip("PREVIEW_SANDBOX_GATEWAY_BIN names no gateway binary").map(|n| match n {}),
    }
}

/// The `npx` on this host's PATH, or `None` to skip.
fn host_npx() -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let found = std::env::split_paths(&path)
        .map(|d| d.join("npx"))
        .find(|p| p.is_file());
    found.or_else(|| skip("npx is not installed").map(|n| match n {}))
}

/// Whether this host runs the sandbox at all (the probe's `/bin/true`);
/// `false` (skip) where it refuses and the rows are not required.
pub(super) async fn sandbox_runs(gateway: &std::path::Path) -> bool {
    match super::probe(gateway).await {
        Ok(()) => true,
        Err(refusal) => skip(&format!("this host refuses the sandbox: {refusal}")).is_some(),
    }
}

/// A bin that reports what the run phase sees: the proxy socket, the marker
/// an install script would write, and its own arguments.
pub(super) const REPORT: &[u8] = b"#!/bin/sh\ntest -e /tmp/proxy.sock && echo sock-present\ntest -e /preview-home/script-marker && echo script-ran\necho bin-ran \"$@\"\n";

/// A package whose `bin` is `bins` (name to file), each file [`REPORT`].
pub(super) fn package(
    name: &'static str,
    bins: &[(&str, &'static str)],
    extra: serde_json::Value,
) -> Package {
    let mut manifest = extra;
    manifest["bin"] = bins
        .iter()
        .map(|(n, f)| ((*n).to_owned(), serde_json::Value::from(*f)))
        .collect::<serde_json::Map<_, _>>()
        .into();
    Package {
        name,
        version: "1.0.0",
        manifest,
        files: bins
            .iter()
            .map(|(_, f)| (*f, REPORT.to_vec(), 0o755))
            .collect(),
    }
}

/// Which CA the fetch's bundle holds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Bundle {
    /// The registry's own CA: the fetch trusts it.
    Registry,
    /// An unrelated test CA: the registry's certificate is untrusted.
    Other,
}

/// `npx spec args` through the fetch step against `packages`: the refusal,
/// or the run's stdout; `None` where the host cannot run the rows.
async fn npx(
    spec: &str,
    args: &[&str],
    packages: Vec<Package>,
    bundle: Bundle,
) -> Option<Result<String, Refusal>> {
    let gateway = gateway_bin()?;
    host_npx()?;
    if !sandbox_runs(&gateway).await {
        return None;
    }
    let registry = Registry::start(packages, "fetch rows CA").await;
    let ca = match bundle {
        Bundle::Registry => registry.ca_pem.clone(),
        Bundle::Other => crate::test_fixture_host::test_pki("registry.npmjs.org", "unrelated CA")
            .ca
            .pem(),
    };
    let args = std::iter::once(spec).chain(args.iter().copied());
    let target = Target {
        program: PathBuf::from("npx"),
        args: args.map(OsString::from).collect(),
    };
    let path = std::env::var_os("PATH");
    Some(preview(&gateway, &target, &ca, registry.port, path, GUARD).await)
}

/// `target` through the fetch step with `ca` as the bundle, the dialer sending
/// the registry to `port` and `path` as the gateway's PATH, its deadline
/// `limit` away: the start's refusal, or the run's stdout. A helper refusing
/// after the start panics instead (NPM.8).
pub(super) async fn preview(
    gateway: &std::path::Path,
    target: &Target,
    ca: &str,
    port: u16,
    path: Option<OsString>,
    limit: Duration,
) -> Result<String, Refusal> {
    let dir = tempfile::tempdir().expect("dir");
    let bundle_path = dir.path().join("bundle.pem");
    std::fs::write(&bundle_path, ca).expect("bundle");
    let ambient = Ambient {
        ca_bundle: Some(bundle_path.into_os_string()),
        runtime_dir: None,
        path,
    };
    let deadline = tokio::time::Instant::now() + limit;
    let mut started = tokio::time::timeout(
        GUARD,
        start_fetching_with(
            gateway,
            target,
            &[],
            deadline,
            ambient,
            Arc::new(TestResolve),
            Arc::new(TestDialer(port)),
        ),
    )
    .await
    .expect("the fetch preview ended within the guard")?;
    drop(started.child.stdin.take());
    let mut out = String::new();
    let mut stdout = started.child.stdout.take().expect("stdout");
    tokio::time::timeout(GUARD, stdout.read_to_string(&mut out))
        .await
        .expect("the run ended within the guard")
        .expect("stdout");
    let mut err = String::new();
    let mut stderr = started.child.stderr.take().expect("stderr");
    tokio::time::timeout(GUARD, stderr.read_to_string(&mut err))
        .await
        .expect("the run's stderr ended within the guard")
        .expect("stderr");
    let status = started.child.wait().await.expect("the run's status");
    // A failed fetch is never a start (NPM.8): every row here expects either
    // the start's own refusal or a run, so a helper that refuses after the
    // start fails the row, naming the step it refused at.
    assert_ne!(
        status.code(),
        Some(i32::from(super::REFUSED)),
        "the preview started, then the helper refused: {}",
        super::classify(&err)
    );
    Ok(out)
}

/// Whether `refusal` is the fetch refused at `step`; the launcher appends how
/// long into the fetch step it came, which the rows do not pin.
pub(super) fn at_step(refusal: &Refusal, step: &str) -> bool {
    matches!(refusal, Refusal::Step(text) if text == step || text.starts_with(&format!("{step} (")))
}

pub(super) fn lines(out: &str) -> Vec<&str> {
    out.lines().map(str::trim_end).collect()
}

/// L7: a cold npx fetch from the fake registry installs the package and the
/// run is its own bin with the server's arguments; the run sees no proxy
/// socket (L-proxy: unmounted and removed before the run).
#[cfg(tp4)]
#[tokio::test]
async fn l7_a_cold_npx_fetch_runs_the_packages_bin() {
    let fake = package(
        "mcp-fake",
        &[("mcp-fake", "bin/cli.sh")],
        serde_json::json!({}),
    );
    let Some(ran) = npx("mcp-fake", &["--flag"], vec![fake], Bundle::Registry).await else {
        return;
    };
    let out = ran.expect("the fetch and the run succeeded");
    assert_eq!(lines(&out), ["bin-ran --flag"], "{out}");
}

/// L7s: a scoped, version-pinned spec installs and runs the bin named after
/// the package, of the two it ships.
#[cfg(tp4)]
#[tokio::test]
async fn l7s_a_scoped_pinned_spec_runs_the_bin_named_after_it() {
    let fake = package(
        "@s/pkg",
        &[("pkg", "bin/cli.sh"), ("other", "bin/o.sh")],
        serde_json::json!({}),
    );
    let Some(ran) = npx("@s/pkg@1.0.0", &[], vec![fake], Bundle::Registry).await else {
        return;
    };
    let out = ran.expect("the fetch and the run succeeded");
    assert_eq!(lines(&out), ["bin-ran"], "{out}");
}

/// L3: no install script runs: every lifecycle script would write the
/// marker the run phase looks for, and the run finds none.
#[cfg(tp4)]
#[tokio::test]
async fn l3_install_scripts_never_run() {
    let mark = "touch /preview-home/script-marker";
    let scripts = serde_json::json!({"scripts": {"preinstall": mark, "install": mark, "postinstall": mark, "prepare": mark}});
    let fake = package("mcp-scripted", &[("mcp-scripted", "bin/cli.sh")], scripts);
    let Some(ran) = npx("mcp-scripted", &[], vec![fake], Bundle::Registry).await else {
        return;
    };
    let out = ran.expect("the fetch and the run succeeded");
    assert_eq!(lines(&out), ["bin-ran"], "{out}");
}

/// L4a: a git dependency refuses the fetch: npm cannot run git
/// (`npm_config_git` names a path that does not exist), and the refusal is
/// npm's own line.
#[cfg(tp4)]
#[tokio::test]
async fn l4a_a_git_dependency_refuses_the_fetch() {
    let deps =
        serde_json::json!({"dependencies": {"from-git": "git+https://example.invalid/x.git"}});
    let fake = package("mcp-gitdep", &[("mcp-gitdep", "bin/cli.sh")], deps);
    let Some(ran) = npx("mcp-gitdep", &[], vec![fake], Bundle::Registry).await else {
        return;
    };
    let refusal = ran.expect_err("a git dependency was installed");
    // npm fails the git edge itself, or the lock check refuses it.
    assert!(
        at_step(&refusal, "the fetch's npm install") || at_step(&refusal, "the fetch's lock check"),
        "{refusal:?}"
    );
}

/// L-tls1: a registry certificate from a CA outside the fetch's bundle is
/// refused (npm's cafile replaces node's roots, strict TLS).
#[cfg(tp4)]
#[tokio::test]
async fn l_tls1_a_registry_outside_the_bundle_is_refused() {
    let fake = package(
        "mcp-fake",
        &[("mcp-fake", "bin/cli.sh")],
        serde_json::json!({}),
    );
    let Some(ran) = npx("mcp-fake", &[], vec![fake], Bundle::Other).await else {
        return;
    };
    ran.expect_err("an untrusted registry was used");
}

/// A writable copy of the host's npm and node in an NVM-shaped tree: the
/// scratch dir and the tree (`bin/node`, `bin/npm`, `bin/npx`, npm's package
/// under `lib/node_modules/npm` without its builtin `npmrc`, an empty `etc`).
fn nvm_copy(npx: &std::path::Path, version: &str) -> (tempfile::TempDir, PathBuf) {
    let npx_real = std::fs::canonicalize(npx).expect("npx's real file");
    let npm_root = npx_real.ancestors().nth(2).expect("npm's package dir");
    let node = std::fs::canonicalize(npx.with_file_name("node")).expect("node beside npx");
    let scratch = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("scratch");
    let tree = scratch.path().join(".nvm/versions/node").join(version);
    let modules = tree.join("lib/node_modules");
    for dir in [tree.join("bin"), tree.join("etc"), modules.clone()] {
        std::fs::create_dir_all(dir).expect("tree");
    }
    // npm's builtin `npmrc` stays behind: L-npmrc plants a token in the host's
    // and removes it again, so it can vanish mid-copy, and no row here wants
    // the host's (L-tls2 writes its own).
    let npm_dir = modules.join("npm");
    std::fs::create_dir_all(&npm_dir).expect("npm's package dir");
    for entry in std::fs::read_dir(npm_root).expect("npm's package dir") {
        let entry = entry.expect("npm's entry");
        if entry.file_name() == "npmrc" {
            continue;
        }
        let copied = std::process::Command::new("cp")
            .arg("-R")
            .arg(entry.path())
            .arg(&npm_dir)
            .status()
            .expect("cp");
        assert!(copied.success(), "copying npm's {:?}", entry.file_name());
    }
    std::fs::copy(&node, tree.join("bin/node")).expect("copying node");
    for tool in ["npm", "npx"] {
        let cli = format!("../lib/node_modules/npm/bin/{tool}-cli.js");
        std::os::unix::fs::symlink(cli, tree.join("bin").join(tool)).expect("link");
    }
    (scratch, tree)
}

/// [`nvm_copy`] with both npmrc files npm reads from its own install
/// (builtin and global) turning TLS off and trusting `hostile_ca`; returns
/// the scratch dir and `bin`.
fn hostile_npm(npx: &std::path::Path, hostile_ca: &str) -> (tempfile::TempDir, PathBuf) {
    let (scratch, tree) = nvm_copy(npx, "v0.0.0-hostile");
    let ca = tree.join("hostile-ca.pem");
    std::fs::write(&ca, hostile_ca).expect("hostile CA");
    let rc = format!("strict-ssl=false\ncafile={}\n", ca.display());
    std::fs::write(tree.join("lib/node_modules/npm/npmrc"), &rc).expect("builtin npmrc");
    std::fs::write(tree.join("etc/npmrc"), &rc).expect("global npmrc");
    (scratch, tree.join("bin"))
}

/// L-tls2: npm's own npmrc files turn TLS off and trust the registry's CA,
/// which the bundle lacks; the fetch still refuses. Kills m-cafile through
/// its positive control (the same copied npm fetches when the bundle holds
/// the registry's CA). The strict-ssl, globalconfig and userconfig pins rest
/// on R-env: npm's builtin npmrc is covered by an empty file and the tree's
/// `etc/npmrc` is not in the root, so no file here can undo them.
#[cfg(tp4)]
#[tokio::test]
async fn l_tls2_a_hostile_npmrc_in_the_npm_tree_changes_nothing() {
    let Some(gateway) = gateway_bin() else {
        return;
    };
    let Some(npx) = host_npx() else {
        return;
    };
    if !sandbox_runs(&gateway).await {
        return;
    }
    let fake = package(
        "mcp-fake",
        &[("mcp-fake", "bin/cli.sh")],
        serde_json::json!({}),
    );
    let registry = Registry::start(vec![fake], "fetch rows CA").await;
    let (_scratch, bin) = hostile_npm(&npx, &registry.ca_pem);
    let mut path = OsString::from(&bin);
    path.push(":/usr/bin:/bin");
    let target = Target {
        program: PathBuf::from("npx"),
        args: vec![OsString::from("mcp-fake")],
    };
    let port = registry.port;
    let trusted = preview(
        &gateway,
        &target,
        &registry.ca_pem,
        port,
        Some(path.clone()),
        GUARD,
    )
    .await;
    let out = trusted.expect("the copied npm fetched with the registry's CA in the bundle");
    assert_eq!(lines(&out), ["bin-ran"], "{out}");
    let other = crate::test_fixture_host::test_pki("registry.npmjs.org", "unrelated CA")
        .ca
        .pem();
    preview(&gateway, &target, &other, port, Some(path), GUARD)
        .await
        .expect_err("npm's own npmrc turned TLS off or trusted another CA");
}

/// The package whose bin runs [`CANARY_BIN`].
fn canary_package() -> Package {
    Package {
        name: "mcp-canary",
        version: "1.0.0",
        manifest: serde_json::json!({"bin": {"mcp-canary": "bin/cli.sh"}}),
        files: vec![("bin/cli.sh", CANARY_BIN.to_vec(), 0o755)],
    }
}

/// The canary package's bin: names each argument it can read content from,
/// then shows node runs in the run phase.
const CANARY_BIN: &[u8] =
    b"#!/bin/sh\nfor f in \"$@\"; do test -s \"$f\" && echo \"readable $f\"; done\nnode -e 'console.log(\"node-ran\")'\necho bin-ran\n";

/// npm's package directory when npx is a `/usr/local` install, else `None`
/// (skip).
fn usr_local_npm() -> Option<PathBuf> {
    let npx = host_npx()?;
    let real = std::fs::canonicalize(&npx).expect("npx's real file");
    let package = real
        .ancestors()
        .nth(2)
        .filter(|p| p.starts_with("/usr/local") && p.ends_with("node_modules/npm"));
    match package {
        Some(package) => Some(package.to_owned()),
        None => skip("npm is not a /usr/local install").map(|n| match n {}),
    }
}

/// `npx mcp-canary <paths>`: the run's stdout lines; `None` to skip.
async fn canary_run(paths: &[&PathBuf]) -> Option<Vec<String>> {
    let fake = canary_package();
    let args: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let ran = npx("mcp-canary", &args, vec![fake], Bundle::Registry).await?;
    let out = ran.expect("the fetch and the run succeeded");
    Some(lines(&out).into_iter().map(str::to_owned).collect())
}

/// L-canary, kills "the fetch binds the /usr/local trees whole": on a
/// `/usr/local` node (the hosted runner's), what already sits beside node in
/// `/usr/local/bin` and beside npm in `/usr/local/lib/node_modules` is not
/// readable by the fetched package's run phase, while node itself runs
/// there. Nothing is written under `/usr/local`: the row reads what is there.
#[cfg(tp4)]
#[tokio::test]
async fn l_canary_a_usr_local_install_shows_the_package_only_node_and_npm() {
    if usr_local_npm().is_none() {
        return;
    }
    // One canary from EACH tree, so a whole-tree bind of either one is
    // probed: a regular file with content, never a symlink (which could
    // point out of the tree), other than what the fetch shows (node and npm,
    // and npm's aliases beside node). In lib/node_modules the entries are
    // package directories, so the canary is another package's package.json.
    let regular = |p: &std::path::Path| {
        std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file() && m.len() > 0)
    };
    let sorted = |dir: &str, shown: &[&str]| {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| !shown.iter().any(|s| e.file_name() == *s))
            .map(|e| e.path())
            .collect();
        entries.sort();
        entries
    };
    let in_bin = sorted("/usr/local/bin", &["node", "npm", "npx"])
        .into_iter()
        .find(|p| regular(p));
    let in_modules = sorted("/usr/local/lib/node_modules", &["npm"])
        .into_iter()
        .filter(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_dir()))
        .map(|p| p.join("package.json"))
        .find(|p| regular(p));
    let (Some(in_bin), Some(in_modules)) = (in_bin, in_modules) else {
        let _ = skip("no in-tree regular file beside node, or beside npm, under /usr/local");
        return;
    };
    let canaries = [in_bin, in_modules];
    let Some(seen) = canary_run(&canaries.iter().collect::<Vec<_>>()).await else {
        return;
    };
    assert_eq!(seen, ["node-ran", "bin-ran"], "{canaries:?}");
}

/// L-npmrc, kills npmrc-unmasked: a registry token in npm's builtin `npmrc`
/// cannot be read by the fetched package (an empty file covers it in the
/// root, whatever npm's layout), and the fetch still works. The token goes
/// into a copy of the host's npm under the row's own temp dir, never into
/// the host's npm, which other processes may read meanwhile.
#[cfg(tp4)]
#[tokio::test]
async fn l_npmrc_a_token_in_npms_builtin_npmrc_stays_unreadable() {
    let Some(gateway) = gateway_bin() else {
        return;
    };
    let Some(npx) = host_npx() else {
        return;
    };
    if !sandbox_runs(&gateway).await {
        return;
    }
    let (_scratch, tree) = nvm_copy(&npx, "v0.0.0-npmrc");
    let npmrc = tree.join("lib/node_modules/npm/npmrc");
    std::fs::write(
        &npmrc,
        b"//registry.npmjs.org/:_authToken=preview-canary-token\n",
    )
    .expect("builtin npmrc");
    let out = canary_run_in(&gateway, &tree, &[npmrc]).await;
    assert_eq!(lines(&out), ["node-ran", "bin-ran"], "{out}");
}

/// L-nvm, kills "a runtime tree is bound whole" end to
/// end: a copy of the host's npm and node in an NVM-shaped tree fetches and
/// runs the package from the two narrow binds alone (npm fetched it, node
/// runs in the run phase), while a token in the tree's `etc/npmrc` and a
/// planted global package's config stay unreadable to the package.
#[cfg(tp4)]
#[tokio::test]
async fn l_nvm_npm_and_node_run_from_the_two_narrow_binds() {
    let Some(gateway) = gateway_bin() else {
        return;
    };
    let Some(npx) = host_npx() else {
        return;
    };
    if !sandbox_runs(&gateway).await {
        return;
    }
    let (_scratch, tree) = nvm_copy(&npx, "v0.0.0-narrow");
    let global = tree.join("lib/node_modules/preview-canary");
    std::fs::create_dir_all(&global).expect("global package");
    let canaries = [tree.join("etc/npmrc"), global.join("config")];
    for canary in &canaries {
        std::fs::write(
            canary,
            b"//registry.npmjs.org/:_authToken=preview-canary-token\n",
        )
        .expect("canary");
    }
    let out = canary_run_in(&gateway, &tree, &canaries).await;
    assert_eq!(lines(&out), ["node-ran", "bin-ran"], "{out}");
}

/// `npx mcp-canary <canaries>` with the copied `tree`'s `bin` first on PATH:
/// the run's stdout.
async fn canary_run_in(
    gateway: &std::path::Path,
    tree: &std::path::Path,
    canaries: &[PathBuf],
) -> String {
    let registry = Registry::start(vec![canary_package()], "fetch rows CA").await;
    let mut path = OsString::from(tree.join("bin"));
    path.push(":/usr/bin:/bin");
    let target = Target {
        program: PathBuf::from("npx"),
        args: std::iter::once("mcp-canary".into())
            .chain(canaries.iter().map(|c| c.clone().into_os_string()))
            .collect(),
    };
    let ran = preview(
        gateway,
        &target,
        &registry.ca_pem,
        registry.port,
        Some(path),
        GUARD,
    )
    .await;
    ran.expect("the copied npm fetched and node ran")
}

/// `ESRCH`: reading an exiting task's `/proc` file fails with this.
const ESRCH: i32 = 3;

/// True when a failed `/proc/<pid>/stat` read tells us nothing: any error but
/// a missing file or ESRCH, both of which mean the process is gone or going.
fn says_nothing(e: &std::io::Error) -> bool {
    e.kind() != std::io::ErrorKind::NotFound && e.raw_os_error() != Some(ESRCH)
}

/// True when a `/proc/<pid>/stat` state field means the process is dead:
/// zombie (`Z`) or dead (`X`, or `x` on older kernels).
fn dead_state(state: Option<&str>) -> bool {
    matches!(state, Some("Z" | "X" | "x"))
}

/// The scan's read rule as a table: out of descriptors keeps a process live,
/// a missing file or ESRCH counts it gone; each dead state counts it gone.
#[cfg(tp4)]
#[test]
fn a_failed_stat_read_keeps_a_process_live_unless_it_is_missing_or_exiting() {
    use std::io::{Error, ErrorKind};
    assert!(says_nothing(&Error::from_raw_os_error(24)), "EMFILE");
    assert!(says_nothing(&Error::from_raw_os_error(5)), "EIO");
    assert!(!says_nothing(&Error::from_raw_os_error(2)), "ENOENT");
    assert!(!says_nothing(&Error::from(ErrorKind::NotFound)), "NotFound");
    assert!(!says_nothing(&Error::from_raw_os_error(ESRCH)), "ESRCH");
    for state in ["Z", "X", "x"] {
        assert!(dead_state(Some(state)), "state {state} reads as dead");
    }
    for state in ["R", "S", "D"] {
        assert!(!dead_state(Some(state)), "state {state} reads as live");
    }
}

/// Every live process whose command line carries `marker` (the `unshare`, the
/// helper and a target all carry the target's arguments).
pub(super) fn marked(marker: &str) -> Vec<u32> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").expect("/proc").flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let read = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        // Only a missing file or ESRCH (an exiting task) means gone; a read
        // failing for another reason says nothing, so the process counts as
        // live, and the caller's wait goes on.
        let unread = read.as_ref().is_err_and(says_nothing);
        let stat = read.unwrap_or_default();
        let state = stat
            .rsplit_once(") ")
            .and_then(|(_, rest)| rest.split_whitespace().next());
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let live = unread || (state.is_some() && !dead_state(state));
        if live && String::from_utf8_lossy(&cmdline).contains(marker) {
            found.push(pid);
        }
    }
    found
}

/// Why a start ended before its fetch reached the registry: its refusal, or
/// what the helper wrote to stderr once the started sandbox ended.
async fn why_ended(ended: Result<crate::preview_sandbox::Started, Refusal>) -> String {
    let mut started = match ended {
        Err(refusal) => return format!("{refusal:?}"),
        Ok(started) => started,
    };
    let mut err = String::new();
    if let Some(mut stderr) = started.child.stderr.take() {
        let _ = tokio::time::timeout(GUARD, stderr.read_to_string(&mut err)).await;
    }
    format!("started, then the helper wrote: {err}")
}

/// NPM.7 (the design's R6b, after the credential), kills "a start dropped
/// mid-fetch leaves the fetch running": the start is dropped once the fake
/// registry has read the fetch's first request (the credential was issued and
/// used). Every process carrying the target's marker ends within the guard,
/// the proxy that held the credential is gone with its directory, and no
/// connection to the registry stays open, so nothing of the fetch can reach it.
#[cfg(tp4)]
#[tokio::test]
async fn l6b_a_start_dropped_mid_fetch_leaves_nothing_running() {
    const MARKER: &str = "l6b-marker-5c1e";
    let Some(gateway) = gateway_bin() else {
        return;
    };
    if host_npx().is_none() || !sandbox_runs(&gateway).await {
        return;
    }
    let fake = package(
        "mcp-dropped",
        &[("mcp-dropped", "bin/cli.sh")],
        serde_json::json!({}),
    );
    let registry = Registry::start(vec![fake], "dropped start CA").await;
    let dir = tempfile::tempdir().expect("dir");
    let bundle = dir.path().join("bundle.pem");
    std::fs::write(&bundle, &registry.ca_pem).expect("bundle");
    let runtime = tempfile::tempdir().expect("runtime dir");
    let ambient = Ambient {
        ca_bundle: Some(bundle.into_os_string()),
        runtime_dir: Some(runtime.path().as_os_str().to_owned()),
        path: std::env::var_os("PATH"),
    };
    let target = Target {
        program: PathBuf::from("npx"),
        args: vec!["mcp-dropped".into(), MARKER.into()],
    };
    let mut start = Box::pin(start_fetching_with(
        &gateway,
        &target,
        &[],
        tokio::time::Instant::now() + GUARD,
        ambient,
        Arc::new(TestResolve),
        Arc::new(TestDialer(registry.port)),
    ));
    let ended = tokio::select! {
        ended = &mut start => Some(ended),
        () = registry.first_request() => None,
        () = tokio::time::sleep(GUARD) => panic!("the registry was not asked within the guard"),
    };
    if let Some(ended) = ended {
        panic!(
            "the start ended before the registry was asked: {}",
            why_ended(ended).await
        );
    }
    drop(start);
    let empty = std::fs::read_dir(runtime.path())
        .expect("runtime dir")
        .count();
    assert_eq!(empty, 0, "the proxy's directory outlived the dropped start");
    let ended = async {
        while !marked(MARKER).is_empty() || registry.open_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    tokio::time::timeout(GUARD, ended)
        .await
        .expect("the sandbox and every registry connection ended within the guard");
}

/// RF6 (NPM.8), kills "a failed npm install reports Started": the fake
/// registry lacks the package, so the start itself refuses at the npm
/// install, and nothing carrying the target's marker is left running.
#[cfg(tp4)]
#[tokio::test]
async fn rf6_a_failed_npm_install_never_reports_started() {
    const MARKER: &str = "rf6-marker-77aa";
    let Some(ran) = npx("mcp-missing", &[MARKER], Vec::new(), Bundle::Registry).await else {
        return;
    };
    let refusal = ran.expect_err("a missing package started");
    assert!(at_step(&refusal, "the fetch's npm install"), "{refusal:?}");
    let ended = async {
        while !marked(MARKER).is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    tokio::time::timeout(GUARD, ended)
        .await
        .expect("the sandbox ended within the guard");
}
