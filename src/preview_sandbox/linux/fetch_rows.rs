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
struct TestResolve;

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
struct TestDialer(u16);

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

/// Whether this host runs the sandbox at all (a plain `/bin/true` preview);
/// `false` (skip) where it refuses and the rows are not required.
pub(super) async fn sandbox_runs(gateway: &std::path::Path) -> bool {
    let target = Target {
        program: PathBuf::from("/bin/true"),
        args: Vec::new(),
    };
    match super::start(gateway, &target, &[]) {
        Ok(mut started) => {
            let _ = started.child.wait().await;
            true
        }
        Err(refusal) => skip(&format!("this host refuses the sandbox: {refusal}")).is_some(),
    }
}

/// A bin that reports what the run phase sees: the proxy socket, the marker
/// an install script would write, and its own arguments.
pub(super) const REPORT: &[u8] = b"#!/bin/sh\ntest -e /tmp/proxy.sock && echo sock-present\ntest -e /preview-home/script-marker && echo script-ran\necho bin-ran \"$@\"\n";

/// A package whose `bin` is `bins` (name to file), each file [`REPORT`].
fn package(name: &'static str, bins: &[(&str, &'static str)], extra: serde_json::Value) -> Package {
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
enum Bundle {
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
/// `limit` away: the refusal, or the run's stdout.
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
    let _ = started.child.wait().await;
    Ok(out)
}

pub(super) fn lines(out: &str) -> Vec<&str> {
    out.lines().map(str::trim_end).collect()
}

/// L7: a cold npx fetch from the fake registry installs the package and the
/// run is its own bin with the server's arguments; the run sees no proxy
/// socket (L-proxy: unmounted and removed before the run).
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
#[tokio::test]
async fn l4a_a_git_dependency_refuses_the_fetch() {
    let deps =
        serde_json::json!({"dependencies": {"from-git": "git+https://example.invalid/x.git"}});
    let fake = package("mcp-gitdep", &[("mcp-gitdep", "bin/cli.sh")], deps);
    let Some(ran) = npx("mcp-gitdep", &[], vec![fake], Bundle::Registry).await else {
        return;
    };
    let refusal = ran.expect_err("a git dependency was installed");
    assert!(
        refusal.to_string().to_ascii_lowercase().contains("git"),
        "{refusal}"
    );
}

/// L-tls1: a registry certificate from a CA outside the fetch's bundle is
/// refused (npm's cafile replaces node's roots, strict TLS).
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

/// A writable copy of the host's npm and node in an NVM-shaped tree, both
/// npmrc files npm reads from its own install (builtin and global) turning
/// TLS off and trusting `hostile_ca`; returns the scratch dir and `bin`.
fn hostile_npm(npx: &std::path::Path, hostile_ca: &str) -> (tempfile::TempDir, PathBuf) {
    let npx_real = std::fs::canonicalize(npx).expect("npx's real file");
    let npm_root = npx_real.ancestors().nth(2).expect("npm's package dir");
    let node = std::fs::canonicalize(npx.with_file_name("node")).expect("node beside npx");
    let scratch = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("scratch");
    let tree = scratch.path().join(".nvm/versions/node/v0.0.0-hostile");
    let modules = tree.join("lib/node_modules");
    for dir in [tree.join("bin"), tree.join("etc"), modules.clone()] {
        std::fs::create_dir_all(dir).expect("tree");
    }
    let copied = std::process::Command::new("cp")
        .arg("-R")
        .arg(npm_root)
        .arg(modules.join("npm"))
        .status()
        .expect("cp");
    assert!(copied.success(), "copying npm");
    std::fs::copy(&node, tree.join("bin/node")).expect("copying node");
    for tool in ["npm", "npx"] {
        let cli = format!("../lib/node_modules/npm/bin/{tool}-cli.js");
        std::os::unix::fs::symlink(cli, tree.join("bin").join(tool)).expect("link");
    }
    let ca = tree.join("hostile-ca.pem");
    std::fs::write(&ca, hostile_ca).expect("hostile CA");
    let rc = format!("strict-ssl=false\ncafile={}\n", ca.display());
    std::fs::write(modules.join("npm/npmrc"), &rc).expect("builtin npmrc");
    std::fs::write(tree.join("etc/npmrc"), &rc).expect("global npmrc");
    let bin = tree.join("bin");
    (scratch, bin)
}

/// L-tls2, kills m-strict-ssl and m-cafile (either left to npm's files):
/// npm's own npmrc files turn TLS off and trust the registry's CA, which the
/// bundle lacks; the fetch still refuses. The globalconfig and userconfig
/// pins fall to R-env (npm ranks the environment above both files).
/// Positive control: the same copied npm fetches when the bundle holds the
/// registry's CA.
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

/// The canary package's bin: names each argument it can see, then shows
/// node runs in the run phase.
const CANARY_BIN: &[u8] =
    b"#!/bin/sh\nfor f in \"$@\"; do test -e \"$f\" && echo \"visible $f\"; done\nnode -e 'console.log(\"node-ran\")'\necho bin-ran\n";

/// Files planted beside node and beside npm under `/usr/local`, removed on drop.
struct Canaries(Vec<PathBuf>);

impl Canaries {
    /// `None` (skip) where this host's `/usr/local` cannot take them.
    fn plant() -> Option<Self> {
        let name = format!("preview-canary-{}", std::process::id());
        let paths = vec![
            PathBuf::from("/usr/local/bin").join(&name),
            PathBuf::from("/usr/local/lib/node_modules").join(&name),
        ];
        let mut canaries = Self(Vec::new());
        for path in paths {
            if let Err(e) = std::fs::write(&path, b"canary") {
                return skip(&format!("cannot plant {} ({e})", path.display())).map(|n| match n {});
            }
            canaries.0.push(path);
        }
        Some(canaries)
    }
}

impl Drop for Canaries {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// L-canary, kills "the fetch binds the /usr/local trees whole": on a
/// `/usr/local` node (the hosted runner's), files planted beside node in
/// `/usr/local/bin` and beside npm in `/usr/local/lib/node_modules` are not
/// visible to the fetched package's run phase, while node itself runs there.
#[tokio::test]
async fn l_canary_a_usr_local_install_shows_the_package_only_node_and_npm() {
    let Some(npx) = host_npx() else {
        return;
    };
    let real = std::fs::canonicalize(&npx).expect("npx's real file");
    if !real.starts_with("/usr/local") {
        let _ = skip("npx is not a /usr/local install");
        return;
    }
    let Some(canaries) = Canaries::plant() else {
        return;
    };
    let fake = Package {
        name: "mcp-canary",
        version: "1.0.0",
        manifest: serde_json::json!({"bin": {"mcp-canary": "bin/cli.sh"}}),
        files: vec![("bin/cli.sh", CANARY_BIN.to_vec(), 0o755)],
    };
    let args: Vec<String> = canaries.0.iter().map(|p| p.display().to_string()).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some(ran) = npx("mcp-canary", &args, vec![fake], Bundle::Registry).await else {
        return;
    };
    let out = ran.expect("the fetch and the run succeeded");
    assert_eq!(lines(&out), ["node-ran", "bin-ran"], "{out}");
    drop(canaries);
}
