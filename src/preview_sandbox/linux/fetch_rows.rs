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
const GUARD: Duration = Duration::from_secs(120);

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
fn gateway_bin() -> Option<PathBuf> {
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
async fn sandbox_runs(gateway: &std::path::Path) -> bool {
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
    let dir = tempfile::tempdir().expect("dir");
    let ca = match bundle {
        Bundle::Registry => registry.ca_pem.clone(),
        Bundle::Other => crate::test_fixture_host::test_pki("registry.npmjs.org", "unrelated CA")
            .ca
            .pem(),
    };
    let bundle_path = dir.path().join("bundle.pem");
    std::fs::write(&bundle_path, ca).expect("bundle");
    let ambient = Ambient {
        ca_bundle: Some(bundle_path.into_os_string()),
        runtime_dir: None,
        path: std::env::var_os("PATH"),
    };
    let target = Target {
        program: PathBuf::from("npx"),
        args: std::iter::once(spec)
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect(),
    };
    let deadline = tokio::time::Instant::now() + GUARD;
    let started = tokio::time::timeout(
        GUARD,
        start_fetching_with(
            &gateway,
            &target,
            &[],
            deadline,
            ambient,
            Arc::new(TestResolve),
            Arc::new(TestDialer(registry.port)),
        ),
    )
    .await
    .expect("the fetch preview ended within the guard");
    let mut started = match started {
        Ok(started) => started,
        Err(refusal) => return Some(Err(refusal)),
    };
    drop(started.child.stdin.take());
    let mut out = String::new();
    let mut stdout = started.child.stdout.take().expect("stdout");
    tokio::time::timeout(GUARD, stdout.read_to_string(&mut out))
        .await
        .expect("the run ended within the guard")
        .expect("stdout");
    let _ = started.child.wait().await;
    Some(Ok(out))
}

fn lines(out: &str) -> Vec<&str> {
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
