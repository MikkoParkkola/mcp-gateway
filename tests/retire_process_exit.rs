// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The HTTP stop ends the whole process inside its total: over plain HTTP and
//! over mTLS, at the minimum total and at the 30 s default, a gateway sent
//! SIGTERM exits by itself, with code 0, before the shipped grace's kill at
//! the total + 1 s (the reap below kills it there and fails the row).
#![cfg(unix)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

/// The smallest `server.shutdown_timeout` an HTTP gateway accepts.
const HTTP_MINIMUM: Duration = Duration::from_secs(13);
/// The shipped default stop total.
const DEFAULT_TOTAL: Duration = Duration::from_secs(30);
/// The shipped grace past the total: the external kill lands here.
const GRACE: Duration = Duration::from_secs(1);
/// How long a gateway may take to report its port.
const READY_BOUND: Duration = Duration::from_secs(60);

/// A server certificate for 127.0.0.1 and its CA, written to `dir`.
fn write_certs(dir: &Path) {
    use mcp_gateway::mtls::{CaParams, CertGenerator, LeafCertParams};
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "stop CA",
        validity_days: 1,
    })
    .expect("CA");
    let server = CertGenerator::issue_leaf(
        &LeafCertParams {
            cn: "gateway",
            ou: None,
            san_dns: vec!["127.0.0.1".to_owned()],
            san_uris: vec![],
            validity_days: 1,
        },
        &ca.cert_pem,
        &ca.key_pem,
    )
    .expect("server certificate");
    CertGenerator::write_to_dir(&server, dir, "server").expect("server files");
    CertGenerator::write_to_dir(&ca, dir, "ca").expect("CA files");
}

/// The config of a gateway on any port with stop total `total`, serving mTLS
/// when `tls` names the folder holding its certificates.
fn write_config(root: &Path, total: Duration, tls: Option<&Path>) -> PathBuf {
    let mut yaml = format!(
        "server:\n  host: 127.0.0.1\n  port: {}\n  shutdown_timeout: {}s\n",
        gateway_bin::ANY_PORT,
        total.as_secs()
    );
    if let Some(dir) = tls {
        let path = |name: &str| dir.join(name).display().to_string();
        write!(
            yaml,
            "mtls:\n  enabled: true\n  server_cert: {}\n  server_key: {}\n  ca_cert: {}\n  \
             require_client_cert: true\n",
            path("server.crt"),
            path("server.key"),
            path("ca.crt"),
        )
        .expect("a String takes the write");
    }
    let config = root.join("gateway.yaml");
    // The gateway refuses a config other users can read.
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, yaml).expect("config");
    config
}

/// How the start watches the log for the `Listening` banner.
#[derive(Clone, Copy)]
enum Watch {
    /// Every 50 ms.
    Relaxed,
    /// Yielding between reads only, so a SIGTERM sent next lands as close to
    /// the banner as the test can see it.
    Tight,
}

/// Start a gateway with stop total `total`, stop it with SIGTERM once it
/// listens, and return how long its exit took. The reap kills a gateway still
/// running at the total + 1 s and fails the row there.
async fn stop_took(total: Duration, tls: bool) -> Duration {
    let (mut reaped, log) = start(total, tls, Watch::Relaxed).await;
    let started = Instant::now();
    let status = reaped.reap_within(total + GRACE).await;
    let took = started.elapsed();
    assert!(
        status.success(),
        "the stopped gateway exited with {status}\n{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    reaped.stop().await;
    took
}

/// A gateway with stop total `total`, once its log holds the `Listening`
/// banner, and the log's path.
async fn start(total: Duration, tls: bool, watch: Watch) -> (gateway_bin::Reaped, PathBuf) {
    let temp = tempfile::tempdir().expect("temp root");
    let root = temp.path().to_path_buf();
    if tls {
        write_certs(&root);
    }
    let config = write_config(&root, total, tls.then_some(root.as_path()));
    let log = root.join("gateway.log");
    let out = std::fs::File::create(&log).expect("log");
    let mut command = tokio::process::Command::from(gateway_bin::command(
        &root.join("home"),
        gateway_bin::Inherit::Environment,
    ));
    command
        .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
        .current_dir(&root)
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out.try_clone().expect("log handle")))
        .stderr(Stdio::from(out))
        .kill_on_drop(true);
    let child = command
        .spawn() // spawn-check: waits for exit: reap_within below; Reaped kills on drop
        .expect("gateway");
    let mut reaped = gateway_bin::Reaped::new(child);
    reaped.owning(temp);
    let ready_by = Instant::now() + READY_BOUND;
    while gateway_bin::logged_port(&log).is_none() {
        assert!(
            Instant::now() < ready_by,
            "the gateway never listened\n{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );
        match watch {
            Watch::Relaxed => tokio::time::sleep(Duration::from_millis(50)).await,
            Watch::Tight => tokio::task::yield_now().await,
        }
    }
    (reaped, log)
}

/// RETIRE.2 over plain HTTP: at the minimum total and at the 30 s default the
/// process exits by itself, code 0, before the total + 1 s.
#[tokio::test]
async fn an_http_gateway_exits_inside_its_stop_total() {
    for total in [HTTP_MINIMUM, DEFAULT_TOTAL] {
        let took = stop_took(total, false).await;
        assert!(took < total + GRACE, "{total:?}: the exit took {took:?}");
    }
}

/// RETIRE.2 over mTLS: the same stop path, the same bound.
#[tokio::test]
async fn an_mtls_gateway_exits_inside_its_stop_total() {
    for total in [HTTP_MINIMUM, DEFAULT_TOTAL] {
        let took = stop_took(total, true).await;
        assert!(took < total + GRACE, "{total:?}: the exit took {took:?}");
    }
}

/// RETIRE.2 from the first moment: a SIGTERM sent as soon as the log shows the
/// `Listening` banner drains the gateway like any other, exit code 0 with the
/// shutdown logged, on every one of twenty starts over plain HTTP and twenty
/// over mTLS. A start that dies of the signal fails the row with its log.
#[tokio::test]
async fn a_sigterm_on_the_listening_banner_drains_the_gateway() {
    const STARTS: usize = 20;
    let mut undrained = Vec::new();
    for tls in [false, true] {
        for start_no in 0..STARTS {
            let (mut reaped, log) = start(HTTP_MINIMUM, tls, Watch::Tight).await;
            let status = reaped.reap_within(HTTP_MINIMUM + GRACE).await;
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if !status.success() || !text.contains("Shutdown signal received") {
                undrained.push(format!("start {start_no} (mTLS: {tls}): {status}\n{text}"));
            }
            reaped.stop().await;
        }
    }
    assert!(
        undrained.is_empty(),
        "{} of {} starts did not drain; the first:\n{}",
        undrained.len(),
        2 * STARTS,
        undrained.first().map_or("", String::as_str)
    );
}
