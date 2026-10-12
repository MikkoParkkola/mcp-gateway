// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 D7: a gateway whose clock reads before 1970 refuses to start, with
//! an error that names the clock, instead of serving expiry checks it cannot
//! judge. `MCP_GATEWAY_TEST_CLOCK` exists in debug builds only.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

/// How long a refusing gateway has to exit; a starting one is still up after.
const BOUND: Duration = Duration::from_secs(20);

fn serve(root: &Path, clock: Option<&str>) -> (Child, std::path::PathBuf) {
    // The gateway refuses a config file other users can read: owner-only on
    // Unix, a protected owner-only ACL on Windows.
    mcp_gateway::gateway::test_helpers::write_owner_only(
        root.join("gateway.yaml"),
        "server:\n  host: 127.0.0.1\n",
    )
    .expect("config");
    let log = root.join("serve.log");
    let out = std::fs::File::create(&log).expect("serve log");
    let err = out.try_clone().expect("log handle");
    let mut command = gateway_bin::command(root, gateway_bin::Inherit::Environment);
    command
        .current_dir(root)
        .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
        .args(["-c", "gateway.yaml", "-p", "0", "serve"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    if let Some(clock) = clock {
        command.env("MCP_GATEWAY_TEST_CLOCK", clock);
    }
    (command.spawn().expect("serve spawns"), log)
}

/// The exit status if the child exits within [`BOUND`]; otherwise it is
/// killed and `None` comes back.
fn exit_within_bound(child: &mut Child) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + BOUND;
    loop {
        if let Some(status) = child.try_wait().expect("child status") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn the_gateway_refuses_to_start_on_a_clock_before_the_epoch() {
    let root = tempfile::tempdir().expect("tempdir");
    let (mut child, log) = serve(root.path(), Some("before-epoch"));
    let status = exit_within_bound(&mut child);
    let logs = std::fs::read_to_string(&log).unwrap_or_default();
    let status = status
        .unwrap_or_else(|| panic!("the gateway kept running on a clock before 1970:\n{logs}"));
    assert!(
        !status.success(),
        "a refused start must exit non-zero:\n{logs}"
    );
    assert!(
        logs.contains("system clock reads before 1970"),
        "the refusal must name the clock:\n{logs}"
    );
}

/// Control: the same gateway on the real clock starts and reports its port.
#[test]
fn the_gateway_starts_on_the_real_clock() {
    let root = tempfile::tempdir().expect("tempdir");
    let (mut child, log) = serve(root.path(), None);
    let deadline = Instant::now() + BOUND;
    let started = loop {
        if gateway_bin::logged_port(&log).is_some() {
            break true;
        }
        if child.try_wait().expect("child status").is_some() || Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = child.kill();
    let _ = child.wait();
    let logs = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        started,
        "control: the gateway did not start on the real clock:\n{logs}"
    );
    assert!(!logs.contains("system clock reads before 1970"), "{logs}");
}

/// One `trust lab evaluate` run that updates the baseline registry, on the
/// real clock or (`dark`) on one that reads before 1970.
fn update_trust_baseline(root: &Path, dark: bool) -> std::process::Output {
    let mut command = gateway_bin::command(root, gateway_bin::Inherit::Environment);
    command
        .current_dir(root)
        .args([
            "trust",
            "lab",
            "evaluate",
            "weather",
            "--capabilities",
            "caps",
            "--baseline-registry",
            "registry",
            "--update-baseline-registry",
            "--baseline-id",
            "weather-baseline",
        ])
        .stdin(Stdio::null());
    if dark {
        command.env("MCP_GATEWAY_TEST_CLOCK", "before-epoch");
    }
    command.output().expect("trust lab evaluate runs")
}

/// MIK-8202.AC.16 (R11, mutant M11): the trust baseline CLI on a clock that
/// reads before 1970 reads the clock before any write: it exits non-zero with
/// an error naming the clock, and both output files (the registry's baseline
/// file and its `manifest.json`) are byte-identical to before. A child
/// process, because the CLI is the binary crate and the in-crate test clock
/// cannot reach it. Mutant M11: a write happens before the clock read.
#[test]
fn the_trust_baseline_cli_writes_nothing_on_a_clock_before_1970() {
    let root = tempfile::tempdir().expect("tempdir");
    let caps = root.path().join("caps");
    std::fs::create_dir_all(&caps).expect("caps dir");
    std::fs::write(
        caps.join("weather.yaml"),
        "name: weather\ndescription: Read weather forecasts\nproviders:\n  primary:\n    \
         service: rest\n    config:\n      base_url: https://example.invalid\nauth:\n  \
         required: true\n  type: api_key\nschema:\n  input:\n    type: object\n    \
         properties:\n      city:\n        type: string\n",
    )
    .expect("capability");
    let seeded = update_trust_baseline(root.path(), false);
    assert!(
        seeded.status.success(),
        "control: the real clock writes the baseline: {}",
        String::from_utf8_lossy(&seeded.stderr)
    );
    let registry = root.path().join("registry");
    let files = [
        registry.join("baselines").join("weather-baseline.json"),
        registry.join("manifest.json"),
    ];
    let before: Vec<Vec<u8>> = files
        .iter()
        .map(|f| std::fs::read(f).expect("seeded output"))
        .collect();
    // The input changes before the dark run, so a write made before the clock
    // refusal (mutant M11) would change the baseline's bytes, not rewrite them.
    let changed = std::fs::read_to_string(caps.join("weather.yaml"))
        .expect("capability")
        .replace(
            "Read weather forecasts",
            "Read weather forecasts and alerts",
        );
    std::fs::write(caps.join("weather.yaml"), changed).expect("changed capability");

    let dark = update_trust_baseline(root.path(), true);
    let stderr = String::from_utf8_lossy(&dark.stderr);
    assert!(!dark.status.success(), "a dark clock must fail: {stderr}");
    assert!(
        stderr.contains("1970"),
        "the error names the clock: {stderr}"
    );
    for (file, before) in files.iter().zip(&before) {
        assert_eq!(
            &std::fs::read(file).expect("output kept"),
            before,
            "{} is unchanged",
            file.display()
        );
    }
}
