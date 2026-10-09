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
    std::fs::write(root.join("gateway.yaml"), "server:\n  host: 127.0.0.1\n").expect("config");
    // The gateway refuses a config file other users can read.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            root.join("gateway.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("config mode");
    }
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
