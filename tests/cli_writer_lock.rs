// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8042: a CLI write to `gateway.yaml` waits for the cross-process config
//! lock (`.gateway.yaml.lock`) instead of writing over another writer.
//!
//! The test holds the lock with `std::fs::File::lock`, the same primitive as
//! the gateway's own lock (`flock` on unix, `LockFileEx` on Windows). The
//! sync point is the CLI's own "Waiting for" line, not a sleep.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Stdio;

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

const START: &str = "# kept by hand\nbackends:\n  old:\n    command: x\n";

/// `mcp-gateway add` in `home`, isolated as the other CLI-write tests run it,
/// with stderr piped so the test can see the CLI start waiting.
fn spawn_add(home: &Path, config: &Path) -> std::process::Child {
    let mut command = gateway_bin::command(home, gateway_bin::Inherit::Nothing);
    command
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("PATH", home.join("no-system-programs"))
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .args([
            "add",
            "--command",
            "echo hi",
            "--config",
            config.to_str().expect("utf-8 path"),
            "local",
        ]);
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    command.spawn().expect("spawn mcp-gateway add")
}

/// R2: while another writer holds the lock, `add` says it is waiting and
/// writes nothing; once the lock is released it completes.
#[test]
fn a_cli_write_waits_for_the_config_lock() {
    let home = tempfile::tempdir().expect("home");
    let path = home.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, START).expect("write");
    // An owner-only sidecar, as the gateway creates it: on Windows the CLI
    // refuses a sidecar whose ACL lets anyone else in.
    let sidecar = home.path().join(".gateway.yaml.lock");
    mcp_gateway::gateway::test_helpers::write_owner_only(&sidecar, "").expect("sidecar");
    let lock = std::fs::File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&sidecar)
        .expect("open the lock sidecar");
    lock.lock().expect("the test holds the config lock");

    let mut child = spawn_add(home.path(), &path);
    let mut stderr = BufReader::new(child.stderr.take().expect("piped stderr"));
    let mut seen = String::new();
    let mut waiting = false;
    let mut line = String::new();
    while stderr.read_line(&mut line).expect("read stderr") > 0 {
        seen.push_str(&line);
        if line.contains("Waiting for") {
            waiting = true;
            break;
        }
        line.clear();
    }
    assert!(
        waiting,
        "the CLI did not wait for the config lock; stderr={seen:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        START,
        "nothing may be written while another writer holds the lock"
    );

    lock.unlock().expect("release the config lock");
    let status = child.wait().expect("wait for add");
    assert!(status.success(), "add failed after the lock was released");
    let written = std::fs::read_to_string(&path).expect("read");
    assert!(
        written.contains("local") && written.contains("# kept by hand"),
        "{written}"
    );
}
