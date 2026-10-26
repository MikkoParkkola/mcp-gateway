// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The command preview's Linux sandbox, through the shipped binary (ADR-027).
//!
//! Each denial has its positive control. A host that refuses the sandbox
//! (Ubuntu 24.04+ without the `AppArmor` step, a container) skips these tests,
//! except where `PREVIEW_SANDBOX_REQUIRED` is set: CI sets it on the job that
//! enables user namespaces, so a refused sandbox there fails instead of
//! passing green.
#![cfg(target_os = "linux")]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use mcp_gateway::preview_sandbox::{Refusal, Started, Target, start_with_helper};
use tokio::io::AsyncReadExt as _;

struct Output {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

/// Run `program args` in the sandbox and collect what it printed, or `None`
/// when this host refuses the sandbox and the tests are not required.
async fn sandboxed(program: &str, args: &[&str]) -> Option<Output> {
    sandboxed_protecting(program, args, &[]).await
}

/// As [`sandboxed`], with `protected` passed to the launcher as gateway paths.
async fn sandboxed_protecting(
    program: &str,
    args: &[&str],
    protected: &[PathBuf],
) -> Option<Output> {
    let target = Target {
        program: PathBuf::from(program),
        args: args.iter().map(Into::into).collect(),
    };
    let started = start_with_helper(Path::new(gateway_bin::path()), &target, protected);
    let Started { mut child, .. } = match started {
        Ok(started) => started,
        Err(refusal) => return skip_or_fail(&refusal),
    };
    drop(child.stdin.take());
    let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let run = async {
        let (mut stdout, mut stderr) = (String::new(), String::new());
        let (a, b) = tokio::join!(
            out.read_to_string(&mut stdout),
            err.read_to_string(&mut stderr)
        );
        a.and(b).expect("read the preview's output");
        (
            child.wait().await.expect("wait for unshare"),
            stdout,
            stderr,
        )
    };
    let (status, stdout, stderr) = tokio::time::timeout(Duration::from_secs(60), run)
        .await
        .expect("the sandboxed command finished within 60 s");
    // The helper only runs once the namespaces exist, so a refusal it prints
    // is a sandbox bug on a host that allows them, never a skip.
    assert!(
        !stderr.contains("preview-sandbox: refused at "),
        "the sandbox refused a step on a working host: {stderr}"
    );
    // `unshare` itself failing is the host refusing the namespaces.
    if stderr.starts_with("unshare:") {
        return skip_or_fail(&Refusal::Step(stderr));
    }
    Some(Output {
        status,
        stdout,
        stderr,
    })
}

fn skip_or_fail(refusal: &Refusal) -> Option<Output> {
    assert!(
        std::env::var_os("PREVIEW_SANDBOX_REQUIRED").is_none(),
        "the sandbox is required here but refused: {refusal}"
    );
    eprintln!("skipped: this host refuses the preview sandbox: {refusal}");
    None
}

/// `tool` is installed, or this test is skipped; where the sandbox is
/// required, a missing tool fails instead, so no test passes by not running.
fn has_tool(tool: &str) -> bool {
    if Path::new(tool).exists() {
        return true;
    }
    assert!(
        std::env::var_os("PREVIEW_SANDBOX_REQUIRED").is_none(),
        "the sandbox tests are required here but {tool} is missing"
    );
    eprintln!("skipped: {tool} is not installed");
    false
}

async fn sh(script: &str) -> Option<Output> {
    sandboxed("/bin/sh", &["-c", script]).await
}

#[tokio::test]
async fn the_run_phase_starts_in_its_own_home() {
    let Some(out) = sh("echo \"$HOME\"; pwd; touch \"$HOME/x\" && echo writable").await else {
        return;
    };
    assert!(out.status.success(), "{}", out.stderr);
    assert_eq!(out.stdout, "/preview-home\n/preview-home\nwritable\n");
}

/// SBX.2: files outside the binds do not exist inside; the same files are
/// readable outside (positive control).
#[tokio::test]
async fn canaries_outside_the_binds_are_unreadable() {
    let dir = Path::new("/var/tmp").join(format!("sbx-canary-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let canary = dir.join("canary");
    std::fs::write(&canary, "secret").unwrap();
    assert_eq!(std::fs::read_to_string(&canary).unwrap(), "secret");
    let home = std::env::var("HOME").unwrap_or_default();
    let script = format!(
        "cat '{}' 2>/dev/null && echo LEAK; for p in /home /root /run /var '{home}'; do \
         test -e \"$p\" && echo \"present $p\"; done; echo done",
        canary.display()
    );
    let out = sh(&script).await;
    std::fs::remove_dir_all(&dir).unwrap();
    let Some(out) = out else { return };
    assert_eq!(out.stdout, "done\n", "{}", out.stderr);
}

/// A runtime file is readable inside (positive control for the canaries).
#[tokio::test]
async fn a_runtime_file_is_readable() {
    let Some(out) = sh("test -r /usr/bin/env && test -d /etc/ssl && echo ok").await else {
        return;
    };
    assert_eq!(out.stdout, "ok\n", "{}", out.stderr);
}

/// SBX.3, run phase: no route anywhere, the test's own listener included;
/// the test reaches that listener itself (positive control).
#[tokio::test]
async fn the_run_phase_cannot_connect_anywhere() {
    if !has_tool("/bin/bash") {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // Positive control: the same bash connect, run outside the sandbox, works.
    let outside = std::process::Command::new("/bin/bash")
        .args([
            "-c",
            &format!("(exec 3<>/dev/tcp/127.0.0.1/{port}) && echo reached"),
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&outside.stdout), "reached\n");
    let script = format!(
        "for a in 127.0.0.1/{port} 169.254.169.254/80 1.1.1.1/443; do \
         (exec 3<>/dev/tcp/$a) 2>/dev/null && echo \"reached $a\"; done; echo done"
    );
    let Some(out) = sandboxed("/bin/bash", &["-c", &script]).await else {
        return;
    };
    assert_eq!(out.stdout, "done\n", "{}", out.stderr);
}

/// SBX.4: a descendant that calls `setsid` and double-forks is running on the
/// host before teardown and gone after it.
#[tokio::test]
async fn a_setsid_descendant_is_gone_after_teardown() {
    let marker = format!("{}.{}0", 3600, std::process::id());
    // The escapee double-forks into its own session; the target then waits on
    // stdin, which the test holds open, so teardown is what ends it.
    let script = format!("setsid sh -c 'sleep {marker} & exit' & exec cat");
    let target = Target {
        program: PathBuf::from("/bin/sh"),
        args: vec!["-c".into(), script.into()],
    };
    let Some(started) = started_until(&target, &marker).await else {
        return;
    };
    drop(started);
    assert_gone_soon(&marker);
}

/// A host process is `sleep <marker>`, matched on its own argument vector, so
/// the marker inside `unshare`'s serialized plan never counts.
fn host_has(marker: &str) -> bool {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .any(|e| {
            std::fs::read(e.path().join("cmdline")).is_ok_and(|c| {
                let mut argv = c.split(|&b| b == 0);
                let program = argv.next().unwrap_or_default();
                program.rsplit(|&b| b == b'/').next() == Some(b"sleep".as_slice())
                    && argv.next() == Some(marker.as_bytes())
            })
        })
}

/// The host root is gone: no old root, no host file through /proc/1/root,
/// the working directory inside the new root; /proc/self/status readable.
#[tokio::test]
async fn the_host_root_is_unreachable() {
    let script = "test -e /.old-root && echo old; test -e /proc/1/root/home && echo host; \
                  readlink /proc/self/cwd; cat /proc/self/status >/dev/null && echo status";
    let Some(out) = sh(script).await else { return };
    assert_eq!(out.stdout, "/preview-home\nstatus\n", "{}", out.stderr);
}

/// The helper is non-dumpable: its environment and descriptors are closed to
/// the processes it starts.
#[tokio::test]
async fn the_helper_cannot_be_read_from_inside() {
    let script = "cat /proc/1/environ >/dev/null 2>&1 && echo environ; \
                  ls /proc/1/fd >/dev/null 2>&1 && echo fd; echo done";
    let Some(out) = sh(script).await else { return };
    assert_eq!(out.stdout, "done\n", "{}", out.stderr);
}

/// Masks: `/usr/local` and `/etc/ssl/private` are empty inside, while
/// `/etc/ssl/certs` stays (positive control).
#[tokio::test]
async fn masked_system_paths_are_empty() {
    let script = "ls -A /usr/local; ls -A /etc/ssl/private 2>/dev/null; \
                  test -e /etc/ssl/certs && echo certs";
    let Some(out) = sh(script).await else { return };
    let expected = if Path::new("/etc/ssl/certs").exists() {
        "certs\n"
    } else {
        ""
    };
    assert_eq!(out.stdout, expected, "{}", out.stderr);
}

/// A gateway path that is a symlink into a bound prefix is masked at its real
/// path too: here a link to `/usr/share/doc` stands in for a state directory
/// placed under `/usr`. The directory is listed outside (positive control).
#[tokio::test]
async fn a_symlinked_gateway_path_is_masked_where_it_really_is() {
    let real = Path::new("/usr/share/doc");
    let listed = std::fs::read_dir(real).map(|d| d.count()).unwrap_or(0);
    if listed == 0 {
        return;
    }
    let link = Path::new("/var/tmp").join(format!("sbx-state-link-{}", std::process::id()));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(real, &link).unwrap();
    let out =
        sandboxed_protecting("/bin/sh", &["-c", "ls -A /usr/share/doc"], &[link.clone()]).await;
    std::fs::remove_file(&link).unwrap();
    let Some(out) = out else { return };
    assert!(out.status.success(), "{}", out.stderr);
    assert_eq!(out.stdout, "", "the real path stayed readable");
}

/// Bounds: `/tmp` stops at 256 MiB.
#[tokio::test]
async fn tmp_is_bounded() {
    let script = "head -c 300M /dev/zero > /tmp/big 2>/dev/null && echo fit; echo done";
    let Some(out) = sh(script).await else { return };
    assert_eq!(out.stdout, "done\n", "{}", out.stderr);
}

/// Bounds: the home stops at 1 GiB (each file stays under the 512 MiB file
/// size limit, so the tmpfs is what refuses).
#[tokio::test]
async fn the_home_is_bounded() {
    let script = "for i in 1 2 3; do head -c 400M /dev/zero > \"$HOME/$i\" 2>/dev/null || \
                  echo \"full at $i\"; done";
    let Some(out) = sh(script).await else { return };
    assert_eq!(out.stdout, "full at 3\n", "{}", out.stderr);
}

/// seccomp: the keyring and `ptrace` answer `EPERM` (positive control:
/// `getpid` works), and on `x86_64` the same calls by their x32 numbers end
/// the child with `SIGSYS`.
#[tokio::test]
async fn the_filter_refuses_keyrings_and_ptrace() {
    if !has_tool("/usr/bin/python3") {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    let (keyctl, ptrace, getpid) = (250, 101, 39);
    #[cfg(target_arch = "aarch64")]
    let (keyctl, ptrace, getpid) = (219, 117, 172);
    let script = format!(
        "import ctypes\nl = ctypes.CDLL(None, use_errno=True)\n\
         print(l.syscall({getpid}) > 0)\n\
         for nr in ({keyctl}, {ptrace}):\n    print(l.syscall(nr, 0, 0, 0, 0), ctypes.get_errno())\n"
    );
    let Some(out) = sandboxed("/usr/bin/python3", &["-c", &script]).await else {
        return;
    };
    assert_eq!(out.stdout, "True\n-1 1\n-1 1\n", "{}", out.stderr);

    #[cfg(target_arch = "x86_64")]
    for nr in [keyctl, ptrace] {
        let script = format!(
            "import ctypes\nctypes.CDLL(None).syscall({})\nprint('survived')",
            0x4000_0000 | nr
        );
        let Some(out) = sandboxed("/usr/bin/python3", &["-c", &script]).await else {
            return;
        };
        // The helper reports a signalled target as 128 plus the signal.
        assert_eq!(
            out.status.code(),
            Some(128 + 31),
            "x32 {nr}: {}",
            out.stdout
        );
    }
}

/// A helper started outside fresh namespaces refuses before any mount. Needs
/// no namespaces itself, so it runs on every Linux host.
#[test]
fn the_helper_refuses_outside_fresh_namespaces() {
    use std::os::unix::fs::MetadataExt as _;
    let inode = |n: &str| {
        std::fs::metadata(format!("/proc/self/ns/{n}"))
            .unwrap()
            .ino()
    };
    let plan = serde_json::json!({
        "host": {"user": inode("user"), "mnt": inode("mnt"), "pid": inode("pid"), "net": inode("net"), "ipc": inode("ipc"), "uts": inode("uts")},
        "read_only": [], "masked": [], "bound_back": [],
        "limits": {"address_space": 1, "file_size": 1, "open_files": 1, "processes": 1},
        "env": [], "target": ["/bin/true"]
    });
    let home = tempfile::tempdir().unwrap();
    let out = gateway_bin::command(home.path(), gateway_bin::Inherit::Nothing)
        .args(["__preview-sandbox", &plan.to_string()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(97));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refused at checking namespaces (the user namespace is the gateway's)"),
        "{stderr}"
    );
}

/// Start `sleep <marker>` in the sandbox and wait until the host sees it, or
/// `None` when the host refuses the sandbox.
async fn started_sleeper(marker: &str) -> Option<Started> {
    let target = Target {
        program: PathBuf::from("/bin/sleep"),
        args: vec![marker.into()],
    };
    started_until(&target, marker).await
}

/// Start `target` and wait until the host runs `sleep <marker>`, or `None`
/// when the host refuses the sandbox.
async fn started_until(target: &Target, marker: &str) -> Option<Started> {
    let started = match start_with_helper(Path::new(gateway_bin::path()), target, &[]) {
        Ok(started) => started,
        Err(refusal) => {
            skip_or_fail(&refusal);
            return None;
        }
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !host_has(marker) {
        if std::time::Instant::now() > deadline {
            // `unshare` refused the namespaces: the sleeper never started.
            skip_or_fail(&Refusal::Step("the sleeper did not start".into()));
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Some(started)
}

fn assert_gone_soon(marker: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while host_has(marker) {
        assert!(
            std::time::Instant::now() < deadline,
            "the sandboxed sleep outlived its drop"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Teardown, dropped future: dropping the preview kills `unshare`, so
/// `--kill-child` kills the helper and the whole namespace with it.
#[tokio::test]
async fn a_dropped_preview_kills_its_namespace() {
    let marker = format!("{}.{}1", 3600, std::process::id());
    let Some(started) = started_sleeper(&marker).await else {
        return;
    };
    drop(started);
    assert_gone_soon(&marker);
}

/// Teardown, idle runtime: the kill is sent in `Drop` itself, so a preview
/// dropped after its runtime is gone still ends.
#[test]
fn a_preview_dropped_after_its_runtime_still_ends() {
    let marker = format!("{}.{}2", 3600, std::process::id());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let started = runtime.block_on(started_sleeper(&marker));
    drop(runtime);
    let Some(started) = started else { return };
    drop(started);
    assert_gone_soon(&marker);
}
