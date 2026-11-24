// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The tls commands refuse to replace output that is already there: before
//! any key is generated or read, `<stem>.crt` and `<stem>.key` under `--out`
//! must hold nothing at all. Each row runs the real binary, so it sees both
//! the exit status and the message that decided.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[cfg(unix)]
#[path = "common/required.rs"]
mod required;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

/// A command that would block (for example on a FIFO) fails the row instead
/// of hanging the suite.
const RUN_BOUND: Duration = Duration::from_secs(20);

struct Ran {
    ok: bool,
    stderr: String,
}

/// Runs the binary with `args`, English OS messages, and a bounded wait.
fn run(args: &[&str]) -> Ran {
    let home = tempfile::tempdir().expect("isolated home");
    let mut command = gateway_bin::command(home.path(), gateway_bin::Inherit::Nothing);
    command.env("LC_ALL", "C");
    finish(command.args(args), args)
}

/// [`run`] with the child under `umask 002`, where a file created with the
/// default mode is group-writable unless the code narrows it.
#[cfg(unix)]
fn run_under_umask_002(args: &[&str]) -> Ran {
    let home = tempfile::tempdir().expect("isolated home");
    let wrapper = ["/bin/sh", "-c", "umask 002; exec \"$0\" \"$@\""];
    let mut command = gateway_bin::wrapped(&wrapper, home.path(), gateway_bin::Inherit::Nothing);
    command.env("LC_ALL", "C");
    finish(command.args(args), args)
}

fn finish(command: &mut std::process::Command, args: &[&str]) -> Ran {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn() // spawn-check: waits for exit: a one-shot tls command; reaped below, killed past RUN_BOUND
        .expect("start mcp-gateway");
    let mut pipe = child.stderr.take().expect("stderr pipe");
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::io::Read::read_to_string(&mut pipe, &mut text);
        text
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the child") {
            break status;
        }
        if started.elapsed() > RUN_BOUND {
            let _ = child.kill();
            let _ = child.wait();
            panic!("mcp-gateway {args:?} did not finish within {RUN_BOUND:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Ran {
        ok: status.success(),
        stderr: reader.join().expect("stderr reader"),
    }
}

fn s(path: &Path) -> &str {
    path.to_str().expect("utf-8 temp path")
}

/// Every name in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list --out")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// The refusal every row expects: a failure whose message names one of
/// `deciding`, says it already exists, and tells the operator what to do.
fn assert_refused(ran: &Ran, deciding: &[PathBuf]) {
    assert!(!ran.ok, "the command succeeded; stderr: {}", ran.stderr);
    assert!(
        deciding.iter().any(|path| ran.stderr.contains(s(path))),
        "no deciding path {deciding:?} in: {}",
        ran.stderr
    );
    let lower = ran.stderr.to_lowercase();
    for phrase in ["already exists", "remove it first", "different", "--out"] {
        assert!(
            lower.contains(phrase),
            "{phrase:?} missing from: {}",
            ran.stderr
        );
    }
}

fn init_ca(out: &Path) -> Ran {
    run(&["tls", "init-ca", "--cn", "Test CA", "--out", s(out)])
}

fn issue_server(ca: &Path, out: &Path) -> Ran {
    run(&[
        "tls",
        "issue-server",
        "--ca-cert",
        s(&ca.join("ca.crt")),
        "--ca-key",
        s(&ca.join("ca.key")),
        "--cn",
        "localhost",
        "--san-dns",
        "localhost",
        "--out",
        s(out),
    ])
}

fn issue_client(ca: &Path, cn: &str, out: &Path) -> Ran {
    run(&[
        "tls",
        "issue-client",
        "--ca-cert",
        s(&ca.join("ca.crt")),
        "--ca-key",
        s(&ca.join("ca.key")),
        "--cn",
        cn,
        "--out",
        s(out),
    ])
}

/// A fresh CA in its own directory.
fn fresh_ca() -> tempfile::TempDir {
    let ca = tempfile::tempdir().expect("ca dir");
    let ran = init_ca(ca.path());
    assert!(ran.ok, "init-ca into an empty dir: {}", ran.stderr);
    ca
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::symlink_metadata(path)
        .expect("stat")
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

// ── init-ca ─────────────────────────────────────────────────────────────────

#[test]
fn r1_init_ca_keeps_an_existing_key() {
    let out = tempfile::tempdir().expect("out");
    #[cfg(unix)]
    set_mode(out.path(), 0o755);
    std::fs::write(out.path().join("ca.key"), b"old-key").expect("stage key");
    let ran = init_ca(out.path());
    assert_refused(&ran, &[out.path().join("ca.key")]);
    assert_eq!(
        std::fs::read(out.path().join("ca.key")).expect("key"),
        b"old-key"
    );
    assert_eq!(names(out.path()), ["ca.key"]);
    #[cfg(unix)]
    assert_eq!(
        mode(out.path()),
        0o755,
        "the refusal changed the directory's mode"
    );
}

#[test]
fn r2_init_ca_keeps_an_existing_cert() {
    let out = tempfile::tempdir().expect("out");
    std::fs::write(out.path().join("ca.crt"), b"old-cert").expect("stage cert");
    let ran = init_ca(out.path());
    assert_refused(&ran, &[out.path().join("ca.crt")]);
    assert_eq!(
        std::fs::read(out.path().join("ca.crt")).expect("cert"),
        b"old-cert"
    );
    assert_eq!(names(out.path()), ["ca.crt"]);
}

#[test]
fn r11_the_existing_key_decides_before_the_validity_is_used() {
    let out = tempfile::tempdir().expect("out");
    std::fs::write(out.path().join("ca.key"), b"old-key").expect("stage key");
    let ran = run(&[
        "tls",
        "init-ca",
        "--validity-days",
        "4294967295",
        "--out",
        s(out.path()),
    ]);
    assert_refused(&ran, &[out.path().join("ca.key")]);
    assert!(
        !ran.stderr.contains("Date calculation"),
        "the date error decided, so the check ran too late: {}",
        ran.stderr
    );
    assert_eq!(
        std::fs::read(out.path().join("ca.key")).expect("key"),
        b"old-key"
    );
}

#[test]
fn r12_a_directory_at_the_key_name_refuses() {
    let out = tempfile::tempdir().expect("out");
    std::fs::create_dir(out.path().join("ca.key")).expect("stage dir");
    let ran = init_ca(out.path());
    assert_refused(&ran, &[out.path().join("ca.key")]);
    assert!(
        out.path().join("ca.key").is_dir(),
        "the directory was replaced"
    );
    assert!(
        names(&out.path().join("ca.key")).is_empty(),
        "something was written into it"
    );
    assert_eq!(names(out.path()), ["ca.key"]);
}

#[cfg(unix)]
#[test]
fn r12b_a_fifo_at_the_cert_name_refuses_without_opening_it() {
    use std::os::unix::fs::FileTypeExt as _;
    let out = tempfile::tempdir().expect("out");
    let fifo = out.path().join("ca.crt");
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()
        .expect("run mkfifo");
    assert!(made.success(), "mkfifo failed");
    let ran = init_ca(out.path());
    assert_refused(&ran, std::slice::from_ref(&fifo));
    let kind = std::fs::symlink_metadata(&fifo).expect("stat").file_type();
    assert!(kind.is_fifo(), "the FIFO was replaced");
    assert_eq!(names(out.path()), ["ca.crt"]);
}

#[cfg(unix)]
#[test]
fn r9_a_dangling_cert_link_refuses() {
    let out = tempfile::tempdir().expect("out");
    let link = out.path().join("ca.crt");
    std::os::unix::fs::symlink("ca.key", &link).expect("stage link");
    let ran = init_ca(out.path());
    assert_refused(&ran, std::slice::from_ref(&link));
    assert_eq!(
        std::fs::read_link(&link).expect("still a link"),
        Path::new("ca.key")
    );
    assert!(
        std::fs::symlink_metadata(out.path().join("ca.key")).is_err(),
        "a key was written through the link"
    );
    assert_eq!(names(out.path()), ["ca.crt"]);
}

#[cfg(unix)]
#[test]
fn r9b_a_dangling_key_link_refuses() {
    let out = tempfile::tempdir().expect("out");
    let link = out.path().join("ca.key");
    std::os::unix::fs::symlink("nowhere", &link).expect("stage link");
    let ran = init_ca(out.path());
    assert_refused(&ran, std::slice::from_ref(&link));
    assert_eq!(
        std::fs::read_link(&link).expect("still a link"),
        Path::new("nowhere")
    );
    assert_eq!(names(out.path()), ["ca.key"]);
}

#[cfg(unix)]
#[test]
fn r10_a_lookup_error_refuses() {
    if rustix::process::geteuid().is_root() {
        required::skip_or_fail("r10 needs a non-root user: root ignores the directory's mode");
        return;
    }
    let out = tempfile::tempdir().expect("out");
    std::fs::write(out.path().join("ca.key"), b"old-key").expect("stage key");
    set_mode(out.path(), 0o600);
    let ran = init_ca(out.path());
    let dir_mode = mode(out.path());
    set_mode(out.path(), 0o700);
    eprintln!("r10 RAN");
    assert!(!ran.ok, "the command succeeded; stderr: {}", ran.stderr);
    // Both lookups fail and the cert is checked first, so either path decides.
    assert!(
        [out.path().join("ca.crt"), out.path().join("ca.key")]
            .iter()
            .any(|path| ran.stderr.contains(s(path))),
        "no path in: {}",
        ran.stderr
    );
    assert!(
        ran.stderr.contains("Permission denied"),
        "no OS error in: {}",
        ran.stderr
    );
    assert!(
        ran.stderr.contains("choose a different --out"),
        "no next step in: {}",
        ran.stderr
    );
    assert_eq!(dir_mode, 0o600, "the refusal changed the directory's mode");
    assert_eq!(
        std::fs::read(out.path().join("ca.key")).expect("key"),
        b"old-key"
    );
    assert_eq!(names(out.path()), ["ca.key"]);
}

// ── issue-server ────────────────────────────────────────────────────────────

#[test]
fn r3_issue_server_keeps_its_earlier_output() {
    let ca = fresh_ca();
    let out = tempfile::tempdir().expect("out");
    assert!(issue_server(ca.path(), out.path()).ok, "first issue-server");
    let cert = std::fs::read(out.path().join("server.crt")).expect("cert");
    let key = std::fs::read(out.path().join("server.key")).expect("key");
    let ran = issue_server(ca.path(), out.path());
    assert_refused(
        &ran,
        &[out.path().join("server.crt"), out.path().join("server.key")],
    );
    assert_eq!(
        std::fs::read(out.path().join("server.crt")).expect("cert"),
        cert
    );
    assert_eq!(
        std::fs::read(out.path().join("server.key")).expect("key"),
        key
    );
    assert_eq!(names(out.path()), ["server.crt", "server.key"]);
}

#[test]
fn r3c_issue_server_keeps_a_cert_whose_key_is_gone() {
    let ca = fresh_ca();
    let out = tempfile::tempdir().expect("out");
    std::fs::write(out.path().join("server.crt"), b"old-cert").expect("stage cert");
    let ran = issue_server(ca.path(), out.path());
    assert_refused(&ran, &[out.path().join("server.crt")]);
    assert_eq!(
        std::fs::read(out.path().join("server.crt")).expect("cert"),
        b"old-cert"
    );
    assert_eq!(names(out.path()), ["server.crt"]);
}

#[cfg(unix)]
#[test]
fn r5s_issue_server_checks_its_output_before_reading_the_ca_key() {
    let ca = fresh_ca();
    set_mode(&ca.path().join("ca.key"), 0o644);
    let out = tempfile::tempdir().expect("out");
    std::fs::write(out.path().join("server.key"), b"old-key").expect("stage key");
    let ran = issue_server(ca.path(), out.path());
    assert_refused(&ran, &[out.path().join("server.key")]);
    assert!(
        !ran.stderr.contains(s(&ca.path().join("ca.key"))),
        "the CA key was read first: {}",
        ran.stderr
    );
    assert_eq!(
        std::fs::read(out.path().join("server.key")).expect("key"),
        b"old-key"
    );
}

#[test]
fn r5s2_issue_server_checks_its_output_before_reading_the_ca_cert() {
    let missing = tempfile::tempdir().expect("no ca here");
    let out = tempfile::tempdir().expect("out");
    std::fs::write(out.path().join("server.key"), b"old-key").expect("stage key");
    let ran = issue_server(missing.path(), out.path());
    assert_refused(&ran, &[out.path().join("server.key")]);
    assert!(
        !ran.stderr.contains(s(&missing.path().join("ca.crt"))),
        "the CA cert was read first: {}",
        ran.stderr
    );
}

// ── issue-client ────────────────────────────────────────────────────────────

#[test]
fn r4_issue_client_keeps_its_earlier_output() {
    let ca = fresh_ca();
    let out = tempfile::tempdir().expect("out");
    assert!(
        issue_client(ca.path(), "agent-7", out.path()).ok,
        "first issue-client"
    );
    let cert = std::fs::read(out.path().join("agent-7.crt")).expect("cert");
    let key = std::fs::read(out.path().join("agent-7.key")).expect("key");
    let ran = issue_client(ca.path(), "agent-7", out.path());
    assert_refused(
        &ran,
        &[
            out.path().join("agent-7.crt"),
            out.path().join("agent-7.key"),
        ],
    );
    assert_eq!(
        std::fs::read(out.path().join("agent-7.crt")).expect("cert"),
        cert
    );
    assert_eq!(
        std::fs::read(out.path().join("agent-7.key")).expect("key"),
        key
    );
    assert_eq!(names(out.path()), ["agent-7.crt", "agent-7.key"]);
}

#[test]
fn r4b_a_client_named_ca_cannot_replace_the_ca() {
    let ca = fresh_ca();
    #[cfg(unix)]
    set_mode(ca.path(), 0o755);
    let cert = std::fs::read(ca.path().join("ca.crt")).expect("ca cert");
    let key = std::fs::read(ca.path().join("ca.key")).expect("ca key");
    let ran = issue_client(ca.path(), "ca", ca.path());
    assert_refused(&ran, &[ca.path().join("ca.crt"), ca.path().join("ca.key")]);
    assert_eq!(
        std::fs::read(ca.path().join("ca.crt")).expect("ca cert"),
        cert
    );
    assert_eq!(
        std::fs::read(ca.path().join("ca.key")).expect("ca key"),
        key
    );
    assert_eq!(names(ca.path()), ["ca.crt", "ca.key"]);
    #[cfg(unix)]
    assert_eq!(
        mode(ca.path()),
        0o755,
        "the refusal changed the directory's mode"
    );
}

#[test]
fn r4c_the_checked_names_are_the_written_names() {
    let ca = fresh_ca();
    let out = tempfile::tempdir().expect("out");
    let first = issue_client(ca.path(), "agent one/a", out.path());
    assert!(first.ok, "first issue-client: {}", first.stderr);
    assert_eq!(names(out.path()), ["agent-one-a.crt", "agent-one-a.key"]);
    let cert = std::fs::read(out.path().join("agent-one-a.crt")).expect("cert");
    let key = std::fs::read(out.path().join("agent-one-a.key")).expect("key");
    let ran = issue_client(ca.path(), "agent one/a", out.path());
    assert_refused(
        &ran,
        &[
            out.path().join("agent-one-a.crt"),
            out.path().join("agent-one-a.key"),
        ],
    );
    assert_eq!(
        std::fs::read(out.path().join("agent-one-a.crt")).expect("cert"),
        cert
    );
    assert_eq!(
        std::fs::read(out.path().join("agent-one-a.key")).expect("key"),
        key
    );
    assert_eq!(names(out.path()), ["agent-one-a.crt", "agent-one-a.key"]);
}

#[test]
fn r4d_issue_client_keeps_a_cert_whose_key_is_gone() {
    let ca = fresh_ca();
    let out = tempfile::tempdir().expect("out");
    std::fs::write(out.path().join("agent-7.crt"), b"old-cert").expect("stage cert");
    let ran = issue_client(ca.path(), "agent-7", out.path());
    assert_refused(&ran, &[out.path().join("agent-7.crt")]);
    assert_eq!(
        std::fs::read(out.path().join("agent-7.crt")).expect("cert"),
        b"old-cert"
    );
    assert_eq!(names(out.path()), ["agent-7.crt"]);
}

#[cfg(unix)]
#[test]
fn r5c_issue_client_checks_its_output_before_reading_the_ca_key() {
    let ca = fresh_ca();
    set_mode(&ca.path().join("ca.key"), 0o644);
    let out = tempfile::tempdir().expect("out");
    std::fs::write(out.path().join("agent-7.key"), b"old-key").expect("stage key");
    let ran = issue_client(ca.path(), "agent-7", out.path());
    assert_refused(&ran, &[out.path().join("agent-7.key")]);
    assert!(
        !ran.stderr.contains(s(&ca.path().join("ca.key"))),
        "the CA key was read first: {}",
        ran.stderr
    );
    assert_eq!(
        std::fs::read(out.path().join("agent-7.key")).expect("key"),
        b"old-key"
    );
}

#[test]
fn r5c2_issue_client_checks_its_output_before_reading_the_ca_cert() {
    let missing = tempfile::tempdir().expect("no ca here");
    let out = tempfile::tempdir().expect("out");
    std::fs::write(out.path().join("agent-7.key"), b"old-key").expect("stage key");
    let ran = issue_client(missing.path(), "agent-7", out.path());
    assert_refused(&ran, &[out.path().join("agent-7.key")]);
    assert!(
        !ran.stderr.contains(s(&missing.path().join("ca.crt"))),
        "the CA cert was read first: {}",
        ran.stderr
    );
}

#[test]
fn r6_a_fresh_client_is_written_at_its_modes() {
    let ca = fresh_ca();
    let out = tempfile::tempdir().expect("out");
    #[cfg(unix)]
    let ran = run_under_umask_002(&[
        "tls",
        "issue-client",
        "--ca-cert",
        s(&ca.path().join("ca.crt")),
        "--ca-key",
        s(&ca.path().join("ca.key")),
        "--cn",
        "agent-7",
        "--out",
        s(out.path()),
    ]);
    #[cfg(not(unix))]
    let ran = issue_client(ca.path(), "agent-7", out.path());
    assert!(ran.ok, "issue-client into an empty dir: {}", ran.stderr);
    assert_eq!(names(out.path()), ["agent-7.crt", "agent-7.key"]);
    // Under umask 002 a default-mode file is 0664: only the code's own
    // narrowing gives these.
    #[cfg(unix)]
    {
        assert_eq!(mode(&out.path().join("agent-7.crt")), 0o644);
        assert_eq!(mode(&out.path().join("agent-7.key")), 0o600);
    }
}

#[test]
fn c2_clients_with_different_names_share_the_ca_directory() {
    let ca = fresh_ca();
    let cert = std::fs::read(ca.path().join("ca.crt")).expect("ca cert");
    let key = std::fs::read(ca.path().join("ca.key")).expect("ca key");
    for cn in ["agent-1", "agent-2"] {
        let ran = issue_client(ca.path(), cn, ca.path());
        assert!(ran.ok, "issue-client {cn} into the CA dir: {}", ran.stderr);
    }
    assert_eq!(
        std::fs::read(ca.path().join("ca.crt")).expect("ca cert"),
        cert
    );
    assert_eq!(
        std::fs::read(ca.path().join("ca.key")).expect("ca key"),
        key
    );
    assert_eq!(
        names(ca.path()),
        [
            "agent-1.crt",
            "agent-1.key",
            "agent-2.crt",
            "agent-2.key",
            "ca.crt",
            "ca.key"
        ]
    );
}
