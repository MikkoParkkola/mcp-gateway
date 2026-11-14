// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the captured invocation (EXEC.1, EXEC.5; test plan
//! test-plan-v2.md, ids INV-*, API-*, MAIN-1). Expected values are literals or
//! read independently by the test, never taken from the module under test.

/// Child-process harness shared by the unix and non-unix rows (test plan H2).
mod child {
    const CASE: &str = "MCPGW_EXEC_CASE";
    const MARKER: &str = "MCPGW_EXEC_MARKER";

    /// Runs `test_path` in a child of this test binary with `case` selected; it
    /// must pass AND write the marker naming the case (a mistyped path runs
    /// zero tests and writes nothing).
    pub(super) fn run_child(test_path: &str, case: &str) {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let out = output_within(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test_path, "--nocapture", "--test-threads=1"])
                .env(CASE, case)
                .env(MARKER, &marker),
            case,
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "child {case}: {:?}\n{stdout}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), case);
    }

    /// Runs `cmd` to its end with stdout and stderr captured, and fails the
    /// test by name if it is still running after 30 s (test plan H8): a wedged
    /// child must not hang the whole test job.
    pub(super) fn output_within(
        cmd: &mut std::process::Command,
        case: &str,
    ) -> std::process::Output {
        use std::io::Read as _;
        use std::process::Stdio;
        use std::time::{Duration, Instant};
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let out = std::thread::spawn(move || {
            let mut v = Vec::new();
            let _ = out.read_to_end(&mut v);
            v
        });
        let err = std::thread::spawn(move || {
            let mut v = Vec::new();
            let _ = err.read_to_end(&mut v);
            v
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child {case}: still running after 30 s; killed");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        std::process::Output {
            status,
            stdout: out.join().unwrap(),
            stderr: err.join().unwrap(),
        }
    }

    /// In a child: true when this run is `case`, after writing the marker.
    pub(super) fn is_child(case: &str) -> bool {
        if std::env::var(CASE).as_deref() != Ok(case) {
            return false;
        }
        std::fs::write(std::env::var_os(MARKER).unwrap(), case).unwrap();
        true
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use clap::Parser as _;
    use nix::sys::signal::{SigSet, Signal};

    use crate::cli::Cli;
    use crate::restart::invocation::{
        CaptureInputs, Invocation, InvocationState, UnavailableReason, capture_from,
        is_executable_regular,
    };

    fn exe(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn plain(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"data\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    fn args(items: &[&str]) -> Vec<OsString> {
        items.iter().map(|s| os(s)).collect()
    }

    fn cli(args: &[OsString]) -> Cli {
        Cli::try_parse_from(args).expect("fixture args parse")
    }

    fn inputs(args: Vec<OsString>, cwd: &Path, path_env: Option<OsString>) -> CaptureInputs {
        CaptureInputs {
            args,
            cwd: Ok(cwd.to_path_buf()),
            path_env,
            mask: SigSet::empty(),
        }
    }

    /// Capture with the real probe, the given Cli parsed from the same args.
    fn capture(args: Vec<OsString>, cwd: &Path, path_env: Option<OsString>) -> InvocationState {
        let given = cli(&args);
        capture_from(inputs(args, cwd, path_env), &given, &is_executable_regular)
    }

    fn ready(state: InvocationState) -> Invocation {
        match state {
            InvocationState::Ready(inv) => *inv,
            InvocationState::Unavailable(r) => panic!("expected Ready, got Unavailable({r:?})"),
        }
    }

    fn reason(state: InvocationState) -> UnavailableReason {
        match state {
            InvocationState::Ready(inv) => panic!("expected Unavailable, got Ready({inv:?})"),
            InvocationState::Unavailable(r) => r,
        }
    }

    fn bytes(p: &Path) -> Vec<u8> {
        p.as_os_str().as_bytes().to_vec()
    }

    fn path_of(dirs: &[&Path]) -> Option<OsString> {
        std::env::join_paths(dirs).ok()
    }

    /// INV-1: the first PATH entry holding an executable regular file wins.
    #[test]
    fn inv1_bare_name_takes_the_first_path_hit() {
        let tmp = tempfile::tempdir().unwrap();
        let (d1, d2) = (tmp.path().join("d1"), tmp.path().join("d2"));
        exe(&d1.join("gw"));
        exe(&d2.join("gw"));
        let inv = ready(capture(args(&["gw"]), tmp.path(), path_of(&[&d1, &d2])));
        assert_eq!(bytes(&inv.target), bytes(&tmp.path().join("d1").join("gw")));
    }

    /// INV-2: a non-executable earlier hit is skipped.
    #[test]
    fn inv2_a_non_executable_earlier_hit_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let (d1, d2) = (tmp.path().join("d1"), tmp.path().join("d2"));
        plain(&d1.join("gw"));
        exe(&d2.join("gw"));
        let inv = ready(capture(args(&["gw"]), tmp.path(), path_of(&[&d1, &d2])));
        assert_eq!(bytes(&inv.target), bytes(&tmp.path().join("d2").join("gw")));
    }

    /// INV-2b: an executable directory is not a hit; alone it gives `NotFound`.
    #[test]
    fn inv2b_an_executable_directory_is_not_a_hit() {
        let tmp = tempfile::tempdir().unwrap();
        let (d1, d2) = (tmp.path().join("d1"), tmp.path().join("d2"));
        std::fs::create_dir_all(d1.join("gw")).unwrap();
        exe(&d2.join("gw"));
        let inv = ready(capture(args(&["gw"]), tmp.path(), path_of(&[&d1, &d2])));
        assert_eq!(bytes(&inv.target), bytes(&tmp.path().join("d2").join("gw")));
        let state = capture(args(&["gw"]), tmp.path(), path_of(&[&d1]));
        assert_eq!(reason(state), UnavailableReason::NotFound);
    }

    /// INV-3: relative and empty PATH entries are anchored to the startup cwd.
    #[test]
    fn inv3_relative_and_empty_path_entries_anchor_to_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        exe(&tmp.path().join("rel").join("gw"));
        let inv = ready(capture(
            args(&["gw"]),
            tmp.path(),
            Some(os(":rel:/nonexistent-dir")),
        ));
        let mut want = tmp.path().as_os_str().as_bytes().to_vec();
        want.extend_from_slice(b"/rel/gw");
        assert_eq!(bytes(&inv.target), want);

        let tmp2 = tempfile::tempdir().unwrap();
        exe(&tmp2.path().join("gw"));
        let inv = ready(capture(
            args(&["gw"]),
            tmp2.path(),
            Some(os(":/nonexistent-dir")),
        ));
        let mut want = tmp2.path().as_os_str().as_bytes().to_vec();
        want.extend_from_slice(b"/gw");
        assert_eq!(bytes(&inv.target), want);
    }

    /// INV-3b: PATH "" is one empty entry (the cwd); an unset PATH searches nothing.
    #[test]
    fn inv3b_unset_path_searches_nothing_and_empty_path_is_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        exe(&tmp.path().join("gw"));
        let inv = ready(capture(args(&["gw"]), tmp.path(), Some(os(""))));
        let mut want = tmp.path().as_os_str().as_bytes().to_vec();
        want.extend_from_slice(b"/gw");
        assert_eq!(bytes(&inv.target), want);
        assert_eq!(
            reason(capture(args(&["gw"]), tmp.path(), None)),
            UnavailableReason::NotFound
        );
        assert_eq!(
            reason(capture(args(&["sh"]), tmp.path(), None)),
            UnavailableReason::NotFound
        );
    }

    /// INV-4: a slash spelling is anchored to the cwd and kept byte for byte.
    #[test]
    fn inv4_slash_spellings_are_kept_as_spelled() {
        let tmp = tempfile::tempdir().unwrap();
        exe(&tmp.path().join("bin").join("gw"));
        for spelled in ["./bin/gw", "bin/../bin/gw"] {
            let inv = ready(capture(args(&[spelled]), tmp.path(), None));
            let mut want = tmp.path().as_os_str().as_bytes().to_vec();
            want.push(b'/');
            want.extend_from_slice(spelled.as_bytes());
            assert_eq!(bytes(&inv.target), want, "{spelled}");
        }
    }

    /// INV-4b: a slash spelling must name an executable regular file.
    #[test]
    fn inv4b_slash_spelling_to_a_non_executable_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        plain(&tmp.path().join("plain"));
        std::fs::create_dir_all(tmp.path().join("dir")).unwrap();
        for spelled in ["./missing", "./plain", "./dir"] {
            let state = capture(args(&[spelled]), tmp.path(), None);
            assert_eq!(reason(state), UnavailableReason::NotExecutable, "{spelled}");
        }
    }

    /// INV-5: a symlink is kept as the link path, not its target.
    #[test]
    fn inv5_a_symlink_is_kept_as_spelled() {
        let tmp = tempfile::tempdir().unwrap();
        exe(&tmp.path().join("real").join("gw"));
        let link = tmp.path().join("link-to-gw");
        std::os::unix::fs::symlink(tmp.path().join("real").join("gw"), &link).unwrap();
        let inv = ready(capture(
            vec![link.clone().into_os_string()],
            tmp.path(),
            None,
        ));
        assert_eq!(bytes(&inv.target), bytes(&link));
    }

    fn found_path(tmp: &Path) -> Option<OsString> {
        exe(&tmp.join("bin").join("gw"));
        path_of(&[&tmp.join("bin")])
    }

    /// INV-6: non-UTF-8 argv0 and tail bytes survive, through `for_test` and capture.
    #[test]
    fn inv6_non_utf8_bytes_round_trip() {
        let inv = Invocation::for_test(
            OsString::from_vec(b"g\xffw".to_vec()),
            vec![OsString::from_vec(b"--x=\xfe".to_vec())],
            PathBuf::from("/w"),
            PathBuf::from("/w/gw"),
            SigSet::empty(),
        );
        assert_eq!(inv.argv0.as_bytes(), b"g\xffw");
        assert_eq!(inv.tail.len(), 1);
        assert_eq!(inv.tail[0].as_bytes(), b"--x=\xfe");

        let tmp = tempfile::tempdir().unwrap();
        let config = OsString::from_vec(b"/tmp/c\xff.toml".to_vec());
        let a = vec![os("gw"), os("--config"), config];
        let inv = ready(capture(a, tmp.path(), found_path(tmp.path())));
        assert_eq!(inv.tail.len(), 2);
        assert_eq!(inv.tail[0].as_bytes(), b"--config");
        assert_eq!(inv.tail[1].as_bytes(), b"/tmp/c\xff.toml");
    }

    /// INV-6 (every unix): a non-UTF-8 absolute argv0 keeps its bytes through
    /// capture; an always-true probe stands in for the file APFS cannot hold.
    #[test]
    fn inv6_non_utf8_argv0_kept_by_capture() {
        let tmp = tempfile::tempdir().unwrap();
        let argv0 = OsString::from_vec(b"/w/g\xffw".to_vec());
        let a = vec![argv0];
        let given = cli(&a);
        let inv = ready(capture_from(
            inputs(a, tmp.path(), None),
            &given,
            &|_: &Path| true,
        ));
        assert_eq!(inv.argv0.as_bytes(), b"/w/g\xffw");
        assert_eq!(bytes(&inv.target), b"/w/g\xffw".to_vec());
    }

    /// INV-6 (Linux: APFS refuses non-UTF-8 names): a non-UTF-8 argv0 naming a
    /// real executable is captured byte for byte.
    #[cfg(target_os = "linux")]
    #[test]
    fn inv6_non_utf8_argv0_through_capture() {
        let tmp = tempfile::tempdir().unwrap();
        let mut name = tmp.path().as_os_str().as_bytes().to_vec();
        name.extend_from_slice(b"/g\xffw");
        let path = PathBuf::from(OsString::from_vec(name.clone()));
        exe(&path);
        let inv = ready(capture(vec![path.into_os_string()], tmp.path(), None));
        assert_eq!(inv.argv0.as_bytes(), name.as_slice());
        assert_eq!(bytes(&inv.target), name);
    }

    /// INV-7: no argv0, or an empty one.
    #[test]
    fn inv7_missing_or_empty_argv0() {
        let tmp = tempfile::tempdir().unwrap();
        let given = cli(&args(&["gw"]));
        for a in [Vec::new(), vec![os("")]] {
            let state = capture_from(
                inputs(a, tmp.path(), found_path(tmp.path())),
                &given,
                &is_executable_regular,
            );
            assert_eq!(reason(state), UnavailableReason::NoArgv0);
        }
    }

    /// INV-8: a bare name on no PATH entry; no `current_exe` fallback.
    #[test]
    fn inv8_bare_name_found_nowhere() {
        let tmp = tempfile::tempdir().unwrap();
        let empty = tmp.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let state = capture(args(&["no-such-gw"]), tmp.path(), path_of(&[&empty]));
        assert_eq!(reason(state), UnavailableReason::NotFound);
    }

    /// INV-9: a getcwd error disables restart for bare and absolute argv0 alike.
    #[test]
    fn inv9_cwd_error_disables_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let path_env = found_path(tmp.path());
        let abs = tmp.path().join("bin").join("gw").into_os_string();
        for argv0 in [os("gw"), abs] {
            let a = vec![argv0];
            let given = cli(&a);
            let mut i = inputs(a, tmp.path(), path_env.clone());
            i.cwd = Err(std::io::Error::from_raw_os_error(nix::libc::ENOENT));
            let state = capture_from(i, &given, &is_executable_regular);
            assert_eq!(reason(state), UnavailableReason::Cwd);
        }
    }

    /// INV-10: each stop signal blocked at entry disables restart, naming it;
    /// another blocked signal does not (A1).
    #[test]
    fn inv10_blocked_stop_signal_disables_restart() {
        let tmp = tempfile::tempdir().unwrap();
        for sig in [
            Signal::SIGINT,
            Signal::SIGTERM,
            Signal::SIGHUP,
            Signal::SIGPIPE,
        ] {
            let a = args(&["gw"]);
            let given = cli(&a);
            let mut i = inputs(a, tmp.path(), found_path(tmp.path()));
            i.mask.add(sig);
            let state = capture_from(i, &given, &is_executable_regular);
            assert_eq!(
                reason(state),
                UnavailableReason::BlockedSignal(sig),
                "{sig}"
            );
        }
        let a = args(&["gw"]);
        let given = cli(&a);
        let mut i = inputs(a, tmp.path(), found_path(tmp.path()));
        i.mask.add(Signal::SIGUSR1);
        ready(capture_from(i, &given, &is_executable_regular));
    }

    /// INV-10b: a Ready capture stores the entry mask and cwd it was given.
    #[test]
    fn inv10b_ready_stores_mask_and_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let a = args(&["gw"]);
        let given = cli(&a);
        let mut i = inputs(a, tmp.path(), found_path(tmp.path()));
        i.mask.add(Signal::SIGUSR1);
        let mut want = SigSet::empty();
        want.add(Signal::SIGUSR1);
        let inv = ready(capture_from(i, &given, &is_executable_regular));
        assert_eq!(inv.entry_mask, want);
        assert_eq!(bytes(&inv.cwd), bytes(tmp.path()));
    }

    /// INV-10c: the mask reader returns the calling thread's real mask.
    #[test]
    fn inv10c_current_thread_mask_reads_the_thread() {
        std::thread::spawn(|| {
            // Set both signals here, so the row does not depend on the mask the
            // test harness thread happened to pass on.
            let mut unblock = SigSet::empty();
            unblock.add(Signal::SIGUSR2);
            unblock.thread_unblock().unwrap();
            let mut block = SigSet::empty();
            block.add(Signal::SIGUSR1);
            block.thread_block().unwrap();
            let mask = crate::restart::invocation::current_thread_mask();
            assert!(mask.contains(Signal::SIGUSR1));
            assert!(!mask.contains(Signal::SIGUSR2));
        })
        .join()
        .unwrap();
    }

    /// INV-11: a subcommand stops before any PATH walk; the control walks it.
    #[test]
    fn inv11_not_serve_stops_before_the_path_walk() {
        let tmp = tempfile::tempdir().unwrap();
        let path_env = found_path(tmp.path());
        let calls = std::cell::Cell::new(0_u32);
        let probe = |p: &Path| {
            calls.set(calls.get() + 1);
            is_executable_regular(p)
        };
        let a = args(&["gw", "tool", "completions", "bash"]);
        let given = cli(&a);
        let state = capture_from(inputs(a, tmp.path(), path_env.clone()), &given, &probe);
        assert_eq!(reason(state), UnavailableReason::NotServe);
        assert_eq!(calls.get(), 0, "NotServe walked PATH");

        let a = args(&["gw"]);
        let given = cli(&a);
        ready(capture_from(
            inputs(a, tmp.path(), path_env),
            &given,
            &probe,
        ));
        assert!(calls.get() > 0, "the control never probed");
    }

    /// A serve field's name and the change that makes only that field differ.
    type FieldChange = (&'static str, fn(&mut Cli));

    /// INV-12: a given Cli differing from the reparse in any one serve field is
    /// Embedded; the identical one is Ready (A1).
    #[test]
    fn inv12_each_serve_field_difference_is_embedded() {
        let tmp = tempfile::tempdir().unwrap();
        let path_env = found_path(tmp.path());
        // Each row changes exactly one field of the parsed value, so it dies when
        // that field's comparison is dropped, whatever clap's defaults link.
        let differing: [FieldChange; 7] = [
            ("config", |c| c.config = Some(PathBuf::from("/other.toml"))),
            ("port", |c| c.port = Some(1)),
            ("host", |c| c.host = Some("192.0.2.1".into())),
            ("log_level", |c| c.log_level = "trace".into()),
            ("log_format", |c| c.log_format = Some("json".into())),
            ("no_meta_mcp", |c| c.no_meta_mcp = !c.no_meta_mcp),
            ("protocol_revision_window", |c| {
                c.protocol_revision_window = Some(crate::config::ProtocolRevisionWindow::Record);
            }),
        ];
        let base = format!("{:?}", cli(&args(&["gw"])));
        for (field, change) in differing {
            let mut given = cli(&args(&["gw"]));
            change(&mut given);
            assert_ne!(format!("{given:?}"), base, "premise: {field} changed");
            let state = capture_from(
                inputs(args(&["gw"]), tmp.path(), path_env.clone()),
                &given,
                &is_executable_regular,
            );
            assert_eq!(reason(state), UnavailableReason::Embedded, "{field}");
        }
        let given = cli(&args(&["gw"]));
        ready(capture_from(
            inputs(args(&["gw"]), tmp.path(), path_env),
            &given,
            &is_executable_regular,
        ));
    }

    /// INV-12b: the subcommand field in each direction.
    #[test]
    fn inv12b_subcommand_on_either_side() {
        let tmp = tempfile::tempdir().unwrap();
        let path_env = found_path(tmp.path());
        let sub = args(&["gw", "tool", "completions", "bash"]);
        let given = cli(&sub);
        let state = capture_from(
            inputs(args(&["gw"]), tmp.path(), path_env.clone()),
            &given,
            &is_executable_regular,
        );
        assert_eq!(reason(state), UnavailableReason::NotServe);
        let given = cli(&args(&["gw"]));
        let state = capture_from(
            inputs(sub, tmp.path(), path_env),
            &given,
            &is_executable_regular,
        );
        assert_eq!(reason(state), UnavailableReason::Embedded);
    }

    /// INV-13: process args that do not parse are Embedded.
    #[test]
    fn inv13_unparseable_process_args_are_embedded() {
        let tmp = tempfile::tempdir().unwrap();
        let given = cli(&args(&["gw"]));
        let a = args(&["gw", "--port", "notanumber"]);
        let state = capture_from(
            inputs(a, tmp.path(), found_path(tmp.path())),
            &given,
            &is_executable_regular,
        );
        assert_eq!(reason(state), UnavailableReason::Embedded);
    }

    fn fixture(argv0: &str, tail: &[&str], cwd: &str, target: &str) -> Invocation {
        Invocation::for_test(
            os(argv0),
            args(tail),
            PathBuf::from(cwd),
            PathBuf::from(target),
            SigSet::empty(),
        )
    }

    fn hex(d: crate::restart::invocation::InvocationDigest) -> String {
        use std::fmt::Write as _;
        d.bytes().iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// INV-16: the encoding layout, pinned by a vector computed outside the module.
    #[test]
    fn inv16_digest_golden_vector() {
        let inv = fixture("gw", &["--port", "1"], "/w", "/w/gw");
        assert_eq!(
            hex(inv.digest()),
            "c622c4e87635c33b39e12b8e7e2a676876db9f2ae46b0dc94bc6c0b2caf642f3"
        );
    }

    /// INV-17: length prefixes and the tail count separate shifted boundaries.
    #[test]
    fn inv17_boundary_shifts_change_the_digest() {
        let pairs = [
            (
                fixture("gw", &["ab", "c"], "/w", "/w/gw"),
                fixture("gw", &["a", "bc"], "/w", "/w/gw"),
            ),
            (
                fixture("a", &["b"], "/w", "/w/gw"),
                fixture("ab", &[], "/w", "/w/gw"),
            ),
            (
                fixture("gw", &[], "/w", "/w/gw"),
                fixture("gw", &[""], "/w", "/w/gw"),
            ),
        ];
        for (i, (x, y)) in pairs.iter().enumerate() {
            assert_ne!(x.digest(), y.digest(), "pair {i}");
        }
    }

    /// INV-18: PATH is not hashed (two PATHs, one target, one digest); cwd is.
    #[test]
    fn inv18_path_excluded_cwd_included() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        exe(&bin.join("gw"));
        let other = tmp.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        let one = ready(capture(args(&["gw"]), tmp.path(), path_of(&[&bin])));
        let two = ready(capture(args(&["gw"]), tmp.path(), path_of(&[&other, &bin])));
        assert_eq!(
            bytes(&one.target),
            bytes(&two.target),
            "premise: same target"
        );
        assert_eq!(one.digest(), two.digest());
        let a = fixture("gw", &[], "/w", "/w/gw");
        let b = fixture("gw", &[], "/v", "/w/gw");
        assert_ne!(a.digest(), b.digest());
    }

    /// INV-19: Debug output never shows argv, cwd or target.
    #[test]
    fn inv19_debug_is_redacted() {
        let inv = fixture("ARGV0MARK", &["TAILMARK"], "/CWDMARK", "/TARGETMARK");
        let text = format!("{inv:?}");
        for mark in ["ARGV0MARK", "TAILMARK", "CWDMARK", "TARGETMARK"] {
            assert!(!text.contains(mark), "{mark} in {text}");
        }
        assert_eq!(format!("{:?}", inv.digest()), "InvocationDigest(..)");
    }

    /// INV-20: the target's identity, read at call time, following symlinks.
    #[test]
    fn inv20_target_file_id() {
        use std::os::unix::fs::MetadataExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("gw");
        exe(&real);
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // Read independently of the module: (dev, ino, size, ctime, ctime_nsec).
        let id = |p: &Path| {
            let m = std::fs::metadata(p).unwrap();
            (m.dev(), m.ino(), m.size(), m.ctime(), m.ctime_nsec())
        };
        let fid = |f: crate::restart::invocation::FileId| {
            (f.dev, f.ino, f.size, f.ctime_sec, f.ctime_nsec)
        };
        let state = capture(vec![real.clone().into_os_string()], tmp.path(), None);
        let got = state.target_file_id().expect("Ready").unwrap();
        assert_eq!(fid(got), id(&real));

        let via = capture(vec![link.into_os_string()], tmp.path(), None);
        let got = via.target_file_id().expect("Ready").unwrap();
        assert_eq!(fid(got), id(&real), "link resolves to its target");

        // Rewritten in place: same inode, new content of another length (ctime
        // alone could share a clock tick with the first write).
        let before = id(&real);
        std::fs::write(&real, b"#!/bin/sh\n# rewritten in place, longer\n").unwrap();
        assert_eq!(id(&real).1, before.1, "premise: same inode");
        let got = state.target_file_id().expect("Ready").unwrap();
        assert_ne!(fid(got), before, "an in-place rewrite changes the file id");
        assert_eq!(fid(got), id(&real));

        let before = id(&real);
        let fresh = tmp.path().join("fresh");
        exe(&fresh);
        std::fs::rename(&fresh, &real).unwrap();
        let got = state.target_file_id().expect("Ready").unwrap();
        assert_ne!(fid(got).1, before.1, "replaced file keeps the old inode");
        assert_eq!(fid(got), id(&real));

        std::fs::remove_file(&real).unwrap();
        let err = state.target_file_id().expect("Ready").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);

        let off = InvocationState::Unavailable(UnavailableReason::NotFound);
        assert!(off.target_file_id().is_none());
        assert!(off.digest().is_none());
    }

    /// INV-14: before capture the global reads `NotCaptured` and stays unset.
    #[test]
    fn inv14_before_capture_is_not_captured() {
        super::child::run_child("restart::invocation_tests::unix::inv14_child", "inv14");
    }

    #[test]
    fn inv14_child() {
        use crate::restart::invocation::{capture_and_install, invocation};
        if !super::child::is_child("inv14") {
            return;
        }
        assert!(matches!(
            invocation(),
            InvocationState::Unavailable(UnavailableReason::NotCaptured)
        ));
        let tmp = tempfile::tempdir().unwrap();
        let a = args(&["gw"]);
        let given = cli(&a);
        capture_and_install(inputs(a, tmp.path(), found_path(tmp.path())), &given);
        assert!(invocation().digest().is_some(), "{:?}", invocation());
    }

    /// INV-15: the first capture wins.
    #[test]
    fn inv15_first_capture_wins() {
        super::child::run_child("restart::invocation_tests::unix::inv15_child", "inv15");
    }

    #[test]
    fn inv15_child() {
        use crate::restart::invocation::{capture_and_install, invocation};
        if !super::child::is_child("inv15") {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let path_env = found_path(tmp.path());
        let (a1, a2) = (args(&["gw"]), args(&["gw", "--port", "1"]));
        let (g1, g2) = (cli(&a1), cli(&a2));
        let d1 = ready(capture_from(
            inputs(a1.clone(), tmp.path(), path_env.clone()),
            &g1,
            &is_executable_regular,
        ))
        .digest();
        let d2 = ready(capture_from(
            inputs(a2.clone(), tmp.path(), path_env.clone()),
            &g2,
            &is_executable_regular,
        ))
        .digest();
        assert_ne!(d1, d2, "premise: the two captures differ");
        capture_and_install(inputs(a1, tmp.path(), path_env.clone()), &g1);
        capture_and_install(inputs(a2, tmp.path(), path_env), &g2);
        assert_eq!(invocation().digest(), Some(d1));
    }
}

/// INV-21: restart is guidance-only off unix; the accessors answer None.
#[cfg(not(unix))]
mod non_unix {
    use clap::Parser as _;

    use crate::cli::Cli;
    use crate::restart::invocation::{
        CaptureInputs, InvocationState, UnavailableReason, capture_and_install, invocation,
    };

    #[test]
    fn inv21_capture_installs_unsupported() {
        super::child::run_child("restart::invocation_tests::non_unix::inv21_child", "inv21");
    }

    #[test]
    fn inv21_child() {
        if !super::child::is_child("inv21") {
            return;
        }
        assert!(matches!(
            invocation(),
            InvocationState::Unavailable(UnavailableReason::NotCaptured)
        ));
        let args = vec![std::ffi::OsString::from("gw")];
        let given = Cli::try_parse_from(&args).unwrap();
        let inputs = CaptureInputs {
            args,
            cwd: std::env::current_dir(),
            path_env: None,
        };
        capture_and_install(inputs, &given);
        assert!(matches!(
            invocation(),
            InvocationState::Unavailable(UnavailableReason::Unsupported)
        ));
        assert!(invocation().digest().is_none());
        assert!(invocation().target_file_id().is_none());
    }
}
