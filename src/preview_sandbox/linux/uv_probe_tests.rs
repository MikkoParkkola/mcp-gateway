// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the uv fetch's launcher probe (its test plan, U-place
//! and U-uv-place): pure, on fixture trees in each row's own temp dir.

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use super::super::elf_fixture::{placement_elfs, sh_elf};
use super::super::{ProgramBind, READ_ONLY, program_bind};
use super::{
    PythonPlace, check_uv, narrow_place, place_python, place_uv, python_real, python_xy, uv_beside,
};
use crate::preview_sandbox::Refusal;

/// A file that is not a script: the probe reads only its first two bytes.
fn binary(path: &Path) {
    std::fs::create_dir_all(path.parent().expect("dir")).expect("dir");
    std::fs::write(path, b"\x7fELF").expect("binary");
}

/// A shell script at `path`.
fn script(path: &Path) {
    std::fs::create_dir_all(path.parent().expect("dir")).expect("dir");
    std::fs::write(path, "#!/bin/sh\nexit 0\n").expect("script");
}

fn s(path: &Path) -> String {
    path.to_str().expect("UTF-8").to_owned()
}

fn system() -> Vec<String> {
    READ_ONLY.iter().map(ToString::to_string).collect()
}

/// A Python 3.12 prefix at `prefix`: the placement ELFs, the stdlib with
/// both package directories, and the Debian-style `lib/python3/dist-packages`.
/// Returns the linked and the unlinked interpreter.
fn prefix_tree(prefix: &Path) -> (PathBuf, PathBuf) {
    let stdlib = prefix.join("lib/python3.12");
    for dir in ["site-packages", "dist-packages"] {
        std::fs::create_dir_all(stdlib.join(dir)).expect("package dir");
    }
    std::fs::write(stdlib.join("os.py"), "").expect("os.py");
    std::fs::create_dir_all(prefix.join("lib/python3/dist-packages")).expect("python3 dir");
    let (_, linked, unlinked) = placement_elfs(&prefix.join("lib"), &prefix.join("bin"));
    (linked, unlinked)
}

/// The masks every layout of a 3.12 prefix gets.
fn masks(prefix: &Path) -> Vec<String> {
    vec![
        s(&prefix.join("lib/python3.12/site-packages")),
        s(&prefix.join("lib/python3.12/dist-packages")),
        s(&prefix.join("lib/python3/dist-packages")),
    ]
}

/// U-place, kills m-tree-bind, m-always-libpython and m-no-mask: a runtime
/// tree (pyenv) and a prefix outside the known trees each get exactly the
/// interpreter's real file, its stdlib dir and, only when the binary links
/// it, libpython, never the tree; every package directory is masked.
#[test]
fn u_place_binds_only_the_interpreter_its_stdlib_and_its_libpython() {
    let root = tempfile::tempdir().expect("root");
    for prefix in [
        root.path().join(".pyenv/versions/3.12.1"),
        root.path().join("usr/local"),
    ] {
        let (linked, unlinked) = prefix_tree(&prefix);
        let stdlib = prefix.join("lib/python3.12");
        assert_eq!(
            place_python(&linked, (3, 12), &system()).expect("linked"),
            PythonPlace {
                read_only: vec![
                    s(&linked),
                    s(&stdlib),
                    s(&prefix.join("lib/libpython3.12.so.1.0")),
                ],
                bound_back: Vec::new(),
                masks: masks(&prefix),
            },
            "linked, {}",
            prefix.display()
        );
        assert_eq!(
            place_python(&unlinked, (3, 12), &system()).expect("unlinked"),
            PythonPlace {
                read_only: vec![s(&unlinked), s(&stdlib)],
                bound_back: Vec::new(),
                masks: masks(&prefix),
            },
            "unlinked, {}",
            prefix.display()
        );
    }
}

/// U-place, the system layout: the system root already shows the host's
/// interpreter, so nothing is bound, and its package directories, listed
/// from the host here, are masked.
#[test]
fn u_place_a_system_interpreter_binds_nothing_and_masks_its_packages() {
    let real = std::fs::canonicalize("/usr/bin/python3").expect("the host has /usr/bin/python3");
    let name = real
        .file_name()
        .and_then(|n| n.to_str())
        .expect("a file name");
    let (x, y) = name
        .strip_prefix("python")
        .and_then(|v| v.split_once('.'))
        .and_then(|(x, y)| Some((x.parse().ok()?, y.parse().ok()?)))
        .expect("the real file is named pythonX.Y");
    let candidates = [
        format!("/usr/lib/python{x}.{y}/site-packages"),
        format!("/usr/lib/python{x}.{y}/dist-packages"),
        "/usr/lib/python3/dist-packages".to_owned(),
    ];
    let present: Vec<String> = candidates
        .into_iter()
        .filter(|d| Path::new(d).is_dir())
        .collect();
    assert_eq!(
        place_python(&real, (x, y), &system()).expect("system"),
        PythonPlace {
            read_only: Vec::new(),
            bound_back: Vec::new(),
            masks: present,
        }
    );
}

/// U-place, kills m-shim-accepted: a version-manager shim (a script) found
/// as `python3` refuses by its path.
#[test]
fn u_place_a_script_interpreter_refuses_by_name() {
    let root = tempfile::tempdir().expect("root");
    let shim = root.path().join("shims/python3");
    script(&shim);
    let refusal = python_real(&shim).expect_err("a script refuses");
    assert_eq!(
        refusal,
        Refusal::Step(format!("placing python3 ({} is a script)", shim.display()))
    );
}

/// U-uv-place, kills m-script-uv: a `uv` that is a script refuses by name.
#[test]
fn u_uv_place_a_script_uv_refuses_by_name() {
    let root = tempfile::tempdir().expect("root");
    binary(&root.path().join("bin/uvx"));
    script(&root.path().join("bin/uv"));
    let refusal = uv_beside(&root.path().join("bin/uvx")).expect_err("a script refuses");
    assert_eq!(
        refusal,
        Refusal::Step(format!(
            "placing uv ({} is a script)",
            root.path().join("bin/uv").display()
        ))
    );
}

/// U-uv-place, kills m-uvx-raw: a `uvx` symlink resolves `uv` beside its
/// real file, not beside the link (a decoy `uv` sits there).
#[test]
fn u_uv_place_uv_is_found_beside_the_real_uvx() {
    let root = tempfile::tempdir().expect("root");
    binary(&root.path().join("real/uvx"));
    binary(&root.path().join("real/uv"));
    binary(&root.path().join("link/uv"));
    symlink(root.path().join("real/uvx"), root.path().join("link/uvx")).expect("link");
    let real = std::fs::canonicalize(root.path().join("real")).expect("real dir");
    assert_eq!(
        uv_beside(&root.path().join("link/uvx")).expect("found"),
        real.join("uv")
    );
}

/// U-uv-place, kills m-lone-uv-tree: a lone `uv` outside the known trees is
/// bound as that one file by the program rule, never its directory.
#[test]
fn u_uv_place_a_lone_uv_binds_as_a_file() {
    let root = tempfile::tempdir().expect("root");
    let uv = root.path().join("tools/uv");
    binary(&uv);
    let real = std::fs::canonicalize(&uv).expect("real");
    assert_eq!(
        program_bind(&real, &system()),
        ProgramBind::File(real.clone())
    );
}

/// A uv stand-in in `dir` answering `--version` with `answer` (a shell
/// command), after writing its environment to `dir/version.env`.
fn uv_answering(dir: &Path, answer: &str) -> PathBuf {
    let env = dir.join("version.env");
    sh_elf(
        dir,
        "uv",
        &format!(
            "/usr/bin/tr '\\0' '\\n' < /proc/$$/environ > '{}'; {answer}",
            env.display()
        ),
    )
}

/// U-floor, kills m-floor and m-version-env: 0.13.0 refuses naming both
/// versions, 0.13.1 and 0.14.0 pass, a malformed answer refuses naming it,
/// and the call sees an empty environment.
#[test]
fn u_floor_uv_below_0_13_1_refuses_and_the_call_has_no_environment() {
    for (answer, want) in [
        (
            "echo 'uv 0.13.0 (aarch64-unknown-linux-gnu)'",
            Err(Refusal::Step("uv 0.13.0 is older than 0.13.1".into())),
        ),
        ("echo 'uv 0.13.1 (aarch64-unknown-linux-gnu)'", Ok(())),
        ("echo 'uv 0.14.0 (x86_64-unknown-linux-gnu)'", Ok(())),
        (
            "echo 'uv x.y'",
            Err(Refusal::Step("reading uv's version (\"uv x.y\")".into())),
        ),
    ] {
        let dir = tempfile::tempdir().expect("dir");
        let uv = uv_answering(dir.path(), answer);
        assert_eq!(check_uv(&uv), want, "{answer}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("version.env")).ok(),
            Some(String::new()),
            "{answer}: the call saw an environment"
        );
    }
}

/// U-floor, the 10 s bound on both sides: an answer after 2 s passes; a uv
/// that never answers refuses no earlier than 10 s and no later than 30 s.
#[test]
fn u_floor_the_version_call_waits_10_s_and_no_longer() {
    let dir = tempfile::tempdir().expect("dir");
    let slow = uv_answering(
        dir.path(),
        "sleep 2; echo 'uv 0.13.1 (x86_64-unknown-linux-gnu)'",
    );
    assert_eq!(check_uv(&slow), Ok(()), "a 2 s answer");
    let dir = tempfile::tempdir().expect("dir");
    let silent = uv_answering(dir.path(), "exec sleep 60");
    let begun = std::time::Instant::now();
    let refused = check_uv(&silent);
    let took = begun.elapsed();
    assert_eq!(
        refused,
        Err(Refusal::Step(
            "uv --version did not answer within 10 s".into()
        ))
    );
    assert!(
        took >= std::time::Duration::from_secs(10),
        "refused after {took:?}"
    );
    assert!(
        took <= std::time::Duration::from_secs(30),
        "refused after {took:?}"
    );
}

/// An interpreter stand-in in `dir` that records its argv and environment
/// size to `dir/host.spawns`, then prints `answer`.
fn python_answering(dir: &Path, answer: &str) -> PathBuf {
    let log = dir.join("host.spawns");
    sh_elf(
        dir,
        "python3.12",
        &format!(
            "n=$(/usr/bin/tr -cd '\\0' < /proc/$$/environ | /usr/bin/wc -c); \
             p=${{HTTPS_PROXY+set}}; \
             {{ printf 'proxy=%s env=%s' \"${{p:-unset}}\" \"$n\"; \
             for a in \"$0\" \"$@\"; do printf '\\t%s' \"$a\"; done; printf '\\n'; }} >> '{}'; \
             printf '%s\\n' '{answer}'",
            log.display()
        ),
    )
}

/// U-probe, kills m-probe-site, m-probe-env and m-fixed-xy: the probe runs
/// the interpreter as `-S -I -c <the version script>` with no environment,
/// takes X.Y from its answer, and refuses an answer it cannot read.
#[test]
fn u_probe_runs_the_interpreter_without_site_and_reads_its_version() {
    for (answer, want) in [
        ("3.12", Ok((3, 12))),
        ("3.13", Ok((3, 13))),
        (
            "nonsense",
            Err(Refusal::Step(
                "reading python3's version (\"nonsense\")".into(),
            )),
        ),
    ] {
        let dir = tempfile::tempdir().expect("dir");
        let python = python_answering(dir.path(), answer);
        assert_eq!(python_xy(&python), want, "{answer}");
        // Absent when the interpreter never ran: an empty record fails below.
        let log = std::fs::read_to_string(dir.path().join("host.spawns")).unwrap_or_default();
        let fields: Vec<&str> = log.trim_end_matches('\n').split('\t').collect();
        assert_eq!(
            fields,
            [
                "proxy=unset env=0",
                python.to_str().expect("UTF-8"),
                "-S",
                "-I",
                "-c",
                "import sys; print('%d.%d' % sys.version_info[:2])",
            ],
            "{answer}"
        );
    }
}

/// U-uv-place (code review r1), kills m-uv-program-rule: uv is bound as its
/// real file alone wherever it lives: inside a runtime tree (never the
/// tree), under `/usr/local` (the file bound back, never `bin` and `lib`),
/// as a lone file, and not at all under the system root.
#[test]
fn u_uv_place_uv_binds_its_real_file_alone() {
    let root = tempfile::tempdir().expect("root");
    let in_tree = root.path().join(".pyenv/versions/3.12.1/bin/uv");
    binary(&in_tree);
    assert_eq!(
        place_uv(&in_tree, &system()).expect("runtime tree"),
        PythonPlace {
            read_only: vec![s(&in_tree)],
            ..PythonPlace::default()
        }
    );
    // Classified by its path alone: nothing is created under /usr/local.
    let usr_local = place_uv(Path::new("/usr/local/bin/uv"), &system()).expect("usr local");
    assert_eq!(
        usr_local,
        PythonPlace {
            bound_back: vec!["/usr/local/bin/uv".to_owned()],
            ..PythonPlace::default()
        }
    );
    for dir in ["/usr/local/bin", "/usr/local/lib"] {
        assert!(
            !usr_local.bound_back.iter().any(|b| b == dir),
            "{dir} is bound back"
        );
    }
    let lone = root.path().join("tools/uv");
    binary(&lone);
    assert_eq!(
        place_uv(&lone, &system()).expect("lone"),
        PythonPlace {
            read_only: vec![s(&lone)],
            ..PythonPlace::default()
        }
    );
    assert_eq!(
        place_uv(Path::new("/usr/bin/uv"), &system()).expect("system"),
        PythonPlace::default()
    );
    // Under a masked secret path: refused by name (classified by its path).
    assert_eq!(
        place_uv(Path::new("/etc/ssl/private/uv"), &system()),
        Err(Refusal::Step(
            "placing uv (/etc/ssl/private/uv lies under a masked secret path)".into()
        ))
    );
}

/// Whether the process whose pid `pid_file` holds has ended. It waits on the
/// event itself through `ended_by`, which stops at the first read that shows
/// the process ended (no stat file, ESRCH as it exits, or a Z, X or x state)
/// and answers with that read. A kill takes effect asynchronously, and a loaded
/// host can take seconds to end and reap the process. The 120 s bound is set
/// by the failure mode, not by a run's timing: the rows' processes sleep
/// 300 s, so a missing kill still leaves the process alive at the bound and
/// fails the row. One still running is killed here, only so a red run leaves
/// nothing behind; the caller's assert fails it.
fn gone(pid_file: &Path) -> bool {
    let pid = std::fs::read_to_string(pid_file).expect("the process started");
    let pid = pid.trim();
    let read = || std::fs::read_to_string(format!("/proc/{pid}/stat"));
    let until = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let ended = ended_by(read, until);
    if !ended {
        let _ = std::process::Command::new("kill")
            .arg("-9")
            .arg(pid)
            .status();
    }
    ended
}

/// `ESRCH`: reading an exiting task's `/proc` file fails with this (as the
/// product reads it, `src/transport/stdio_sweep_linux.rs`).
const ESRCH: i32 = 3;

/// Polls `read` (one read of a process's `/proc/<pid>/stat`) every 50 ms
/// until it shows the process ended or `until` passes, and answers whether it
/// ended. A seam, so the rows below can feed it the reads an exiting task
/// gives. The process ended when a read shows a dead state (zombie `Z`, or
/// dead `X` or `x`) or fails with a missing file or ESRCH; any other failed
/// read says nothing, so the wait goes on. The answer is the read that ended
/// the wait: an exiting task can read as running once more after ESRCH.
fn ended_by(mut read: impl FnMut() -> std::io::Result<String>, until: std::time::Instant) -> bool {
    let mut ended = || match read() {
        Err(e) => e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(ESRCH),
        Ok(stat) => stat
            .rsplit_once(')')
            .is_some_and(|(_, rest)| rest.trim_start().starts_with(['Z', 'X', 'x'])),
    };
    loop {
        if ended() {
            return true;
        }
        if std::time::Instant::now() >= until {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// A `/proc/<pid>/stat` line for a process in `state`.
#[allow(clippy::unnecessary_wraps)] // the reads the seam takes are results
fn stat_in(state: char) -> std::io::Result<String> {
    Ok(format!("4242 (sleep) {state} 1 4242 4242 0 -1"))
}

/// One `/proc/<pid>/stat` read, as the rows feed it to `ended_by`.
type StatRead = fn() -> std::io::Result<String>;

/// The reads in `reads`, then `last` for every read after them; the count of
/// reads taken is kept in `taken`.
fn reads_then(
    reads: Vec<std::io::Result<String>>,
    last: StatRead,
    taken: &std::cell::Cell<usize>,
) -> impl FnMut() -> std::io::Result<String> + '_ {
    let mut reads = reads.into_iter();
    move || {
        taken.set(taken.get() + 1);
        reads.next().unwrap_or_else(last)
    }
}

/// The two-hit flake of 2026-11-20: reading an exiting task's `/proc` file
/// fails with ESRCH (the product reads it as gone,
/// `src/transport/stdio_sweep_linux.rs`), and the same task can read as running
/// once more before it turns zombie. ESRCH ends the wait, and the answer is
/// the one that ended it.
#[test]
fn ended_by_an_exiting_task_read_as_esrch_has_ended_even_if_it_reads_running_after() {
    let taken = std::cell::Cell::new(0);
    let reads = vec![Err(std::io::Error::from_raw_os_error(3)), stat_in('R')];
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    assert!(
        ended_by(reads_then(reads, || stat_in('R'), &taken), until),
        "an ESRCH read means the task is exiting; it was answered as alive"
    );
}

/// A read that fails for another reason (here: out of descriptors) says
/// nothing about the process, so the wait goes on until a read does.
#[test]
fn ended_by_a_failed_read_that_is_not_esrch_or_missing_keeps_waiting() {
    let taken = std::cell::Cell::new(0);
    let reads = vec![Err(std::io::Error::from_raw_os_error(24)), stat_in('S')];
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let missing = || Err(std::io::Error::from(std::io::ErrorKind::NotFound));
    let ended = ended_by(reads_then(reads, missing, &taken), until);
    assert!(ended, "the process was gone at the third read");
    assert_eq!(
        taken.get(),
        3,
        "the wait ended before the read that showed it gone"
    );
}

/// Controls: a process that keeps running is not ended before the bound (the
/// rows above, which need several reads, stay able to fail on a kill that
/// never lands); a dead state is ended.
#[test]
fn ended_by_a_running_process_is_not_ended_and_a_zombie_is() {
    let taken = std::cell::Cell::new(0);
    // limit-under-test (fires-only): the bound handed to ended_by; a stall only lengthens the wait, and the row asserts only that it answered no sooner
    let bound = std::time::Duration::from_millis(200);
    let start = std::time::Instant::now();
    assert!(!ended_by(
        reads_then(Vec::new(), || stat_in('S'), &taken),
        start + bound
    ));
    assert!(
        start.elapsed() >= bound,
        "the wait answered running after {:?}, before its bound",
        start.elapsed()
    );
    let dead: [(char, StatRead); 3] = [
        ('Z', || stat_in('Z')),
        ('X', || stat_in('X')),
        ('x', || stat_in('x')),
    ];
    for (state, read) in dead {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        assert!(
            ended_by(reads_then(Vec::new(), read, &taken), until),
            "state {state} was not read as ended"
        );
    }
}

/// U-floor deadline (code review r1 fold, gpt IMPROVEMENT and muse MEDIUM),
/// kills m-deadline-group-left and m-leader-unkilled: a version call that
/// never answers is refused at the bound and leaves nothing behind. Its
/// descendant, still in the call's group, is ended by the group kill; the
/// call itself, which moved to its parent's group (a group leader cannot
/// setsid), is ended by its own kill, so the reap cannot wait on it.
#[test]
fn u_floor_a_silent_call_that_left_its_group_is_refused_at_the_bound_and_ended() {
    let dir = tempfile::tempdir().expect("dir");
    let descendant = dir.path().join("descendant.pid");
    let leader = dir.path().join("leader.pid");
    // Written only once the move succeeded: without it the row would pass on
    // the descendant's held pipe alone and never test the escape.
    let moved = dir.path().join("moved");
    let uv = uv_answering(
        dir.path(),
        &format!(
            "sleep 300 & echo $! > '{}'; echo $$ > '{}'; exec /usr/bin/python3 -c \
             'import os, time; os.setpgid(0, os.getpgid(os.getppid())); \
             open(\"{}\", \"w\").close(); time.sleep(300)'",
            descendant.display(),
            leader.display(),
            moved.display()
        ),
    );
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(check_uv(&uv));
    });
    let answered = rx.recv_timeout(std::time::Duration::from_secs(30));
    let descendant_alive = !gone(&descendant);
    let leader_alive = !gone(&leader);
    assert!(moved.exists(), "premise: the call moved out of its group");
    assert_eq!(
        answered,
        Ok(Err(Refusal::Step(
            "uv --version did not answer within 10 s".into()
        ))),
        "the call was refused at the bound"
    );
    assert!(!descendant_alive, "the descendant outlived the call");
    assert!(!leader_alive, "the call outlived its refusal");
}

/// U-floor (code review r1, muse MEDIUM; lead: the bound covers the whole
/// read), kills m-read-to-eof and m-group-left: a version call whose
/// descendant keeps the output pipe open answers once its line is out, and
/// the call leaves no process behind: the descendant is gone when it
/// returns, ended by the probe itself.
#[test]
fn u_floor_a_descendant_holding_the_pipe_neither_holds_the_call_nor_outlives_it() {
    let dir = tempfile::tempdir().expect("dir");
    let pid_file = dir.path().join("descendant.pid");
    let uv = uv_answering(
        dir.path(),
        &format!(
            "sleep 300 & echo $! > '{}'; echo 'uv 0.13.1 (x86_64-linux-gnu)'",
            pid_file.display()
        ),
    );
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(check_uv(&uv));
    });
    let answered = rx.recv_timeout(std::time::Duration::from_secs(30));
    let alive = !gone(&pid_file);
    assert_eq!(answered, Ok(Ok(())), "the call answered with its line");
    assert!(!alive, "the descendant outlived the call");
}

/// U-place (code review r1, muse LOW and gpt), kills m-usrlocal-arm: each
/// class of the program rule sends the narrow binds where it must, the
/// `/usr/local` arm included (a fixture tree in a temp dir never reaches
/// it, so the classes are given here): bound back, read-only, nothing, or
/// refused by name.
#[test]
fn u_place_each_program_class_sends_the_narrow_binds_its_way() {
    let binds = || {
        vec![
            "/x/bin/python3.12".to_owned(),
            "/x/lib/python3.12".to_owned(),
        ]
    };
    let real = Path::new("/x/bin/python3.12");
    let usr_local = ProgramBind::UsrLocal(vec![PathBuf::from("/usr/local/bin")]);
    assert_eq!(
        narrow_place(&usr_local, binds(), "python3", real),
        Ok(PythonPlace {
            bound_back: binds(),
            ..PythonPlace::default()
        })
    );
    for class in [
        ProgramBind::Runtime(PathBuf::from("/x")),
        ProgramBind::File(PathBuf::from("/x/bin/python3.12")),
    ] {
        assert_eq!(
            narrow_place(&class, binds(), "python3", real),
            Ok(PythonPlace {
                read_only: binds(),
                ..PythonPlace::default()
            }),
            "{class:?}"
        );
    }
    assert_eq!(
        narrow_place(&ProgramBind::System, binds(), "python3", real),
        Ok(PythonPlace::default())
    );
    assert_eq!(
        narrow_place(&ProgramBind::Refused, binds(), "python3", real),
        Err(Refusal::Step(
            "placing python3 (/x/bin/python3.12 lies under a masked secret path)".into()
        ))
    );
}
