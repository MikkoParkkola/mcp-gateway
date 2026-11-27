// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the Linux walk over a fake process tree: a directory laid out like
//! `/proc` (each pid's `stat`, each task's `children`), so the reading's bounds,
//! its pruning and its fallback are deterministic. The fake pids sit above any
//! real `pid_max`, so nothing here can name a real process.

use std::path::Path;
use std::time::Duration;

use super::*;

/// A fake pid: far above the kernel's largest `pid_max`.
fn fake(n: u32) -> u32 {
    9_000_000 + n
}

fn who(pid: u32, start: u64) -> Identity {
    Identity { pid, start }
}

/// A `stat` line: state, parent, start time in field 22.
fn stat_line(pid: u32, parent: u32, state: char, start: u64) -> String {
    let fillers = "0 ".repeat(17);
    format!("{pid} (fake) {state} {parent} {fillers}{start}\n")
}

/// A `/proc`-shaped directory. `walkable` writes the probe file the table
/// checks for at creation (`self/task/<tid>/children`); without it, the table
/// has no children files and must fall back to the full scan.
struct Tree {
    dir: tempfile::TempDir,
}

impl Tree {
    fn new(walkable: bool) -> Self {
        let tree = Self {
            dir: tempfile::tempdir().expect("temp dir"),
        };
        if walkable {
            let tid = rustix::thread::gettid().as_raw_nonzero().get();
            tree.write(&format!("self/task/{tid}/children"), "");
        }
        tree
    }

    fn write(&self, rel: &str, text: &str) {
        let path = self.dir.path().join(rel);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("dirs");
        std::fs::write(path, text).expect("write");
    }

    /// One process: its `stat` (state, parent, start time in field 22) and its
    /// main thread (same state).
    fn proc(&self, pid: u32, parent: u32, state: char, start: u64, children: &[u32]) {
        self.write(
            &format!("{pid}/stat"),
            &stat_line(pid, parent, state, start),
        );
        self.task(pid, pid, state, children);
    }

    /// A second thread, sleeping.
    fn thread(&self, pid: u32, tid: u32, children: &[u32]) {
        self.task(pid, tid, 'S', children);
    }

    /// One task: its own `stat` and its `children`.
    fn task(&self, pid: u32, tid: u32, state: char, children: &[u32]) {
        self.write(
            &format!("{pid}/task/{tid}/stat"),
            &stat_line(tid, 1, state, 1),
        );
        let list: Vec<String> = children.iter().map(u32::to_string).collect();
        self.write(&format!("{pid}/task/{tid}/children"), &list.join(" "));
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

fn pids(listing: &Listing) -> Vec<u32> {
    let mut found: Vec<u32> = listing.rows.iter().map(|(id, _)| id.pid).collect();
    found.sort_unstable();
    found
}

/// One expiry case: its name, how it builds the tree, and its seeds.
type Case = (&'static str, Box<dyn Fn(&Tree)>, Vec<Identity>);

/// R-bound, until already passed: a reading of a deep chain, a wide children
/// file, a thread-heavy process or a long seed list stops after at most one
/// read, cut short (not complete, not settled).
#[test]
fn an_expired_reading_stops_at_once_whatever_the_tree() {
    let root = fake(1);
    let cases: [Case; 4] = [
        (
            "a 5,000-link chain",
            Box::new(move |tree| {
                for n in 1..=5_000 {
                    let next = if n < 5_000 {
                        vec![fake(n + 1)]
                    } else {
                        Vec::new()
                    };
                    tree.proc(fake(n), fake(n - 1), 'S', 1, &next);
                }
            }),
            Vec::new(),
        ),
        (
            "one children file listing 5,000 pids",
            Box::new(move |tree| {
                let kids: Vec<u32> = (2..=5_001).map(fake).collect();
                tree.proc(root, 1, 'S', 1, &kids);
            }),
            Vec::new(),
        ),
        (
            "a process with 5,000 threads",
            Box::new(move |tree| {
                tree.proc(root, 1, 'S', 1, &[]);
                for tid in 2..=5_001 {
                    tree.thread(root, fake(tid), &[]);
                }
            }),
            Vec::new(),
        ),
        (
            "5,000 dropped seeds",
            Box::new(move |tree| tree.proc(root, 1, 'S', 1, &[])),
            (2..=5_001).map(|n| who(fake(n), 1)).collect(),
        ),
    ];
    for (name, build, dropped) in cases {
        let tree = Tree::new(true);
        build(&tree);
        let mut table = LinuxTable::with_root(tree.path());
        let listing = table.read(&[who(root, 1)], &dropped, Duration::ZERO);
        assert!(
            !listing.complete,
            "{name}: an expired reading claimed complete"
        );
        assert!(
            !listing.settled,
            "{name}: an expired reading claimed settled"
        );
        assert!(
            table.reads <= 1,
            "{name}: {} reads after until",
            table.reads
        );
    }
}

/// R-bound, until passed mid-walk: the clock jumps past until after exactly
/// `k` reads, and the reading stops there, neither earlier nor later.
#[test]
fn a_reading_stops_at_the_read_where_until_passes() {
    let tree = Tree::new(true);
    for n in 1..=50 {
        let next = if n < 50 {
            vec![fake(n + 1)]
        } else {
            Vec::new()
        };
        tree.proc(fake(n), fake(n - 1), 'S', 1, &next);
    }
    let mut table = LinuxTable::with_root(tree.path());
    table.expire_after_reads = Some(10);
    let listing = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert_eq!(table.reads, 10, "the reading did not stop at the 10th read");
    assert!(!listing.complete, "a reading cut short claimed complete");
    assert!(
        !listing.rows.is_empty(),
        "the reads before until found nothing"
    );
}

/// R-gone, fake root: a seed whose pid now has another start time, and a seed
/// whose pid has no entry, are both in `gone`; a seed that matches is not.
#[test]
fn a_seed_is_gone_on_its_own_evidence() {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'S', 1, &[]);
    tree.proc(fake(2), 1, 'S', 6, &[]);
    let mut table = LinuxTable::with_root(tree.path());
    let seeds = [who(fake(1), 1), who(fake(2), 5), who(fake(3), 1)];
    let listing = table.read(&seeds, &[], Duration::MAX);
    assert_eq!(
        listing.gone,
        vec![who(fake(2), 5), who(fake(3), 1)],
        "gone must name exactly the reused and the missing seed"
    );
}

/// R-thread, fake root: a child forked by a second thread is found through
/// that thread's own children file, and a thread whose file has vanished counts
/// as gone without switching to the full scan (a process outside the tree is
/// never listed).
#[test]
fn every_threads_children_are_walked_and_a_vanished_thread_is_no_switch() {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'S', 1, &[fake(2)]);
    tree.thread(fake(1), fake(10), &[fake(3)]);
    std::fs::create_dir_all(tree.path().join(format!("{}/task/{}", fake(1), fake(11))))
        .expect("a thread dir with no children file");
    tree.proc(fake(2), fake(1), 'S', 1, &[]);
    tree.proc(fake(3), fake(1), 'S', 1, &[]);
    tree.proc(fake(900), 1, 'S', 1, &[]);
    let mut table = LinuxTable::with_root(tree.path());
    let listing = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert_eq!(pids(&listing), vec![fake(1), fake(2), fake(3)]);
    assert!(
        listing.complete,
        "a vanished thread made the reading incomplete"
    );
}

/// R-fallback: with no children file at creation, the table uses the full scan
/// of its proc root for life: a process outside the tree is listed too.
#[test]
fn without_children_files_the_table_scans_its_whole_root() {
    let tree = Tree::new(false);
    tree.proc(fake(1), 1, 'S', 1, &[]);
    tree.proc(fake(900), 1, 'S', 1, &[]);
    let mut table = LinuxTable::with_root(tree.path());
    let listing = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert_eq!(pids(&listing), vec![fake(1), fake(900)]);
    assert!(listing.complete);
}

/// R-dropped: a dropped seed is read for its own death only. Its children
/// file lists a live child, and that child is never read; a dropped seed
/// with no entry is in `gone`.
#[test]
fn a_dropped_seed_is_stated_only_and_never_walked() {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'S', 1, &[]);
    tree.proc(fake(2), 1, 'S', 1, &[fake(3)]);
    tree.proc(fake(3), fake(2), 'S', 1, &[]);
    let mut table = LinuxTable::with_root(tree.path());
    let dropped = [who(fake(2), 1), who(fake(4), 1)];
    let listing = table.read(&[who(fake(1), 1)], &dropped, Duration::MAX);
    assert!(
        !pids(&listing).contains(&fake(3)),
        "a dropped seed's child was read"
    );
    assert!(
        pids(&listing).contains(&fake(1)),
        "the walked root is missing from a complete reading"
    );
    assert_eq!(
        listing.gone,
        vec![who(fake(4), 1)],
        "the missing dropped seed is not gone"
    );
}

// Real processes from here on: Linux only, run on Spark.

fn spawn(script: &str) -> std::process::Child {
    std::process::Command::new("sh")
        .args(["-c", script])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("sh starts")
}

fn real(pid: u32) -> Identity {
    let start = LinuxTable::identity_of(pid)
        .expect("a live process has a stat")
        .start;
    who(pid, start)
}

/// The first child `pid`'s main thread lists, waited for up to 10 s.
fn first_child(pid: u32) -> u32 {
    for _ in 0..1000 {
        let file = format!("/proc/{pid}/task/{pid}/children");
        if let Some(first) = std::fs::read_to_string(file)
            .ok()
            .and_then(|text| text.split_whitespace().next().map(str::to_owned))
        {
            return first.parse().expect("a pid");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("no child of {pid} within 10 s");
}

/// A signal through the table's own held descriptor: the pidfd is opened and
/// its start time checked first, so it can only reach `id` (no raw pid signal).
fn send(table: &mut LinuxTable, id: Identity, sig: Sig) {
    table
        .signal(id, sig, true)
        .expect("the signal reaches the process");
}

fn wait_for(table: &mut LinuxTable, id: Identity, want: ProcState) {
    for _ in 0..1000 {
        if table.state(id) == want {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("{id:?} never reached {want:?} within 10 s");
}

/// R-settled-linux: a reading is settled only when every pid whose children it
/// read was stopped: both running, then only the parent stopped, are not.
#[test]
fn a_reading_is_settled_only_when_every_walked_parent_is_stopped() {
    let mut sh = spawn("sleep 60 & wait");
    let parent = real(sh.id());
    let child = real(first_child(parent.pid));
    let mut table = LinuxTable::new();
    let read = |table: &mut LinuxTable| table.read(&[parent], &[], Duration::MAX);
    assert!(
        !read(&mut table).settled,
        "running parent and child read as settled"
    );
    send(&mut table, parent, Sig::Stop);
    wait_for(&mut table, parent, ProcState::Stopped);
    assert!(!read(&mut table).settled, "a running child read as settled");
    send(&mut table, child, Sig::Stop);
    wait_for(&mut table, child, ProcState::Stopped);
    let listing = read(&mut table);
    assert!(listing.settled, "a fully stopped tree read as not settled");
    assert!(
        listing.rows.iter().any(|(id, _)| *id == child),
        "the child is missing"
    );
    send(&mut table, child, Sig::Kill);
    send(&mut table, parent, Sig::Kill);
    let _ = sh.wait();
}

/// R-gone, real: a seed killed and reaped is in `gone`.
#[test]
fn a_reaped_seed_is_gone() {
    let mut sleeper = spawn("exec sleep 60");
    let id = real(sleeper.id());
    sleeper.kill().expect("kill");
    sleeper.wait().expect("reap");
    let listing = LinuxTable::new().read(&[id], &[], Duration::MAX);
    assert_eq!(listing.gone, vec![id]);
}

/// R-seed, real: a member seen in the snapshot whose parent then dies is
/// reparented away from the tree, and is still killed by the sweep.
#[test]
fn a_member_reparented_after_the_snapshot_is_still_killed() {
    let mut outer = spawn("sh -c 'sleep 60 & wait' & wait");
    let root = real(outer.id());
    let inner = real(first_child(root.pid));
    let leaf = real(first_child(inner.pid));
    let mut table = LinuxTable::new();
    let config = super::super::SweepConfig {
        freeze_slice: Duration::from_secs(10),
        cap: 64,
    };
    let mut sweep = super::super::Sweep::new(root, config);
    sweep.snapshot(&mut table);
    send(&mut table, inner, Sig::Kill);
    // The sweep must meet the member reparented: wait (10 s deadline, on the
    // process state) until the inner is gone, then the leaf names another parent.
    wait_for(&mut table, inner, ProcState::Gone);
    let now = table.read(&[leaf], &[], Duration::MAX).rows;
    assert!(
        now.iter()
            .any(|(id, ppid)| *id == leaf && *ppid != inner.pid),
        "premise: the leaf was not reparented: {now:?}"
    );
    let report = sweep.run(&mut table, &super::super::PidfdBudget::new(64));
    assert!(
        report.killed.contains(&leaf),
        "the reparented member was not killed"
    );
    wait_for(&mut table, leaf, ProcState::Gone);
    let _ = outer.wait();
}

/// R-thread, real: a child forked by a thread other than the main one is found.
#[test]
fn a_child_forked_by_a_second_thread_is_found() {
    let script = "import subprocess, threading, time\n\
                  threading.Thread(target=lambda: [subprocess.Popen(['sleep', '60']), time.sleep(60)], daemon=True).start()\n\
                  time.sleep(60)";
    let mut py = std::process::Command::new("python3")
        .args(["-c", script])
        .stdin(std::process::Stdio::null())
        .spawn()
        .expect("python starts");
    let parent = real(py.id());
    let mut table = LinuxTable::new();
    let found = (0..500).find_map(|_| {
        std::thread::sleep(Duration::from_millis(10));
        let listing = table.read(&[parent], &[], Duration::MAX);
        listing
            .rows
            .iter()
            .find(|(id, ppid)| *ppid == parent.pid && id.pid != parent.pid)
            .map(|(id, _)| *id)
    });
    let child = found.expect("the thread's child was never listed");
    send(&mut table, child, Sig::Kill);
    py.kill().expect("kill");
    let _ = py.wait();
}

/// R-walk-eq-scan: with the tree stopped, the walk's rows equal the full
/// scan's rows restricted to the tree.
#[test]
fn a_stopped_trees_walk_equals_the_scan_of_it() {
    let mut sh = spawn("sleep 60 & sleep 60 & wait");
    let parent = real(sh.id());
    let mut table = LinuxTable::new();
    let mut kids: Vec<Identity> = Vec::new();
    for _ in 0..1000 {
        let file = format!("/proc/{0}/task/{0}/children", parent.pid);
        let text = std::fs::read_to_string(file).unwrap_or_default();
        let pids: Vec<u32> = text
            .split_whitespace()
            .filter_map(|p| p.parse().ok())
            .collect();
        if pids.len() == 2 {
            kids = pids.into_iter().map(real).collect();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(kids.len(), 2, "two children within 10 s");
    for id in std::iter::once(parent).chain(kids.iter().copied()) {
        send(&mut table, id, Sig::Stop);
        wait_for(&mut table, id, ProcState::Stopped);
    }
    let tree = |listing: Listing| {
        let mut ids: Vec<Identity> = listing
            .rows
            .into_iter()
            .filter(|(id, ppid)| *id == parent || *ppid == parent.pid)
            .map(|(id, _)| id)
            .collect();
        ids.sort();
        ids
    };
    let walked = tree(table.read(&[parent], &[], Duration::MAX));
    let mut scan = LinuxTable::new();
    scan.force_full_scan = true;
    let scanned = tree(scan.read(&[parent], &[], Duration::MAX));
    assert_eq!(
        walked, scanned,
        "the walk and the scan disagree on a stopped tree"
    );
    assert_eq!(
        walked.len(),
        3,
        "the tree is the parent and its two children"
    );
    for id in std::iter::once(parent).chain(kids) {
        send(&mut table, id, Sig::Kill);
    }
    let _ = sh.wait();
}

#[path = "stdio_sweep_linux_settle_tests.rs"]
mod settle;
