// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settlement rows for the Linux walk (design delta D5'''): when a reading may
//! end the freeze loop. Fake-tree helpers come from the parent walk rows.

use super::*;

/// R-settle-threads: the leader's state does not vouch for its threads. A
/// Stopped leader with a running second thread leaves the reading unsettled
/// (the old leader-only rule settled it); with that thread Stopped it settles.
/// A Zombie leader (exited while its threads run) settles nothing (D5''').
#[test]
fn a_running_thread_under_a_zombie_leader_leaves_the_reading_unsettled() {
    for (leader, thread, settles) in [('T', 'R', false), ('T', 'T', true), ('Z', 'T', false)] {
        let tree = Tree::new(true);
        tree.proc(fake(1), 1, leader, 1, &[]);
        tree.task(fake(1), fake(10), thread, &[fake(2)]);
        tree.proc(fake(2), fake(1), 'T', 1, &[]);
        let mut table = LinuxTable::with_root(tree.path());
        let listing = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
        let case = format!("leader {leader}, thread {thread}");
        assert_eq!(pids(&listing), vec![fake(1), fake(2)], "{case}");
        assert_eq!(listing.settled, settles, "{case}: settled");
    }
}

/// An unreadable task `stat` proves nothing about that task: the reading is
/// neither settled nor complete.
#[test]
fn an_unreadable_task_state_settles_nothing() {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'T', 1, &[]);
    tree.write(&format!("{0}/task/{0}/stat", fake(1)), "no parens");
    let mut table = LinuxTable::with_root(tree.path());
    let listing = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert!(!listing.settled, "an unreadable task state settled");
    assert!(
        !listing.complete,
        "an unreadable task state left it complete"
    );
}

/// D5''' (ii): a stopped parent's listed child settles the reading only while
/// it is still that parent's child and Stopped at its listing stat. Zombie,
/// running, gone (the trace of a mid-read removal, when the kernel skips a
/// sibling), or a pid now held by another parent's process all unsettle it,
/// and the last is not added.
#[test]
fn a_listed_child_settles_only_while_stopped_and_still_that_parents() {
    let cases: [(&str, Option<(u32, char)>, bool); 5] = [
        ("stopped", Some((fake(1), 'T')), true),
        ("zombie", Some((fake(1), 'Z')), false),
        ("gone", None, false),
        ("running", Some((fake(1), 'R')), false),
        ("pid reused by another parent", Some((fake(7), 'T')), false),
    ];
    for (name, child, settles) in cases {
        let tree = Tree::new(true);
        tree.proc(fake(1), 1, 'T', 1, &[fake(2)]);
        if let Some((parent, state)) = child {
            tree.proc(fake(2), parent, state, 1, &[]);
        }
        let mut table = LinuxTable::with_root(tree.path());
        let listing = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
        assert_eq!(listing.settled, settles, "{name}: settled");
        if name.starts_with("pid reused") {
            assert!(!pids(&listing).contains(&fake(2)), "a reused pid was added");
        }
    }
}

/// D5''' (i): a task must read Stopped at both reads. It reads Stopped before
/// its children file and Zombie after (the seam rewrites its stat once read 2,
/// the task-before read, has returned: seed stat 1, task-before 2), so the
/// reading is unsettled; untouched, it settles. That the before-read saw
/// Stopped is shown by the mutant that drops the after-read check: this row
/// goes red under it only because the before-read passed.
#[test]
fn a_task_whose_state_changes_across_its_read_settles_nothing() {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'T', 1, &[]);
    let control = LinuxTable::with_root(tree.path()).read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert!(control.settled, "a stopped lone root did not settle");
    let mut table = LinuxTable::with_root(tree.path());
    table.rewrite_after_read = Some((
        2,
        tree.path().join(format!("{0}/task/{0}/stat", fake(1))),
        stat_line(fake(1), 1, 'Z', 1),
    ));
    let listing = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert!(
        table.rewrite_fired,
        "the rewrite did not land between the reads"
    );
    assert!(
        !listing.settled,
        "a task that changed state across its read settled"
    );
}

/// D5''' (iii): a thread created after the first task-directory read was never
/// walked. The seam adds one after read 4 (task-after on a lone root: seed 1,
/// task-before 2, children 3, task-after 4), between the two directory reads,
/// so the reading is unsettled; untouched, it settles.
#[test]
fn a_thread_created_during_the_walk_settles_nothing() {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'T', 1, &[]);
    let control = LinuxTable::with_root(tree.path()).read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert!(control.settled, "a stopped lone root did not settle");
    let mut table = LinuxTable::with_root(tree.path());
    table.rewrite_after_read = Some((
        4,
        tree.path()
            .join(format!("{}/task/{}/stat", fake(1), fake(10))),
        stat_line(fake(10), 1, 'T', 1),
    ));
    let listing = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert!(table.rewrite_fired, "the new thread was not added mid-walk");
    assert!(
        listing.complete,
        "the new thread's fixture broke a read, so this row proves nothing"
    );
    assert!(
        !listing.settled,
        "a thread created during the walk was missed"
    );
}

/// D5' multi-pass: a gone second thread unsettles reading 1. As the kernel
/// does when a thread exits, its child then moves to the leader task's file,
/// and reading 2 collects it.
#[test]
fn a_gone_threads_child_is_collected_by_the_next_reading() {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'T', 1, &[]);
    std::fs::create_dir_all(tree.path().join(format!("{}/task/{}", fake(1), fake(10))))
        .expect("a gone thread's directory");
    let mut table = LinuxTable::with_root(tree.path());
    let first = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert!(!first.settled, "a gone thread settled the reading");
    tree.task(fake(1), fake(1), 'T', &[fake(2)]);
    tree.proc(fake(2), fake(1), 'T', 1, &[]);
    let second = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert!(
        pids(&second).contains(&fake(2)),
        "the handed child was not collected"
    );
}

/// D5' H4, an in-tree subreaper: root A lists child B, which is gone at its
/// stat, so reading 1 is unsettled. B's child C then appears in A's own file
/// (A reaps for its descendants), and reading 2 collects it.
#[test]
fn a_grandchild_handed_to_an_in_tree_subreaper_is_collected_next() {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'T', 1, &[fake(2)]);
    let mut table = LinuxTable::with_root(tree.path());
    let first = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert!(!first.settled, "a gone listed child settled the reading");
    tree.task(fake(1), fake(1), 'T', &[fake(3)]);
    tree.proc(fake(3), fake(1), 'T', 1, &[]);
    let second = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert!(
        pids(&second).contains(&fake(3)),
        "the grandchild handed to the subreaper was not collected"
    );
}

/// A stopped parent S = fake(1) listing one child K = fake(2) in state `k`.
/// Read order (D5'''): S seed 1, S task-before 2, S children 3, K stat 4,
/// S task-after 5, then K's walk from read 6.
fn s_and_k(k: char) -> Tree {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'T', 1, &[fake(2)]);
    tree.proc(fake(2), fake(1), k, 1, &[]);
    tree
}

/// One reading of `tree` from S, with the seam set to write `text` to `rel`
/// after read `at`; the seam must fire.
fn read_with_rewrite(tree: &Tree, at: usize, rel: &str, text: &str) -> Listing {
    let mut table = LinuxTable::with_root(tree.path());
    table.rewrite_after_read = Some((at, tree.path().join(rel), text.to_owned()));
    let listing = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert!(table.rewrite_fired, "the seam did not fire after read {at}");
    listing
}

fn read_from_s(tree: &Tree) -> Listing {
    LinuxTable::with_root(tree.path()).read(&[who(fake(1), 1)], &[], Duration::MAX)
}

/// D5''' window 1: K is killed before its stat and reads Zombie there; its
/// child may already sit in S's file, read before K died. A listed Zombie
/// settles nothing. Untouched (K Stopped), the tree settles.
#[test]
fn a_child_that_died_before_its_stat_unsettles_the_reading() {
    assert!(
        read_from_s(&s_and_k('T')).settled,
        "the untouched tree did not settle"
    );
    assert!(
        !read_from_s(&s_and_k('Z')).settled,
        "a Zombie listed child settled"
    );
}

/// D5''' windows 2 and 3: K is killed after its stat (read 4) and before its
/// own walk, just after the stat (window 2) or after S's task-after (window 3,
/// read 5). K's children went to a parent already read; K's leader task reads
/// Zombie when the walk reaches it, so the reading is unsettled.
#[test]
fn a_child_that_dies_before_its_own_walk_unsettles_the_reading() {
    for (window, at) in [(2, 4), (3, 5)] {
        let listing = read_with_rewrite(
            &s_and_k('T'),
            at,
            &format!("{0}/task/{0}/stat", fake(2)),
            &stat_line(fake(2), fake(1), 'Z', 1),
        );
        assert!(!listing.settled, "window {window}: the dead child settled");
    }
}

/// D5'' window 4: K is killed after its own children read, so G = fake(3) is
/// listed under K while its stat already names S. The reading is unsettled
/// and does not add G under K; once S's file lists G, the next reading
/// collects it there.
#[test]
fn a_reparented_grandchild_is_skipped_unsettles_and_is_found_under_its_new_parent() {
    let tree = s_and_k('T');
    tree.task(fake(2), fake(2), 'T', &[fake(3)]);
    tree.proc(fake(3), fake(1), 'T', 1, &[]);
    let first = read_from_s(&tree);
    assert!(
        !first.settled,
        "a reparented grandchild settled the reading"
    );
    assert!(!pids(&first).contains(&fake(3)), "G was added under K");
    tree.task(fake(1), fake(1), 'T', &[fake(2), fake(3)]);
    let second = read_from_s(&tree);
    assert!(
        pids(&second).contains(&fake(3)),
        "G was not collected under S"
    );
}

/// D5''' cost row: a stopped tree holding one Zombie child (exited before the
/// freeze; its frozen parent cannot reap it) reads complete but unsettled, on
/// every reading, so the freeze loop over it runs to freeze_end (R-omit pins
/// that only a settled reading ends the loop). A stopped tree without the
/// zombie settles.
#[test]
fn a_tree_holding_a_zombie_never_settles() {
    assert!(
        read_from_s(&s_and_k('T')).settled,
        "the zombie-free tree did not settle"
    );
    let tree = s_and_k('Z');
    let mut table = LinuxTable::with_root(tree.path());
    for reading in 1..=3 {
        let listing = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
        assert!(listing.complete, "reading {reading}: incomplete");
        assert!(
            !listing.settled,
            "reading {reading}: a zombie-holding tree settled"
        );
    }
}

/// A child turned away under one parent (its stat names another) is still
/// collected when its real parent's file lists it later in the same reading.
/// S lists M then K; the walk takes K first (last in, first out), K lists G
/// whose stat names M, and M's file lists G too.
#[test]
fn a_child_turned_away_under_one_parent_is_taken_under_its_real_one() {
    let (s, k, g, m) = (fake(1), fake(2), fake(3), fake(4));
    let tree = Tree::new(true);
    tree.proc(s, 1, 'T', 1, &[m, k]);
    tree.proc(k, s, 'T', 1, &[g]);
    tree.proc(m, s, 'T', 1, &[g]);
    tree.proc(g, m, 'T', 1, &[]);
    let listing = read_from_s(&tree);
    assert!(
        pids(&listing).contains(&g),
        "G was lost after K turned it away"
    );
    assert!(
        !listing.settled,
        "K's listing of a child that names another parent did not unsettle"
    );
}

/// D5''' (ii): a listed child must be Stopped when its parent's file is read,
/// not only at its own later walk. K's process stat reads Running at its
/// listing stat while its task stat reads Stopped when the walk reaches it, so
/// only the listing-time check can unsettle this reading.
#[test]
fn a_child_running_when_listed_unsettles_though_stopped_at_its_walk() {
    let tree = s_and_k('T');
    tree.write(
        &format!("{}/stat", fake(2)),
        &stat_line(fake(2), fake(1), 'R', 1),
    );
    assert!(
        read_from_s(&s_and_k('T')).settled,
        "the untouched tree did not settle"
    );
    assert!(
        !read_from_s(&tree).settled,
        "a child running when listed settled the reading"
    );
}

/// A listed child that vanishes before its own walk (its stat was read when it
/// was listed; its task directory is gone when the walk reaches it) was never
/// judged by the task rule, so the reading is unsettled. It reads Stopped at
/// its listing stat, so the listing check passes and only the vanished walk
/// can unsettle this reading (a Running child here would pass for the wrong
/// reason: the sabotage job's M7 found exactly that).
#[test]
fn a_child_gone_before_its_own_walk_unsettles_the_reading() {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'T', 1, &[fake(2)]);
    tree.write(
        &format!("{}/stat", fake(2)),
        &stat_line(fake(2), fake(1), 'T', 1),
    );
    let listing = read_from_s(&tree);
    assert!(
        pids(&listing).contains(&fake(2)),
        "premise: the child was listed and added"
    );
    assert!(
        !listing.settled,
        "a child gone before its walk settled the reading"
    );
}

/// `n` readings of `walk` through one table (one freeze): each reading's
/// settled flag, every reading complete.
fn settled_over(tree: &Tree, walk: &[Identity], n: usize) -> Vec<bool> {
    let mut table = LinuxTable::with_root(tree.path());
    (1..=n)
        .map(|reading| {
            let listing = table.read(walk, &[], Duration::MAX);
            assert!(listing.complete, "reading {reading}: incomplete");
            listing.settled
        })
        .collect()
}

/// E1 (D5'''' (i')): a lone exited root (task dir = its leader only, Zombie,
/// no children) unsettles the first reading that finds it and settles every
/// later one of the same freeze. Red under D5''' (never settles) and if the
/// earlier-reading condition is dropped (settles on reading 1).
#[test]
fn an_exited_root_settles_from_the_second_reading_on() {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'Z', 1, &[]);
    assert_eq!(
        settled_over(&tree, &[who(fake(1), 1)], 3),
        vec![false, true, true]
    );
}

/// E2, E3: an exited leader still holding a second task (a worker that is
/// stopped, or itself exiting and Zombie), or one whose children file lists a
/// pid, is not EXITED: no reading of the freeze settles. A Stopped tree of the
/// same shape settles at once, so only the exit is what keeps these unsettled.
/// The exiting worker is the case only the leader-only rule refuses.
#[test]
fn a_zombie_with_a_second_task_or_a_child_never_settles() {
    let cases = [
        ("stopped worker", 'Z', 'T', [false; 3]),
        ("exiting worker", 'Z', 'Z', [false; 3]),
        ("control", 'T', 'T', [true; 3]),
    ];
    for (case, leader, worker, want) in cases {
        let tree = Tree::new(true);
        tree.proc(fake(1), 1, leader, 1, &[]);
        tree.task(fake(1), fake(10), worker, &[]);
        assert_eq!(settled_over(&tree, &[who(fake(1), 1)], 3), want, "{case}");
    }
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'Z', 1, &[fake(2)]);
    tree.proc(fake(2), fake(1), 'T', 1, &[]);
    assert_eq!(
        settled_over(&tree, &[who(fake(1), 1)], 3),
        vec![false; 3],
        "a zombie listing a child settled"
    );
}

/// E4: the earlier reading must have found the SAME process. A zombie found
/// exited in reading 1 whose pid then holds a new zombie (another start time)
/// unsettles reading 2, and reading 3 settles on the new one.
#[test]
fn a_reused_pid_does_not_inherit_an_earlier_exit() {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'Z', 1, &[]);
    let mut table = LinuxTable::with_root(tree.path());
    let first = table.read(&[who(fake(1), 1)], &[], Duration::MAX);
    assert!(!first.settled, "reading 1 settled");
    tree.proc(fake(1), 1, 'Z', 2, &[]);
    let walk = [who(fake(1), 2)];
    let second = table.read(&walk, &[], Duration::MAX);
    assert!(!second.settled, "the new process took the old one's exit");
    assert!(table.read(&walk, &[], Duration::MAX).settled, "reading 3");
}

/// E7 (D5'''' (ii'')): a Stopped parent and its zombie child, BOTH walked as
/// seeds (the child became a member), never settle: the parent's listing still
/// judges the child, which is not Stopped. Red if a seen child skips (ii).
#[test]
fn a_zombie_member_listed_by_its_stopped_parent_never_settles() {
    let walk = [who(fake(1), 1), who(fake(2), 1)];
    assert_eq!(
        settled_over(&s_and_k('Z'), &walk, 3),
        vec![false; 3],
        "a zombie member under a live parent settled"
    );
    assert_eq!(settled_over(&s_and_k('T'), &walk, 2), vec![true; 2]);
}

/// E8: the exits recorded live only for one freeze (one table). A second
/// table's first reading of the same exited root is unsettled again.
#[test]
fn an_exit_seen_in_one_freeze_does_not_carry_to_the_next() {
    let tree = Tree::new(true);
    tree.proc(fake(1), 1, 'Z', 1, &[]);
    let walk = [who(fake(1), 1)];
    assert_eq!(settled_over(&tree, &walk, 2), vec![false, true]);
    assert_eq!(settled_over(&tree, &walk, 1), vec![false], "carried over");
}
