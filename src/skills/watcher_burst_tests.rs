// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Burst and mid-pass rows for the skills watcher regen loop (MIK-8690).

use super::*;

/// One capability YAML, shaped like the existing watcher test's.
fn cap_yaml(name: &str, category: &str, description: &str) -> String {
    format!(
        "name: {name}\ndescription: {description}\nproviders:\n  primary:\n    \
         service: rest\n    config:\n      base_url: https://example.com\n\
         metadata:\n  category: {category}\n"
    )
}

/// The `SKILL.md` of the bundle regenerated for `category`.
fn skill_md(out: &Path, category: &str) -> PathBuf {
    out.join(format!("mcp-gateway-{category}")).join("SKILL.md")
}

/// SKW.1: a burst bigger than the channel drops its overflow today, so 50
/// of the 150 bundles are never regenerated.
#[tokio::test]
async fn a_burst_over_the_channel_size_regenerates_every_skill() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let out = tmp.path().join("skills");
    let mut paths = Vec::new();
    for i in 0..150 {
        let path = tmp.path().join(format!("cap{i}.yaml"));
        let yaml = cap_yaml(&format!("cap{i}"), &format!("burst{i}"), "Burst test");
        tokio::fs::write(&path, yaml)
            .await
            .expect("write capability");
        paths.push(path);
    }

    let (changes, source) = change_set();
    for path in &paths {
        changes.push(path.clone());
    }
    let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    SkillsWatcher::spawn_regen_task(source, shutdown_rx, out.clone(), vec![]);

    crate::test_wait::wait_until(crate::test_wait::HANG_BOUND, || async {
        let missing: Vec<String> = (0..150)
            .map(|i| format!("burst{i}"))
            .filter(|category| !skill_md(&out, category).exists())
            .collect();
        match missing.first() {
            None => std::ops::ControlFlow::Break(()),
            Some(first) => std::ops::ControlFlow::Continue(format!(
                "{} bundles missing, first missing category {first}",
                missing.len()
            )),
        }
    })
    .await
    .expect("every skill in the burst is regenerated");
}

/// SKW.2 guard: an edit pushed after a pass read the file is kept and
/// regenerated on the next pass.
#[tokio::test]
async fn an_edit_during_a_pass_is_regenerated_next_pass() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let out = tmp.path().join("skills");
    let p = tmp.path().join("p.yaml");
    tokio::fs::write(
        &p,
        cap_yaml("midpass_cap", "midpass", "midpass-before-edit"),
    )
    .await
    .expect("write capability midpass-before-edit");

    let (changes, source) = change_set();
    let (reached, release) = source.after_pass.arm();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    SkillsWatcher::spawn_regen_task(source, shutdown_rx, out.clone(), vec![]);
    changes.push(p.clone());

    crate::test_pause::within("the first pass", reached.notified()).await;
    let first =
        std::fs::read_to_string(skill_md(&out, "midpass")).expect("read the first pass bundle");
    assert!(
        first.contains("midpass-before-edit"),
        "the first pass read midpass-before-edit: {first}"
    );

    tokio::fs::write(&p, cap_yaml("midpass_cap", "midpass", "midpass-after-edit"))
        .await
        .expect("write capability midpass-after-edit");
    changes.push(p);
    release.notify_one();

    crate::test_wait::wait_until(crate::test_wait::HANG_BOUND, || async {
        let contents = std::fs::read_to_string(skill_md(&out, "midpass")).unwrap_or_default();
        if contents.contains("midpass-after-edit") {
            std::ops::ControlFlow::Break(())
        } else {
            std::ops::ControlFlow::Continue(format!(
                "SKILL.md does not contain midpass-after-edit yet: {contents}"
            ))
        }
    })
    .await
    .expect("the edit during the pass is regenerated on the next pass");
}

/// SKW.3: a pass that leaves changes behind warns once that they were
/// deferred. The warn does not exist yet, so this sees zero warns today.
#[test]
fn a_pass_that_leaves_changes_behind_warns_once() {
    let (_logs, warned) =
        crate::test_log_capture::live_count("WARN mcp_gateway::skills::watcher: Skills watcher: ");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let out = tmp.path().join("skills");
        let p = tmp.path().join("p.yaml");
        tokio::fs::write(
            &p,
            cap_yaml("midpass_cap", "midpass", "midpass-before-edit"),
        )
        .await
        .expect("write capability midpass-before-edit");

        let (changes, source) = change_set();
        let (reached, release) = source.after_pass.arm();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        SkillsWatcher::spawn_regen_task(source, shutdown_rx, out.clone(), vec![]);
        changes.push(p.clone());

        crate::test_pause::within("the first pass", reached.notified()).await;
        let first =
            std::fs::read_to_string(skill_md(&out, "midpass")).expect("read the first pass bundle");
        assert!(
            first.contains("midpass-before-edit"),
            "the first pass read midpass-before-edit: {first}"
        );

        tokio::fs::write(&p, cap_yaml("midpass_cap", "midpass", "midpass-after-edit"))
            .await
            .expect("write capability midpass-after-edit");
        changes.push(p);
        release.notify_one();

        crate::test_wait::wait_until(crate::test_wait::HANG_BOUND, || async {
            let seen = *warned.borrow();
            if seen >= 1 {
                std::ops::ControlFlow::Break(())
            } else {
                std::ops::ControlFlow::Continue(format!("{seen} warns so far"))
            }
        })
        .await
        .expect("a pass that leaves changes behind warns");

        crate::test_wait::wait_until(crate::test_wait::HANG_BOUND, || async {
            let contents = std::fs::read_to_string(skill_md(&out, "midpass")).unwrap_or_default();
            if contents.contains("midpass-after-edit") {
                std::ops::ControlFlow::Break(())
            } else {
                std::ops::ControlFlow::Continue(format!(
                    "SKILL.md does not contain midpass-after-edit yet: {contents}"
                ))
            }
        })
        .await
        .expect("the edit during the pass is regenerated on the next pass");

        // One more tick with nothing left behind must not warn again.
        // timing: absence
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(*warned.borrow(), 1, "the deferred changes warn once");
    });
}

/// SKW.3 control: a single edit with nothing behind it warns nothing.
#[test]
fn a_single_quiet_edit_warns_nothing() {
    let (_logs, warned) =
        crate::test_log_capture::live_count("WARN mcp_gateway::skills::watcher: Skills watcher: ");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let out = tmp.path().join("skills");
        let p = tmp.path().join("p.yaml");
        tokio::fs::write(&p, cap_yaml("quiet_cap", "quiet", "midpass-before-edit"))
            .await
            .expect("write capability");

        let (changes, source) = change_set();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        SkillsWatcher::spawn_regen_task(source, shutdown_rx, out.clone(), vec![]);
        changes.push(p);

        crate::test_wait::wait_until(crate::test_wait::HANG_BOUND, || async {
            if skill_md(&out, "quiet").exists() {
                std::ops::ControlFlow::Break(())
            } else {
                std::ops::ControlFlow::Continue("bundle not written yet".to_owned())
            }
        })
        .await
        .expect("the quiet edit is regenerated");

        // timing: absence
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(*warned.borrow(), 0, "a single quiet edit warns nothing");
    });
}

/// The set coalesces: a path pushed twice is taken once, and the batch comes
/// back sorted.
#[test]
fn a_path_pushed_twice_is_taken_once() {
    let (changes, _source) = change_set();
    changes.push(PathBuf::from("b.yaml"));
    changes.push(PathBuf::from("a.yaml"));
    changes.push(PathBuf::from("b.yaml"));
    assert_eq!(changes.pending_count(), 2, "the repeated path is held once");
    assert_eq!(
        changes.take_if_quiet(Duration::ZERO),
        [PathBuf::from("a.yaml"), PathBuf::from("b.yaml")]
    );
    assert_eq!(changes.pending_count(), 0, "the take empties the set");
}

/// A batch that is not yet quiet stays pending; it is not taken and not lost.
#[test]
fn a_change_inside_the_quiet_window_stays_pending() {
    let (changes, _source) = change_set();
    changes.push(PathBuf::from("a.yaml"));
    assert!(
        changes.take_if_quiet(Duration::from_secs(3600)).is_empty(),
        "nothing is due inside the quiet window"
    );
    assert_eq!(changes.pending_count(), 1, "the path is still pending");
    assert_eq!(
        changes.take_if_quiet(Duration::ZERO),
        [PathBuf::from("a.yaml")]
    );
}
