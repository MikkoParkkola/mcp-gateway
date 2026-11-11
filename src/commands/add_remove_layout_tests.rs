// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The CLI writers follow ADR-024: without `--force` they write an existing
//! gateway.yaml only as an in-place edit, comments or not; `--force` still
//! rewrites it.

use super::*;
use mcp_gateway::config::Config;
use tempfile::TempDir;

const FLOW: &str = "server: {port: 39401}\nbackends: {alpha: {command: x}}\n";

fn file_with(text: &str) -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, text).unwrap();
    (dir, path)
}

async fn add(name: &str, path: &Path, mode: CommentLoss) -> ExitCode {
    run_add_command(
        name,
        Some("echo hi"),
        None,
        None,
        super::AddValues::default(),
        path,
        mode,
    )
    .await
}

/// K1: `add` without `--force` into a comment-free flow-style file it cannot
/// edit in place fails and leaves the file byte-identical.
#[tokio::test]
async fn an_add_it_cannot_make_in_place_is_refused_without_force() {
    let (_dir, path) = file_with(FLOW);
    assert_eq!(
        add("gamma", &path, CommentLoss::Refuse).await,
        ExitCode::FAILURE
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), FLOW);
}

/// K2: the same `add` under `--force` rewrites the file and keeps both entries.
#[tokio::test]
async fn force_still_rewrites_a_file_it_cannot_edit_in_place() {
    let (_dir, path) = file_with(FLOW);
    assert_eq!(
        add("gamma", &path, CommentLoss::Rewrite).await,
        ExitCode::SUCCESS
    );
    let config = Config::load_literal(Some(&path)).unwrap();
    assert!(config.backends.contains_key("alpha") && config.backends.contains_key("gamma"));
}

/// K3: an existing file that does not parse is never rewritten: `edit_config`
/// fails before any write, with or without `--force`.
#[tokio::test]
async fn an_unparseable_file_is_left_alone() {
    let broken = "backends: [unclosed\n";
    for mode in [CommentLoss::Refuse, CommentLoss::Rewrite] {
        let (_dir, path) = file_with(broken);
        assert_eq!(
            add("gamma", &path, mode).await,
            ExitCode::FAILURE,
            "{mode:?}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), broken, "{mode:?}");
    }
}

/// C5: a file the gateway wrote itself takes a second, distinct backend in
/// place: after a first `add` into a missing file, and after a `--force`
/// rewrite. If our own output could not be spliced, every second `add`
/// would be refused.
#[tokio::test]
async fn the_gateways_own_output_takes_a_second_add_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let fresh = dir.path().join("gateway.yaml");
    assert_eq!(
        add("alpha", &fresh, CommentLoss::Refuse).await,
        ExitCode::SUCCESS
    );
    let (_forced_dir, forced) = file_with(FLOW);
    assert_eq!(
        add("alpha2", &forced, CommentLoss::Rewrite).await,
        ExitCode::SUCCESS
    );
    for path in [&fresh, &forced] {
        let before = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            add("beta", path, CommentLoss::Refuse).await,
            ExitCode::SUCCESS
        );
        let after = std::fs::read_to_string(path).unwrap();
        let mut rest = after.lines();
        for line in before.lines() {
            assert!(rest.any(|l| l == line), "{line:?} lost or moved:\n{after}");
        }
        assert!(
            Config::load_literal(Some(path))
                .unwrap()
                .backends
                .contains_key("beta")
        );
    }
}

/// A5c (code review r1, both seats): a write refused after the store step
/// (a flow-style file `add` cannot edit in place, no `--force`) leaves the
/// file unchanged and no entry holding the value: the entries made for it
/// are removed with the refused write.
#[tokio::test]
async fn a_refused_write_after_the_store_step_leaves_no_entry() {
    let flow = "secrets: {store: files}\nbackends: {alpha: {command: x}}\n";
    let (dir, path) = file_with(flow);
    // The value comes from an env file outside the scanned dir.
    let elsewhere = tempfile::tempdir().unwrap();
    let env_file = elsewhere.path().join("env.json");
    std::fs::write(&env_file, br#"{"API_KEY":"sk-live-0123456789"}"#).unwrap();
    let code = run_add_command(
        "gamma",
        Some("echo hi"),
        None,
        None,
        super::AddValues {
            env_vars: &[],
            env_file: Some(&env_file),
            keep_as_text: &[],
        },
        &path,
        CommentLoss::Refuse,
    )
    .await;
    assert_eq!(code, ExitCode::FAILURE);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), flow);
    let mut holding = Vec::new();
    let mut dirs = vec![dir.path().to_path_buf()];
    while let Some(d) = dirs.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                dirs.push(p);
            } else if std::fs::read(&p)
                .unwrap_or_default()
                .windows(18)
                .any(|w| w == b"sk-live-0123456789")
            {
                holding.push(p);
            }
        }
    }
    assert!(
        holding.is_empty(),
        "the value outlived the refused write: {holding:?}"
    );
}
