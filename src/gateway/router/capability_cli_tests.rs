// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A CLI user edits a capability through `mcp-gateway api` against a served
//! router, using only what the CLI prints: the load prints the revision, a
//! save or delete without one is told how to get it, and following that text
//! keeps another writer's change instead of overwriting it.

use std::net::SocketAddr;
use std::sync::Arc;

use super::AppState;
use super::create_router;
use super::tests::test_router_app_state_with_auth;
use crate::cli::api::ApiArgs;
use crate::config::{ApiKeyConfig, AuthConfig};

const BEARER: &str = "cli-revision-key-62d8";
const PATH: &str = "/ui/api/capabilities/twofield";
/// The two fields the two writers change, one each.
const THEIR_FIELD: (&str, &str) = (
    "description: before",
    "description: changed by the other writer",
);
const MY_FIELD: (&str, &str) = ("path: /alpha", "path: /beta");
/// The 428 a save meets without a revision, as the CLI prints it.
const SAVE_RECIPE: &str = "Run api GET /ui/api/capabilities/twofield again, apply your change to the text it returns, and save that with --if-match set to the revision it printed.";
const DELETE_RECIPE: &str = "Run api GET /ui/api/capabilities/twofield, confirm it is the version you mean to remove, and delete with --if-match set to the revision it printed.";

/// The capability both writers start from.
fn original() -> String {
    [
        "fulcrum: \"1.0\"",
        "name: twofield",
        "description: before",
        "providers:",
        "  primary:",
        "    service: rest",
        "    config:",
        "      base_url: https://twofield.example.test",
        "      path: /alpha",
    ]
    .join("\n")
        + "\n"
}

struct Served {
    base: String,
    file: std::path::PathBuf,
    _keep: (
        Arc<tempfile::TempDir>,
        crate::gateway::router::tests::FixtureDir,
    ),
}

/// A router holding `twofield.yaml`, an admin key, served on a loopback port.
async fn served() -> Served {
    let key = ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(BEARER.as_bytes())),
        name: "cli-revision-admin".to_string(),
        backends: vec!["*".to_string()],
        admin: true,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    };
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![key],
        ..Default::default()
    };
    let (mut state, store) = test_router_app_state_with_auth(&auth).await;
    let root = crate::test_dir_keep::kept_tempdir();
    let dir = root.path().join("caps");
    std::fs::create_dir(&dir).expect("the capability directory is made");
    let file = dir.join("twofield.yaml");
    crate::gateway::test_helpers::write_owner_only(&file, original()).expect("the file is written");
    Arc::get_mut(&mut state)
        .expect("the state has one owner")
        .capability_dirs = vec![dir.to_string_lossy().into_owned()];
    let base = serve(state).await;
    Served {
        base,
        file,
        _keep: (root, store),
    }
}

async fn serve(state: Arc<AppState>) -> String {
    // port-check: the listener serves on in the spawned task
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let base = format!("http://{}", listener.local_addr().expect("its address"));
    let app = create_router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    base
}

/// What one run printed, and its exit code.
struct Printed {
    code: u8,
    stdout: String,
    stderr: String,
}

/// `mcp-gateway api <words>` as the shell would pass them, with `stdin`.
async fn cli(fx: &Served, words: &[&str], stdin: &str) -> Printed {
    use clap::{Args as _, FromArgMatches as _};
    let matches = ApiArgs::augment_args(clap::Command::new("api"))
        .try_get_matches_from(std::iter::once("api").chain(words.iter().copied()))
        .expect("the CLI accepts these words");
    let args = ApiArgs::from_arg_matches(&matches).expect("api arguments");
    let out =
        crate::commands::run_api_for_tests(&args, &fx.base, BEARER, stdin.as_bytes().to_vec())
            .await;
    Printed {
        code: out.exit().code(),
        stdout: String::from_utf8(out.stdout().to_vec()).expect("text on stdout"),
        stderr: out.stderr().to_owned(),
    }
}

/// The revision the load printed, read from its stderr and nowhere else.
fn printed_revision(stderr: &str) -> String {
    stderr
        .lines()
        .find_map(|line| line.strip_prefix("api: revision "))
        .and_then(|rest| rest.split_once("; "))
        .map_or_else(
            || panic!("the load printed no revision: {stderr}"),
            |(token, _)| token.to_owned(),
        )
}

fn on_disk(fx: &Served) -> String {
    std::fs::read_to_string(&fx.file).expect("the capability file reads")
}

/// The other writer's change, made through the CLI with the revision it loaded.
async fn other_writer_saves(fx: &Served, loaded: &str, revision: &str) {
    let theirs = loaded.replace(THEIR_FIELD.0, THEIR_FIELD.1);
    let out = cli(
        fx,
        &["PUT", PATH, "--data", "-", "--if-match", revision],
        &theirs,
    )
    .await;
    assert_eq!(
        out.code, 0,
        "premise: the other writer saves: {}",
        out.stderr
    );
}

/// CLI428.1: load, a concurrent save by someone else, a save without the
/// revision told how to recover, a save with the stale revision refused, and
/// the recovery the refusal describes keeping both changes.
#[tokio::test]
async fn a_cli_save_recovers_by_the_printed_text_and_keeps_another_writers_change() {
    let fx = served().await;
    let load = cli(&fx, &["GET", PATH], "").await;
    assert_eq!(load.code, 0, "{}", load.stderr);
    assert_eq!(load.stdout, original(), "the load prints the file's text");
    let first = printed_revision(&load.stderr);
    other_writer_saves(&fx, &load.stdout, &first).await;
    // The file as the other writer's save left it, for the refused saves below.
    let theirs = on_disk(&fx);

    let mine = load.stdout.replace(MY_FIELD.0, MY_FIELD.1);
    let bare = cli(&fx, &["PUT", PATH, "--data", "-"], &mine).await;
    assert_ne!(bare.code, 0, "a save without a revision is refused");
    assert!(
        bare.stderr.contains(&format!(
            "\n{SAVE_RECIPE} Gateway reason: precondition_required.\n"
        )),
        "the refusal must say how to save: {}",
        bare.stderr
    );

    let stale = cli(
        &fx,
        &["PUT", PATH, "--data", "-", "--if-match", &first],
        &mine,
    )
    .await;
    assert_ne!(stale.code, 0, "the first load's revision no longer matches");
    assert!(
        stale
            .stderr
            .contains(&format!("\n{SAVE_RECIPE} Gateway reason: stale.\n")),
        "{}",
        stale.stderr
    );
    // Both refused saves left the file exactly as the other writer saved it.
    assert_eq!(on_disk(&fx), theirs, "a refused save changed the file");

    let reload = cli(&fx, &["GET", PATH], "").await;
    let second = printed_revision(&reload.stderr);
    let rebased = reload.stdout.replace(MY_FIELD.0, MY_FIELD.1);
    let saved = cli(
        &fx,
        &["PUT", PATH, "--data", "-", "--if-match", &second],
        &rebased,
    )
    .await;
    assert_eq!(saved.code, 0, "{}", saved.stderr);
    let now = on_disk(&fx);
    assert!(
        now.contains(THEIR_FIELD.1),
        "the other writer's change survives: {now}"
    );
    assert!(
        now.contains(MY_FIELD.1),
        "the user's change is saved: {now}"
    );
}

/// A delete without a revision is told how to get one; with the printed one
/// it removes the file.
#[tokio::test]
async fn a_cli_delete_uses_the_printed_revision() {
    let fx = served().await;
    let load = cli(&fx, &["GET", PATH], "").await;
    let revision = printed_revision(&load.stderr);
    let bare = cli(&fx, &["DELETE", PATH], "").await;
    assert_ne!(bare.code, 0, "a delete without a revision is refused");
    assert!(
        bare.stderr.contains(&format!(
            "\n{DELETE_RECIPE} Gateway reason: precondition_required.\n"
        )),
        "{}",
        bare.stderr
    );
    assert!(fx.file.exists(), "the refused delete removed nothing");
    let gone = cli(&fx, &["DELETE", PATH, "--if-match", &revision], "").await;
    assert_eq!(gone.code, 0, "{}", gone.stderr);
    assert!(!fx.file.exists(), "the delete removed the file");
}

/// A delete with a revision another writer has since replaced is refused, and
/// the file keeps that writer's change.
#[tokio::test]
async fn a_cli_delete_of_a_changed_capability_is_refused() {
    let fx = served().await;
    let load = cli(&fx, &["GET", PATH], "").await;
    let checked = printed_revision(&load.stderr);
    other_writer_saves(&fx, &load.stdout, &checked).await;
    let theirs = on_disk(&fx);
    let late = cli(&fx, &["DELETE", PATH, "--if-match", &checked], "").await;
    assert_ne!(late.code, 0, "the checked revision is no longer the file's");
    // Refused as stale, and told to retry the delete on a fresh load, not to
    // edit and save.
    assert!(
        late.stderr
            .contains(&format!("\n{DELETE_RECIPE} Gateway reason: stale.\n")),
        "{}",
        late.stderr
    );
    assert_eq!(on_disk(&fx), theirs, "the file and its change stay");
}
