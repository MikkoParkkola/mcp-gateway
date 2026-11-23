// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One recorded changed-capability file that cannot be read, or whose pin
//! line does not parse, is its own To do item: the list, the count and every
//! other resolve keep answering (rows F1-F8 of the design).

#[cfg(unix)]
use std::collections::BTreeSet;
use std::path::PathBuf;

use super::*;
use crate::capability::hash::{compute_capability_hash, rewrite_with_pin};
use crate::capability::{CapabilityBackend, CapabilityExecutor};

const STEADY: &str = "As it was loaded";
const SENTINEL: &str = "sentinel-onefile-4417";
const UNREADABLE: &str = "capability_unreadable";
const CHANGED: &str = "capability_changed";

/// A capability spec named `name`, pinned to its own bytes.
fn spec(name: &str) -> String {
    let text = format!(
        "name: {name}\ndescription: {STEADY}\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.com\n      path: /v1\n"
    );
    rewrite_with_pin(&text, &compute_capability_hash(&text))
}

/// A gateway with capabilities loaded and then changed on disk (one pin
/// mismatch recorded per file), an open access request, and the tick running.
struct Bench {
    state: Arc<AppState>,
    // Read only by the unix rows (the capability-loaded checks).
    #[cfg(unix)]
    backend: Arc<CapabilityBackend>,
    folder: Arc<tempfile::TempDir>,
    request: String,
    digest: String,
    _held: (
        crate::gateway::router::tests::FixtureDir,
        Arc<TransparencyLogger>,
        tokio::sync::broadcast::Sender<()>,
    ),
}

impl Bench {
    /// `tools` loaded then changed; the access request names `asked_for`.
    async fn start(tools: &[&str], asked_for: &str) -> Self {
        let folder = crate::test_dir_keep::kept_tempdir();
        for tool in tools {
            std::fs::write(folder.path().join(format!("{tool}.yaml")), spec(tool)).expect("spec");
        }
        let backend = Arc::new(CapabilityBackend::new(
            "onefile",
            Arc::new(CapabilityExecutor::new()),
        ));
        backend
            .load_from_directory(folder.path().to_str().expect("a utf-8 folder"))
            .await
            .expect("the specs load");
        for tool in tools {
            let changed = spec(tool).replace(STEADY, &format!("Changed since, {SENTINEL}"));
            std::fs::write(folder.path().join(format!("{tool}.yaml")), changed).expect("changed");
        }
        assert_eq!(backend.detect_rug_pulls().await.len(), tools.len());
        let log = log_in(&folder, 1 << 20, 12);
        let now = crate::clock::utc_now().expect("a readable clock");
        write(&log, note(asked_for, now));
        let (governance, store) = governance_in(&folder);
        let (state, fixture) = state_with_store(&log, &store).await;
        *state.meta_mcp.capabilities.write() = Some(Arc::clone(&backend));
        let (stop, shutdown) = tokio::sync::broadcast::channel(1);
        let _tick = start(
            &state.meta_mcp,
            None,
            shutdown,
            state.control_plane_store.clone(),
        );
        let body = served_when(&state, |body| {
            of_kind(body, "access_request").len() == 1
                && of_kind(body, CHANGED).len() == tools.len()
        })
        .await;
        let asked = of_kind(&body, "access_request")[0];
        let request = asked["id"].as_str().expect("an id").to_owned();
        let digest = asked["scope_digest"].as_str().expect("a digest").to_owned();
        Self {
            state,
            #[cfg(unix)]
            backend,
            folder,
            request,
            digest,
            _held: (fixture, governance, stop),
        }
    }

    fn file(&self, tool: &str) -> PathBuf {
        self.folder.path().join(format!("{tool}.yaml"))
    }

    /// The list's answer once `done` holds, else the last answer after a
    /// generous bound (the row then asserts on what it got).
    async fn settle(&self, done: impl Fn(StatusCode, &Value) -> bool) -> (StatusCode, Value) {
        let bound = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let (status, body) = get(&self.state, true).await;
            if done(status, &body) || tokio::time::Instant::now() >= bound {
                return (status, body);
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }

    /// A deny of `id` with `digest`, as the To do page sends it.
    async fn deny(&self, id: &str, digest: &str) -> (StatusCode, Value) {
        let guard = Guard::for_route(
            routes::UI_DECISIONS_RESOLVE,
            &Method::POST,
            Some(client(true)),
        );
        let reply = resolve_decision(
            State(Arc::clone(&self.state)),
            axum::Extension(self.state.live_config.generation()),
            guard,
            axum::extract::Path(id.to_owned()),
            axum::body::Bytes::from(
                json!({"action": "deny", "reason": "not needed", "scope_digest": digest})
                    .to_string(),
            ),
        )
        .await;
        let code = reply.status();
        let raw = to_bytes(reply.into_body(), usize::MAX)
            .await
            .expect("the reply");
        (code, serde_json::from_slice(&raw).unwrap_or_default())
    }
}

/// The listed items of `kind`.
fn of_kind<'a>(body: &'a Value, kind: &str) -> Vec<&'a Value> {
    body["decisions"]
        .as_array()
        .map(|items| items.iter().filter(|item| item["kind"] == kind).collect())
        .unwrap_or_default()
}

/// The `tool` of each listed item of `kind`.
#[cfg(unix)]
fn tools_of(body: &Value, kind: &str) -> BTreeSet<String> {
    of_kind(body, kind)
        .iter()
        .filter_map(|item| item["tool"].as_str().map(str::to_owned))
        .collect()
}

#[cfg(unix)]
fn lock(file: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
}

#[cfg(unix)]
fn unlock(file: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
}

/// Bytes whose pin line does not parse, carrying the sentinel.
fn garble(file: &std::path::Path) {
    std::fs::write(file, format!("name: [unclosed {SENTINEL}\n")).expect("garbled");
}

/// F1 (ONEFILE.2): an unreadable file leaves the list, the count and a deny
/// of the unrelated access request working.
#[cfg(unix)]
#[tokio::test]
async fn f1_an_unreadable_changed_file_leaves_list_count_and_resolve_working() {
    let bench = Bench::start(&["alpha"], "stripe.charges").await;
    lock(&bench.file("alpha"));
    let (status, body) = bench
        .settle(|code, body| code == StatusCode::OK && of_kind(body, UNREADABLE).len() == 1)
        .await;
    assert_eq!(
        (status, of_kind(&body, UNREADABLE).len()),
        (StatusCode::OK, 1),
        "the bad file is not listed: {body}"
    );
    let (count_status, count_body) = count(&bench.state, true).await;
    assert_eq!(count_status, StatusCode::OK, "{count_body}");
    let (denied, reply) = bench.deny(&bench.request, &bench.digest).await;
    unlock(&bench.file("alpha"));
    assert_eq!(denied, StatusCode::OK, "{reply}");
}

/// F2 (ONEFILE.2): the same with the file garbled.
#[tokio::test]
async fn f2_a_garbled_changed_file_leaves_list_count_and_resolve_working() {
    let bench = Bench::start(&["bravo"], "stripe.charges").await;
    garble(&bench.file("bravo"));
    let (status, body) = bench
        .settle(|code, body| code == StatusCode::OK && of_kind(body, UNREADABLE).len() == 1)
        .await;
    assert_eq!(
        (status, of_kind(&body, UNREADABLE).len()),
        (StatusCode::OK, 1),
        "the bad file is not listed: {body}"
    );
    let (count_status, count_body) = count(&bench.state, true).await;
    assert_eq!(count_status, StatusCode::OK, "{count_body}");
    let (denied, reply) = bench.deny(&bench.request, &bench.digest).await;
    assert_eq!(denied, StatusCode::OK, "{reply}");
}

/// F2b (ONEFILE.2): both at once, beside a readable change; the count's
/// number is the list's length, both bad files included.
#[cfg(unix)]
#[tokio::test]
async fn f2b_an_unreadable_and_a_garbled_file_together_leave_everything_working() {
    let bench = Bench::start(&["charlie", "delta", "echo"], "stripe.charges").await;
    lock(&bench.file("charlie"));
    garble(&bench.file("delta"));
    let (status, body) = bench
        .settle(|code, body| code == StatusCode::OK && of_kind(body, UNREADABLE).len() == 2)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        tools_of(&body, UNREADABLE),
        BTreeSet::from(["charlie".to_owned(), "delta".to_owned()])
    );
    let (count_status, counted) = count(&bench.state, true).await;
    assert_eq!(
        (count_status, counted["count"].clone()),
        (
            StatusCode::OK,
            json!(body["decisions"].as_array().map_or(0, Vec::len))
        )
    );
    let (denied, reply) = bench.deny(&bench.request, &bench.digest).await;
    unlock(&bench.file("charlie"));
    assert_eq!(denied, StatusCode::OK, "{reply}");
}

/// F3 (ONEFILE.1): each bad file's item shows only its tool, backend and a
/// reason class: exact keys, never the path or the bytes.
#[cfg(unix)]
#[tokio::test]
async fn f3_the_item_names_the_tool_and_a_reason_never_the_path_or_bytes() {
    let bench = Bench::start(&["foxtrot", "golf", "hotel"], "stripe.charges").await;
    lock(&bench.file("foxtrot"));
    garble(&bench.file("golf"));
    // A directory where the file was: unreadable, for neither permission
    // nor absence.
    std::fs::remove_file(bench.file("hotel")).expect("removed");
    std::fs::create_dir(bench.file("hotel")).expect("a directory in its place");
    let (_, body) = bench
        .settle(|code, body| code == StatusCode::OK && of_kind(body, UNREADABLE).len() == 3)
        .await;
    unlock(&bench.file("foxtrot"));
    let reasons: BTreeSet<(String, String)> = of_kind(&body, UNREADABLE)
        .iter()
        .map(|item| {
            (
                item["tool"].as_str().unwrap_or_default().to_owned(),
                item["reason"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        reasons,
        BTreeSet::from([
            ("foxtrot".to_owned(), "no_permission".to_owned()),
            ("golf".to_owned(), "did_not_parse".to_owned()),
            ("hotel".to_owned(), "not_a_readable_file".to_owned()),
        ])
    );
    let keys: BTreeSet<&str> = of_kind(&body, UNREADABLE)[0]
        .as_object()
        .map(|item| item.keys().map(String::as_str).collect())
        .unwrap_or_default();
    assert_eq!(
        keys,
        BTreeSet::from([
            "backend",
            "id",
            "kind",
            "observed_at",
            "reason",
            "tool",
            "trusted_name",
            "waits_on"
        ])
    );
    let text = body.to_string();
    assert!(
        !text.contains(&*bench.folder.path().to_string_lossy()),
        "{text}"
    );
    assert!(!text.contains(SENTINEL), "{text}");
}

/// F4 (ONEFILE.2): beside a bad file, the access request and a readable
/// change are listed as before.
#[cfg(unix)]
#[tokio::test]
async fn f4_the_other_items_stay_listed_beside_a_bad_file() {
    let bench = Bench::start(&["hotel", "india"], "stripe.charges").await;
    lock(&bench.file("hotel"));
    let (_, body) = bench
        .settle(|code, body| code == StatusCode::OK && of_kind(body, UNREADABLE).len() == 1)
        .await;
    unlock(&bench.file("hotel"));
    assert_eq!(
        (
            of_kind(&body, "access_request").len(),
            tools_of(&body, CHANGED)
        ),
        (1, BTreeSet::from(["india".to_owned()]))
    );
}

/// F5 (ONEFILE.3): listed while bad with the capability off; gone, with no
/// changed item, once the bytes match their pin again or the file is gone.
#[cfg(unix)]
#[tokio::test]
async fn f5_the_item_lasts_while_the_file_is_bad_and_then_goes() {
    for removed in [false, true] {
        let bench = Bench::start(&["juliet"], "stripe.charges").await;
        let file = bench.file("juliet");
        lock(&file);
        let (_, body) = bench
            .settle(|code, body| code == StatusCode::OK && of_kind(body, UNREADABLE).len() == 1)
            .await;
        assert_eq!(
            tools_of(&body, UNREADABLE),
            BTreeSet::from(["juliet".to_owned()])
        );
        assert!(
            !bench.backend.has_capability("juliet"),
            "stays off while listed"
        );
        unlock(&file);
        if removed {
            std::fs::remove_file(&file).expect("removed");
        } else {
            std::fs::write(&file, spec("juliet")).expect("matching bytes");
        }
        let (_, body) = bench
            .settle(|code, body| {
                code == StatusCode::OK
                    && of_kind(body, UNREADABLE).is_empty()
                    && of_kind(body, CHANGED).is_empty()
            })
            .await;
        assert_eq!(
            (tools_of(&body, UNREADABLE), tools_of(&body, CHANGED)),
            (BTreeSet::new(), BTreeSet::new()),
            "removed={removed}: {body}"
        );
    }
}

/// F5b (ONEFILE.3): one file through unreadable, garbled, changed,
/// unreadable, matching. One id while it is bad, the same id when it is bad
/// again, never two items at once.
#[cfg(unix)]
#[tokio::test]
async fn f5b_one_file_keeps_one_item_through_every_state() {
    let bench = Bench::start(&["kilo"], "stripe.charges").await;
    let file = bench.file("kilo");
    lock(&file);
    let (_, first) = bench
        .settle(|code, body| code == StatusCode::OK && of_kind(body, UNREADABLE).len() == 1)
        .await;
    // Listed while unreadable: without this the id comparisons below would
    // hold between two absent items.
    assert_eq!(
        of_kind(&first, UNREADABLE).len(),
        1,
        "listed while unreadable: {first}"
    );
    let unreadable = of_kind(&first, UNREADABLE)
        .first()
        .map(|item| (*item).clone());
    unlock(&file);
    garble(&file);
    let (_, garbled) = bench
        .settle(|code, body| {
            code == StatusCode::OK
                && of_kind(body, UNREADABLE)
                    .first()
                    .is_some_and(|item| item["reason"] == "did_not_parse")
        })
        .await;
    assert_eq!(
        of_kind(&garbled, UNREADABLE).len(),
        1,
        "listed while garbled: {garbled}"
    );
    let as_garbled = of_kind(&garbled, UNREADABLE)
        .first()
        .map(|item| (*item).clone());
    assert_eq!(
        (
            as_garbled.as_ref().map(|item| item["id"].clone()),
            as_garbled.as_ref().map(|item| item["observed_at"].clone())
        ),
        (
            unreadable.as_ref().map(|item| item["id"].clone()),
            unreadable.as_ref().map(|item| item["observed_at"].clone())
        ),
        "one item across unreadable -> garbled"
    );
    std::fs::write(&file, spec("kilo").replace(STEADY, "Changed again")).expect("changed");
    let (_, changed) = bench
        .settle(|code, body| code == StatusCode::OK && of_kind(body, UNREADABLE).is_empty())
        .await;
    assert_eq!(
        (
            of_kind(&changed, UNREADABLE).len(),
            tools_of(&changed, CHANGED)
        ),
        (0, BTreeSet::from(["kilo".to_owned()]))
    );
    lock(&file);
    let (_, again) = bench
        .settle(|code, body| code == StatusCode::OK && of_kind(body, UNREADABLE).len() == 1)
        .await;
    unlock(&file);
    assert_eq!(
        of_kind(&again, UNREADABLE)
            .first()
            .map(|item| item["id"].clone()),
        unreadable.as_ref().map(|item| item["id"].clone()),
        "the same file is the same item"
    );
    std::fs::write(&file, spec("kilo")).expect("matching bytes");
    let (_, settled) = bench
        .settle(|code, body| {
            code == StatusCode::OK
                && of_kind(body, UNREADABLE).is_empty()
                && of_kind(body, CHANGED).is_empty()
        })
        .await;
    assert_eq!(
        (
            of_kind(&settled, UNREADABLE).len(),
            of_kind(&settled, CHANGED).len()
        ),
        (0, 0)
    );
}

/// F6 (ONEFILE.4): every recorded file is listed exactly once, as changed or
/// as unreadable; never missing, never twice.
#[cfg(unix)]
#[tokio::test]
async fn f6_every_recorded_file_is_listed_exactly_once() {
    let bench = Bench::start(&["lima", "mike", "november"], "stripe.charges").await;
    lock(&bench.file("mike"));
    garble(&bench.file("november"));
    let (_, body) = bench
        .settle(|code, body| code == StatusCode::OK && of_kind(body, UNREADABLE).len() == 2)
        .await;
    unlock(&bench.file("mike"));
    let recorded = bench.backend.rug_pull_records().len();
    let listed = of_kind(&body, CHANGED).len() + of_kind(&body, UNREADABLE).len();
    let mut every: BTreeSet<String> = tools_of(&body, CHANGED);
    every.extend(tools_of(&body, UNREADABLE));
    assert_eq!(
        (every, listed, recorded),
        (
            BTreeSet::from(["lima".to_owned(), "mike".to_owned(), "november".to_owned()]),
            3,
            3
        )
    );
}

/// F7 (D3): an access request waiting on the bad file's trusted name waits
/// on its item.
#[cfg(unix)]
#[tokio::test]
async fn f7_a_request_for_the_bad_tool_waits_on_its_item() {
    let bench = Bench::start(&["oscar"], "oscar").await;
    lock(&bench.file("oscar"));
    let (_, body) = bench
        .settle(|code, body| code == StatusCode::OK && of_kind(body, UNREADABLE).len() == 1)
        .await;
    unlock(&bench.file("oscar"));
    let item = of_kind(&body, UNREADABLE)
        .first()
        .map(|item| item["id"].clone())
        .unwrap_or_default();
    let waits = of_kind(&body, "access_request")
        .first()
        .map(|request| request["waits_on"].clone())
        .unwrap_or_default();
    assert!(
        waits.as_array().is_some_and(|ids| ids.contains(&item)),
        "{waits} should hold {item}"
    );
}

/// F8 (D5): the new item is not resolvable.
#[cfg(unix)]
#[tokio::test]
async fn f8_the_bad_files_item_is_not_resolvable() {
    let bench = Bench::start(&["papa"], "stripe.charges").await;
    lock(&bench.file("papa"));
    let (_, body) = bench
        .settle(|code, body| code == StatusCode::OK && of_kind(body, UNREADABLE).len() == 1)
        .await;
    let id = of_kind(&body, UNREADABLE)
        .first()
        .and_then(|item| item["id"].as_str())
        .unwrap_or("absent")
        .to_owned();
    let (code, reply) = bench.deny(&id, &"0".repeat(64)).await;
    unlock(&bench.file("papa"));
    assert_eq!(
        (code, reply["error"].clone()),
        (StatusCode::UNPROCESSABLE_ENTITY, json!("not_resolvable"))
    );
}
