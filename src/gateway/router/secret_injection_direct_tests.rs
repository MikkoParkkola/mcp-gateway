// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's secret-injection rules apply on the direct route
//! `/mcp/{name}` as they do through `gateway_invoke`: an `argument` rule's
//! secret reaches the backend in the tool call's arguments and a `header`
//! rule's as that header. The secret is in what is sent and nowhere the
//! gateway answers or keeps.

use serde_json::json;

use super::direct_continuation_tests::call;
use super::direct_guards_fixture::fixture_with_secrets;
#[cfg(feature = "firewall")]
use super::direct_guards_fixture::{initialize, post_meta_invoke, send_with_headers};
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget};

/// The secret the rule injects: a literal, so no environment is read.
pub(super) const SECRET: &str = "direct-route-secret-4c1e";

/// One `argument` rule injecting [`SECRET`] as `api_key`.
pub(super) fn argument_rule() -> CredentialRule {
    CredentialRule {
        name: "api".to_string(),
        credential_type: CredentialType::ApiKey,
        value: SECRET.to_string(),
        inject_as: InjectTarget::Argument,
        inject_key: "api_key".to_string(),
        tools: vec!["*".to_string()],
    }
}

/// The direct route applies an `argument` rule, on a gated and a passthrough
/// backend.
#[tokio::test]
async fn the_direct_route_applies_an_argument_rule() {
    for backend in ["alpha", "alpha-pt"] {
        let fx = fixture_with_secrets(vec![argument_rule()], None, None).await;
        let (_, body) = call(&fx, backend, None, json!({})).await;
        assert!(body.get("error").is_none(), "{backend}: premise: {body}");
        let seen = fx.seen.lock().expect("recorder").clone();
        assert!(
            seen.iter()
                .any(|params| params.pointer("/arguments/api_key") == Some(&json!(SECRET))),
            "{backend}: the argument rule's secret never reached the backend: {seen:?}"
        );
    }
}

/// What one `tools/call` reached the backend with: its params and headers.
type Sends = std::sync::Arc<std::sync::Mutex<Vec<(serde_json::Value, Vec<(String, String)>)>>>;

/// Both fixture backends: list `read`, answer every call, record each
/// `tools/call` with its headers.
struct Recorder(Sends);

#[async_trait::async_trait]
impl crate::transport::Transport for Recorder {
    /// A recording double: these rows check what a call sends, not what its
    /// answer echoes, so it stands in for a transport holding its set
    /// (DELTA-10 refuses an injected call on one that does not).
    fn redacts_injected_values(&self) -> bool {
        true
    }

    async fn request(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.request_with_headers(
            method,
            params,
            &[],
            None,
            crate::transport::ResendPermission::Denied,
        )
        .await
    }
    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
        extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let id = crate::protocol::RequestId::Number(1);
        if method == "tools/list" {
            let tool = json!({"name": "read", "inputSchema": {"type": "object"}});
            return Ok(crate::protocol::JsonRpcResponse::success(
                id,
                json!({"tools": [tool]}),
            ));
        }
        if method == "tools/call" {
            self.0.lock().expect("recorder").push((
                params.unwrap_or(serde_json::Value::Null),
                extra_headers.to_vec(),
            ));
        }
        Ok(crate::protocol::JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A `header` rule's secret reaches the backend as that header on the direct
/// route, on a gated and a passthrough backend.
#[tokio::test]
async fn the_direct_route_applies_a_header_rule() {
    for backend in ["alpha", "alpha-pt"] {
        let sends = Sends::default();
        let rule = CredentialRule {
            inject_as: InjectTarget::Header,
            inject_key: "X-Api-Key".to_string(),
            ..argument_rule()
        };
        let transport = std::sync::Arc::new(Recorder(std::sync::Arc::clone(&sends)));
        let fx = fixture_with_secrets(vec![rule], Some(transport), None).await;
        let (_, body) = call(&fx, backend, None, json!({})).await;
        assert!(body.get("error").is_none(), "{backend}: premise: {body}");
        let sends = sends.lock().expect("recorder").clone();
        assert!(
            sends.iter().any(|(_, headers)| headers
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("X-Api-Key") && value == SECRET)),
            "{backend}: no X-Api-Key header carried the secret: {sends:?}"
        );
    }
}

/// Every file under `dir`, with its bytes. A directory or file that cannot be
/// read fails the row: an unread store must not pass as a clean one. The one
/// exception is a lock sidecar the live store holds: Windows refuses to read
/// a file another handle has locked (`fs_lock::ExclusiveFileLock` is
/// `LockFileEx` there). The skip is keyed on the sidecars' names: every
/// `fs_lock` lock file is `*.lock`, and the task store's lease is
/// `store.lease` (`task_service/store.rs`, custody state, never a record); no
/// store's data file has either name.
#[cfg(feature = "firewall")]
pub(super) fn files_under(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).expect("the store directory reads") {
        let path = entry.expect("a directory entry reads").path();
        if path.is_dir() {
            files.extend(files_under(&path));
            continue;
        }
        match std::fs::read(&path) {
            Ok(bytes) => files.push((path, bytes)),
            Err(error) if locked_sidecar(&path, &error) => {}
            Err(error) => panic!("a stored file reads: {}: {error}", path.display()),
        }
    }
    files
}

/// Whether `error` is Windows' lock violation (os error 33) on a lock
/// sidecar: a `*.lock` file or the task store's `store.lease`.
#[cfg(feature = "firewall")]
fn locked_sidecar(path: &std::path::Path, error: &std::io::Error) -> bool {
    let sidecar = path
        .extension()
        .is_some_and(|extension| extension == "lock")
        || path.file_name().is_some_and(|name| name == "store.lease");
    cfg!(windows) && error.raw_os_error() == Some(33) && sidecar
}

/// Whether `bytes` holds `text`.
#[cfg(feature = "firewall")]
pub(super) fn holds(bytes: &[u8], text: &str) -> bool {
    bytes
        .windows(text.len())
        .any(|window| window == text.as_bytes())
}

/// The `_meta` of a modern call that declares the tasks extension.
#[cfg(feature = "firewall")]
fn task_meta() -> serde_json::Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":
            {"extensions": {"io.modelcontextprotocol/tasks": {}}},
    })
}

/// Submits `gateway_invoke read` on `alpha` as a task under idempotency key
/// `key`: the task id and the creating answer.
#[cfg(feature = "firewall")]
pub(super) async fn submit_task(
    fx: &super::direct_guards_fixture::Fx,
    key: &str,
) -> (String, serde_json::Value) {
    let mut meta = task_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let task = json!({"name": "gateway_invoke", "task": {}, "_meta": meta,
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}}});
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    let (_, made) =
        send_with_headers(fx, "/mcp", "k-std", "tools/call", task, None, &headers).await;
    let id = made
        .pointer("/result/task/taskId")
        .or_else(|| made.pointer("/result/taskId"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    (id, made)
}

/// Polls task `id` until it leaves `working`; it must have completed.
#[cfg(feature = "firewall")]
pub(super) async fn finished_task(
    fx: &super::direct_guards_fixture::Fx,
    id: &str,
) -> serde_json::Value {
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tasks/get"),
        ("mcp-name", id),
    ];
    let poll = async {
        loop {
            let get = json!({"taskId": id, "_meta": task_meta()});
            let (_, got) =
                send_with_headers(fx, "/mcp", "k-std", "tasks/get", get, None, &headers).await;
            if got.pointer("/result/status") != Some(&json!("working")) {
                return got;
            }
            tokio::task::yield_now().await;
        }
    };
    let finished = tokio::time::timeout(std::time::Duration::from_secs(30), poll)
        .await
        .expect("the task finished within the bound");
    assert_eq!(
        finished.pointer("/result/status"),
        Some(&json!("completed")),
        "premise: the task completed: {finished}"
    );
    finished
}

/// How many `tools/call`s reached the backend, and whether the last carried
/// the secret.
#[cfg(feature = "firewall")]
fn sends(fx: &super::direct_guards_fixture::Fx) -> (usize, bool) {
    let seen = fx.seen.lock().expect("recorder");
    let last = seen
        .last()
        .is_some_and(|params| params.pointer("/arguments/api_key") == Some(&json!(SECRET)));
    (seen.len(), last)
}

/// The secret goes into what is sent and into nothing the gateway answers or
/// keeps: not the answer, not a repeat the idempotency cache serves, not a
/// task's answer or a resubmitted task, not the task store on disk, and not
/// the audit log. Each sink is first shown to have recorded the call.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn the_secret_is_sent_and_nothing_answered_or_kept_holds_it() {
    let audit_dir = tempfile::tempdir().expect("audit directory");
    let audit = audit_dir.path().join("audit.jsonl");
    let fx = fixture_with_secrets(vec![argument_rule()], None, Some(audit.clone())).await;
    let session = initialize(&fx, "k-std").await;
    let mut answers = Vec::new();
    for _ in 0..2 {
        let (_, body) = post_meta_invoke(
            &fx,
            "k-std",
            "alpha",
            "read",
            json!({}),
            Some("idem-secret-1"),
            Some(&session),
        )
        .await;
        assert!(body.get("error").is_none(), "premise: {body}");
        answers.push(body);
    }
    assert_eq!(
        sends(&fx),
        (1, true),
        "premise: one send, the repeat served from the cache"
    );

    let (id, made) = submit_task(&fx, "idem-secret-task").await;
    let finished = finished_task(&fx, &id).await;
    assert_eq!(
        sends(&fx),
        (2, true),
        "premise: the task's own send carried the secret"
    );
    let (again, resubmitted) = submit_task(&fx, "idem-secret-task").await;
    assert_eq!(again, id, "premise: the keyed resubmit names the same task");
    assert_eq!(sends(&fx).0, 2, "premise: the resubmit dispatched nothing");
    answers.extend([made, finished, resubmitted]);
    for answer in &answers {
        assert!(
            !answer.to_string().contains(SECRET),
            "an answer holds the secret: {answer}"
        );
    }

    let stored = files_under(fx.store_path());
    assert!(
        stored.iter().any(|(_, bytes)| holds(bytes, &id)),
        "premise: a scanned file holds the stored task"
    );
    let kept: Vec<_> = stored
        .iter()
        .filter(|(_, bytes)| holds(bytes, SECRET))
        .map(|(path, _)| path)
        .collect();
    assert!(kept.is_empty(), "a stored file holds the secret: {kept:?}");

    let audited = std::fs::read(&audit).expect("the audit log was written");
    assert!(
        holds(&audited, "alpha"),
        "premise: the audit log recorded the call"
    );
    assert!(!holds(&audited, SECRET), "the audit log holds the secret");
}
