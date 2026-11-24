// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway with no capability directory (capabilities off, or on with an
//! empty list) refuses the OpenAPI import and the capability create route
//! before it fetches or writes anything. The gateway runs as a child in a
//! fresh working directory holding a sentinel `capabilities/` folder, never
//! the repository, so a write into the old relative fallback would show.
#![cfg(feature = "webui")]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use mcp_gateway::gateway::test_helpers::{CAPABILITIES_OFF, write_owner_only};
use serde_json::{Value, json};

const TOKEN: &str = "import-off-test-token-0123456789";

/// A valid document with one read operation.
const DOC: &str = "openapi: 3.0.0\ninfo:\n  title: a\n  version: \"1\"\npaths:\n  /users:\n    get:\n      operationId: listUsers\n      responses:\n        \"200\":\n          description: ok\n";

/// A capability the create route would accept and write.
const CAPABILITY: &str = "fulcrum: \"1.0\"\nname: made\ndescription: made here\n\nschema:\n  input:\n    type: object\n  output:\n    type: object\n\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://api.example\n      path: /api\n      method: GET\n";

/// The sentinel file in the working directory's `capabilities/` folder.
const SENTINEL: &[u8] = b"name: kept\n";

const OFF: &str = "capabilities:\n  enabled: false\n";
const NO_DIRECTORY: &str = "capabilities:\n  enabled: true\n  directories: []\n";

/// A running gateway, its port, and the working directory it was started in.
struct Gateway {
    child: Child,
    port: u16,
    work: tempfile::TempDir,
    _home: tempfile::TempDir,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts the gateway with `capabilities` (a config block) in a fresh working
/// directory holding `capabilities/kept.yaml`, and waits until it serves.
fn start(capabilities: &str) -> Gateway {
    let home = tempfile::tempdir().expect("home");
    let work = tempfile::tempdir().expect("working directory");
    std::fs::create_dir(work.path().join("capabilities")).expect("sentinel folder");
    std::fs::write(work.path().join("capabilities").join("kept.yaml"), SENTINEL)
        .expect("sentinel file");
    let config = home.path().join("gateway.yaml");
    let text = format!(
        "server:\n  host: 127.0.0.1\n  port: {}\nauth:\n  enabled: true\n  bearer_token: {TOKEN}\n\
         security:\n  ssrf_protection: false\ntasks:\n  store_dir: {}\n{capabilities}",
        gateway_bin::ANY_PORT,
        home.path().join("tasks").display()
    );
    write_owner_only(&config, text).expect("write config");
    let log = home.path().join("gateway.log");
    let out = std::fs::File::create(&log).expect("log file");
    let err = out.try_clone().expect("log handle");
    let mut child = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
        .env("MCP_GATEWAY_CONFIG_DIR", home.path().join("state"))
        .current_dir(work.path())
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("the built mcp-gateway binary spawns");
    let logs = || std::fs::read_to_string(&log).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(60);
    let port = loop {
        if let Some(port) =
            gateway_bin::logged_port(&log).filter(|p| gateway_bin::answers_livez(*p))
        {
            break port;
        }
        if let Some(status) = child.try_wait().expect("wait on the gateway") {
            panic!("the gateway exited {status} before serving:\n{}", logs());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the gateway never answered /livez:\n{}", logs());
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    Gateway {
        child,
        port,
        work,
        _home: home,
    }
}

impl Gateway {
    async fn post(&self, path: &str, body: &Value) -> (u16, String, Value) {
        let answer = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{}{path}", self.port))
            .bearer_auth(TOKEN)
            .json(body)
            .send()
            .await
            .expect("the gateway answers");
        let status = answer.status().as_u16();
        let kind = answer
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let text = answer.text().await.expect("a body");
        let json = serde_json::from_str(&text).unwrap_or(Value::Null);
        (status, kind, json)
    }

    /// The working directory holds only the sentinel folder, and that only
    /// the sentinel file, byte for byte.
    fn assert_untouched(&self, what: &str) {
        let names = |dir: &Path| {
            let mut names: Vec<String> = std::fs::read_dir(dir)
                .expect("list")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        let folder = self.work.path().join("capabilities");
        assert_eq!(names(self.work.path()), ["capabilities"], "{what}");
        assert_eq!(names(&folder), ["kept.yaml"], "{what}");
        let kept = std::fs::read(folder.join("kept.yaml")).expect("sentinel");
        assert_eq!(kept, SENTINEL, "{what}: the sentinel changed");
    }
}

/// A local server serving [`DOC`]; its address and the requests it took.
async fn serving_doc() -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&hits);
    let app = axum::Router::new().fallback(move || {
        count.fetch_add(1, Ordering::SeqCst);
        async { DOC }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}/spec.yaml"), hits)
}

/// IMPBIND.3: with no capability directory, the preview and the import (a
/// valid document and its correct digest, so nothing else stands in the way)
/// answer 409 before fetching, and nothing is written anywhere.
#[tokio::test]
async fn impbind3_with_no_capability_directory_the_import_refuses_before_fetching() {
    use sha2::Digest as _;
    let digest = hex::encode(sha2::Sha256::digest(DOC.as_bytes()));
    for capabilities in [OFF, NO_DIRECTORY] {
        let gateway = start(capabilities);
        let (url, hits) = serving_doc().await;
        let refused = json!({ "error": CAPABILITIES_OFF });

        let preview = gateway
            .post("/ui/api/import/openapi/preview", &json!({ "url": url }))
            .await;
        assert_eq!((preview.0, &preview.2), (409, &refused), "{capabilities}");
        let import = gateway
            .post(
                "/ui/api/import/openapi",
                &json!({ "url": url, "digest": digest }),
            )
            .await;
        assert_eq!((import.0, &import.2), (409, &refused), "{capabilities}");

        assert_eq!(hits.load(Ordering::SeqCst), 0, "{capabilities}: fetched");
        gateway.assert_untouched(capabilities);
    }
}

/// IMPBIND.5: the capability create route refuses a valid capability the
/// same way, and still answers its template to a body with no YAML.
#[tokio::test]
async fn impbind5_with_no_capability_directory_the_create_route_refuses() {
    let gateway = start(OFF);

    let body = json!({ "name": "made", "yaml": CAPABILITY });
    let (status, _, answer) = gateway.post("/ui/api/capabilities", &body).await;
    assert_eq!(status, 409, "{answer}");
    let want = json!({ "error": "capabilities_off", "message": CAPABILITIES_OFF });
    assert_eq!(answer, want);
    gateway.assert_untouched("create");

    let (status, kind, _) = gateway.post("/ui/api/capabilities", &json!({})).await;
    assert_eq!(status, 200, "the template");
    assert!(kind.starts_with("text/yaml"), "{kind}");
    gateway.assert_untouched("template");
}
