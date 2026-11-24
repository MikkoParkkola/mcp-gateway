// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway with no capability directory (capabilities off, or on with an
//! empty list) refuses the OpenAPI import and the capability create route
//! before it fetches or writes anything. The gateway runs as a child (the
//! shared HTTP fixture) whose working directory is a fresh folder, never the
//! repository; a sentinel `capabilities/` folder there makes a write into the
//! old relative fallback show.
#![cfg(feature = "webui")]

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;
// `common/signing_gateway.rs` names `crate::yaml`, so this crate declares it.
#[path = "common/yaml.rs"]
mod yaml;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use mcp_gateway::gateway::test_helpers::CAPABILITIES_OFF;
use serde_json::{Value, json};
use signing_gateway::HttpGateway;

const TOKEN: &str = "import-off-test-token-0123456789";

/// A valid document with one read operation.
const DOC: &str = "openapi: 3.0.0\ninfo:\n  title: a\n  version: \"1\"\npaths:\n  /users:\n    get:\n      operationId: listUsers\n      responses:\n        \"200\":\n          description: ok\n";

/// A capability the create route would accept and write.
const CAPABILITY: &str = "fulcrum: \"1.0\"\nname: made\ndescription: made here\n\nschema:\n  input:\n    type: object\n  output:\n    type: object\n\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://api.example\n      path: /api\n      method: GET\n";

/// The sentinel file in the working directory's `capabilities/` folder.
const SENTINEL: &[u8] = b"name: kept\n";

/// The two ways a gateway has no capability directory.
fn no_directory_configs() -> [(&'static str, Value); 2] {
    [
        ("off", json!({ "enabled": false })),
        (
            "on, no directory",
            json!({ "enabled": true, "directories": [] }),
        ),
    ]
}

/// The gateway, its working directory, and that directory's entries once
/// the sentinel folder was placed (before any request).
struct NoDirectory {
    gateway: HttpGateway,
    work: PathBuf,
    entries: Vec<String>,
}

/// The entries of `dir`, sorted, leaving out dot-entries: the fixture's folder
/// is also the gateway's home, where it keeps its own state.
fn entries_of(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with('.'))
        .collect();
    names.sort();
    names
}

impl NoDirectory {
    /// A gateway with `capabilities` as its capability settings, admin by
    /// bearer, allowed to fetch from loopback.
    async fn start(capabilities: Value) -> Self {
        let config = json!({
            "auth": { "enabled": true, "bearer_token": TOKEN },
            "security": { "ssrf_protection": false },
            "capabilities": capabilities,
        });
        let gateway = HttpGateway::start(config).await;
        let work = gateway
            .config_path()
            .parent()
            .expect("the gateway's directory")
            .to_path_buf();
        std::fs::create_dir(work.join("capabilities")).expect("sentinel folder");
        std::fs::write(work.join("capabilities").join("kept.yaml"), SENTINEL)
            .expect("sentinel file");
        let entries = entries_of(&work);
        Self {
            gateway,
            work,
            entries,
        }
    }

    async fn post(&self, path: &str, body: &Value) -> (u16, String, Value) {
        let answer = self
            .gateway
            .client
            .post(format!("{}{path}", self.gateway.url))
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

    /// No entry appeared in the working directory, and the sentinel folder
    /// holds only the sentinel file, byte for byte.
    fn assert_untouched(&self, what: &str) {
        let folder = self.work.join("capabilities");
        assert_eq!(entries_of(&self.work), self.entries, "{what}");
        assert_eq!(entries_of(&folder), ["kept.yaml"], "{what}");
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
    for (case, capabilities) in no_directory_configs() {
        let gateway = NoDirectory::start(capabilities).await;
        let (url, hits) = serving_doc().await;
        let refused = json!({ "error": CAPABILITIES_OFF });

        let preview = gateway
            .post("/ui/api/import/openapi/preview", &json!({ "url": url }))
            .await;
        assert_eq!((preview.0, &preview.2), (409, &refused), "{case}");
        let import = gateway
            .post(
                "/ui/api/import/openapi",
                &json!({ "url": url, "digest": digest }),
            )
            .await;
        assert_eq!((import.0, &import.2), (409, &refused), "{case}");

        assert_eq!(hits.load(Ordering::SeqCst), 0, "{case}: fetched");
        gateway.assert_untouched(case);
        gateway.gateway.stop().await;
    }
}

/// IMPBIND.5: the capability create route refuses a valid capability the
/// same way, and still answers its template to a body with no YAML.
#[tokio::test]
async fn impbind5_with_no_capability_directory_the_create_route_refuses() {
    let [(_, off), _] = no_directory_configs();
    let gateway = NoDirectory::start(off).await;

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
    gateway.gateway.stop().await;
}
