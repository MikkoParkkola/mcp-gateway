// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The pinned FastMCP + fastmcp-tasks + pydocket peer, as an owned child.
//!
//! Its Docket backend is the caller-supplied Redis service, so the job is held
//! by a task runtime that is neither this test nor the gateway. The child is
//! killed on drop, and every wait below carries a finite deadline.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::Value;

use crate::pins::{PEER_BOUND, POLL_GAP, fixture_script, pinned_python, redis_url};

/// The SDK peer's own tool, and the string only its body can produce.
pub const SDK_TOOL: &str = "slow_echo";
pub const SDK_TEXT: &str = "vertical";
pub const SDK_MARKER: &str = "upstream-sdk-answered:vertical";

pub struct SdkPeer {
    child: std::process::Child,
    port: u16,
    log: PathBuf,
    client: reqwest::Client,
}

impl Drop for SdkPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl SdkPeer {
    /// Spawn the fixture under the pinned interpreter.
    ///
    /// Writes are kept inside `root` by naming the directories the interpreter
    /// and its libraries actually consult — a temporary directory and the XDG
    /// base directories — rather than by repurposing `HOME`, and bytecode
    /// writing is off so the checked-in fixture directory stays clean.
    pub fn start(root: &Path, client: &reqwest::Client) -> Self {
        let port = crate::helper::free_port();
        let gate = root.join("sdk-gate");
        let cache = root.join("sdk-xdg");
        std::fs::create_dir_all(&cache).expect("an owned XDG root");
        let log = root.join("sdk-peer.log");
        let out = std::fs::File::create(&log).expect("an owned peer log");
        let err = out.try_clone().expect("the peer log handle clones");

        let child = std::process::Command::new(pinned_python())
            .arg(fixture_script())
            .arg("--port")
            .arg(port.to_string())
            .arg("--redis-url")
            .arg(redis_url())
            .arg("--gate-dir")
            .arg(&gate)
            .env("TMPDIR", root)
            .env("XDG_CACHE_HOME", cache.join("cache"))
            .env("XDG_CONFIG_HOME", cache.join("config"))
            .env("XDG_DATA_HOME", cache.join("data"))
            .env("XDG_STATE_HOME", cache.join("state"))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("the pinned interpreter runs the SDK fixture");

        Self {
            child,
            port,
            log,
            client: client.clone(),
        }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.port)
    }

    pub fn logs(&self) -> String {
        let body =
            std::fs::read_to_string(&self.log).unwrap_or_else(|e| format!("<unreadable: {e}>"));
        format!("--- {} ---\n{body}", self.log.display())
    }

    async fn get(&self, route: &str) -> Value {
        self.client
            .get(format!("http://127.0.0.1:{}{route}", self.port))
            .send()
            .await
            .unwrap_or_else(|e| panic!("the SDK peer did not answer {route}: {e}\n{}", self.logs()))
            .json()
            .await
            .unwrap_or_else(|e| panic!("{route} did not answer JSON: {e}\n{}", self.logs()))
    }

    pub async fn counters(&self) -> Value {
        self.get("/counters").await
    }

    pub async fn queries(&self) -> u64 {
        self.counters().await["queries"]
            .as_u64()
            .unwrap_or_default()
    }

    pub async fn gate(&self) -> Value {
        self.get("/gate").await
    }

    /// Release the held job. Idempotent on the fixture side.
    pub async fn release(&self) {
        let response = self
            .client
            .post(format!("http://127.0.0.1:{}/release", self.port))
            .send()
            .await
            .unwrap_or_else(|e| panic!("the gate did not release: {e}\n{}", self.logs()));
        assert!(
            response.status().is_success(),
            "the gate did not release: {}\n{}",
            response.status(),
            self.logs()
        );
    }

    pub async fn wait_until_ready(&mut self) {
        let url = format!("http://127.0.0.1:{}/counters", self.port);
        let deadline = tokio::time::Instant::now() + PEER_BOUND;
        loop {
            if let Some(status) = self.child.try_wait().expect("owned child status") {
                panic!(
                    "the pinned SDK peer exited before listening ({status})\n{}",
                    self.logs()
                );
            }
            if self.client.get(&url).send().await.is_ok() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the pinned SDK peer never listened on {url} within {PEER_BOUND:?}\n{}",
                self.logs()
            );
            tokio::time::sleep(POLL_GAP).await;
        }
    }

    /// Wait until the tool body has ENTERED the gate — the fixture's own state,
    /// not an elapsed interval this test would otherwise have to trust.
    pub async fn wait_until_entered(&self) {
        let deadline = tokio::time::Instant::now() + PEER_BOUND;
        loop {
            let gate = self.gate().await;
            if gate["entered"] == Value::Bool(true) {
                assert_eq!(
                    gate["released"],
                    Value::Bool(false),
                    "the gate released itself before the test asked: {gate}"
                );
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the SDK tool body never entered the gate within {PEER_BOUND:?}: \
                 {gate}\n{}",
                self.logs()
            );
            tokio::time::sleep(POLL_GAP).await;
        }
    }

    /// The job is entered and has neither finished nor timed out: it is still
    /// running, as a fact reported by the process running it.
    pub async fn assert_still_held(&self, when: &str) {
        let gate = self.gate().await;
        assert_eq!(
            (
                gate["entered"].clone(),
                gate["finished"].clone(),
                gate["expired"].clone()
            ),
            (Value::Bool(true), Value::Bool(false), Value::Bool(false)),
            "the SDK job must still be running {when}: {gate}\n{}",
            self.logs()
        );
    }
}
