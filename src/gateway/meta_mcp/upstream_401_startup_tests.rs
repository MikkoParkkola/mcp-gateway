// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A managed account whose backend refuses its startup with HTTP 401: the
//! tools/call was never sent, so the call is refused before its backend and
//! its idempotency key is released, while the caller still gets the
//! reconnect refusal a 401 on a managed credential earns.
//!
//! The backend is a real HTTP peer on a loopback listener that answers every
//! request with an empty-body 401, which the HTTP transport types as
//! `Error::Http(401)`, the error the meta route reads as an upstream 401.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::backend::PoolKey;
use crate::config::{AuthConfig, TransportConfig};
use crate::gateway::meta_mcp::dispatch_log::PreSend;
use crate::gateway::server::account_bindings::ServeMode;
use crate::protocol::JsonRpcResponse;

use super::super::super::account_resolver_fixture::{
    ALICE_WORK_TOKEN, Bind, Descriptors, ProviderStep, ROTATED_TOKEN, WORK, account_key, caller_as,
    custody_with_steps, execute, gateway_in_with, grant, identity, slots,
};

const FRESH: u64 = u64::MAX;

/// A loopback HTTP peer that answers every request with an empty-body 401 and
/// records the JSON-RPC method of each request it read.
fn refusing_peer() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let url = format!("http://{}/mcp", listener.local_addr().expect("its address"));
    let methods = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&methods);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(&stream);
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; length];
            let _ = reader.read_exact(&mut body);
            let method = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|value| value["method"].as_str().map(str::to_owned))
                .unwrap_or_default();
            seen.lock().push(method);
            let _ = stream.write_all(
                b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            );
        }
    });
    (url, methods)
}

/// A slot transport that reports itself disconnected, so the next call on the
/// slot starts a real transport from the backend's configuration.
struct Disconnected;

#[async_trait::async_trait]
impl crate::transport::Transport for Disconnected {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        unreachable!("a disconnected slot is started again before any request")
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        false
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// R12b: the managed slot's catalogue is warm; the slot is then cold, and its
/// start meets a 401. The keyed call reads refused before its backend, no
/// tools/call reaches the peer, and the same key is not answered from a
/// stored entry (it was released).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_managed_start_refused_with_401_is_refused_before_its_backend() {
    let custody = custody_with_steps(
        &[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))],
        ROTATED_TOKEN,
        &[ProviderStep::InvalidGrant, ProviderStep::InvalidGrant],
    );
    let installed = custody.installed();
    let (url, methods) = refusing_peer();
    let (_log, mut meta, _dispatches) = gateway_in_with(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK)]),
        (ServeMode::Http, AuthConfig::default()),
        move |backend| {
            backend.transport = TransportConfig::Http {
                http_url: url.clone(),
                streamable_http: Some(true),
                protocol_version: None,
            };
        },
    );
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        std::time::Duration::from_secs(300),
    );
    let alice = identity("alice");
    // Warm the catalogue through the seeded slot, so the keyed call lists
    // nothing and its own start is what meets the 401.
    Box::pin(execute(&meta, "mail", Some(&alice)))
        .await
        .expect("premise: the seeded slot serves the first call");
    let backend = meta
        .backends
        .for_test()
        .get("mail")
        .expect("the fixture registers mail");
    for binding in slots(&[("alice", WORK)]) {
        backend.set_pooled_transport_for_test(
            &PoolKey::PerUser { binding },
            Arc::new(Disconnected) as Arc<dyn crate::transport::Transport>,
        );
    }

    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("k-start-401".to_owned()),
        ..Default::default()
    };
    let mut caller = caller_as(Some(&alice), None);
    caller.retry = &retry;
    let call = json!({"server": "mail", "tool": "read", "arguments": {"folder": "inbox"}});

    let first = crate::gateway::delivery_facts::scope(Box::pin(meta.invoke_tool_sourced(
        &call,
        Some("fixture-session"),
        &caller,
        "t".to_owned(),
    )))
    .await;
    assert!(first.outcome.is_err(), "premise: the start was refused");
    let started = methods.lock().len();
    assert!(started >= 1, "premise: the start reached the peer");
    assert!(
        !methods.lock().iter().any(|method| method == "tools/call"),
        "premise: no tools/call was sent: {:?}",
        methods.lock()
    );
    assert_eq!(
        first.pre_send,
        PreSend::Refused,
        "a start refused with 401 read as a dispatched call"
    );

    let again = crate::gateway::delivery_facts::scope(Box::pin(meta.invoke_tool_sourced(
        &call,
        Some("fixture-session"),
        &caller,
        "t".to_owned(),
    )))
    .await;
    // A kept key would answer the stored may-have-run entry (the side effect
    // marker the early return commits), as a live value.
    let replayed = matches!(
        &again.outcome,
        Ok(crate::gateway::meta_mcp::invoke::SourcedOutcome::Live((value, _, _)))
            if value.to_string().contains("Side effect executed")
    );
    assert!(
        !replayed,
        "the same key was answered from the stored failure: {:?}",
        methods.lock()
    );
}
