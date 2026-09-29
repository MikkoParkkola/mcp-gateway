// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ASI07 increment 2, direct `/mcp/{backend}` route: origin-link emission,
//! backend-chain strip and request-nonce validation. Red-first.

use super::*;
use crate::config::ChainEmit;
use crate::gateway::chain_test_support::{
    CHAIN_KEY, NONCE_KEY, carries_chain, chain_of, origin_link, signer, verify_self,
};
use crate::protocol::mrtr::chain_nonce_from_params;
use crate::security::signature_chain::{LinkSource, content_digest};

const NONCE: &str = "direct-chain-nonce";

struct FixedTransport {
    response: JsonRpcResponse,
}

#[async_trait]
impl Transport for FixedTransport {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        Ok(self.response.clone())
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

fn ok_body() -> Value {
    json!({"content": [{"type": "text", "text": "hello"}], "isError": false})
}

/// POST one `tools/call` to `/mcp/demo` against a backend returning `response`.
/// `nonce` becomes `params._meta` chain-nonce verbatim when present.
async fn post_direct(
    response: JsonRpcResponse,
    emit: Option<ChainEmit>,
    provenance: bool,
    nonce: Option<Value>,
) -> Value {
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(FixedTransport { response }));
    let (state, _store) = test_router_app_state_with_meta(backend, |meta| {
        if let Some(emit) = emit {
            meta.set_chain_signer(signer(), emit);
        }
        if provenance {
            meta.enable_provenance_stamping(
                crate::attestation::BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
                    .derive_domain(crate::attestation::RESULT_PROVENANCE_DOMAIN_INFO),
            );
        }
    })
    .await;
    let mut params = json!({"name": "search", "arguments": {}});
    if let Some(nonce) = nonce {
        params["_meta"] = json!({ NONCE_KEY: nonce });
    }
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .unwrap();
    let response = create_router(state).oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn success(result: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(RequestId::Number(1), result)
}

#[tokio::test]
async fn origin_link_emitted_direct_route() {
    let json = post_direct(
        success(ok_body()),
        Some(ChainEmit::OnRequest),
        false,
        Some(json!(NONCE)),
    )
    .await;
    let chain = chain_of(&json["result"]).expect("chain emitted");
    let digest = content_digest(&ok_body()).expect("digest");
    std::assert_eq!(
        verify_self(chain, &digest, NONCE).expect("verifies").len(),
        1
    );
    let link = origin_link(chain, LinkSource::Live, Some(NONCE));
    std::assert_eq!(link.out.as_deref(), Some(digest.as_str()));
}

#[tokio::test]
async fn no_link_without_nonce_on_request_direct() {
    for provenance in [false, true] {
        let json = post_direct(
            success(ok_body()),
            Some(ChainEmit::OnRequest),
            provenance,
            None,
        )
        .await;
        assert!(!carries_chain(&json["result"]), "provenance={provenance}");
    }
}

#[tokio::test]
async fn backend_chain_stripped_without_emission_direct() {
    for provenance in [false, true] {
        let mut forged = ok_body();
        forged["_meta"] = json!({CHAIN_KEY: [{"gw": "attacker"}], "keep": 1});
        let json = post_direct(success(forged), None, provenance, Some(json!(NONCE))).await;
        assert!(!carries_chain(&json["result"]), "provenance={provenance}");
        std::assert_eq!(json["result"]["_meta"]["keep"], 1);
        let mut only = ok_body();
        only["_meta"] = json!({CHAIN_KEY: []});
        let json = post_direct(success(only), None, false, None).await;
        assert!(
            json["result"].get("_meta").is_none(),
            "emptied _meta dropped"
        );
    }
}

#[tokio::test]
async fn is_error_backend_result_chained_direct() {
    let mut failing = ok_body();
    failing["isError"] = json!(true);
    let json = post_direct(
        success(failing),
        Some(ChainEmit::OnRequest),
        false,
        Some(json!(NONCE)),
    )
    .await;
    assert!(chain_of(&json["result"]).is_some());
}

#[tokio::test]
async fn json_rpc_error_not_chained_direct() {
    let failure = JsonRpcResponse::error(Some(RequestId::Number(1)), -32000, "backend failed");
    let json = post_direct(failure, Some(ChainEmit::Always), false, Some(json!(NONCE))).await;
    assert!(!json.to_string().contains(CHAIN_KEY));
}

#[tokio::test]
async fn unhashable_final_content_refused_direct() {
    let mut unhashable = ok_body();
    unhashable["structuredContent"] = json!({"n": 9_007_199_254_740_993_u64});
    let json = post_direct(success(unhashable), Some(ChainEmit::Always), false, None).await;
    std::assert_eq!(json["error"]["code"], -32001);
    assert!(!json.to_string().contains(CHAIN_KEY));
}

#[tokio::test]
async fn oversized_outgoing_link_refused_direct() {
    let control_nonce = json!("\0".repeat(256));
    let json = post_direct(
        success(ok_body()),
        Some(ChainEmit::Always),
        false,
        Some(control_nonce),
    )
    .await;
    std::assert_eq!(json["error"]["code"], -32001);
}

#[tokio::test]
async fn chain_nonce_invalid_refused_direct() {
    for bad in [json!(""), json!("n".repeat(257)), json!(5)] {
        let json = post_direct(
            success(ok_body()),
            Some(ChainEmit::OnRequest),
            false,
            Some(bad),
        )
        .await;
        std::assert_eq!(json["error"]["code"], -32602);
    }
    let json = post_direct(
        success(ok_body()),
        Some(ChainEmit::OnRequest),
        false,
        Some(json!("n".repeat(256))),
    )
    .await;
    assert!(chain_of(&json["result"]).is_some(), "256 bytes accepted");
}

#[test]
fn chain_nonce_invalid_refused_params() {
    let with = |nonce: Value| chain_nonce_from_params(Some(&json!({"_meta": {NONCE_KEY: nonce}})));
    std::assert_eq!(with(json!("ok")), Ok(Some("ok".to_owned())));
    assert!(with(json!("")).is_err());
    assert!(with(json!("n".repeat(257))).is_err());
    assert!(with(json!(5)).is_err());
    std::assert_eq!(chain_nonce_from_params(None), Ok(None));
}
