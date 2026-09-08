// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Server-owned signing context and final-response signing primitive.
//!
//! Only a literal external `gateway_invoke` can carry a signing context. The
//! adapters capture protocol metadata before any request sanitization.

use serde_json::Value;

use crate::gateway::meta_mcp_helpers::extract_required_str;
use crate::security::message_signing::{NONCE_REASON_INVALID, record_nonce_rejection};

pub(crate) fn wire_error_message(error: &crate::Error) -> String {
    match error {
        crate::Error::JsonRpc { message, .. } => message.clone(),
        _ => error.to_string(),
    }
}

enum CapturedNonce {
    Missing,
    Value(String),
    Invalid,
}

pub(crate) struct SigningInvocationContext {
    external_gateway_invoke: bool,
    nonce: CapturedNonce,
    request_id: Option<Value>,
    prepared_target: Option<(String, String)>,
}

pub(crate) enum SigningDelivery<'a> {
    Unsigned,
    GatewayInvoke { nonce: Option<&'a str> },
}

impl SigningInvocationContext {
    /// Move protocol metadata out of the raw request. Invalid nonce values are
    /// dropped here without copying them; policy still decides before refusal.
    pub(crate) fn capture(request: &mut Value) -> Self {
        let external_gateway_invoke = Self::is_external(request);
        let mut context = Self {
            external_gateway_invoke,
            nonce: CapturedNonce::Missing,
            request_id: None,
            prepared_target: None,
        };
        if external_gateway_invoke {
            context.request_id = request.as_object_mut().and_then(|o| o.remove("id"));
            context.nonce = match request
                .pointer_mut("/params/arguments")
                .and_then(Value::as_object_mut)
                .and_then(|o| o.remove("nonce"))
            {
                None => CapturedNonce::Missing,
                Some(Value::String(value)) if !value.is_empty() && value.len() <= 256 => {
                    CapturedNonce::Value(value)
                }
                Some(_) => CapturedNonce::Invalid,
            };
        }
        context
    }

    fn is_external(request: &Value) -> bool {
        request.get("method").and_then(Value::as_str) == Some("tools/call")
            && request.pointer("/params/name").and_then(Value::as_str) == Some("gateway_invoke")
    }

    /// Sanitization cannot change routing origin or the request ID, or create a
    /// replacement nonce from an alias. Nested backend arguments stay untouched.
    pub(crate) fn restore(&mut self, request: &mut Value) -> crate::Result<()> {
        if Self::is_external(request) != self.external_gateway_invoke {
            return Err(crate::Error::json_rpc(
                -32600,
                "Invalid signing request origin",
            ));
        }
        if self.external_gateway_invoke {
            if let Some(id) = self.request_id.take() {
                if !id.is_string() && id.as_i64().is_none() {
                    return Err(crate::Error::json_rpc(-32600, "Invalid signing request ID"));
                }
                request
                    .as_object_mut()
                    .expect("external request is an object")
                    .insert("id".into(), id);
            }
            if let Some(arguments) = request
                .pointer_mut("/params/arguments")
                .and_then(Value::as_object_mut)
            {
                arguments.remove("nonce");
            }
        }
        Ok(())
    }

    pub(crate) fn prepared_for(&self, server: &str, tool: &str) -> bool {
        self.prepared_target
            .as_ref()
            .is_some_and(|(s, t)| s == server && t == tool)
    }

    pub(crate) fn owns_signature(&self) -> bool {
        self.external_gateway_invoke
    }

    #[cfg(test)]
    pub(crate) fn internal_for_test() -> Self {
        Self {
            external_gateway_invoke: false,
            nonce: CapturedNonce::Missing,
            request_id: None,
            prepared_target: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn external_for_test(nonce: Option<&str>) -> Self {
        let nonce = match nonce {
            None => CapturedNonce::Missing,
            Some(value) if !value.is_empty() && value.len() <= 256 => {
                CapturedNonce::Value(value.to_owned())
            }
            Some(_) => CapturedNonce::Invalid,
        };
        Self {
            external_gateway_invoke: true,
            nonce,
            request_id: None,
            prepared_target: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn invalid_for_test() -> Self {
        Self {
            external_gateway_invoke: true,
            nonce: CapturedNonce::Invalid,
            request_id: None,
            prepared_target: None,
        }
    }

    pub(crate) fn delivery(&self) -> crate::Result<SigningDelivery<'_>> {
        if !self.external_gateway_invoke {
            return Ok(SigningDelivery::Unsigned);
        }
        let nonce = match &self.nonce {
            CapturedNonce::Missing => None,
            CapturedNonce::Value(value) => Some(value.as_str()),
            CapturedNonce::Invalid => {
                return Err(crate::Error::json_rpc(-32602, "Invalid signing nonce"));
            }
        };
        Ok(SigningDelivery::GatewayInvoke { nonce })
    }
}

impl super::MetaMcp {
    pub(crate) fn signing_enabled(&self) -> bool {
        self.message_signer.is_some()
    }

    /// Complete policy and nonce checks once, before outer execution admission
    /// can parse arguments or return a retained result.
    pub(crate) fn prepare_signing_invocation(
        &self,
        context: &mut SigningInvocationContext,
        arguments: &Value,
        session: Option<&str>,
        caller: &super::MetaMcpCallerContext<'_>,
    ) -> crate::Result<()> {
        if !context.external_gateway_invoke || !self.signing_enabled() {
            return Ok(());
        }
        self.check_invocation_policy(arguments, session, caller)?;
        // A raw nonce that never became a string is refused here, before the
        // store, so the store's own telemetry cannot see it. Counted at THIS
        // boundary rather than inside `delivery()`: the finalizer consults
        // `delivery()` too, and a hook there would count one client's mistake
        // again on a path that is not an admission decision at all.
        let SigningDelivery::GatewayInvoke { nonce } = context
            .delivery()
            .inspect_err(|_| record_nonce_rejection(NONCE_REASON_INVALID))?
        else {
            unreachable!("external origin checked above")
        };
        if let Some(store) = &self.nonce_store {
            match nonce {
                Some(nonce) => store.check_and_register_for_principal(
                    nonce,
                    caller.authorizer.quota_principal().map_or(
                        "anonymous",
                        crate::gateway::auth::QuotaPrincipal::as_store_key,
                    ),
                )?,
                None if self.require_nonce => {
                    return Err(crate::Error::json_rpc(
                        -32001,
                        "Nonce required when message signing is enforced",
                    ));
                }
                None => {}
            }
        }
        context.prepared_target = Some((
            extract_required_str(arguments, "server")?.to_owned(),
            extract_required_str(arguments, "tool")?.to_owned(),
        ));
        Ok(())
    }

    // Transport activation is separate from this defensive signing boundary.
    pub(crate) fn finalize_gateway_invoke_response(
        &self,
        response: &mut crate::protocol::JsonRpcResponse,
        nonce: Option<&str>,
    ) -> crate::Result<()> {
        if response.error.is_some() || response.result.is_none() {
            return Ok(());
        }
        let Some(signer) = &self.message_signer else {
            return Ok(());
        };
        let result = (|| {
            if self.require_nonce && nonce.is_none() {
                return Err(crate::Error::json_rpc(-32603, "Signing nonce is required"));
            }
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| crate::Error::json_rpc(-32603, "Signing clock is invalid"))?
                .as_secs();
            signer.sign_json_rpc_response_at(response, nonce, timestamp)
        })();
        result.inspect_err(|_| {
            #[cfg(feature = "metrics")]
            telemetry_metrics::counter!("mcp_message_signing_failures_total").increment(1);
        })
    }
}

#[cfg(test)]
#[path = "signing_delivery_tests.rs"]
mod delivery_tests;

// SIGNING.5: the raw-nonce refusals decided here, before the nonce store.
#[cfg(all(test, feature = "metrics"))]
#[path = "signing_nonce_metrics_tests.rs"]
mod nonce_metrics_tests;
