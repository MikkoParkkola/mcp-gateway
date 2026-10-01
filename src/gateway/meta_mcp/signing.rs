// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Server-owned signing context and final-response signing primitive.
//!
//! A literal external `gateway_invoke` carries a signing context, its nonce in
//! `arguments.nonce`. Under `security.posture: hardened` every other
//! `tools/call` carries one too, its nonce in
//! `params._meta["io.mcp-gateway/nonce"]` (GH1942.HARDEN.1 row 7). The adapters
//! capture protocol metadata before any request sanitization.

use serde_json::Value;

use crate::gateway::meta_mcp_helpers::extract_required_str;
use crate::security::message_signing::{NONCE_REASON_INVALID, record_nonce_rejection};

pub(crate) fn wire_error_message(error: &crate::Error) -> String {
    match error {
        crate::Error::JsonRpc { message, .. } => message.clone(),
        _ => error.to_string(),
    }
}

/// Where a hardened `tools/call` carries its signing nonce (wire key, M1).
pub(crate) const NONCE_META: &str = "io.mcp-gateway/nonce";

enum CapturedNonce {
    Missing,
    Value(String),
    Invalid,
    /// A `gateway_invoke` carrying both an argument and a `_meta` nonce: one
    /// call never has two replay identities.
    Conflict,
}

/// Which requests the adapter gives a signing context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigningScope {
    /// Only a literal external `gateway_invoke` (the `standard` posture).
    InvokeOnly,
    /// Every `tools/call` (`hardened`).
    EveryToolCall,
}

impl SigningScope {
    pub(crate) fn of(posture: crate::security::SecurityPosture) -> Self {
        if posture == crate::security::SecurityPosture::Hardened {
            Self::EveryToolCall
        } else {
            Self::InvokeOnly
        }
    }
}

/// What a captured request is, for signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// Neither below: delivered unsigned.
    Unsigned,
    /// A literal external `gateway_invoke`.
    GatewayInvoke,
    /// Any other `tools/call`, under [`SigningScope::EveryToolCall`].
    ToolCall,
}

pub(crate) struct SigningInvocationContext {
    origin: Origin,
    scope: SigningScope,
    nonce: CapturedNonce,
    request_id: Option<Value>,
    prepared_target: Option<(String, String)>,
    /// The nonce passed admission. Only an admitted context signs, so a
    /// response is never signed over a nonce the store did not register.
    admitted: bool,
}

pub(crate) enum SigningDelivery<'a> {
    Unsigned,
    Signed { nonce: Option<&'a str> },
}

/// A nonce value as the wire carries it: a non-empty string of at most 256
/// bytes, anything else invalid.
fn captured(value: Option<Value>) -> CapturedNonce {
    match value {
        None => CapturedNonce::Missing,
        Some(Value::String(value)) if !value.is_empty() && value.len() <= 256 => {
            CapturedNonce::Value(value)
        }
        Some(_) => CapturedNonce::Invalid,
    }
}

impl SigningInvocationContext {
    /// Move protocol metadata out of the raw request. Invalid nonce values are
    /// dropped here without copying them; policy still decides before refusal.
    pub(crate) fn capture(request: &mut Value) -> Self {
        Self::capture_scoped(request, SigningScope::InvokeOnly)
    }

    /// [`Self::capture`] under `scope`: under [`SigningScope::EveryToolCall`]
    /// every `tools/call` gets a context, its nonce taken from `_meta`.
    pub(crate) fn capture_scoped(request: &mut Value, scope: SigningScope) -> Self {
        let origin = Self::origin_of(request, scope);
        let mut context = Self {
            origin,
            scope,
            nonce: CapturedNonce::Missing,
            request_id: None,
            prepared_target: None,
            admitted: false,
        };
        if origin == Origin::Unsigned {
            return context;
        }
        context.request_id = request.as_object_mut().and_then(|o| o.remove("id"));
        let meta_nonce = (scope == SigningScope::EveryToolCall)
            .then(|| take_meta_nonce(request.get_mut("params")))
            .flatten();
        context.nonce = match origin {
            Origin::GatewayInvoke => {
                let argument = request
                    .pointer_mut("/params/arguments")
                    .and_then(Value::as_object_mut)
                    .and_then(|o| o.remove("nonce"));
                if argument.is_some() && meta_nonce.is_some() {
                    CapturedNonce::Conflict
                } else {
                    captured(argument.or(meta_nonce))
                }
            }
            Origin::ToolCall | Origin::Unsigned => captured(meta_nonce),
        };
        context
    }

    fn origin_of(request: &Value, scope: SigningScope) -> Origin {
        if Self::is_external(request) {
            Origin::GatewayInvoke
        } else if scope == SigningScope::EveryToolCall
            && request.get("method").and_then(Value::as_str) == Some("tools/call")
        {
            Origin::ToolCall
        } else {
            Origin::Unsigned
        }
    }

    fn is_external(request: &Value) -> bool {
        request.get("method").and_then(Value::as_str) == Some("tools/call")
            && request.pointer("/params/name").and_then(Value::as_str) == Some("gateway_invoke")
    }

    /// Sanitization cannot change routing origin or the request ID, or create a
    /// replacement nonce from an alias. Nested backend arguments stay untouched.
    pub(crate) fn restore(&mut self, request: &mut Value) -> crate::Result<()> {
        if Self::origin_of(request, self.scope) != self.origin {
            return Err(crate::Error::json_rpc(
                -32600,
                "Invalid signing request origin",
            ));
        }
        if self.origin == Origin::Unsigned {
            return Ok(());
        }
        if let Some(id) = self.request_id.take() {
            if !id.is_string() && id.as_i64().is_none() {
                return Err(crate::Error::json_rpc(-32600, "Invalid signing request ID"));
            }
            request
                .as_object_mut()
                .expect("a signed request is an object")
                .insert("id".into(), id);
        }
        if self.origin == Origin::GatewayInvoke
            && let Some(arguments) = request
                .pointer_mut("/params/arguments")
                .and_then(Value::as_object_mut)
        {
            arguments.remove("nonce");
        }
        if self.scope == SigningScope::EveryToolCall {
            take_meta_nonce(request.get_mut("params"));
        }
        Ok(())
    }

    pub(crate) fn prepared_for(&self, server: &str, tool: &str) -> bool {
        self.prepared_target
            .as_ref()
            .is_some_and(|(s, t)| s == server && t == tool)
    }

    /// Whether this context signs what it delivers, so a stored copy of the
    /// result must be kept without its `_signature`.
    pub(crate) fn owns_signature(&self) -> bool {
        self.origin != Origin::Unsigned
    }

    #[cfg(test)]
    pub(crate) fn internal_for_test() -> Self {
        Self {
            origin: Origin::Unsigned,
            scope: SigningScope::InvokeOnly,
            nonce: CapturedNonce::Missing,
            request_id: None,
            prepared_target: None,
            admitted: false,
        }
    }

    /// An external `gateway_invoke` context that has passed admission.
    #[cfg(test)]
    pub(crate) fn external_for_test(nonce: Option<&str>) -> Self {
        Self {
            origin: Origin::GatewayInvoke,
            scope: SigningScope::InvokeOnly,
            nonce: captured(nonce.map(|value| Value::String(value.to_owned()))),
            request_id: None,
            prepared_target: None,
            admitted: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn invalid_for_test() -> Self {
        Self {
            origin: Origin::GatewayInvoke,
            scope: SigningScope::InvokeOnly,
            nonce: CapturedNonce::Invalid,
            request_id: None,
            prepared_target: None,
            admitted: true,
        }
    }

    /// The well-formed `gateway_invoke` `nonce`, if any: the chain's fallback
    /// nonce. Never validates, admits or consumes anything.
    pub(crate) fn invoke_nonce(&self) -> Option<&str> {
        match &self.nonce {
            CapturedNonce::Value(value) if self.origin == Origin::GatewayInvoke => {
                Some(value.as_str())
            }
            _ => None,
        }
    }

    /// The captured nonce, or the refusal of a malformed one.
    fn nonce_value(&self) -> crate::Result<Option<&str>> {
        match &self.nonce {
            CapturedNonce::Missing => Ok(None),
            CapturedNonce::Value(value) => Ok(Some(value.as_str())),
            CapturedNonce::Invalid => Err(crate::Error::json_rpc(-32602, "Invalid signing nonce")),
            CapturedNonce::Conflict => Err(crate::Error::json_rpc(-32602, "two signing nonces")),
        }
    }

    /// How the response is delivered: a malformed nonce cannot deliver, and
    /// a well-formed one signs only once it has passed admission.
    pub(crate) fn delivery(&self) -> crate::Result<SigningDelivery<'_>> {
        if self.origin == Origin::Unsigned {
            return Ok(SigningDelivery::Unsigned);
        }
        let nonce = self.nonce_value()?;
        if !self.admitted {
            return Ok(SigningDelivery::Unsigned);
        }
        Ok(SigningDelivery::Signed { nonce })
    }
}

/// Take the hardened nonce off `params._meta`, before sanitization can rewrite
/// or reject its bytes (ASI07).
pub(crate) fn take_meta_nonce(params: Option<&mut Value>) -> Option<Value> {
    params?
        .get_mut("_meta")?
        .as_object_mut()?
        .remove(NONCE_META)
}

/// The hardened direct route's nonce: taken off `params._meta` and checked
/// by the rule the meta route applies, refusing a malformed one.
pub(crate) fn take_direct_nonce(params: Option<&mut Value>) -> crate::Result<Option<String>> {
    match captured(take_meta_nonce(params)) {
        CapturedNonce::Missing => Ok(None),
        CapturedNonce::Value(value) => Ok(Some(value)),
        CapturedNonce::Invalid | CapturedNonce::Conflict => {
            record_nonce_rejection(NONCE_REASON_INVALID);
            Err(crate::Error::json_rpc(-32602, "Invalid signing nonce"))
        }
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
        if context.origin == Origin::Unsigned || !self.signing_enabled() {
            return Ok(());
        }
        if context.origin == Origin::GatewayInvoke {
            self.check_invocation_policy(arguments, session, caller)?;
        }
        // A raw nonce that never became a string is refused here, before the
        // store, so the store's own telemetry cannot see it. Counted at THIS
        // boundary rather than inside `delivery()`: the finalizer consults
        // `delivery()` too, and a hook there would count one client's mistake
        // again on a path that is not an admission decision at all.
        let nonce = context
            .nonce_value()
            .inspect_err(|_| record_nonce_rejection(NONCE_REASON_INVALID))?;
        self.admit_signing_nonce(
            nonce,
            caller.authorizer.quota_principal().map_or(
                "anonymous",
                crate::gateway::auth::QuotaPrincipal::as_store_key,
            ),
        )?;
        if context.origin == Origin::GatewayInvoke {
            context.prepared_target = Some((
                extract_required_str(arguments, "server")?.to_owned(),
                extract_required_str(arguments, "tool")?.to_owned(),
            ));
        }
        context.admitted = true;
        Ok(())
    }

    /// Admit `nonce` for `principal` in the one replay store both routes share,
    /// or refuse: a nonce seen within the window, or none when one is required.
    pub(crate) fn admit_signing_nonce(
        &self,
        nonce: Option<&str>,
        principal: &str,
    ) -> crate::Result<()> {
        let Some(store) = &self.nonce_store else {
            return Ok(());
        };
        match nonce {
            Some(nonce) => store.check_and_register_for_principal(nonce, principal),
            None if self.require_nonce => Err(crate::Error::json_rpc(
                -32001,
                "Nonce required when message signing is enforced",
            )),
            None => Ok(()),
        }
    }

    /// Sign a hardened direct-route delivery over its admitted `nonce`. A
    /// result the primitive cannot sign is replaced by a refusal: it is never
    /// delivered unsigned, as on the meta route.
    pub(crate) fn sign_direct_delivery(
        &self,
        response: &mut crate::protocol::JsonRpcResponse,
        nonce: Option<&str>,
    ) {
        if self
            .finalize_gateway_invoke_response(response, nonce)
            .is_err()
        {
            *response = crate::protocol::JsonRpcResponse::delivery_refusal_error(
                response.id.clone(),
                -32603,
                "Response signing failed",
            );
        }
    }

    // Transport activation is separate from this defensive signing boundary.
    // Signs any admitted delivery: an external `gateway_invoke`, and under
    // `hardened` every `tools/call` on either route.
    pub(crate) fn finalize_gateway_invoke_response(
        &self,
        response: &mut crate::protocol::JsonRpcResponse,
        nonce: Option<&str>,
    ) -> crate::Result<()> {
        if response.error.is_some() || response.result.is_none() {
            return Ok(());
        }
        // PARENT.6: every signing exit, replays included, signs the scope the
        // client will receive.
        if let Some(result) = response.result.as_mut() {
            crate::protocol::cacheable::clamp_delivered_scope(result);
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

// GH1942.HARDEN.1 row 7: the hardened signing scope.
#[cfg(test)]
#[path = "signing_scope_tests.rs"]
mod scope_tests;

// SIGNING.5: the raw-nonce refusals decided here, before the nonce store.
#[cfg(all(test, feature = "metrics"))]
#[path = "signing_nonce_metrics_tests.rs"]
mod nonce_metrics_tests;
