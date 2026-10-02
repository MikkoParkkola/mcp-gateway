// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `events/list`, `events/subscribe`, `events/unsubscribe` (design §6.2-6.4).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::EventsHub;
use super::records::{Credential, Subscription};
use super::store::{CapHit, Caps};
use super::types::{EventDescriptor, RpcError, Visibility};

/// Who is calling, as the transport resolved it. Owned, so it can be held
/// across the verification POST.
pub(crate) struct Caller {
    /// The canonical principal; `None` when the call is not authenticated
    /// (or authentication is off).
    pub principal: Option<String>,
    /// The credential the caller presented.
    pub credential: Credential,
    /// Of the backends the catalogue scopes to ([`EventsHub::scope_backends`]),
    /// the ones the caller may see: the predicate `tools/list` filters with.
    pub visible_backends: std::collections::HashSet<String>,
}

impl Caller {
    fn sees(&self, hub: &EventsHub, descriptor: &EventDescriptor) -> bool {
        match &descriptor.scope {
            Visibility::Backend(backend) => {
                self.visible_backends.contains(backend)
                    && hub.live_admits(self.credential.api_key.as_ref(), backend)
            }
            // Owner-scoped types (task events, I4) are listed to anyone who
            // can own a record; operator types land in 4.0.1.
            Visibility::Owner => self.principal.is_some(),
            Visibility::Operator => false,
        }
    }
}

impl EventsHub {
    /// The backends the current catalogue scopes event types to; the
    /// transport resolves which of them a caller may see.
    pub(crate) fn scope_backends(&self) -> Vec<String> {
        let mut backends: Vec<String> = self
            .catalogue()
            .into_iter()
            .filter_map(|d| match d.scope {
                Visibility::Backend(backend) => Some(backend),
                _ => None,
            })
            .collect();
        backends.sort();
        backends.dedup();
        backends
    }

    /// `events/list`: the caller's visible catalogue, one page.
    pub(crate) fn list(&self, caller: &Caller, params: Option<&Value>) -> Result<Value, RpcError> {
        if params
            .and_then(|p| p.get("cursor"))
            .is_some_and(|c| !c.is_null())
        {
            // Every catalogue fits one page, so no cursor was ever issued.
            return Err(RpcError::invalid("cursor"));
        }
        let events: Vec<Value> = self
            .catalogue()
            .iter()
            .filter(|d| caller.sees(self, d))
            .map(EventDescriptor::to_wire)
            .collect();
        Ok(json!({ "events": events }))
    }

    /// The visible descriptor called `name`; invisible and missing are one
    /// answer, so the catalogue cannot be probed (design §7.4).
    fn visible(&self, caller: &Caller, name: &str) -> Result<EventDescriptor, RpcError> {
        self.catalogue()
            .into_iter()
            .find(|d| d.name == name && caller.sees(self, d))
            .ok_or_else(RpcError::not_found)
    }
}

/// Canonical (RFC 8785) arguments, after the descriptor's `inputSchema`:
/// an object whose keys it names, each value of the declared type.
fn checked_arguments(
    descriptor: &EventDescriptor,
    arguments: Option<&Value>,
) -> Result<Value, RpcError> {
    let arguments = arguments.cloned().unwrap_or_else(|| json!({}));
    let Some(map) = arguments.as_object() else {
        return Err(RpcError::invalid("arguments"));
    };
    let properties = &descriptor.input_schema["properties"];
    for (key, value) in map {
        let Some(schema) = properties.get(key) else {
            return Err(RpcError::invalid("arguments"));
        };
        if schema.get("type").and_then(Value::as_str) == Some("string") && !value.is_string() {
            return Err(RpcError::invalid("arguments"));
        }
    }
    Ok(arguments)
}

/// `sub_` + 32 hex of SHA-256 over the JCS array `[principal, url, name,
/// arguments]` (design §6.3 step 7).
pub(crate) fn subscription_id(principal: &str, url: &str, name: &str, arguments: &Value) -> String {
    use sha2::Digest as _;
    let canonical = serde_json_canonicalizer::to_vec(&json!([principal, url, name, arguments]))
        .unwrap_or_default();
    let digest = hex::encode(sha2::Sha256::digest(canonical));
    format!("sub_{}", &digest[..32])
}

/// The `-32013` answer for a cap an admission hit.
fn cap_refusal(hit: CapHit) -> RpcError {
    match hit {
        CapHit::PerPrincipal(max) | CapHit::Global(max) => {
            RpcError::exhausted("subscriptions", Some(max))
        }
        // Only reachable for a fresh opt-in, which the store never refuses
        // as unverified.
        CapHit::Unverified => RpcError::internal(),
    }
}

/// The `events/subscribe` result; `deliveryStatus` only on a refresh.
fn subscribe_answer(
    id: &str,
    expires_at: Option<DateTime<Utc>>,
    existing: Option<&Subscription>,
    throttled: bool,
) -> Value {
    let mut answer = json!({
        "id": id,
        "refreshBefore": to_wire_time(expires_at),
        "cursor": null,
        "truncated": false,
    });
    if let Some(old) = existing {
        answer["deliveryStatus"] = json!({
            "active": old.active,
            "lastError": old.last_error,
            "throttled": throttled,
        });
    }
    answer
}

/// A callback URL: absolute `https` with a host.
fn callback_url(raw: Option<&Value>) -> Result<url::Url, RpcError> {
    raw.and_then(Value::as_str)
        .and_then(|s| url::Url::parse(s).ok())
        .filter(|u| u.scheme() == "https" && u.host_str().is_some_and(|h| !h.is_empty()))
        .ok_or_else(|| RpcError::invalid("delivery.url"))
}

/// The granted expiry for a `ttlMs` (design §6.3, TTL).
fn granted_expiry(
    hub: &EventsHub,
    params: &Value,
    now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, RpcError> {
    let config = &hub.config;
    let ttl = match params.get("ttlMs") {
        None => config.default_ttl,
        Some(Value::Null) if config.allow_no_expiry => return Ok(None),
        Some(Value::Null) => config.max_ttl,
        Some(v) => {
            let ms = v.as_u64().ok_or_else(|| RpcError::invalid("ttlMs"))?;
            std::time::Duration::from_millis(ms).clamp(config.min_ttl, config.max_ttl)
        }
    };
    let ttl = chrono::Duration::from_std(ttl).map_err(|_| RpcError::invalid("ttlMs"))?;
    Ok(Some(now + ttl))
}

fn to_wire_time(at: Option<DateTime<Utc>>) -> Value {
    at.map_or(Value::Null, |t| {
        json!(t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
    })
}

/// Run a store operation on a blocking thread.
async fn blocking<T: Send + 'static>(
    hub: &Arc<EventsHub>,
    op: impl FnOnce(&super::store::Store) -> std::io::Result<T> + Send + 'static,
) -> Result<T, RpcError> {
    let store = Arc::clone(&hub.store);
    tokio::task::spawn_blocking(move || op(&store))
        .await
        .map_err(|_| RpcError::internal())?
        .map_err(|error| {
            tracing::warn!(%error, "events store commit failed");
            RpcError::internal()
        })
}

impl EventsHub {
    /// `events/subscribe`, refusals cheapest first (design §6.3).
    pub(crate) async fn subscribe(
        self: &Arc<Self>,
        caller: &Caller,
        params: Option<&Value>,
    ) -> Result<Value, RpcError> {
        let principal = caller.principal.clone().ok_or_else(RpcError::forbidden)?;
        let params = params.cloned().unwrap_or_else(|| json!({}));
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let descriptor = self.visible(caller, name)?;
        let delivery = &params["delivery"];
        match delivery.get("mode") {
            Some(Value::String(mode)) if mode == "webhook" => {}
            Some(mode) => return Err(RpcError::unsupported_mode(mode)),
            None => return Err(RpcError::invalid("delivery.mode")),
        }
        let arguments = checked_arguments(&descriptor, params.get("arguments"))?;
        let url = callback_url(delivery.get("url"))?;
        let secret = delivery
            .get("secret")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let key = super::client::decode_whsec(secret)
            .ok_or_else(|| RpcError::invalid("delivery.secret"))?;
        let now = Utc::now();
        let expires_at = granted_expiry(self, &params, now)?;
        let id = subscription_id(&principal, url.as_str(), &descriptor.name, &arguments);
        let caps = Caps {
            per_principal: self.config.max_subscriptions_per_principal,
            global: self.config.max_subscriptions,
        };
        if self.store.get(&id).as_ref().is_none_or(|s| !s.live(now)) {
            self.store
                .would_admit(&principal, caps, now)
                .map_err(cap_refusal)?;
        }

        let tail = super::tail_policy(&self.config);
        let mut verified = self.store.is_verified(&principal, url.as_str(), now, tail);
        let existing = self.store.get(&id).filter(|s| s.live(now));
        let grace = chrono::Duration::from_std(self.config.secret_rotation_grace)
            .unwrap_or_else(|_| chrono::Duration::zero());
        let record = Subscription {
            v: 1,
            id: id.clone(),
            principal,
            api_key: caller.credential.api_key.clone(),
            credential_kind: Some(caller.credential.kind),
            credential_principal: Some(caller.credential.principal.clone()),
            legacy_api_key_name: None,
            url: url.as_str().to_owned(),
            name: descriptor.name.clone(),
            arguments,
            secret: secret.to_owned(),
            // Rotation and delivery history are taken from the stored row
            // inside the store's commit, never from this earlier read.
            previous_secret: None,
            previous_until: None,
            granted_at: now,
            expires_at,
            active: true,
            failed_since: None,
            last_delivery_at: None,
            last_error: None,
        };
        // At most two passes: a cached opt-in can vanish (tail eviction)
        // between the read above and the commit; the store then refuses
        // and the callback is challenged before a second commit.
        for _pass in 0..2 {
            if !verified {
                self.challenge(&url, &id, &key).await?;
            }
            let attempt = record.clone();
            let fresh = !verified;
            match blocking(self, move |store| {
                store.admit(attempt, fresh, caps, grace, now, tail)
            })
            .await?
            {
                Ok(()) => {
                    // A refresh may have reactivated a suspended row.
                    self.runtime.wake.notify_one();
                    let throttled = self.runtime.rates.throttled(&id);
                    return Ok(subscribe_answer(
                        &id,
                        expires_at,
                        existing.as_ref(),
                        throttled,
                    ));
                }
                Err(CapHit::Unverified) if verified => verified = false,
                Err(hit) => return Err(cap_refusal(hit)),
            }
        }
        Err(RpcError::internal())
    }

    /// Challenge the callback once: literal check, per-host limit, then the
    /// verification POST.
    async fn challenge(&self, url: &url::Url, id: &str, key: &[u8]) -> Result<(), RpcError> {
        self.client.check_literal(url).map_err(RpcError::callback)?;
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        if !self.host_admitted(&host) {
            return Err(RpcError::exhausted("verifications", None));
        }
        self.client
            .verify(url, id, key)
            .await
            .map_err(RpcError::callback)
    }

    /// `events/unsubscribe`: `{}` whether or not the caller's key existed
    /// (design §6.4). The key includes the caller's principal, so no caller
    /// can address another's row, and an `id` field is never read.
    pub(crate) async fn unsubscribe(
        self: &Arc<Self>,
        caller: &Caller,
        params: Option<&Value>,
    ) -> Result<Value, RpcError> {
        let principal = caller.principal.clone().ok_or_else(RpcError::forbidden)?;
        let params = params.cloned().unwrap_or_else(|| json!({}));
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let Ok(url) = callback_url(params["delivery"].get("url")) else {
            return Ok(json!({}));
        };
        let id = subscription_id(&principal, url.as_str(), name, &arguments);
        let tail = super::tail_policy(&self.config);
        let removed = id.clone();
        blocking(self, move |store| store.remove(&removed, Utc::now(), tail)).await?;
        // A concurrent unsubscribe of the same key waits too. An attempt
        // still busy at the bound is not acknowledged as stopped.
        if self.settled(&id).await {
            Ok(json!({}))
        } else {
            Err(RpcError::internal())
        }
    }

    /// Wait until an attempt claimed before subscription `id` was removed
    /// has settled, so nothing reaches the callback after the unsubscribe
    /// answer (T23). Bounded by the client's own total timeout; `false` when
    /// the attempt is still busy at the bound.
    async fn settled(&self, id: &str) -> bool {
        let deadline = tokio::time::Instant::now() + super::client::TOTAL_TIMEOUT * 2;
        loop {
            let busy = self.runtime.busy.lock().contains(id);
            if !busy {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}

#[cfg(test)]
#[path = "rpc_tests.rs"]
mod tests;
