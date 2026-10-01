// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `events/list`, `events/subscribe`, `events/unsubscribe` (design §6.2-6.4).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::EventsHub;
use super::records::Subscription;
use super::types::{EventDescriptor, RpcError, Visibility};

/// Who is calling, as the transport resolved it.
pub(crate) struct Caller<'a> {
    /// The canonical principal; `None` when the call is not authenticated
    /// (or authentication is off).
    pub principal: Option<String>,
    /// The API key the caller presented, if any.
    pub api_key_name: Option<String>,
    /// The visibility predicate `tools/list` filters with.
    pub sees_backend: &'a dyn Fn(&str) -> bool,
}

impl Caller<'_> {
    fn sees(&self, descriptor: &EventDescriptor) -> bool {
        match &descriptor.scope {
            Visibility::Backend(backend) => (self.sees_backend)(backend),
            // Owner-scoped types (task events, I4) are listed to anyone who
            // can own a record; operator types land in 4.0.1.
            Visibility::Owner => self.principal.is_some(),
            Visibility::Operator => false,
        }
    }
}

impl EventsHub {
    /// `events/list`: the caller's visible catalogue, one page.
    pub(crate) fn list(
        &self,
        caller: &Caller<'_>,
        params: Option<&Value>,
    ) -> Result<Value, RpcError> {
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
            .filter(|d| caller.sees(d))
            .map(EventDescriptor::to_wire)
            .collect();
        Ok(json!({ "events": events }))
    }

    /// The visible descriptor called `name`; invisible and missing are one
    /// answer, so the catalogue cannot be probed (design §7.4).
    fn visible(&self, caller: &Caller<'_>, name: &str) -> Result<EventDescriptor, RpcError> {
        self.catalogue()
            .into_iter()
            .find(|d| d.name == name && caller.sees(d))
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
        caller: &Caller<'_>,
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
        let existing = self.store.get(&id).filter(|s| s.live(now));
        if existing.is_none() {
            self.check_caps(&principal, now)?;
        }

        let tail = super::tail_policy(&self.config);
        let verified = self.store.is_verified(&principal, url.as_str(), now, tail);
        if !verified {
            let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
            self.client
                .check_literal(&url)
                .map_err(RpcError::callback)?;
            if self.verify_limit.check_key(&host).is_err() {
                return Err(RpcError::exhausted("verifications", None));
            }
            self.client
                .verify(&url, &id, &key)
                .await
                .map_err(RpcError::callback)?;
        }

        let _writes = self.writes.lock().await;
        let existing = self.store.get(&id).filter(|s| s.live(now));
        if existing.is_none() {
            self.check_caps(&principal, now)?;
        }
        let grace = chrono::Duration::from_std(self.config.secret_rotation_grace)
            .unwrap_or_else(|_| chrono::Duration::zero());
        let (previous_secret, previous_until) = match &existing {
            Some(old) if old.secret != secret => (Some(old.secret.clone()), Some(now + grace)),
            Some(old) => (old.previous_secret.clone(), old.previous_until),
            None => (None, None),
        };
        let record = Subscription {
            v: 1,
            id: id.clone(),
            principal,
            api_key_name: caller.api_key_name.clone(),
            url: url.as_str().to_owned(),
            name: descriptor.name.clone(),
            arguments,
            secret: secret.to_owned(),
            previous_secret,
            previous_until,
            granted_at: now,
            expires_at,
            active: true,
            failed_since: existing.as_ref().and_then(|s| s.failed_since),
            last_delivery_at: existing.as_ref().and_then(|s| s.last_delivery_at),
            last_error: existing.as_ref().and_then(|s| s.last_error.clone()),
        };
        blocking(self, move |store| store.upsert(record, !verified, now)).await?;
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
            });
        }
        Ok(answer)
    }

    fn check_caps(&self, principal: &str, now: DateTime<Utc>) -> Result<(), RpcError> {
        let per_principal = self.config.max_subscriptions_per_principal;
        if self.store.live_count(Some(principal), now) >= per_principal {
            return Err(RpcError::exhausted("subscriptions", Some(per_principal)));
        }
        let global = self.config.max_subscriptions;
        if self.store.live_count(None, now) >= global {
            return Err(RpcError::exhausted("subscriptions", Some(global)));
        }
        Ok(())
    }

    /// `events/unsubscribe`: `{}` whether or not the caller's key existed
    /// (design §6.4). The key includes the caller's principal, so no caller
    /// can address another's row, and an `id` field is never read.
    pub(crate) async fn unsubscribe(
        self: &Arc<Self>,
        caller: &Caller<'_>,
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
        let _writes = self.writes.lock().await;
        blocking(self, move |store| store.remove(&id, Utc::now(), tail)).await?;
        Ok(json!({}))
    }
}

#[cfg(test)]
#[path = "rpc_tests.rs"]
mod tests;
