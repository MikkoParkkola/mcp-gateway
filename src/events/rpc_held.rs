// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Held webhook subscriptions at `events/subscribe` (MIK-8057, MIK-8076): a
//! held row's refresh is accepted and says so, and a cap refusal names the
//! caller's held rows.

use std::sync::Arc;

use chrono::Utc;
use serde_json::{Value, json};

use super::{
    Caller, callback_url, cap_refusal, credential_ceiling, granted_ttl, subscribe_answer,
    subscription_id, to_wire_time,
};
use crate::events::EventsHub;
use crate::events::records::Subscription;
use crate::events::store::{CapHit, Caps, Grant};
use crate::events::types::RpcError;

/// How a subscribe commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Commit {
    /// Its arguments re-checked against the offered route at the commit.
    Checked,
    /// A held row's refresh: the route does not serve it now, by definition.
    Held,
}

impl EventsHub {
    /// A refresh of a held subscription (MIK-8057, MIK-8076): accepted, its
    /// lease extended, and the answer says it is held, why and until when.
    /// Its arguments are not checked against a route that does not serve
    /// them: they are the stored row's own. `None` when the subscription
    /// named is not a live held row of the caller's.
    pub(super) async fn refresh_held(
        self: &Arc<Self>,
        caller: &Caller,
        principal: &str,
        name: &str,
        params: &Value,
    ) -> Result<Option<Value>, RpcError> {
        let delivery = &params["delivery"];
        let Ok(url) = callback_url(delivery.get("url")) else {
            return Ok(None);
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let id = subscription_id(principal, url.as_str(), name, &arguments);
        let now = Utc::now();
        let (Some(held), Some(existing)) = (
            self.store.held(&id),
            self.store.get(&id).filter(|s| s.live(now)),
        ) else {
            return Ok(None);
        };
        match delivery.get("mode") {
            Some(Value::String(mode)) if mode == "webhook" => {}
            Some(mode) => return Err(RpcError::unsupported_mode(mode)),
            None => return Err(RpcError::invalid("delivery.mode")),
        }
        let secret = delivery
            .get("secret")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let key = crate::events::client::decode_whsec(secret)
            .ok_or_else(|| RpcError::invalid("delivery.secret"))?;
        let grant = Grant {
            ttl: granted_ttl(self, params)?,
            until: credential_ceiling(&caller.credential, params)?,
        };
        let record = Subscription {
            api_key: caller.credential.api_key.clone(),
            credential_kind: Some(caller.credential.kind),
            credential_principal: Some(caller.credential.principal.clone()),
            read_key: caller.read_key.clone(),
            binding: caller.credential.binding.clone(),
            secret: secret.to_owned(),
            previous_secret: None,
            previous_until: None,
            granted_at: now,
            expires_at: grant.expires_at(now),
            ..existing.clone()
        };
        let caps = self.caps();
        let tail = crate::events::tail_policy(&self.config);
        let grace = chrono::Duration::from_std(self.config.secret_rotation_grace)
            .unwrap_or_else(|_| chrono::Duration::zero());
        let mut verified = self.store.is_verified(principal, url.as_str(), now, tail);
        for _pass in 0..2 {
            if !verified {
                self.challenge(caller, name, &url, &id, &key).await?;
            }
            let outcome = self
                .commit_started(
                    &record,
                    grant,
                    !verified,
                    (caps, grace, tail),
                    now,
                    (caller, &url, Commit::Held),
                )
                .await;
            match outcome? {
                Ok((_, expires_at)) => {
                    let mut answer = subscribe_answer(&id, expires_at, Some(&existing), false);
                    let until = match (expires_at, existing.held_until) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    };
                    answer["held"] = json!({
                        "reason": held.reason,
                        "key": held.key,
                        "until": to_wire_time(until),
                    });
                    return Ok(Some(answer));
                }
                Err(CapHit::Unverified) if verified => verified = false,
                Err(hit) => return Err(self.cap_refusal_for(principal, hit)),
            }
        }
        Err(RpcError::internal())
    }

    /// [`cap_refusal`], naming the caller's held subscriptions: they keep
    /// their slots, and unsubscribing one frees it (MIK-8057).
    pub(super) fn cap_refusal_for(&self, principal: &str, hit: CapHit) -> RpcError {
        let mut refusal = cap_refusal(hit);
        let held = self.store.held_types_of(principal);
        if !held.is_empty()
            && let Some(data) = refusal.data.as_mut()
        {
            let types: Vec<Value> = held
                .iter()
                .map(|(name, n)| json!({"name": name, "count": n}))
                .collect();
            data["held"] = json!({
                "count": held.iter().map(|(_, n)| n).sum::<usize>(),
                "types": types,
            });
        }
        refusal
    }

    /// The subscription caps in force.
    pub(super) fn caps(&self) -> Caps {
        Caps {
            per_principal: self.config.max_subscriptions_per_principal,
            global: self.config.max_subscriptions,
        }
    }

    /// The payload fields event type `name` carries now: a webhook route's
    /// mapped fields, none for any other source (MIK-8076).
    pub(super) fn payload_fields(&self, name: &str) -> Vec<String> {
        self.webhook_registry
            .get()
            .map(|registry| crate::events::reload::payload_fields(registry, name))
            .unwrap_or_default()
    }
}
