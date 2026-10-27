// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `events/subscribe` handshake (design §6.3): admission order, the
//! callback challenge and probe, and the started-row commit.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::{
    Caller, CapHit, Caps, Commit, Grant, HoldCommit, blocking, callback_url, checked_arguments,
    credential_ceiling, granted_ttl, rotation_grace, subscribe_answer, subscription_id,
};
use crate::events::EventsHub;
use crate::events::governance::{Attribution, Lifecycle};
use crate::events::records::Subscription;
use crate::events::types::RpcError;

/// The delivery's `whsec_` secret and the signing key it decodes to.
fn delivery_secret(delivery: &Value) -> Result<(&str, Vec<u8>), RpcError> {
    let secret = delivery
        .get("secret")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let key = crate::events::client::decode_whsec(secret)
        .ok_or_else(|| RpcError::invalid("delivery.secret"))?;
    Ok((secret, key))
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
        if let Some(answer) = self.refresh_held(caller, &principal, name, &params).await? {
            return Ok(answer);
        }
        let descriptor = self.visible(caller, name)?;
        let delivery = &params["delivery"];
        match delivery.get("mode") {
            Some(Value::String(mode)) if mode == "webhook" => {}
            Some(mode) => return Err(RpcError::unsupported_mode(mode)),
            None => return Err(RpcError::invalid("delivery.mode")),
        }
        let arguments = checked_arguments(&descriptor, params.get("arguments"))?;
        let url = callback_url(delivery.get("url"))?;
        let (secret, key) = delivery_secret(delivery)?;
        // Checked before any challenge; fixed to a time only at the commit.
        let grant = Grant {
            ttl: granted_ttl(self, &params)?,
            until: credential_ceiling(&caller.credential, &params)?,
        };
        // A lease, a cap and the callback opt-in's tail are not judged on a
        // clock before 1970: an opt-in it cannot date is never reused without
        // a fresh challenge, so the subscribe is refused.
        let now = crate::clock::utc_now().map_err(|_| RpcError::internal())?;
        let id = subscription_id(&principal, url.as_str(), &descriptor.name, &arguments);
        // The answer's handle, before anything is committed: a hub that
        // cannot key it refuses with no row written.
        let handle = self.handle(&id)?;
        let caps = self.caps();
        if self.store.get(&id).as_ref().is_none_or(|s| !s.live(now)) {
            self.store
                .would_admit(&principal, caps, now)
                .map_err(|hit| self.cap_refusal_for(&principal, hit))?;
        }

        // After the cheap refusals and before any callback traffic, since it
        // may start the backend; and before the source's own check, which may
        // read the backend's resource catalogue.
        self.resolve_upstream(&descriptor.name).await?;
        let observed = self.observe(caller, &descriptor.name)?;
        if let Some(source) = self.source_offering(&descriptor.name) {
            source
                .authorize(&principal, &descriptor.name, &arguments)
                .await?;
        }
        let tail = crate::events::tail_policy(&self.config);
        let mut verified = self.store.is_verified(&principal, url.as_str(), now, tail);
        let existing = self.store.get(&id).filter(|s| s.live(now));
        let grace = rotation_grace(self);
        let record = Subscription {
            generation: 0,
            incarnation: 0,
            v: 1,
            id: id.clone(),
            principal,
            api_key: caller.credential.api_key.clone(),
            credential_kind: Some(caller.credential.kind),
            credential_principal: Some(caller.credential.principal.clone()),
            read_key: caller.read_key.clone(),
            binding: caller.credential.binding.clone(),
            legacy_api_key_name: None,
            url: url.as_str().to_owned(),
            name: descriptor.name.clone(),
            arguments,
            secret: secret.to_owned(),
            // Rotation and delivery history are taken from the stored row
            // inside the store's commit, never from this earlier read.
            previous_secret: None,
            previous_until: None,
            // Provisional: the store's commit sets both.
            granted_at: now,
            expires_at: grant.expires_at(now),
            active: true,
            failed_since: None,
            last_delivery_at: None,
            last_error: None,
            payload_fields: self.payload_fields(&descriptor.name),
            unoffered_since: None,
            held_until: None,
            watch_class: None,
            observed_identity: caller.stored_identity(observed.as_ref()),
            obs_basis: observed.clone(),
        };
        // At most two passes: a cached opt-in can vanish (tail eviction)
        // between the read above and the commit; the store then refuses
        // and the callback is challenged before a second commit.
        let (policy, by) = ((caps, grace, tail), (caller, &url, Commit::Checked));
        for _pass in 0..2 {
            if !verified {
                self.challenge(caller, &descriptor.name, &url, &id, &key)
                    .await?;
            }
            let outcome = self
                .commit_started(&record, grant, !verified, policy, now, by)
                .await;
            match outcome? {
                Ok((_, expires_at)) => {
                    // A refresh may have reactivated a suspended row.
                    self.runtime.wake.notify_one();
                    let throttled = self.runtime.rates.empty(&id, std::time::Instant::now())
                        // The subscribe's own read: an earlier `now` can
                        // only under-report a due record.
                        && self.store.has_due(&id, now);
                    let answer =
                        subscribe_answer(&handle, expires_at, existing.as_ref(), throttled);
                    return Ok(self.held_answer(answer, &id));
                }
                Err(CapHit::Unverified) if verified => verified = false,
                Err(hit) => return Err(self.cap_refusal_for(&record.principal, hit)),
            }
        }
        Err(RpcError::internal())
    }

    /// Start the source's upstream work for the subscription (when it is the
    /// first of its key), commit it and audit it (as `by`), under one
    /// lifecycle lock: a stop for another key cannot land between them
    /// (lifecycle.rs), and racing subscribes are audited in commit order. A
    /// commit that fails undoes the start it made.
    pub(super) async fn commit_started(
        self: &Arc<Self>,
        record: &Subscription,
        grant: Grant,
        fresh: bool,
        policy: (Caps, chrono::Duration, crate::events::store::TailPolicy),
        now: DateTime<Utc>,
        (caller, url, commit): (&Caller, &url::Url, Commit),
    ) -> Result<Result<crate::events::store::Admitted, CapHit>, RpcError> {
        let mut attempt = record.clone();
        let mut started = self.lifecycle.lock().await;
        self.upstream_admits(&record.name)?;
        let begun = self.start_key(&mut started, record, now).await?;
        let hub = Arc::clone(self);
        let outcome = blocking(self, move |store| {
            // Under the catalogue gate, then the store lock (the order every
            // withdraw takes): a reload that removed or narrowed the type
            // while the callback was challenged refuses the commit, so no
            // subscription is stored that its route can no longer serve.
            let _gate = hub.catalogue_lock();
            // Checked against the routes now, with the payload fields they
            // carry now and no hold stamp.
            let checked = |attempt: &mut Subscription| -> Result<(), RpcError> {
                hub.still_admits(attempt)?;
                attempt.payload_fields = hub.payload_fields(&attempt.name);
                attempt.watch_class = hub.watch_class(&attempt.name);
                attempt.unoffered_since = None;
                attempt.held_until = None;
                Ok(())
            };
            // A held row's refresh keeps the row's hold as the store holds it
            // at the commit; every other commit is checked, and the store
            // keeps the hold of a row held by then.
            let mut hold = HoldCommit::Keep;
            if commit == Commit::Checked {
                if let Err(refused) = checked(&mut attempt) {
                    // A reload held the row while this refresh waited: it
                    // refreshes as the held row it is; anything else is
                    // refused as checked.
                    if store.held(&attempt.id).is_none() {
                        return Ok(Err(refused));
                    }
                    let kept = store.admit_granted(attempt, grant, fresh, policy, now, hold)?;
                    return Ok(match kept {
                        Err(CapHit::HeldRowGone) => Err(refused),
                        other => Ok(other),
                    });
                }
                hold = HoldCommit::End;
            }
            #[cfg(test)]
            tokio::runtime::Handle::current().block_on(hub.before_admit.pause());
            let admitted = store.admit_granted(attempt.clone(), grant, fresh, policy, now, hold)?;
            if !matches!(admitted, Err(CapHit::HeldRowGone)) {
                return Ok(Ok(admitted));
            }
            // The held row went while the refresh waited: a fresh subscribe.
            if let Err(refused) = checked(&mut attempt) {
                return Ok(Err(refused));
            }
            store
                .admit_granted(attempt, grant, fresh, policy, now, HoldCommit::End)
                .map(Ok)
        })
        .await
        .and_then(|checked| checked);
        if !matches!(outcome, Ok(Ok(_)))
            && let Some(key) = begun
        {
            self.undo_start(&mut started, key).await;
        }
        if let Ok(Ok((admission, _))) = &outcome {
            #[cfg(test)]
            self.after_commit.pause().await;
            self.subscribed(caller, *admission, &record.id, &record.name, url)
                .await;
        }
        drop(started);
        outcome
    }

    /// Challenge the callback once, and record how it went.
    pub(super) async fn challenge(
        &self,
        caller: &Caller,
        name: &str,
        url: &url::Url,
        id: &str,
        key: &[u8],
    ) -> Result<(), RpcError> {
        let outcome = self.probe(url, id, key).await;
        let detail = match &outcome {
            Ok(()) => "verified",
            Err(error) => error
                .data
                .as_ref()
                .and_then(|d| d["reason"].as_str().or_else(|| d["limit"].as_str()))
                .unwrap_or("refused"),
        };
        self.govern(
            &Lifecycle {
                action: "events.verification",
                subscription_id: id,
                event_name: name,
                callback_host: url.host_str().unwrap_or_default(),
                detail,
                event_id: None,
                failed_with: outcome.as_ref().err().map(|e| e.code),
            },
            Attribution::Caller(caller),
        )
        .await;
        outcome
    }

    /// The verification probe: literal check, per-host limit, then the POST.
    async fn probe(&self, url: &url::Url, id: &str, key: &[u8]) -> Result<(), RpcError> {
        self.client.check_literal(url).map_err(RpcError::callback)?;
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        if !self.host_admitted(&host) {
            return Err(RpcError::exhausted("verifications", None));
        }
        self.client
            .verify(url, &self.handle(id)?, key)
            .await
            .map_err(RpcError::callback)
    }
}
