// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `events/list`, `events/subscribe`, `events/unsubscribe` (design §6.2-6.4).

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::EventsHub;
use super::governance::{Attribution, Lifecycle};
use super::records::{Credential, Subscription};
use super::store::{CapHit, Caps, Grant};
use super::types::{EventDescriptor, RpcError, Visibility};
use super::upstream::{self, Ineligible, Judged, Kind};

/// Who is calling, as the transport resolved it. Owned, so it can be held
/// across the verification POST.
pub(crate) struct Caller {
    /// The canonical principal; `None` when the call is not authenticated
    /// (or authentication is off).
    pub principal: Option<String>,
    /// The caller key the read verdict judges this caller's frames under;
    /// `None` when the verdict is off or the caller has no identity.
    pub read_key: Option<String>,
    /// The credential the caller presented.
    pub credential: Credential,
    /// Of the backends the catalogue scopes to ([`EventsHub::scope_backends`]),
    /// the ones the caller may see: the predicate `tools/list` filters with.
    pub visible_backends: std::collections::HashSet<String>,
    /// Admin standing, set only by the transport from the authenticated
    /// caller; operator-scoped types are listed and subscribable with it.
    pub admin: bool,
}

impl Caller {
    fn sees(&self, hub: &EventsHub, descriptor: &EventDescriptor) -> bool {
        match &descriptor.scope {
            Visibility::Backend(backend) => self.sees_backend(hub, backend),
            // Owner-scoped types (task events, I4) are listed to anyone who
            // can own a record; operator types (gateway health, kill switch)
            // to admins, whose standing their source re-checks at delivery.
            Visibility::Owner => self.principal.is_some(),
            Visibility::Operator => self.admin,
        }
    }

    /// Whether this caller may see event types scoped to `backend`.
    fn sees_backend(&self, hub: &EventsHub, backend: &str) -> bool {
        self.visible_backends.contains(backend)
            && hub.live_admits(self.credential.api_key.as_ref(), backend)
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
            .chain(self.ineligible_backends().into_keys())
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

    /// Catalogue entries a keyword search finds (a case-insensitive
    /// substring of name or description), for the callers `visible` admits,
    /// as `gateway_search` entries (design §3.9, §18), at most `limit`.
    pub(crate) fn search(
        &self,
        query: &str,
        limit: usize,
        visible: impl Fn(&Visibility) -> bool,
    ) -> Vec<Value> {
        let query = query.to_lowercase();
        self.catalogue()
            .iter()
            .filter(|d| visible(&d.scope))
            .filter(|d| {
                d.name.to_lowercase().contains(&query)
                    || d.description.to_lowercase().contains(&query)
            })
            .take(limit)
            .map(|d| {
                json!({
                    "kind": "event",
                    "name": d.name,
                    "description": d.description,
                    "inputSchema": d.input_schema,
                })
            })
            .collect()
    }

    /// The JSON Schema of one [`Self::search`] row, as `gateway_search_tools`
    /// publishes it beside the tool row (MIK-7819).
    pub(crate) fn search_row_schema() -> Value {
        json!({
            "type": "object",
            "description": "A subscribable event (events/subscribe), not a tool",
            "properties": {
                "kind":        { "const": "event" },
                "name":        { "type": "string", "description": "Event name" },
                "description": { "type": "string", "description": "Event description" },
                "inputSchema": { "type": "object", "description": "Subscription filter schema" }
            },
            "required": ["kind", "name", "description"]
        })
    }

    /// The visible descriptor called `name`; invisible and missing are one
    /// answer, so the catalogue cannot be probed (design §7.4).
    ///
    /// The one exception: an upstream-notification event of a backend the
    /// caller may see but which cannot offer it is refused with the reason
    /// (I5 design §11 D2/D3), so the subscription is never silently dead.
    /// Under the catalogue gate: whether `record`'s type is still offered and
    /// its arguments still valid against the descriptor offered now.
    fn still_admits(&self, record: &Subscription) -> Result<(), RpcError> {
        let descriptor = self
            .catalogue()
            .into_iter()
            .find(|d| d.name == record.name)
            .ok_or_else(RpcError::not_found)?;
        checked_arguments(&descriptor, Some(&record.arguments)).map(|_| ())
    }

    fn visible(&self, caller: &Caller, name: &str) -> Result<EventDescriptor, RpcError> {
        if let Some(found) = self
            .catalogue()
            .into_iter()
            .find(|d| d.name == name && caller.sees(self, d))
        {
            return Ok(found);
        }
        let refusal = super::upstream::parse_name(name)
            .filter(|(backend, _)| caller.sees_backend(self, backend))
            .and_then(|(backend, _)| self.ineligible_backends().remove(backend))
            .map(|reason| RpcError::unsupported_backend_events(name, reason.as_str()));
        Err(refusal.unwrap_or_else(RpcError::not_found))
    }

    /// The configured backends that cannot offer upstream-notification
    /// events, under the live config and connections; none while that source
    /// is off.
    fn ineligible_backends(&self) -> BTreeMap<String, Ineligible> {
        upstream::refused(self.judged_backends())
    }

    /// Every configured backend that cannot offer upstream-notification
    /// events yet, refused or unresolved (MIK-7969).
    fn judged_backends(&self) -> BTreeMap<String, Judged> {
        let Some(services) = self.runtime.services.get() else {
            return BTreeMap::new();
        };
        if !self.config.sources.backend_notifications {
            return BTreeMap::new();
        }
        let multi_user = upstream::multi_user(services.live.running());
        let registry = self.runtime.backends.get();
        let detected = |name: &str| registry?.get(name)?.connected_streamable();
        upstream::judged_backends(&services.live.get(), multi_user, &detected)
    }

    /// An upstream-notification event of a backend whose HTTP transport no
    /// live connection has detected: start the backend as a client request
    /// would, bounded by its timeout, then judge the transport it connected
    /// with (MIK-7969). A failed start answers the backend error, never an
    /// SSE refusal.
    async fn resolve_upstream(&self, name: &str) -> Result<(), RpcError> {
        let Some((backend, kind)) = upstream::parse_name(name) else {
            return Ok(());
        };
        if kind == Kind::ToolsChanged {
            return Ok(());
        }
        match self.judged_backends().get(backend) {
            None => return Ok(()),
            // Refused already: answer it before anything reads the backend.
            Some(Judged::Refused(_)) => {}
            Some(Judged::Unresolved) => {
                let Some(handle) = self.runtime.backends.get().and_then(|r| r.get(backend)) else {
                    return Err(RpcError::not_found());
                };
                if !handle.resolve_for_events().await {
                    return Err(RpcError::backend_unavailable());
                }
            }
        }
        self.upstream_admits(name)
    }

    /// Whether an upstream-notification subscription to `name` may commit:
    /// its backend is configured and offers the events over a transport a
    /// live connection detected, or needs none (stdio, WebSocket). Run under
    /// the lifecycle lock, so a stop or a switch to SSE since the subscribe
    /// resolved it refuses the commit (MIK-7969).
    fn upstream_admits(&self, name: &str) -> Result<(), RpcError> {
        let Some((backend, kind)) = upstream::parse_name(name) else {
            return Ok(());
        };
        if kind == Kind::ToolsChanged || !self.config.sources.backend_notifications {
            return Ok(());
        }
        match self.judged_backends().remove(backend) {
            Some(Judged::Refused(reason)) => {
                Err(RpcError::unsupported_backend_events(name, reason.as_str()))
            }
            Some(Judged::Unresolved) => Err(RpcError::backend_unavailable()),
            // Removed since the subscribe saw it.
            None if self.source_offering(name).is_none() => Err(RpcError::not_found()),
            None => Ok(()),
        }
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

/// `sub_` + 32 hex of SHA-256 over the canonical array `[principal, url,
/// name, arguments]` (design §6.3 step 7; see `canonical`).
pub(crate) fn subscription_id(principal: &str, url: &str, name: &str, arguments: &Value) -> String {
    use sha2::Digest as _;
    let canonical = canonical(&json!([principal, url, name, arguments]));
    let digest = hex::encode(sha2::Sha256::digest(canonical));
    format!("sub_{}", &digest[..32])
}

/// The JCS form of `value` (RFC 8785), except for integers: JCS writes
/// every number through `f64`, so integers past 2^53 can collide, and here
/// an integer keeps its own exact digits. Within 2^53 either way those are
/// the bytes JCS writes, so stored ids keep theirs; past it only ids that
/// could already collide change (MIK-7977).
pub(super) fn canonical(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        // Its own digits: what JCS writes within 2^53, and exact past it.
        Value::Number(n) if n.is_i64() || n.is_u64() => {
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // JCS orders members by their names' UTF-16 code units.
            let mut members: Vec<_> = map.iter().collect();
            members.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (at, (key, item)) in members.into_iter().enumerate() {
                if at > 0 {
                    out.push(b',');
                }
                out.extend(jcs_leaf(&Value::String(key.clone())));
                out.push(b':');
                write_canonical(item, out);
            }
            out.push(b'}');
        }
        leaf => out.extend(jcs_leaf(leaf)),
    }
}

/// A scalar in the library's JCS form.
fn jcs_leaf(leaf: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(leaf).unwrap_or_default()
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

/// The granted length for a `ttlMs` (design §6.3, TTL); `None` is no
/// expiry. It becomes a time only at the commit ([`Grant`]).
fn granted_ttl(hub: &EventsHub, params: &Value) -> Result<Option<chrono::Duration>, RpcError> {
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
    chrono::Duration::from_std(ttl)
        .map(Some)
        .map_err(|_| RpcError::invalid("ttlMs"))
}

/// A subscription made with a credential other than an API key ends no later
/// than the credential (design F9): `ttlMs: null` is refused for it, and the
/// grant is cut at the credential's own expiry when it has one.
fn credential_ceiling(
    credential: &Credential,
    params: &Value,
) -> Result<Option<DateTime<Utc>>, RpcError> {
    if !credential.bounded() {
        return Ok(None);
    }
    if params.get("ttlMs").is_some_and(Value::is_null) {
        return Err(RpcError::invalid("ttlMs"));
    }
    Ok(credential.expires_at)
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
        let secret = delivery
            .get("secret")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let key = super::client::decode_whsec(secret)
            .ok_or_else(|| RpcError::invalid("delivery.secret"))?;
        // Checked before any challenge; fixed to a time only at the commit.
        let grant = Grant {
            ttl: granted_ttl(self, &params)?,
            until: credential_ceiling(&caller.credential, &params)?,
        };
        let now = Utc::now();
        let id = subscription_id(&principal, url.as_str(), &descriptor.name, &arguments);
        let caps = Caps {
            per_principal: self.config.max_subscriptions_per_principal,
            global: self.config.max_subscriptions,
        };
        if self.store.get(&id).as_ref().is_none_or(|s| !s.live(now)) {
            self.store
                .would_admit(&principal, caps, now)
                .map_err(|hit| self.cap_refusal_for(&principal, hit))?;
        }

        // After the cheap refusals and before any callback traffic, since it
        // may start the backend; and before the source's own check, which may
        // read the backend's resource catalogue.
        self.resolve_upstream(&descriptor.name).await?;
        if let Some(source) = self.source_offering(&descriptor.name) {
            source
                .authorize(&principal, &descriptor.name, &arguments)
                .await?;
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
                        && self.store.has_due(&id, Utc::now());
                    return Ok(subscribe_answer(
                        &id,
                        expires_at,
                        existing.as_ref(),
                        throttled,
                    ));
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
    async fn commit_started(
        self: &Arc<Self>,
        record: &Subscription,
        grant: Grant,
        fresh: bool,
        policy: (Caps, chrono::Duration, super::store::TailPolicy),
        now: DateTime<Utc>,
        (caller, url, commit): (&Caller, &url::Url, Commit),
    ) -> Result<Result<super::store::Admitted, CapHit>, RpcError> {
        let attempt = record.clone();
        let mut started = self.lifecycle.lock().await;
        self.upstream_admits(&record.name)?;
        let begun = self
            .start_key(
                &mut started,
                &record.principal,
                &record.name,
                &record.arguments,
            )
            .await?;
        let hub = Arc::clone(self);
        let outcome = blocking(self, move |store| {
            // Under the catalogue gate, then the store lock (the order every
            // withdraw takes): a reload that removed or narrowed the type
            // while the callback was challenged refuses the commit, so no
            // subscription is stored that its route can no longer serve
            // (MIK-8038).
            let _gate = hub.catalogue_lock();
            if commit == Commit::Checked
                && let Err(refused) = hub.still_admits(&attempt)
            {
                return Ok(Err(refused));
            }
            #[cfg(test)]
            tokio::runtime::Handle::current().block_on(hub.before_admit.pause());
            store
                .admit_granted(attempt, grant, fresh, policy, now)
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
    async fn challenge(
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
        let was_there =
            blocking(self, move |store| store.remove(&removed, Utc::now(), tail)).await?;
        self.govern(
            &Lifecycle {
                action: "events.unsubscribe",
                subscription_id: &id,
                event_name: name,
                callback_host: url.host_str().unwrap_or_default(),
                detail: if was_there { "removed" } else { "absent" },
                event_id: None,
                failed_with: None,
            },
            Attribution::Caller(caller),
        )
        .await;
        self.reconcile_stops().await;
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

#[path = "rpc_held.rs"]
mod held;
use held::Commit;

#[cfg(test)]
#[path = "rpc_tests.rs"]
mod tests;
