// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `watch.<capability>.changed` (event-sources design §2): poll a read-only
//! REST capability and emit when its answer changes. The payload carries
//! digests and the JSON pointers that changed, never values: a subscriber
//! reads the new value through the capability, under its own authorization.
//!
//! One poller per lifecycle key. A credential-free capability shares one
//! poller among every principal watching the same arguments; a credentialed
//! one runs a poller per principal, under that principal's key, and its
//! occurrences carry the key so they reach that principal alone (MIK-7811).
//!
//! The source cannot see a caller's credential at subscribe (the trait gives
//! it the principal only), so the credential checks run against the stored
//! subscription: at every fan-out, and before every poll, where a holder that
//! no longer passes is revoked before the call is made.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use chrono::Utc;
use serde_json::{Map, Value, json};

use super::fanout::SourceEvent;
use super::records::{ApiKeyRef, Subscription};
use super::types::{EventDescriptor, RpcError, SourceKind, Visibility};
use super::{EventSource, EventsHub};

const PREFIX: &str = "watch.";
const SUFFIX: &str = ".changed";
/// Seconds between polls when the subscription names none.
const DEFAULT_INTERVAL: u64 = 300;
/// The floor and ceiling of `interval`, in seconds.
const MIN_INTERVAL: u64 = 60;
const MAX_INTERVAL: u64 = 3600;
/// Consecutive failed polls before a poller backs off to [`MAX_INTERVAL`].
const BACKOFF_AFTER: u32 = 5;
/// Top-level keys left out of the digest when `fields` is absent: they
/// change on every call without the answer changing.
const VOLATILE: [&str; 4] = ["timestamp", "requestId", "request_id", "generatedAt"];

/// Whose credential a capability call needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialUse {
    /// None: one poller serves every principal.
    Free,
    /// A gateway-held key (env, keychain, file): a poller per principal.
    Keyed,
    /// A per-user account credential: not watchable (needs the caller's
    /// verified identity, which a stored subscription does not hold).
    Account,
}

/// One REST capability as the watch source sees it.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub capability: String,
    /// The backend the capability is served under (visibility scope).
    pub backend: String,
    /// Classified read-only as data (MIK-7216.IDEM.1); anything else is
    /// side-effecting and never watchable.
    pub read_only: bool,
    // ci-allow-secret-debug: an enum naming whose credential a call needs; it holds no secret.
    pub credential: CredentialUse,
    pub input_schema: Value,
}

/// The subscriber a poll runs as.
#[derive(Debug, Clone)]
pub(crate) struct Holder {
    pub principal: String,
    // ci-allow-secret-debug: a key's name and digest-derived principal, never the secret.
    pub api_key: ApiKeyRef,
}

/// Which budget a poll is charged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Charge {
    /// The holder's own (a credentialed poller).
    Holder,
    /// The gateway's global budget (a shared poller).
    Global,
}

/// A poll that produced no answer: refused by a control or failed upstream.
#[derive(Debug)]
pub(crate) struct PollFailed;

/// One read of the capability catalogue (MIK-8037).
#[derive(Debug, Clone, Default)]
pub(crate) struct Catalogue {
    /// Every REST capability in it, read-only or not.
    pub targets: Vec<Target>,
    /// Every capability name in it, REST-served or not: a capability not
    /// here was not read, which is not the same as reclassified.
    pub present: std::collections::HashSet<String>,
    /// Every capability directory loaded, after the startup scan completed.
    pub complete: bool,
    /// The catalogue generation it was read at.
    pub generation: u64,
}

/// What the gateway lends the source: the capability catalogue, the live
/// grant check and the enforced poll.
#[async_trait::async_trait]
pub(crate) trait WatchHost: Send + Sync {
    /// The catalogue now, read once: its contents, completeness and
    /// generation agree (MIK-8037).
    fn catalogue(&self) -> Catalogue;
    /// Every REST capability now, read-only or not.
    fn targets(&self) -> Vec<Target> {
        self.catalogue().targets
    }
    /// The catalogue generation now: it moves at every catalogue write, so a
    /// denial is trusted only when it has not moved since the read the
    /// decision started from (MIK-8037).
    fn catalogue_generation(&self) -> u64;
    /// Whether `holder` may invoke `target` now (the `tools/list` predicate).
    fn may_invoke(&self, holder: &Holder, target: &Target) -> bool;
    /// Call `target` as `holder` with every control a `tools/call` gets, and
    /// return the firewall-approved application value, before per-call
    /// metadata is attached.
    async fn poll(
        &self,
        holder: &Holder,
        target: &Target,
        arguments: &Value,
        charge: Charge,
    ) -> Result<Value, PollFailed>;
}

/// The capability `name` watches, if it is a watch type.
fn capability_of(name: &str) -> Option<&str> {
    name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)
}

/// Whether `catalogue` could not read `name`'s capability: partial, and the
/// capability not in it. Such an absence ends nothing (MIK-8037).
fn unread(catalogue: &Catalogue, name: &str) -> bool {
    !catalogue.complete && capability_of(name).is_none_or(|c| !catalogue.present.contains(c))
}

/// `watch.<capability>.changed` for `capability`.
pub(crate) fn event_name(capability: &str) -> String {
    format!("{PREFIX}{capability}{SUFFIX}")
}

/// A subscription's watch options, validated.
#[derive(Debug, Clone, PartialEq)]
struct Options {
    arguments: Value,
    interval: Duration,
    fields: Option<Vec<String>>,
}

fn options(arguments: &Value) -> Result<Options, RpcError> {
    let call = match arguments.get("arguments") {
        None => json!({}),
        Some(object @ Value::Object(_)) => object.clone(),
        Some(_) => return Err(RpcError::invalid("arguments.arguments")),
    };
    let interval = match arguments.get("interval") {
        None => DEFAULT_INTERVAL,
        Some(value) => value
            .as_u64()
            .filter(|s| (MIN_INTERVAL..=MAX_INTERVAL).contains(s))
            .ok_or_else(|| RpcError::invalid("arguments.interval"))?,
    };
    let fields = match arguments.get("fields") {
        None => None,
        Some(Value::Array(items)) if !items.is_empty() => Some(
            items
                .iter()
                .map(|p| p.as_str().filter(|p| p.starts_with('/')).map(str::to_owned))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| RpcError::invalid("arguments.fields"))?,
        ),
        Some(_) => return Err(RpcError::invalid("arguments.fields")),
    };
    Ok(Options {
        arguments: call,
        interval: Duration::from_secs(interval),
        fields,
    })
}

/// The part of an answer the digest covers, as pointer -> value: the named
/// `fields`, or every top-level key but `_meta` and the volatile ones.
fn projection(value: &Value, fields: Option<&[String]>) -> BTreeMap<String, Value> {
    match fields {
        Some(pointers) => pointers
            .iter()
            .filter_map(|p| value.pointer(p).map(|v| (p.clone(), v.clone())))
            .collect(),
        None => match value {
            Value::Object(map) => map
                .iter()
                .filter(|(k, _)| k.as_str() != "_meta" && !VOLATILE.contains(&k.as_str()))
                .map(|(k, v)| {
                    (
                        format!("/{}", k.replace('~', "~0").replace('/', "~1")),
                        v.clone(),
                    )
                })
                .collect(),
            other => BTreeMap::from([(String::new(), other.clone())]),
        },
    }
}

/// SHA-256 over the JCS of a projection, `sha256:` + hex.
fn digest(projection: &BTreeMap<String, Value>) -> String {
    use sha2::Digest as _;
    let map: Map<String, Value> = projection.clone().into_iter().collect();
    let bytes = serde_json::to_vec(&Value::Object(map)).unwrap_or_default();
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

/// A poller's lifecycle key: the principal it runs for (none when shared),
/// the event name and the arguments. Serialized with sorted keys and every
/// integer kept, so arguments differing past 2^53 are two pollers.
fn poll_key(principal: Option<&str>, name: &str, arguments: &Value) -> String {
    match principal {
        Some(principal) => json!([principal, name, arguments]),
        None => json!([name, arguments]),
    }
    .to_string()
}

/// The pointers whose values differ between two projections.
fn changed(before: &BTreeMap<String, Value>, after: &BTreeMap<String, Value>) -> Vec<String> {
    let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|k| before.get(*k) != after.get(*k))
        .cloned()
        .collect()
}

/// A running poller and the principal that opened it, against whose cap it
/// counts (shared or not). Stopped by its flag, not aborted: the stop can
/// come from inside the poller's own task (it revoked its last holder), and
/// an abort there would cut short the core's lifecycle bookkeeping it is
/// running. A poller that ends on its own sets the flag too.
struct Poller {
    stop: Arc<AtomicBool>,
    owner: String,
}

/// The REST capability watch source.
pub(crate) struct WatchSource {
    hub: Weak<EventsHub>,
    host: Arc<dyn WatchHost>,
    max_pollers: usize,
    max_per_principal: usize,
    pollers: parking_lot::Mutex<HashMap<String, Poller>>,
}

impl WatchSource {
    pub(crate) fn new(hub: &Arc<EventsHub>, host: Arc<dyn WatchHost>) -> Self {
        Self {
            hub: Arc::downgrade(hub),
            host,
            max_pollers: hub.config.watch.max_pollers,
            max_per_principal: hub.config.watch.max_pollers_per_principal,
            pollers: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// The watchable target named `name`: read-only now. A target that left
    /// the catalogue or was reclassified is `None`.
    fn target(&self, name: &str) -> Option<Target> {
        self.host
            .targets()
            .into_iter()
            .find(|t| t.read_only && event_name(&t.capability) == name)
    }

    /// Live rows of `principal` for `name` with these canonical `arguments`.
    fn rows(hub: &EventsHub, principal: &str, name: &str, arguments: &Value) -> Vec<Subscription> {
        let now = Utc::now();
        hub.store
            .subscriptions()
            .into_iter()
            .filter(|s| s.live(now) && s.principal == principal && s.name == name)
            .filter(|s| s.arguments == *arguments)
            .collect()
    }

    /// The holder a stored row polls as, when its credential still passes:
    /// an API key that is live and may invoke `target`.
    fn holder(&self, row: &Subscription, target: &Target) -> Option<Holder> {
        let api_key = row
            .api_key
            .clone()
            .filter(|_| row.legacy_api_key_name.is_none())?;
        let holder = Holder {
            principal: row.principal.clone(),
            api_key,
        };
        self.host.may_invoke(&holder, target).then_some(holder)
    }
}

#[async_trait::async_trait]
impl EventSource for WatchSource {
    fn kind(&self) -> SourceKind {
        SourceKind::RestWatch
    }

    fn descriptors(&self) -> Vec<EventDescriptor> {
        self.host
            .targets()
            .into_iter()
            .filter(|t| t.read_only)
            .map(|t| EventDescriptor {
                name: event_name(&t.capability),
                description: format!(
                    "The answer of the read-only capability {} changed. Polled every \
                     `interval` seconds (default {DEFAULT_INTERVAL}, {MIN_INTERVAL} to \
                     {MAX_INTERVAL}). Name `fields` (JSON pointers) to ignore parts that change \
                     on every call; without them the top-level keys {} are ignored. The \
                     payload names what changed, never the values: read them with the \
                     capability itself.",
                    t.capability,
                    VOLATILE.join(", "),
                ),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "arguments": t.input_schema,
                        "interval": {"type": "integer", "minimum": MIN_INTERVAL,
                                     "maximum": MAX_INTERVAL, "default": DEFAULT_INTERVAL},
                        "fields": {"type": "array", "items": {"type": "string"}},
                    },
                    "additionalProperties": false,
                }),
                payload_schema: json!({
                    "type": "object",
                    "properties": {
                        "capability": {"type": "string"},
                        "changed": {"type": "array", "items": {"type": "string"}},
                        "digest_before": {"type": "string"},
                        "digest_after": {"type": "string"},
                        "observed_at": {"type": "string"},
                    },
                    "additionalProperties": false,
                }),
                scope: Visibility::Backend(t.backend),
                kind: SourceKind::RestWatch,
            })
            .collect()
    }

    fn offers(&self, name: &str) -> bool {
        name.starts_with(PREFIX) && name.ends_with(SUFFIX) && self.target(name).is_some()
    }

    /// The capability must still be watchable and the options valid. Where
    /// the principal already holds rows (every fan-out), each must still have
    /// a live API key that may invoke the capability; at subscribe no row
    /// exists yet, and the first poll judges the new one before any call.
    async fn authorize(
        &self,
        principal: &str,
        name: &str,
        arguments: &Value,
    ) -> Result<(), RpcError> {
        let catalogue = self.host.catalogue();
        let Some(target) = catalogue
            .targets
            .iter()
            .find(|t| t.read_only && event_name(&t.capability) == name)
            .cloned()
        else {
            // Only a confirmed absence revokes; an unread one skips (MIK-8037).
            return Err(if unread(&catalogue, name) {
                RpcError::not_found()
            } else {
                RpcError::forbidden()
            });
        };
        if target.credential == CredentialUse::Account {
            return Err(RpcError {
                code: -32014,
                message: "Unsupported",
                data: Some(json!({"feature": "watch", "reason": "account_credential"})),
            });
        }
        options(arguments)?;
        let Some(hub) = self.hub.upgrade() else {
            return Err(RpcError::internal());
        };
        // ponytail: scans the store per check; an index by principal is the
        // upgrade if many watch rows make fan-out measurable.
        let rows = Self::rows(&hub, principal, name, arguments);
        if rows.iter().any(|row| self.holder(row, &target).is_none()) {
            // A reload since the read may be the denial's cause: skip, keep.
            return Err(
                if self.host.catalogue_generation() == catalogue.generation {
                    RpcError::forbidden()
                } else {
                    RpcError::not_found()
                },
            );
        }
        Ok(())
    }

    fn matches(&self, principal: &str, arguments: &Value, event: &SourceEvent) -> bool {
        event
            .lifecycle_key
            .as_deref()
            .is_some_and(|key| self.lifecycle_key(principal, &event.name, arguments) == key)
    }

    /// Shared across principals for a credential-free capability; per
    /// principal otherwise, so one principal's credential never answers for
    /// another's subscription.
    fn lifecycle_key(&self, principal: &str, name: &str, arguments: &Value) -> String {
        let shared = self
            .target(name)
            .is_some_and(|t| t.credential == CredentialUse::Free);
        poll_key((!shared).then_some(principal), name, arguments)
    }

    async fn on_first_subscriber(
        &self,
        key: &str,
        principal: &str,
        name: &str,
        arguments: &Value,
    ) -> Result<(), RpcError> {
        let target = self.target(name).ok_or_else(RpcError::forbidden)?;
        let options = options(arguments)?;
        let shared = target.credential == CredentialUse::Free;
        let mut pollers = self.pollers.lock();
        // An entry whose poller ended on its own is replaced, not joined.
        pollers.retain(|_, p| !p.stop.load(Ordering::Acquire));
        if pollers.contains_key(key) {
            return Ok(());
        }
        if pollers.len() >= self.max_pollers {
            return Err(RpcError::exhausted("watch_pollers", Some(self.max_pollers)));
        }
        if pollers.values().filter(|p| p.owner == principal).count() >= self.max_per_principal {
            return Err(RpcError::exhausted(
                "watch_pollers_per_principal",
                Some(self.max_per_principal),
            ));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let run = Run {
            stop: Arc::clone(&stop),
            hub: self.hub.clone(),
            host: Arc::clone(&self.host),
            key: key.to_owned(),
            name: name.to_owned(),
            options,
            charge: if shared {
                Charge::Global
            } else {
                Charge::Holder
            },
        };
        pollers.insert(
            key.to_owned(),
            Poller {
                stop: {
                    tokio::spawn(run.forever());
                    stop
                },
                owner: principal.to_owned(),
            },
        );
        Ok(())
    }

    async fn on_last_subscriber(&self, key: &str) {
        if let Some(poller) = self.pollers.lock().remove(key) {
            poller.stop.store(true, Ordering::Release);
        }
    }
}

/// What one poll came to.
enum Step {
    Polled,
    Failed,
    /// The capability left, or no holder may poll it: the poller ends.
    Stop,
}

/// One poller's loop.
struct Run {
    /// Set when the last subscription for the key went away.
    stop: Arc<AtomicBool>,
    hub: Weak<EventsHub>,
    host: Arc<dyn WatchHost>,
    key: String,
    name: String,
    options: Options,
    charge: Charge,
}

/// `base` stretched by up to a tenth, so pollers started together do not stay
/// in step. Never shrunk: two polls stay at least the interval apart, so the
/// 60 s floor holds for the polls, not only the setting.
fn jitter(base: Duration) -> Duration {
    base.mul_f64(1.0 + rand::random::<f64>() / 10.0)
}

impl Run {
    async fn forever(self) {
        self.poll_until_stopped().await;
        self.stop.store(true, Ordering::Release);
    }

    async fn poll_until_stopped(&self) {
        let mut wait = jitter(Duration::from_secs(2));
        let mut last = None;
        let mut failures = 0_u32;
        loop {
            tokio::time::sleep(wait).await;
            if self.stop.load(Ordering::Acquire) {
                return;
            }
            let Some(hub) = self.hub.upgrade() else {
                return;
            };
            wait = match self.once(&hub, &mut last).await {
                Step::Stop => return,
                Step::Polled => {
                    failures = 0;
                    jitter(self.options.interval)
                }
                Step::Failed => {
                    failures += 1;
                    if failures == BACKOFF_AFTER {
                        self.audit_backoff(&hub, failures).await;
                    }
                    if failures >= BACKOFF_AFTER {
                        jitter(Duration::from_secs(MAX_INTERVAL))
                    } else {
                        jitter(self.options.interval)
                    }
                }
            };
        }
    }

    /// The lifecycle key a row holds under this poller's sharing rule.
    fn key_of(&self, row: &Subscription) -> String {
        let alone = (self.charge == Charge::Holder).then_some(row.principal.as_str());
        poll_key(alone, &row.name, &row.arguments)
    }

    /// The live rows that hold this poller's key.
    fn holders(&self, hub: &EventsHub) -> Vec<Subscription> {
        let now = Utc::now();
        hub.store
            .subscriptions()
            .into_iter()
            .filter(|s| s.live(now) && s.name == self.name && self.key_of(s) == self.key)
            .collect()
    }

    /// No holder is left: retire the key under the lock a subscribe commits
    /// under, so the next subscribe starts a fresh poller instead of finding
    /// the key started with nothing polling. A holder that committed while
    /// this poll read the store joined the key: the poller goes on.
    async fn retire(&self, hub: &EventsHub) -> Step {
        let mut started = hub.lifecycle.lock().await;
        if !self.holders(hub).is_empty() {
            return Step::Polled;
        }
        started.remove(&(SourceKind::RestWatch, self.key.clone()));
        self.stop.store(true, Ordering::Release);
        Step::Stop
    }

    async fn once(
        &self,
        hub: &Arc<EventsHub>,
        last: &mut Option<(BTreeMap<String, Value>, String)>,
    ) -> Step {
        // The classification is re-read every poll (MIK-7216.IDEM.1). A
        // capability removed, reclassified as side-effecting, or moved to
        // another credential class (a shared poller never calls under one
        // sharer's credential) takes its subscriptions with it; subscribers
        // subscribe again under the new class.
        let watchable = |t: &Target| {
            t.read_only
                && event_name(&t.capability) == self.name
                && t.credential != CredentialUse::Account
                && (t.credential == CredentialUse::Free) == (self.charge == Charge::Global)
        };
        // A partial catalogue that could not read the capability ends
        // nothing: the poll waits for the next complete one (MIK-8037).
        let first = self.host.catalogue();
        let found = first.targets.iter().find(|&t| watchable(t)).cloned();
        let (target, generation) = if let Some(target) = found {
            (target, first.generation)
        } else if unread(&first, &self.name) {
            return Step::Polled;
        } else {
            // Confirmed under the lock a subscribe commits under: a
            // capability watchable again by now keeps every subscription.
            let mut started = hub.lifecycle.lock().await;
            let again = self.host.catalogue();
            if let Some(target) = again.targets.iter().find(|&t| watchable(t)).cloned() {
                (target, again.generation)
            } else if unread(&again, &self.name) {
                return Step::Polled;
            } else {
                let (gone, owner) = (vec![self.name.clone()], Arc::clone(hub));
                let _ = tokio::task::spawn_blocking(move || owner.withdraw(&gone)).await;
                // Retired before the lock goes, as in `retire`: a subscribe
                // next must start a fresh poller, not join this one.
                started.remove(&(SourceKind::RestWatch, self.key.clone()));
                self.stop.store(true, Ordering::Release);
                drop(started);
                hub.reconcile_stops_in_background();
                return Step::Stop;
            }
        };
        let now = Utc::now();
        let rows = self.holders(hub);
        let Some(services) = hub.runtime.services.get().cloned() else {
            return Step::Failed;
        };
        let mut chosen = None;
        let mut denied = Vec::new();
        for row in rows {
            let passes = services
                .admits_subscription(&row, Some(target.backend.as_str()))
                .await;
            let api_key = row
                .api_key
                .clone()
                .filter(|_| row.legacy_api_key_name.is_none());
            let holder = api_key
                .map(|api_key| Holder {
                    principal: row.principal.clone(),
                    api_key,
                })
                .filter(|h| passes && self.host.may_invoke(h, &target));
            match holder {
                Some(holder) => {
                    if chosen.is_none() {
                        chosen = Some(holder);
                    }
                }
                None => denied.push(row),
            }
        }
        if !denied.is_empty() {
            // A reload since the read may be the denial's cause (the
            // capability gone from the live catalogue): nothing is revoked
            // or called, and the next poll decides afresh (MIK-8037).
            if self.host.catalogue_generation() != generation {
                return Step::Polled;
            }
            // Revoked before any call is made for them.
            for row in &denied {
                hub.revoke(row).await;
            }
        }
        let Some(holder) = chosen else {
            return self.retire(hub).await;
        };
        let Ok(value) = self
            .host
            .poll(&holder, &target, &self.options.arguments, self.charge)
            .await
        else {
            return Step::Failed;
        };
        let after = projection(&value, self.options.fields.as_deref());
        let digest_after = digest(&after);
        if let Some((before, digest_before)) = last.as_ref()
            && *digest_before != digest_after
        {
            hub.emit(SourceEvent {
                kind: SourceKind::RestWatch,
                name: self.name.clone(),
                backend: target.backend.clone(),
                scope: Visibility::Backend(target.backend.clone()),
                owner: None,
                // A fresh id per transition: a flap A->B->A is three
                // occurrences, and a restarted poller repeats none.
                upstream_id: hex::encode(rand::random::<[u8; 16]>()),
                occurred_at: now,
                data: json!({
                    "capability": target.capability,
                    "changed": changed(before, &after),
                    "digest_before": digest_before,
                    "digest_after": digest_after,
                    "observed_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                }),
                lifecycle_key: Some(self.key.clone()),
            });
        }
        *last = Some((after, digest_after));
        Step::Polled
    }

    /// One governance record when a poller backs off: a poll failure is not
    /// an event, but a poller that stopped answering is worth a trace.
    async fn audit_backoff(&self, hub: &EventsHub, failures: u32) {
        let Some(log) = hub.runtime.services.get().and_then(|s| s.audit.clone()) else {
            return;
        };
        let mut fields = Map::new();
        fields.insert("action".into(), "events.watch_backoff".into());
        fields.insert("timestamp".into(), Utc::now().to_rfc3339().into());
        fields.insert("event_name".into(), self.name.clone().into());
        fields.insert("failures".into(), failures.into());
        let envelope = crate::security::audit::AuditEnvelope::gateway();
        let written = log
            .append_bounded(move |log| log.append_event(fields, &envelope).map(|_| ()))
            .await;
        if let Err(error) = written {
            tracing::warn!(%error, "events: watch backoff audit record not written");
        }
    }
}

impl EventsHub {
    /// Offer `watch.<capability>.changed` for the read-only capabilities
    /// `host` lists.
    pub(crate) fn install_watch_source(self: &Arc<Self>, host: Arc<dyn WatchHost>) {
        self.register_source(Arc::new(WatchSource::new(self, host)));
    }
}

#[cfg(test)]
#[path = "watch_source_tests.rs"]
mod tests;
