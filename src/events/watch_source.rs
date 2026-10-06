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
#![allow(
    dead_code,
    unused_imports,
    clippy::unused_self,
    reason = "stub until the source lands"
)]

use std::collections::{BTreeMap, HashMap};
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
    pub credential: CredentialUse,
    pub input_schema: Value,
}

/// The subscriber a poll runs as.
#[derive(Debug, Clone)]
pub(crate) struct Holder {
    pub principal: String,
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

/// What the gateway lends the source: the capability catalogue, the live
/// grant check and the enforced poll.
#[async_trait::async_trait]
pub(crate) trait WatchHost: Send + Sync {
    /// Every REST capability now, read-only or not.
    fn targets(&self) -> Vec<Target>;
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
            .map(|p| (p.clone(), value.pointer(p).cloned().unwrap_or(Value::Null)))
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
    let bytes = serde_json_canonicalizer::to_vec(&Value::Object(map)).unwrap_or_default();
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
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

/// A running poller and whose credential it runs under, if only one.
struct Poller {
    task: tokio::task::JoinHandle<()>,
    alone: Option<String>,
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

// Stub: the rows in `watch_source_tests.rs` fail against it until the
// source lands.
#[async_trait::async_trait]
impl EventSource for WatchSource {
    fn kind(&self) -> SourceKind {
        SourceKind::RestWatch
    }

    fn descriptors(&self) -> Vec<EventDescriptor> {
        Vec::new()
    }

    fn matches(&self, _principal: &str, _arguments: &Value, _event: &SourceEvent) -> bool {
        false
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
    hub: Weak<EventsHub>,
    host: Arc<dyn WatchHost>,
    key: String,
    name: String,
    options: Options,
    charge: Charge,
}

/// `base` stretched or shrunk by up to a tenth, so pollers started together
/// do not stay in step.
fn jitter(base: Duration) -> Duration {
    base.mul_f64(0.9 + rand::random::<f64>() / 5.0)
}

impl Run {
    async fn forever(self) {
        let mut wait = jitter(Duration::from_secs(2));
        let mut last = None;
        let mut failures = 0_u32;
        loop {
            tokio::time::sleep(wait).await;
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
        let key = match self.charge {
            Charge::Global => json!([row.name, row.arguments]),
            Charge::Holder => json!([row.principal, row.name, row.arguments]),
        };
        String::from_utf8(serde_json_canonicalizer::to_vec(&key).unwrap_or_default())
            .unwrap_or_default()
    }

    async fn once(
        &self,
        _hub: &Arc<EventsHub>,
        _last: &mut Option<(BTreeMap<String, Value>, String)>,
    ) -> Step {
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
