// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `schedule.tick` (event-sources design §4): a wake-up on a cron
//! expression, so an agent can run a standing instruction on a timetable.
//!
//! One timer per canonical `(cron, timezone, label)`, started by the first
//! subscription holding it and stopped after the last. One minute-boundary
//! ticker serves every timer. Before each emit the timer's `scheduled_for` is
//! written to its own file under `<store>/schedule/`, so a restart inside the
//! same minute does not fire it twice. A tick missed while the gateway was
//! down is not sent late (emit-only).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use chrono::{DateTime, Duration, DurationRound as _, TimeZone as _, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::fanout::SourceEvent;
use super::types::{EventDescriptor, RpcError, SourceKind, Visibility};
use super::{EventSource, EventsHub};
use crate::scheduler::CronExpression;

pub(crate) const NAME: &str = "schedule.tick";
/// The shortest gap two ticks of one expression may have.
const FLOOR_MINUTES: i64 = 5;
/// The longest label, in characters.
const MAX_LABEL: usize = 64;

/// A validated subscription's timer.
struct Timer {
    cron: CronExpression,
    zone: Tz,
    label: String,
}

/// The longest cron expression accepted, in bytes.
const MAX_CRON: usize = 128;

/// A subscription's arguments, canonical but unvalidated: the timer key and
/// its parts. Cheap: matching, keying and cap counting read only this. The
/// key is the JCS of `[cron, timezone, label]` with whitespace in `cron`
/// collapsed, the zone's canonical IANA name and the defaults filled in.
struct Parts {
    key: String,
    cron: String,
    zone: Tz,
    label: String,
}

fn parts(arguments: &Value) -> Result<Parts, RpcError> {
    let cron = arguments
        .get("cron")
        .and_then(Value::as_str)
        .filter(|text| text.len() <= MAX_CRON)
        .ok_or_else(|| RpcError::invalid("arguments.cron"))?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let zone = match arguments.get("timezone") {
        None => Tz::UTC,
        Some(Value::String(name)) => name
            .parse::<Tz>()
            .map_err(|_| RpcError::invalid("arguments.timezone"))?,
        Some(_) => return Err(RpcError::invalid("arguments.timezone")),
    };
    let label = match arguments.get("label") {
        None => String::new(),
        Some(Value::String(label)) if label.chars().count() <= MAX_LABEL => label.clone(),
        Some(_) => return Err(RpcError::invalid("arguments.label")),
    };
    let key = String::from_utf8(
        serde_json_canonicalizer::to_vec(&json!([cron, zone.name(), label])).unwrap_or_default(),
    )
    .unwrap_or_default();
    Ok(Parts {
        key,
        cron,
        zone,
        label,
    })
}

/// Validated arguments: `(key, timer)`, or the refusal naming the offending
/// field. Parses the expression and runs the floor scan, so only subscribe
/// and timer start call it.
fn canonical(arguments: &Value) -> Result<(String, Timer), RpcError> {
    let Parts {
        key,
        cron,
        zone,
        label,
    } = parts(arguments)?;
    let parsed = CronExpression::parse(&cron).map_err(|_| RpcError::invalid("arguments.cron"))?;
    if fires_too_often(&cron) {
        return Err(RpcError::invalid("arguments.cron"));
    }
    Ok((
        key,
        Timer {
            cron: parsed,
            zone,
            label,
        },
    ))
}

/// Whether two ticks of `cron` can fall less than [`FLOOR_MINUTES`] apart.
/// Judged on the minute and hour fields over two days, as though every day
/// matched: a day restriction can only spread ticks out, so this refuses at
/// worst an expression whose day fields would have kept two ticks apart
/// across midnight.
fn fires_too_often(cron: &str) -> bool {
    let mut fields = cron.split_whitespace();
    let (Some(minute), Some(hour)) = (fields.next(), fields.next()) else {
        return true;
    };
    let Ok(daily) = CronExpression::parse(&format!("{minute} {hour} * * *")) else {
        return true;
    };
    let start = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .single()
        .unwrap_or_default();
    let mut previous: Option<i64> = None;
    for minute in 0..2 * 24 * 60 {
        // Two days of minutes: always in range.
        if Duration::try_minutes(minute).is_some_and(|offset| daily.matches(&(start + offset))) {
            if previous.is_some_and(|p| minute - p < FLOOR_MINUTES) {
                return true;
            }
            previous = Some(minute);
        }
    }
    false
}

/// Whether `timer` fires at UTC minute `minute`. Fields are matched against
/// the zone's wall clock. Across a forward jump (a skipped hour) the local
/// minutes the jump skipped count at the first minute after it, so they fire
/// once there, together. Across a backward jump (a repeated hour) a local
/// minute fires only on its first occurrence.
fn due(timer: &Timer, minute: DateTime<Utc>) -> bool {
    let local = |at: DateTime<Utc>| at.with_timezone(&timer.zone).naive_local();
    let now = local(minute);
    let before = local(minute - crate::duration_bound::delta!(minutes, 1));
    // Wall-clock fields only: the naive local time read as if it were UTC.
    let matches = |naive: chrono::NaiveDateTime| timer.cron.matches(&Utc.from_utc_datetime(&naive));
    if now - before > crate::duration_bound::delta!(minutes, 1) {
        let mut skipped = before + crate::duration_bound::delta!(minutes, 1);
        while skipped <= now {
            if matches(skipped) {
                return true;
            }
            skipped += crate::duration_bound::delta!(minutes, 1);
        }
        return false;
    }
    // A repeated local minute: the earliest instant it names is the first.
    let first = match timer.zone.from_local_datetime(&now) {
        chrono::LocalResult::Ambiguous(earliest, _) => earliest.with_timezone(&Utc) == minute,
        _ => true,
    };
    first && matches(now)
}

/// The last tick one timer emitted, one file per timer.
#[derive(Serialize, Deserialize)]
struct Fired {
    v: u32,
    key: String,
    last: DateTime<Utc>,
}

fn fired_file(key: &str) -> String {
    use sha2::Digest as _;
    format!("{}.json", hex::encode(sha2::Sha256::digest(key.as_bytes())))
}

/// Whether `key` is among the earliest-granted `cap` of the timers `held`.
fn within_cap(held: &HashMap<String, DateTime<Utc>>, key: &str, cap: usize) -> bool {
    let mut order: Vec<(DateTime<Utc>, &String)> = held.iter().map(|(k, at)| (*at, k)).collect();
    order.sort();
    order
        .iter()
        .position(|(_, k)| *k == key)
        .is_some_and(|rank| rank < cap)
}

/// The `schedule.tick` source.
pub(crate) struct ScheduleSource {
    hub: Weak<EventsHub>,
    dir: PathBuf,
    max_timers: usize,
    max_per_principal: usize,
    timers: parking_lot::Mutex<HashMap<String, Timer>>,
    /// Last emitted tick per timer key, read from `dir` once.
    last: parking_lot::Mutex<Option<HashMap<String, DateTime<Utc>>>>,
}

impl ScheduleSource {
    pub(crate) fn new(hub: &Arc<EventsHub>, dir: PathBuf) -> Self {
        Self {
            hub: Arc::downgrade(hub),
            dir,
            max_timers: hub.config.schedule.max_timers,
            max_per_principal: hub.config.schedule.max_timers_per_principal,
            timers: parking_lot::Mutex::new(HashMap::new()),
            last: parking_lot::Mutex::new(None),
        }
    }

    fn load(dir: &Path) -> HashMap<String, DateTime<Utc>> {
        if let Err(error) = super::records::create_private_dir(dir) {
            tracing::warn!(%error, "events: schedule state directory not created");
        }
        super::records::load_records::<Fired>(dir)
            .into_iter()
            .map(|(_, fired)| (fired.key, fired.last))
            .collect()
    }

    /// Fire every timer whose expression matches the minute of `now` and
    /// that has not fired for that minute yet. The ticker calls this at each
    /// minute boundary; tests call it with their own clock.
    pub(crate) fn tick_at(&self, now: DateTime<Utc>) {
        let Some(hub) = self.hub.upgrade() else {
            return;
        };
        let minute = now
            .duration_trunc(crate::duration_bound::delta!(minutes, 1))
            .unwrap_or(now);
        let firing: Vec<(String, String)> = self
            .timers
            .lock()
            .iter()
            .filter(|(_, timer)| due(timer, minute))
            .map(|(key, timer)| (key.clone(), timer.label.clone()))
            .collect();
        let mut guard = self.last.lock();
        let last = guard.get_or_insert_with(|| Self::load(&self.dir));
        self.prune(last, minute);
        for (key, label) in firing {
            // Stopped since it was selected: its state is gone and stays gone.
            if !self.timers.lock().contains_key(&key) {
                continue;
            }
            // The floor holds in UTC too: a daylight-saving jump can bring a
            // collapsed tick within minutes of a regular one, and the later
            // is dropped. It also stops a second tick in the same minute.
            if last.get(&key).is_some_and(|at| {
                minute - *at < crate::duration_bound::delta!(minutes, FLOOR_MINUTES)
            }) {
                continue;
            }
            last.insert(key.clone(), minute);
            // Written before the emit: a restart in this minute reads it back.
            let fired = Fired {
                v: 1,
                key: key.clone(),
                last: minute,
            };
            // Not durable, not sent: an unrecorded tick could repeat after a
            // restart and break the floor.
            if let Err(error) = super::records::write_record(&self.dir, &fired_file(&key), &fired)
                .and_then(super::records::Placed::durable)
            {
                tracing::warn!(%error, "events: schedule tick not persisted, so not sent");
                continue;
            }
            let at = minute.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            hub.emit(SourceEvent {
                kind: SourceKind::Schedule,
                name: NAME.into(),
                backend: "schedule".into(),
                scope: Visibility::Owner,
                owner: None,
                upstream_id: format!("{key}|{at}"),
                occurred_at: minute,
                data: json!({ "scheduled_for": at, "label": label }),
                lifecycle_key: None,
            });
        }
    }

    /// Drop the state of timers no subscription has run for a day: those
    /// whose subscriptions ended while the gateway was down never see
    /// `on_last_subscriber`. A day, not at once: at startup the timers are
    /// restarted after the first tick may already have run.
    fn prune(&self, last: &mut HashMap<String, DateTime<Utc>>, now: DateTime<Utc>) {
        let timers = self.timers.lock();
        let stale: Vec<String> = last
            .iter()
            .filter(|(key, at)| {
                !timers.contains_key(*key) && now - **at > crate::duration_bound::delta!(days, 1)
            })
            .map(|(key, _)| key.clone())
            .collect();
        drop(timers);
        for key in stale {
            last.remove(&key);
            if let Err(error) = super::records::remove_record(&self.dir, &fired_file(&key)) {
                tracing::warn!(%error, "events: stale schedule tick state not removed");
            }
        }
    }

    /// The principals holding the timer `key` in live subscriptions.
    fn holders(&self, key: &str) -> std::collections::BTreeSet<String> {
        let Some(hub) = self.hub.upgrade() else {
            return std::collections::BTreeSet::new();
        };
        let now = Utc::now();
        hub.store
            .subscriptions()
            .into_iter()
            .filter(|s| s.name == NAME && s.live(now))
            .filter(|s| parts(&s.arguments).is_ok_and(|p| p.key == key))
            .map(|s| s.principal)
            .collect()
    }

    /// The distinct timer keys `principal` holds in live subscriptions, each
    /// with the earliest time one of them was granted.
    fn held_by(&self, principal: &str) -> HashMap<String, DateTime<Utc>> {
        let Some(hub) = self.hub.upgrade() else {
            return HashMap::new();
        };
        let now = Utc::now();
        let mut held: HashMap<String, DateTime<Utc>> = HashMap::new();
        for sub in hub.store.subscriptions() {
            if sub.name != NAME || sub.principal != principal || !sub.live(now) {
                continue;
            }
            if let Ok(Parts { key, .. }) = parts(&sub.arguments) {
                let first = held.entry(key).or_insert(sub.granted_at);
                *first = (*first).min(sub.granted_at);
            }
        }
        held
    }
}

#[async_trait::async_trait]
impl EventSource for ScheduleSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Schedule
    }

    fn descriptors(&self) -> Vec<EventDescriptor> {
        vec![EventDescriptor {
            name: NAME.into(),
            description: "A wake-up on a five-field cron expression (minute hour day month \
                          weekday) in an IANA timezone (UTC by default), at most once every 5 minutes. \
                          A skipped or repeated daylight-saving hour fires once. The label you give comes \
                          back in each tick."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "cron": {"type": "string", "description": "Five fields, no seconds."},
                    "timezone": {"type": "string", "description": "IANA name, such as Europe/Helsinki; default UTC."},
                    "label": {"type": "string", "maxLength": MAX_LABEL},
                },
                "required": ["cron"],
                "additionalProperties": false,
            }),
            payload_schema: json!({
                "type": "object",
                "properties": {
                    "scheduled_for": {"type": "string"},
                    "label": {"type": "string"},
                },
                "additionalProperties": false,
            }),
            scope: Visibility::Owner,
            kind: SourceKind::Schedule,
        }]
    }

    fn offers(&self, name: &str) -> bool {
        name == NAME
    }

    /// Any authenticated principal, within the cron floor, the label cap and
    /// the timer caps, counted on distinct timers. A timer the principal
    /// already holds (every fan-out) was validated when it was taken and never
    /// counts against itself; any other is fully validated and refused at
    /// either cap, the same whether or not another principal holds it, so a
    /// refusal reveals nothing of other principals' schedules.
    async fn authorize(
        &self,
        principal: &str,
        _name: &str,
        arguments: &Value,
    ) -> Result<(), RpcError> {
        let Parts { key, .. } = parts(arguments)?;
        let held = self.held_by(principal);
        if held.contains_key(&key) {
            // Two subscribes that join running timers at once both pass the
            // check below; here, at every fan-out, a principal past the cap
            // keeps its earliest timers and loses the rest.
            return if within_cap(&held, &key, self.max_per_principal) {
                Ok(())
            } else {
                Err(RpcError::forbidden())
            };
        }
        canonical(arguments)?;
        if self.timers.lock().len() >= self.max_timers {
            return Err(RpcError::exhausted(
                "schedule_timers",
                Some(self.max_timers),
            ));
        }
        if held.len() >= self.max_per_principal {
            return Err(RpcError::exhausted(
                "schedule_timers_per_principal",
                Some(self.max_per_principal),
            ));
        }
        Ok(())
    }

    fn matches(&self, _principal: &str, arguments: &Value, event: &SourceEvent) -> bool {
        let Ok(Parts { key, .. }) = parts(arguments) else {
            return false;
        };
        event
            .upstream_id
            .rsplit_once('|')
            .is_some_and(|(timer, _)| timer == key)
    }

    /// The timer key, so spellings of one timer share it.
    fn lifecycle_key(&self, _principal: &str, name: &str, arguments: &Value) -> String {
        parts(arguments).map_or_else(
            |_| {
                String::from_utf8(
                    serde_json_canonicalizer::to_vec(&json!([name, arguments])).unwrap_or_default(),
                )
                .unwrap_or_default()
            },
            |p| p.key,
        )
    }

    async fn on_first_subscriber(
        &self,
        key: &str,
        principal: &str,
        _name: &str,
        arguments: &Value,
    ) -> Result<(), RpcError> {
        let (_, timer) = canonical(arguments)?;
        // Again under the lifecycle lock, against committed rows: two
        // concurrent subscribes for new timers cannot both pass the cap, and
        // after a restart or a lowered cap the earliest timers still start.
        let held = self.held_by(principal);
        let within = if held.contains_key(key) {
            // A held key (a replay, or one a refusal left unstarted) starts
            // when any live holder ranks it within that holder's own cap:
            // the replay asks for whichever row it read first.
            self.holders(key)
                .iter()
                .any(|p| within_cap(&self.held_by(p), key, self.max_per_principal))
        } else {
            held.len() < self.max_per_principal
        };
        if !within {
            return Err(RpcError::exhausted(
                "schedule_timers_per_principal",
                Some(self.max_per_principal),
            ));
        }
        let mut timers = self.timers.lock();
        if !timers.contains_key(key) && timers.len() >= self.max_timers {
            return Err(RpcError::exhausted(
                "schedule_timers",
                Some(self.max_timers),
            ));
        }
        timers.insert(key.to_owned(), timer);
        Ok(())
    }

    /// The timer stops and its last-tick state goes with it, so timer churn
    /// leaves nothing behind.
    async fn on_last_subscriber(&self, key: &str) {
        self.timers.lock().remove(key);
        if let Some(last) = self.last.lock().as_mut() {
            last.remove(key);
        }
        if let Err(error) = super::records::remove_record(&self.dir, &fired_file(key)) {
            tracing::warn!(%error, "events: schedule tick state not removed");
        }
    }
}

impl EventsHub {
    /// Offer `schedule.tick`, keeping timer state under `store_dir/schedule`,
    /// and start the one minute-boundary ticker.
    pub(crate) fn install_schedule_source(self: &Arc<Self>, store_dir: &Path) {
        let source = Arc::new(ScheduleSource::new(self, store_dir.join("schedule")));
        self.register_source(Arc::clone(&source) as Arc<dyn EventSource>);
        let ticker = Arc::downgrade(&source);
        tokio::spawn(async move {
            loop {
                let now = Utc::now();
                let next = now
                    .duration_trunc(crate::duration_bound::delta!(minutes, 1))
                    .unwrap_or(now)
                    + crate::duration_bound::delta!(minutes, 1);
                let wait = (next - now).to_std().unwrap_or_default();
                tokio::time::sleep(wait).await;
                let Some(source) = ticker.upgrade() else {
                    return;
                };
                // Off the runtime: a minute with many due timers syncs a file each.
                let joined = tokio::task::spawn_blocking(move || source.tick_at(Utc::now())).await;
                if let Err(error) = joined {
                    tracing::warn!(%error, "events: schedule tick task failed");
                }
            }
        });
    }
}

#[cfg(test)]
#[path = "schedule_source_tests.rs"]
mod tests;
