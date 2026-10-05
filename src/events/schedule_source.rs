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

use std::collections::{HashMap, HashSet};
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

/// Canonical arguments: `(key, timer)`, or the refusal naming the offending
/// field. The key is the JCS of `[cron, timezone, label]` with whitespace in
/// `cron` collapsed, the zone's canonical IANA name and the defaults filled in.
fn canonical(arguments: &Value) -> Result<(String, Timer), RpcError> {
    let cron_text = arguments
        .get("cron")
        .and_then(Value::as_str)
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
    let cron =
        CronExpression::parse(&cron_text).map_err(|_| RpcError::invalid("arguments.cron"))?;
    if fires_too_often(&cron_text) {
        return Err(RpcError::invalid("arguments.cron"));
    }
    let key = String::from_utf8(
        serde_json_canonicalizer::to_vec(&json!([cron_text, zone.name(), label]))
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    Ok((key, Timer { cron, zone, label }))
}

/// Whether two ticks of `cron` can fall less than [`FLOOR_MINUTES`] apart.
/// Judged on the minute and hour fields over two days, as though every day
/// matched: a day restriction can only spread ticks out, so this refuses at
/// worst an expression whose day fields would have kept two ticks apart
/// across midnight.
fn fires_too_often(cron: &str) -> bool {
    let fields: Vec<&str> = cron.split_whitespace().collect();
    let Ok(daily) = CronExpression::parse(&format!("{} {} * * *", fields[0], fields[1])) else {
        return true;
    };
    let start = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .single()
        .unwrap_or_default();
    let mut previous: Option<i64> = None;
    for minute in 0..2 * 24 * 60 {
        if daily.matches(&(start + Duration::minutes(minute))) {
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
    let before = local(minute - Duration::minutes(1));
    // Wall-clock fields only: the naive local time read as if it were UTC.
    let matches = |naive: chrono::NaiveDateTime| timer.cron.matches(&Utc.from_utc_datetime(&naive));
    if now - before > Duration::minutes(1) {
        let mut skipped = before + Duration::minutes(1);
        while skipped <= now {
            if matches(skipped) {
                return true;
            }
            skipped += Duration::minutes(1);
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
        let minute = now.duration_trunc(Duration::minutes(1)).unwrap_or(now);
        let firing: Vec<(String, String)> = self
            .timers
            .lock()
            .iter()
            .filter(|(_, timer)| due(timer, minute))
            .map(|(key, timer)| (key.clone(), timer.label.clone()))
            .collect();
        let mut guard = self.last.lock();
        let last = guard.get_or_insert_with(|| Self::load(&self.dir));
        for (key, label) in firing {
            if last.get(&key).is_some_and(|at| *at >= minute) {
                continue;
            }
            last.insert(key.clone(), minute);
            // Written before the emit: a restart in this minute reads it back.
            let fired = Fired {
                v: 1,
                key: key.clone(),
                last: minute,
            };
            if let Err(error) = super::records::write_record(&self.dir, &fired_file(&key), &fired)
                .and_then(super::records::Placed::durable)
            {
                tracing::warn!(%error, "events: schedule tick not persisted; a restart this minute may repeat it");
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
            });
        }
    }

    /// Distinct timer keys `principal` holds in live subscriptions.
    fn held_by(&self, principal: &str) -> HashSet<String> {
        let Some(hub) = self.hub.upgrade() else {
            return HashSet::new();
        };
        let now = Utc::now();
        hub.store
            .subscriptions()
            .into_iter()
            .filter(|s| s.name == NAME && s.principal == principal && s.live(now))
            .filter_map(|s| canonical(&s.arguments).ok().map(|(key, ..)| key))
            .collect()
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
    /// the per-principal timer cap (counted on distinct timers, so a timer
    /// the principal already holds never counts against itself).
    async fn authorize(
        &self,
        principal: &str,
        _name: &str,
        arguments: &Value,
    ) -> Result<(), RpcError> {
        let (key, ..) = canonical(arguments)?;
        let mut held = self.held_by(principal);
        held.remove(&key);
        if held.len() >= self.max_per_principal {
            return Err(RpcError::exhausted(
                "schedule_timers_per_principal",
                Some(self.max_per_principal),
            ));
        }
        Ok(())
    }

    fn matches(&self, _principal: &str, arguments: &Value, event: &SourceEvent) -> bool {
        let Ok((key, ..)) = canonical(arguments) else {
            return false;
        };
        event
            .upstream_id
            .rsplit_once('|')
            .is_some_and(|(timer, _)| timer == key)
    }

    /// The timer key, so spellings of one timer share it.
    fn lifecycle_key(&self, _principal: &str, name: &str, arguments: &Value) -> String {
        canonical(arguments).map_or_else(
            |_| {
                String::from_utf8(
                    serde_json_canonicalizer::to_vec(&json!([name, arguments])).unwrap_or_default(),
                )
                .unwrap_or_default()
            },
            |(key, ..)| key,
        )
    }

    async fn on_first_subscriber(
        &self,
        key: &str,
        _principal: &str,
        _name: &str,
        arguments: &Value,
    ) -> Result<(), RpcError> {
        let (_, timer) = canonical(arguments)?;
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

    async fn on_last_subscriber(&self, key: &str) {
        self.timers.lock().remove(key);
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
                let next =
                    now.duration_trunc(Duration::minutes(1)).unwrap_or(now) + Duration::minutes(1);
                let wait = (next - now).to_std().unwrap_or_default();
                tokio::time::sleep(wait).await;
                let Some(source) = ticker.upgrade() else {
                    return;
                };
                // Off the runtime: a minute with many due timers syncs a file each.
                let ticked = tokio::task::spawn_blocking(move || source.tick_at(Utc::now())).await;
                if let Err(error) = ticked {
                    tracing::warn!(%error, "events: schedule tick task failed");
                }
            }
        });
    }
}

#[cfg(test)]
#[path = "schedule_source_tests.rs"]
mod tests;
