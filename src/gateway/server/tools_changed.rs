// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every change to the tool set discovery shows reaches `announce_tools_changed`
//! once (F24, `MIK-8127`).
//!
//! The HTTP server advertises `tools.listChanged: true`. Every path that can
//! change what discovery shows nudges one channel: a registry backend's
//! registration, removal and every list its shared slot stores, its warm-up
//! settling without a list, and the capability catalogue's reloads. A nudge is
//! not an announcement. This drain compares what discovery shows now with what
//! it last announced, and announces only a difference, so no path can be
//! forgotten, none announces twice, and an unchanged refill stays silent.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::backend::tools_nudge::{NudgeKind, SlotEvent, SlotView, ToolsNudge};
use crate::gateway::router::AppState;
use crate::protocol::Tool;

/// A stable digest of a tool list as clients see it: order-free, and every
/// field of every tool counts, so a schema or description change is a change.
pub(super) fn fingerprint(tools: &[Tool]) -> u64 {
    let mut rendered: Vec<String> = tools
        .iter()
        .map(|tool| serde_json::to_string(tool).unwrap_or_else(|_| tool.name.clone()))
        .collect();
    rendered.sort_unstable();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    rendered.hash(&mut hasher);
    hasher.finish()
}

/// What the drain can see of one backend name at the moment it looks.
pub(super) enum Seen {
    /// No registry backend holds this name.
    Unregistered,
    /// The registered instance, its stored list's fingerprint if any, and
    /// whether it ever stored one.
    Registered {
        instance: u64,
        stored: Option<u64>,
        populated: bool,
    },
}

/// Where an instance stands before its tools are known.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// No stored list yet, and its warm-up may still store one: not decided.
    Undecided,
    /// Settled without a list: it shows nothing.
    Resolved,
    /// It has stored a list; a missing one now means it shows nothing.
    Populated,
}

/// What each listener was last told. An absent backend entry means it was
/// told nothing is there.
#[derive(Default)]
pub(super) struct Announced {
    backends: HashMap<String, u64>,
    phases: HashMap<String, (u64, Phase)>,
    catalogues: HashMap<String, u64>,
    /// `MIK-8148`: each backend's per-user views.
    views: HashMap<String, views::Views>,
}

impl Announced {
    /// Whether listeners must hear about backend `name` after this nudge.
    pub(super) fn backend(
        &mut self,
        name: &str,
        instance: u64,
        kind: NudgeKind,
        seen: &Seen,
    ) -> bool {
        let empty = fingerprint(&[]);
        let visible = match *seen {
            Seen::Unregistered => {
                self.phases.remove(name);
                empty
            }
            Seen::Registered {
                instance: current,
                stored,
                populated,
            } => {
                // A replaced instance's late nudge: its successor's own follow.
                if current != instance {
                    return false;
                }
                let phase = self
                    .phases
                    .entry(name.to_string())
                    .or_insert((current, Phase::Undecided));
                if phase.0 != current {
                    *phase = (current, Phase::Undecided);
                }
                if stored.is_some() || populated {
                    phase.1 = Phase::Populated;
                } else if kind == NudgeKind::Resolved && phase.1 == Phase::Undecided {
                    phase.1 = Phase::Resolved;
                }
                match (stored, phase.1) {
                    (Some(stored), _) => stored,
                    (None, Phase::Undecided) => return false,
                    (None, _) => empty,
                }
            }
        };
        let before = self.backends.get(name).copied().unwrap_or(empty);
        if visible == before {
            return false;
        }
        if visible == empty {
            self.backends.remove(name);
        } else {
            self.backends.insert(name.to_string(), visible);
        }
        true
    }

    /// `MIK-8148`: whether backend `name`'s audience must hear that per-user
    /// slot `binding` changed after `event`, given what it holds now.
    pub(super) fn binding(
        &mut self,
        name: &str,
        instance: u64,
        binding: &str,
        event: SlotEvent,
        seen: views::SlotSeen,
    ) -> bool {
        let views = self
            .views
            .entry(name.to_string())
            .or_insert_with(|| views::Views::new(instance));
        let overflow = views.adopt(instance);
        let changed = match event {
            SlotEvent::Revoked => views.revoked(binding),
            SlotEvent::Idle | SlotEvent::Stored => views.slot(binding, seen),
        };
        overflow | changed
    }

    /// `MIK-8148`: after a backend-wide nudge, whether any per-user view of
    /// `name` changed. `present` is every per-user slot now, or `None` when
    /// the backend is gone, which changes every view that showed tools.
    pub(super) fn backend_views(
        &mut self,
        name: &str,
        instance: u64,
        present: Option<&PerUserNow>,
    ) -> bool {
        let Some(present) = present else {
            return self
                .views
                .remove(name)
                .is_some_and(|views| views.any_shown());
        };
        let views = self
            .views
            .entry(name.to_string())
            .or_insert_with(|| views::Views::new(instance));
        views.adopt(instance) | views.recompute(&present.slots, present.filter)
    }

    /// Whether listeners must hear about capability catalogue `name`, whose
    /// tools now have `visible` as their fingerprint. Before its first report
    /// listeners were shown nothing from it, so an empty first report (an
    /// empty startup scan) is no change.
    pub(super) fn catalogue(&mut self, name: &str, visible: u64) -> bool {
        let before = self.catalogues.insert(name.to_string(), visible);
        before.unwrap_or_else(|| fingerprint(&[])) != visible
    }
}

/// Decide and announce every nudge sent on `rx`, until the senders go or
/// `shutdown` fires. The registry inside `AppState` keeps a sender, so
/// without the shutdown branch the task and the state it holds outlive the
/// server (#2260).
pub(super) fn spawn_drain(
    state: Arc<AppState>,
    rx: tokio::sync::mpsc::UnboundedReceiver<ToolsNudge>,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    let announced = Arc::new(parking_lot::Mutex::new(Announced::default()));
    tokio::spawn(drain_until(rx, shutdown, move |nudge: ToolsNudge| {
        let (state, announced) = (Arc::clone(&state), Arc::clone(&announced));
        async move {
            let Some((name, reach)) = decide(&state, &announced, nudge) else {
                return;
            };
            match reach {
                Reach::Tools => state.announce_tools_changed(&name).await,
                Reach::View => state.announce_backend_view_changed(&name).await,
            }
        }
    }));
}

/// What nudge `nudge` means for listeners: the name to announce and who
/// hears it, or `None` when nothing they can see changed.
fn decide(
    state: &AppState,
    announced: &parking_lot::Mutex<Announced>,
    nudge: ToolsNudge,
) -> Option<(String, Reach)> {
    let decided = match nudge {
        ToolsNudge::Backend {
            name,
            instance,
            kind,
        } => {
            let backend = state.backends.get(&name);
            let seen = backend.as_ref().map_or(Seen::Unregistered, |b| {
                let (stored, populated) = b.stored_tools_snapshot();
                Seen::Registered {
                    instance: b.instance(),
                    stored: stored.map(|tools| fingerprint(&tools)),
                    populated,
                }
            });
            // Read before the lock: it walks the pool.
            // ponytail: fingerprints every per-user slot per backend
            // nudge; cache per-slot fingerprints if slots x stores bites.
            let present = backend
                .as_ref()
                .filter(|b| b.instance() == instance)
                .map(|b| per_user_seen(b));
            let mut told = announced.lock();
            let shared = told.backend(&name, instance, kind, &seen);
            let private = match (&backend, present) {
                (None, _) => told.backend_views(&name, instance, None),
                (Some(_), Some(present)) => told.backend_views(&name, instance, Some(&present)),
                (Some(_), None) => false,
            };
            drop(told);
            match (shared, private) {
                (true, _) => (name, Reach::Tools),
                (false, true) => (name, Reach::View),
                (false, false) => return None,
            }
        }
        ToolsNudge::Binding {
            name,
            instance,
            binding,
            event,
        } => {
            // A replaced instance's late nudge: its successor's own follow.
            let backend = state
                .backends
                .get(&name)
                .filter(|b| b.instance() == instance)?;
            backend.take_slot_nudge(&binding);
            let seen = slot_seen(backend.per_user_view(&binding));
            if !announced
                .lock()
                .binding(&name, instance, &binding, event, seen)
            {
                return None;
            }
            (name, Reach::View)
        }
        ToolsNudge::Catalogue { name } => {
            // A capability reload also refreshes webhook event routes,
            // whether or not its tools changed.
            state.meta_mcp.events_capabilities_reloaded(&name);
            let visible = state
                .meta_mcp
                .capability_tools(&name)
                .map_or_else(|| fingerprint(&[]), |tools| fingerprint(&tools));
            if !announced.lock().catalogue(&name, visible) {
                return None;
            }
            (name, Reach::Tools)
        }
    };
    Some(decided)
}

/// Who hears an announcement.
#[derive(Debug, PartialEq, Eq)]
enum Reach {
    /// Every listener of the backend, and the webhook hub: the shared tools changed.
    Tools,
    /// The backend's listeners only (`MIK-8148`): some per-user view changed.
    View,
}

fn slot_seen(view: SlotView) -> views::SlotSeen {
    match view {
        SlotView::Absent => views::SlotSeen::Absent,
        SlotView::Unfilled => views::SlotSeen::Unfilled,
        SlotView::Holds(tools) => views::SlotSeen::Holds(fingerprint(&tools)),
    }
}

/// Every per-user slot of one backend now, and its descriptor filter.
pub(super) struct PerUserNow {
    slots: Vec<(String, views::SlotSeen)>,
    filter: u64,
}

fn per_user_seen(backend: &crate::backend::Backend) -> PerUserNow {
    let slots = backend
        .per_user_bindings()
        .into_iter()
        .map(|binding| {
            let seen = slot_seen(backend.per_user_view(&binding));
            (binding, seen)
        })
        .collect();
    PerUserNow {
        slots,
        filter: backend.visibility_filter_fingerprint(),
    }
}

async fn drain_until<T, F, Fut>(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<T>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    mut announce: F,
) where
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            next = rx.recv() => match next {
                Some(nudge) => announce(nudge).await,
                None => break,
            },
        }
    }
}

mod views;

#[cfg(test)]
mod decision_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // MIK-8148: a per-user store is a VIEW change: the backend's listeners hear
    // it, the webhook hub does not (a shared-tools change would tell both).
    #[tokio::test]
    async fn a_per_user_store_is_announced_once_as_a_view_change() {
        let (state, _store) = crate::gateway::router::tests::direct_route_state_with_identity(
            crate::config::AgentIdentityConfig::default(),
        )
        .await;
        let backend = state.backends.get("demo").expect("fixture backend");
        let announced = parking_lot::Mutex::new(Announced::default());
        let user = "idp:1:u:1:a";
        let nudge = |instance: u64| ToolsNudge::Binding {
            name: "demo".into(),
            instance,
            binding: user.into(),
            event: SlotEvent::Stored,
        };
        let tool: Tool = serde_json::from_value(serde_json::json!({
            "name": "x", "description": "one", "inputSchema": { "type": "object" }
        }))
        .expect("tool");

        backend.store_per_user_tools_for_test(user, vec![tool.clone()]);
        assert_eq!(
            decide(&state, &announced, nudge(backend.instance())),
            Some(("demo".to_string(), Reach::View))
        );
        backend.store_per_user_tools_for_test(user, vec![tool]);
        assert_eq!(
            decide(&state, &announced, nudge(backend.instance())),
            None,
            "an identical refill"
        );
        assert_eq!(
            decide(&state, &announced, nudge(backend.instance() + 1_000)),
            None,
            "a replaced instance's late nudge"
        );
    }

    // MIK-8148: the view-change announcement reaches a `subscriptions/listen`
    // listener exactly once.
    #[tokio::test]
    async fn a_view_change_reaches_a_listener_once() {
        let (state, _store) = crate::gateway::router::tests::direct_route_state_with_identity(
            crate::config::AgentIdentityConfig::default(),
        )
        .await;
        let mut listener = state.subscriptions.subscribe().expect("a listener slot");
        state.announce_backend_view_changed("demo").await;
        let first = tokio::time::timeout(Duration::from_secs(5), listener.recv())
            .await
            .expect("delivered")
            .expect("open");
        assert_eq!(
            first.notification["method"],
            "notifications/tools/list_changed"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.recv())
                .await
                .is_err(),
            "exactly once"
        );
    }

    // #2260: the task must drop what it holds when shutdown fires, even though
    // a sender (the registry's) is still alive.
    #[tokio::test]
    async fn drain_releases_its_state_on_shutdown_while_a_sender_lives() {
        let state = Arc::new(());
        let weak = Arc::downgrade(&state);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (sd_tx, sd_rx) = tokio::sync::broadcast::channel(1);
        let held = Arc::clone(&state);
        let task = tokio::spawn(drain_until(rx, sd_rx, move |_| {
            let _keep = Arc::clone(&held);
            async {}
        }));
        drop(state);
        tx.send("a".into()).unwrap();
        assert!(weak.upgrade().is_some(), "state is held while running");
        sd_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("drain exits on shutdown")
            .unwrap();
        assert!(weak.upgrade().is_none(), "state dropped after shutdown");
        drop(tx);
    }

    // MIK-7659: the same, through `spawn_drain` with a real `AppState`, so the
    // wiring (the shutdown receiver passed on, the state captured only by the
    // task) is what is tested.
    #[tokio::test]
    async fn spawn_drain_releases_the_app_state_on_shutdown_while_a_sender_lives() {
        let (state, _store) = crate::gateway::router::tests::direct_route_state_with_identity(
            crate::config::AgentIdentityConfig::default(),
        )
        .await;
        assert_eq!(
            Arc::strong_count(&state),
            1,
            "premise: the drain is the only holder of the state"
        );
        let weak = Arc::downgrade(&state);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (sd_tx, sd_rx) = tokio::sync::broadcast::channel(1);
        spawn_drain(state, rx, sd_rx);
        tx.send(ToolsNudge::Catalogue {
            name: "demo".into(),
        })
        .unwrap();
        sd_tx.send(()).unwrap();
        let released = async {
            while weak.upgrade().is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), released)
            .await
            .expect("the drain released its AppState on shutdown");
        drop(tx);
    }
}
