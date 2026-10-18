// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 PR-B T4 (the view table) and T5 (the `Registry` forwarders),
//! test plan v2 §5.

use std::sync::Arc;

use super::MetaMcp;
use super::scoped_backends::{Absence, Registry, ScopedBackends, Unscoped};
use super::visible::{record_absent, with_visibility_memo};
use crate::backend::{Backend, BackendRegistry};
use crate::gateway::authz::BackendGrant;

const CAP: &str = "cap";

fn backend(name: &str) -> Arc<Backend> {
    Arc::new(Backend::new(
        name,
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ))
}

/// Registry `{alpha, beta}`.
fn registry() -> Arc<BackendRegistry> {
    let registry = Arc::new(BackendRegistry::new());
    for name in ["alpha", "beta"] {
        assert!(registry.register(backend(name)), "fixture registration");
    }
    registry
}

/// The same registry under a `MetaMcp` whose capability provider is `cap`.
fn meta(registry: &Arc<BackendRegistry>) -> MetaMcp {
    let meta = MetaMcp::new(Arc::clone(registry));
    meta.set_capabilities(Arc::new(crate::capability::CapabilityBackend::new(
        CAP,
        Arc::new(crate::capability::CapabilityExecutor::new()),
    )));
    meta
}

/// The two ways a view is built; they must agree.
enum Builder<'a> {
    Registry(&'a Registry),
    Meta(&'a MetaMcp),
}

impl Builder<'_> {
    fn view<'v>(&'v self, grant: BackendGrant<'v>) -> ScopedBackends<'v> {
        match self {
            Self::Registry(registry) => registry.scoped(grant, Some(CAP.to_string())),
            Self::Meta(meta) => meta.scoped(grant),
        }
    }
}

/// T4's table: per grant and name, `(scoped_get is_some, absence,
/// absent_step, absent_step once Withheld(Absent) is recorded)`, each cell
/// in a request memo of its own.
async fn table(builder: &Builder<'_>) -> Vec<String> {
    let alpha_ghost = ["alpha".to_string(), "ghost".to_string()];
    let alpha_cap = ["alpha".to_string(), CAP.to_string()];
    let grants: [(&str, BackendGrant<'_>); 4] = [
        ("Scoped([alpha, ghost])", BackendGrant::Scoped(&alpha_ghost)),
        ("Scoped([alpha, cap])", BackendGrant::Scoped(&alpha_cap)),
        ("Empty", BackendGrant::Empty),
        ("Unscoped", BackendGrant::Unscoped),
    ];
    let mut rows = Vec::new();
    for (label, grant) in grants {
        for name in ["alpha", "beta", "ghost", "nosuch", CAP] {
            let cell: (bool, Option<Absence>, bool, bool) = with_visibility_memo(async {
                let view = builder.view(grant);
                let before = (
                    view.scoped_get(name).is_some(),
                    view.absence(name),
                    view.absent_step(name, "t"),
                );
                record_absent(name, "t");
                (before.0, before.1, before.2, view.absent_step(name, "t"))
            })
            .await;
            rows.push(format!("{label} {name}: {cell:?}"));
        }
    }
    rows
}

/// T4, the view table: every grant and name, pinned, built both through
/// `Registry::scoped(.., Some("cap"))` and through `MetaMcp::scoped`, which
/// must agree. Mutants: M31 (registration judged before scope: `nosuch`
/// under `Scoped([alpha, ghost])` turns `Unregistered`), M32 (`Empty` as
/// `Scoped([])`), M33 (`scoped_get` ignores the grant), M34
/// (`MetaMcp::scoped` passes no capability: `cap` turns `Unregistered`).
#[tokio::test]
async fn t4_the_view_table_is_pinned_and_both_builders_agree() {
    let inner = registry();
    let wrapped = Registry::new(Arc::clone(&inner));
    let meta = meta(&inner);
    let via_registry = table(&Builder::Registry(&wrapped)).await;
    let via_meta = table(&Builder::Meta(&meta)).await;
    assert_eq!(
        via_registry, via_meta,
        "T4: Registry::scoped and MetaMcp::scoped disagree"
    );
    let want = [
        "Scoped([alpha, ghost]) alpha: (true, None, false, true)",
        "Scoped([alpha, ghost]) beta: (false, Some(OutOfScope), true, true)",
        "Scoped([alpha, ghost]) ghost: (false, Some(Unregistered), true, true)",
        "Scoped([alpha, ghost]) nosuch: (false, Some(OutOfScope), true, true)",
        "Scoped([alpha, ghost]) cap: (false, Some(OutOfScope), true, true)",
        "Scoped([alpha, cap]) alpha: (true, None, false, true)",
        "Scoped([alpha, cap]) beta: (false, Some(OutOfScope), true, true)",
        "Scoped([alpha, cap]) ghost: (false, Some(OutOfScope), true, true)",
        "Scoped([alpha, cap]) nosuch: (false, Some(OutOfScope), true, true)",
        "Scoped([alpha, cap]) cap: (false, None, false, true)",
        "Empty alpha: (true, None, false, true)",
        "Empty beta: (true, None, false, true)",
        "Empty ghost: (false, None, false, true)",
        "Empty nosuch: (false, None, false, true)",
        "Empty cap: (false, None, false, true)",
        "Unscoped alpha: (true, None, false, true)",
        "Unscoped beta: (true, None, false, true)",
        "Unscoped ghost: (false, None, false, true)",
        "Unscoped nosuch: (false, None, false, true)",
        "Unscoped cap: (false, None, false, true)",
    ];
    assert_eq!(via_registry, want, "T4: the view table");
}

/// T5, the forwarders (COV.3): each `*_for` operation answers what the raw
/// registry answers, whatever its class. Mutants T5-m1..m6: each forwarder
/// replaced by an empty answer (`None`, an empty list or map, a constant
/// epoch, a receiver of a closed channel, a no-op nudge).
#[tokio::test]
async fn t5_every_registry_operation_forwards_for_every_class() {
    let inner = registry();
    let wrapped = Registry::new(Arc::clone(&inner));
    let raw = wrapped.for_test();
    let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
    raw.set_change_feed(feed);
    let mut started = wrapped.subscribe_started_for(Unscoped::Lifecycle);
    assert!(
        matches!(
            started.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ),
        "T5: subscribe_started_for is not on the registry's live feed"
    );
    for why in [
        Unscoped::Visibility,
        Unscoped::Discovery,
        Unscoped::Background,
        Unscoped::Admin,
        Unscoped::Lifecycle,
    ] {
        assert!(
            wrapped.get_for(why, "alpha").is_some(),
            "T5 {why:?}: get_for forwarded nothing"
        );
        assert!(
            wrapped.get_for(why, "nosuch").is_none(),
            "T5 {why:?}: get_for invented a backend"
        );
        let mut names: Vec<String> = wrapped
            .all_for(why)
            .iter()
            .map(|b| b.name.clone())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["alpha", "beta"],
            "T5 {why:?}: all_for forwarded nothing"
        );
        assert_eq!(
            wrapped.membership_for(why, |epoch| epoch),
            raw.with_membership(|epoch| epoch),
            "T5 {why:?}: membership_for forwarded nothing"
        );
        assert_eq!(
            wrapped.statuses_for(why).len(),
            2,
            "T5 {why:?}: statuses_for forwarded nothing"
        );
        wrapped.nudge_catalogue_for(why, "alpha");
        assert!(
            matches!(
                nudges.try_recv(),
                Ok(crate::backend::tools_nudge::ToolsNudge::Catalogue { name }) if name == "alpha"
            ),
            "T5 {why:?}: nudge_catalogue_for forwarded nothing"
        );
    }
}
