// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restores the daily cost totals a previous run saved.

/// Puts the daily totals a previous run saved back into `enforcer`, so a
/// restart does not reset a budget.
pub(super) fn restore_persisted_costs(
    enforcer: &crate::cost_accounting::enforcer::BudgetEnforcer,
    path: &std::path::Path,
) {
    super::persistence::load_if_exists(
        path,
        |path| {
            crate::cost_accounting::persistence::load(path)
                .map(|persisted| enforcer.restore(&persisted))
        },
        "Failed to load persisted cost data",
        "Loaded persisted cost data",
    );
}

#[cfg(test)]
mod tests {
    use super::restore_persisted_costs;
    use crate::cost_accounting::config::CostGovernanceConfig;
    use crate::cost_accounting::enforcer::BudgetEnforcer;
    use crate::cost_accounting::persistence as cost_persistence;
    use crate::cost_accounting::registry::CostRegistry;
    use crate::gateway::server::support::build_persisted_costs;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn enforcer() -> BudgetEnforcer {
        let cfg = CostGovernanceConfig {
            enabled: true,
            ..CostGovernanceConfig::default()
        };
        let registry = Arc::new(CostRegistry::new(&cfg));
        BudgetEnforcer::new(cfg, registry)
    }

    // Spend recorded for two keys, saved the way a graceful
    // shutdown saves it, reads back as the same global, per-tool and per-key
    // daily totals on the next start.
    #[test]
    fn the_saved_daily_totals_come_back_after_a_restart() {
        let dir = tempfile::tempdir().expect("state dir");
        let path = dir.path().join("costs.json");

        let before = enforcer();
        before.record_spend("search", Some("alice"), 0.30);
        before.record_spend("fetch", Some("bob"), 0.20);
        before.record_spend("search", Some("bob"), 0.05);
        cost_persistence::save(&path, &build_persisted_costs(&before.snapshot()))
            .expect("save costs");

        let after = enforcer();
        restore_persisted_costs(&after, &path);

        let (was, is) = (before.snapshot(), after.snapshot());
        assert!(
            (was.global_daily_usd - is.global_daily_usd).abs() < 1e-6,
            "{is:?}"
        );
        assert!(is.global_daily_usd > 0.0, "nothing was restored");
        for (tool, usd) in &was.tool_daily {
            assert!((usd - is.tool_daily[tool]).abs() < 1e-6, "{tool}: {is:?}");
        }
        for (key, usd) in &was.key_daily {
            assert!((usd - is.key_daily[key]).abs() < 1e-6, "{key}: {is:?}");
        }
    }

    // An unreadable costs.json does not stop the gateway; it
    // starts at zero, with one warning that says where the damaged data is.
    #[test]
    fn an_unreadable_costs_json_starts_at_zero_with_one_warning_naming_it() {
        use tracing::field::{Field, Visit};
        use tracing_subscriber::Registry;
        use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

        #[derive(Default)]
        struct Fields(HashMap<String, String>);

        impl Visit for Fields {
            fn record_str(&mut self, field: &Field, value: &str) {
                self.0.insert(field.name().to_string(), value.to_string());
            }

            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.0
                    .insert(field.name().to_string(), format!("{value:?}"));
            }
        }

        struct Collector(Arc<std::sync::Mutex<Vec<HashMap<String, String>>>>);

        impl<S: tracing::Subscriber> Layer<S> for Collector {
            fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                let mut fields = Fields::default();
                event.record(&mut fields);
                self.0.lock().expect("collector lock").push(fields.0);
            }
        }

        // `tracing` caches each callsite's interest process-wide; an interested
        // global default keeps it live for the thread-local subscriber below.
        static INTEREST: std::sync::Once = std::sync::Once::new();
        INTEREST.call_once(|| {
            let _ = tracing::subscriber::set_global_default(
                Registry::default().with(tracing::level_filters::LevelFilter::TRACE),
            );
        });

        let dir = tempfile::tempdir().expect("state dir");
        let path = dir.path().join("costs.json");
        std::fs::write(&path, "{ not json").expect("write damaged costs");

        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let after = enforcer();
        tracing::subscriber::with_default(
            Registry::default().with(Collector(events.clone())),
            || restore_persisted_costs(&after, &path),
        );

        let snap = after.snapshot();
        assert!(snap.global_daily_usd.abs() < 1e-9, "{snap:?}");
        let events = events.lock().expect("collector lock");
        let warnings: Vec<_> = events
            .iter()
            .filter(|fields| {
                fields
                    .get("message")
                    .is_some_and(|m| m.contains("Failed to load persisted cost data"))
            })
            .collect();
        assert_eq!(warnings.len(), 1, "one warning: {events:?}");
        assert_eq!(
            warnings[0].get("path").map(String::as_str),
            Some(path.display().to_string().as_str()),
            "the warning names where the damaged data is: {:?}",
            warnings[0]
        );
    }
}
