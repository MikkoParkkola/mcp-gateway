// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a failed start writes to the log (split from
//! `package_cache_retry_tests.rs` for the file-size ceiling).

use super::*;

#[test]
fn a_failed_start_logs_the_classification_and_not_the_childs_text() {
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

    // `tracing` caches each callsite's interest process-wide, and the other
    // tests in this file reach this callsite with no subscriber installed.
    // An interested global default keeps the cached interest live so the
    // thread-local subscriber below decides each event instead.
    static INTEREST: std::sync::Once = std::sync::Once::new();
    INTEREST.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            Registry::default().with(tracing::level_filters::LevelFilter::TRACE),
        );
    });

    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), LEAKY_DYING_STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "always-fail", CACHE_SHAPED, &cache.root);
    let transport = transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        Some(&cache.root),
    );

    let events: Arc<std::sync::Mutex<Vec<HashMap<String, String>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = Registry::default().with(Collector(events.clone()));
    tracing::subscriber::with_default(subscriber, || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");
        let _ = runtime.block_on(start_with_repair(&transport));
    });

    let captured = events.lock().expect("collector lock");
    let every_field = captured
        .iter()
        .flat_map(|fields| fields.values())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    let classification = captured
        .iter()
        .find(|fields| {
            fields.get("message").map(String::as_str)
                == Some("start failed; reporting how the child ended, not what it printed")
        })
        .expect("a failed start names the classification of the child's output");
    assert_eq!(
        classification.get("needle").map(String::as_str),
        Some("MODULE_NOT_FOUND"),
        "the log says which needle the child's output matched: {classification:?}"
    );
    assert!(
        classification
            .get("exit_status")
            .is_some_and(|status| status.contains('3')),
        "and how the child ended, which is not text the child chose: {classification:?}"
    );
    // The sweep below only means something if the transport's own report of
    // the early exit was captured with it.
    assert!(
        captured.iter().any(|fields| fields
            .get("message")
            .is_some_and(|message| message.starts_with("stdio backend"))
            && fields.contains_key("class")),
        "the early-exit report reaches this collector: {every_field}"
    );
    assert!(
        !every_field.contains("ghp_SENTINELSENTINELSENTINELSENTINEL01"),
        "the child's stderr never reaches the log, at any level: {every_field}"
    );
    assert!(
        !every_field.contains("Authorization"),
        "nor any other part of it: {every_field}"
    );
    assert_eq!(
        spawns(&log).len(),
        2,
        "the classification is what drives the repair, not a substitute for it"
    );
}
