// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The error-budget section, duration serialization and debug redaction.

use super::*;

// ── GH #475 — error_budget section ─────────────────────────────────────────────

/// Load YAML through the production loader (figment + validation), not
/// `serde_yaml::from_str`: `deny_unknown_fields` and `validate_with_env` only
/// interact on the real path.
fn gh475_load(yaml: &str) -> Result<Config> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, yaml).expect("write config");
    Config::load(Some(&path))
}

fn gh475_reject(yaml: &str, field: &str) {
    let err = gh475_load(yaml).expect_err("must be rejected");
    let text = err.to_string();
    assert!(
        text.contains(field),
        "rejection must name {field}, got: {text}"
    );
}

/// GH475.CFG.1 — the documented block parses into the expected struct.
#[test]
fn gh475_cfg_1_documented_yaml_parses() {
    let cfg = gh475_load(
        "error_budget:\n  threshold: 0.5\n  window_size: 200\n  window_duration: 10m\n  \
         min_samples: 20\n  capability:\n    threshold: 0.6\n    window_size: 25\n    \
         window_duration: 2m\n    min_samples: 3\n    cooldown: 90s\n",
    )
    .expect("documented block must load");

    let backend = cfg.error_budget.backend_config();
    assert!((backend.threshold - 0.5).abs() < f64::EPSILON);
    assert_eq!(backend.window_size, 200);
    assert_eq!(backend.window_duration, std::time::Duration::from_secs(600));
    assert_eq!(backend.min_samples, 20);

    let capability = cfg.error_budget.capability_config();
    assert!((capability.threshold - 0.6).abs() < f64::EPSILON);
    assert_eq!(capability.window_size, 25);
    assert_eq!(
        capability.window_duration,
        std::time::Duration::from_secs(120)
    );
    assert_eq!(capability.min_samples, 3);
    assert_eq!(capability.cooldown, std::time::Duration::from_secs(90));
}

/// GH475.CFG.2 — one backend key overrides only itself.
#[test]
fn gh475_cfg_2_threshold_only_keeps_other_backend_defaults() {
    let cfg = gh475_load("error_budget:\n  threshold: 0.5\n").expect("partial section must load");
    let got = cfg.error_budget.backend_config();
    let base = crate::kill_switch::budget::ErrorBudgetConfig::default();

    assert!((got.threshold - 0.5).abs() < f64::EPSILON);
    assert_eq!(got.window_size, base.window_size);
    assert_eq!(got.window_duration, base.window_duration);
    assert_eq!(got.min_samples, base.min_samples);
}

/// GH475.CFG.3 — one capability key overrides only itself.
#[test]
fn gh475_cfg_3_capability_min_samples_only_keeps_other_defaults() {
    let cfg = gh475_load("error_budget:\n  capability:\n    min_samples: 2\n")
        .expect("nested partial section must load");
    let got = cfg.error_budget.capability_config();
    let base = crate::kill_switch::budget::CapabilityErrorBudgetConfig::default();

    assert_eq!(got.min_samples, 2);
    assert!((got.threshold - base.threshold).abs() < f64::EPSILON);
    assert_eq!(got.window_size, base.window_size);
    assert_eq!(got.window_duration, base.window_duration);
    assert_eq!(got.cooldown, base.cooldown);
    // The backend half must not move when only the capability half was written.
    assert_eq!(
        cfg.error_budget.backend_config().min_samples,
        crate::kill_switch::budget::ErrorBudgetConfig::default().min_samples
    );
}

/// GH475.CFG.4 — an absent section is today's behaviour, value for value.
#[test]
fn gh475_cfg_4_absent_section_matches_todays_defaults() {
    let cfg = gh475_load("server:\n  host: 127.0.0.1\n").expect("config without the section loads");
    let backend = cfg.error_budget.backend_config();
    let base = crate::kill_switch::budget::ErrorBudgetConfig::default();
    assert!((backend.threshold - base.threshold).abs() < f64::EPSILON);
    assert_eq!(backend.window_size, base.window_size);
    assert_eq!(backend.window_duration, base.window_duration);
    assert_eq!(backend.min_samples, base.min_samples);

    let capability = cfg.error_budget.capability_config();
    let cap_base = crate::kill_switch::budget::CapabilityErrorBudgetConfig::default();
    assert!((capability.threshold - cap_base.threshold).abs() < f64::EPSILON);
    assert_eq!(capability.window_size, cap_base.window_size);
    assert_eq!(capability.window_duration, cap_base.window_duration);
    assert_eq!(capability.min_samples, cap_base.min_samples);
    assert_eq!(capability.cooldown, cap_base.cooldown);
}

/// GH475.CFG.7 — the block shipped in `examples/gateway-full.yaml` loads.
#[test]
fn gh475_cfg_7_shipped_example_block_parses() {
    let example = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/gateway-full.yaml"),
    )
    .expect("read shipped example");
    assert!(
        example.contains("\nerror_budget:"),
        "the example config must document the error_budget section"
    );
    // The example file as a whole documents optional sections that do not load
    // standalone (`backends:` is a commented-out placeholder), so lift the block
    // this AC is about and load exactly that.
    let block: String = example
        .split("\nerror_budget:")
        .nth(1)
        .map(|rest| {
            let body: String = rest
                .lines()
                .take_while(|l| l.starts_with(char::is_whitespace) || l.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            format!("error_budget:{body}\n")
        })
        .expect("the example must carry an error_budget block");

    let cfg = gh475_load(&block).expect("shipped example block must load");
    // A commented-out block would parse and prove nothing; assert the values
    // actually reached the struct.
    assert!(
        cfg.error_budget != ErrorBudgetSection::default(),
        "the shipped block must be uncommented, not decorative"
    );
}

/// GH475.VAL.1 — a threshold outside (0.0, 1.0] is refused, field named.
#[test]
fn gh475_val_1_threshold_out_of_range_rejected() {
    for value in ["1.5", "0.0", "-1.0"] {
        gh475_reject(
            &format!("error_budget:\n  threshold: {value}\n"),
            "error_budget.threshold",
        );
    }
}

/// GH475.VAL.2 — `.nan` is refused rather than accepted-and-inert.
#[test]
fn gh475_val_2_nan_threshold_rejected() {
    gh475_reject(
        "error_budget:\n  threshold: .nan\n",
        "error_budget.threshold",
    );
}

/// GH475.VAL.3 — a window or sample floor of zero is refused.
#[test]
fn gh475_val_3_sub_one_sizes_rejected() {
    gh475_reject(
        "error_budget:\n  window_size: 0\n",
        "error_budget.window_size",
    );
    gh475_reject(
        "error_budget:\n  min_samples: 0\n",
        "error_budget.min_samples",
    );
}

/// GH475.VAL.4 — a floor above the window can never be reached.
#[test]
fn gh475_val_4_min_samples_above_window_size_rejected() {
    gh475_reject(
        "error_budget:\n  window_size: 10\n  min_samples: 11\n",
        "error_budget.min_samples",
    );
    // Asymmetric across the two levels: 60 is fine against the backend default
    // window of 100 and impossible against the capability default of 50.
    gh475_reject(
        "error_budget:\n  capability:\n    min_samples: 60\n",
        "error_budget.capability.min_samples",
    );
}

/// GH475.VAL.5 — a zero-length window never holds a sample.
#[test]
fn gh475_val_5_zero_duration_rejected() {
    gh475_reject(
        "error_budget:\n  window_duration: 0s\n",
        "error_budget.window_duration",
    );
}

/// GH475.VAL.6 — an absurd window is refused rather than allocated.
#[test]
fn gh475_val_6_window_size_above_upper_bound_rejected() {
    gh475_reject(
        "error_budget:\n  window_size: 100001\n",
        "error_budget.window_size",
    );
}

/// GH475.VAL.7 — every backend rejection repeats one level down.
#[test]
fn gh475_val_7_capability_repeats_every_rejection() {
    let cases = [
        ("threshold: 1.5", "error_budget.capability.threshold"),
        ("threshold: 0.0", "error_budget.capability.threshold"),
        ("threshold: .nan", "error_budget.capability.threshold"),
        ("window_size: 0", "error_budget.capability.window_size"),
        ("window_size: 100001", "error_budget.capability.window_size"),
        ("min_samples: 0", "error_budget.capability.min_samples"),
        (
            "window_duration: 0s",
            "error_budget.capability.window_duration",
        ),
        ("cooldown: 0s", "error_budget.capability.cooldown"),
    ];
    for (line, field) in cases {
        gh475_reject(
            &format!("error_budget:\n  capability:\n    {line}\n"),
            field,
        );
    }
}

/// GH475.VAL.8 — the accepted side of every boundary still loads.
#[test]
fn gh475_val_8_accepted_boundary_values_parse() {
    let cfg = gh475_load(
        "error_budget:\n  threshold: 1.0\n  window_size: 1\n  min_samples: 1\n  \
         window_duration: 1s\n  capability:\n    window_size: 100000\n    min_samples: 100000\n    \
         cooldown: 1s\n",
    )
    .expect("boundary values must be accepted");

    assert!((cfg.error_budget.backend_config().threshold - 1.0).abs() < f64::EPSILON);
    assert_eq!(cfg.error_budget.backend_config().window_size, 1);
    assert_eq!(cfg.error_budget.capability_config().window_size, 100_000);
    assert_eq!(cfg.error_budget.capability_config().min_samples, 100_000);
}

/// An unknown key under `capability:` is a typo, not a silent no-op.
#[test]
fn gh475_unknown_capability_key_rejected() {
    let err = gh475_load("error_budget:\n  capability:\n    treshold: 0.5\n")
        .expect_err("a typo must not pass silently");
    assert!(
        err.to_string().contains("treshold"),
        "rejection must name the unknown key, got: {err}"
    );
}

#[test]
fn duration_serialize_preserves_25ms_config_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  owned:\n    command: \"echo hi\"\n    stop_when_idle_for: 25ms\n",
    )
    .expect("write");
    let cfg = Config::load(Some(&path)).expect("load 25ms");
    let yaml = serde_yaml::to_string(&cfg).expect("serialize");
    assert!(
        yaml.contains("25ms"),
        "as_secs truncation would emit 0s; got {yaml}"
    );
    assert!(
        !yaml.contains("stop_when_idle_for: 0s"),
        "original serializer maps 25ms to 0s; got {yaml}"
    );
    write_owner_only(&path, &yaml).expect("rewrite");
    let again = Config::load(Some(&path)).expect("reload");
    std::assert_eq!(
        again
            .backends
            .get("owned")
            .expect("backend")
            .stop_when_idle_for,
        Some(std::time::Duration::from_millis(25))
    );
}

#[test]
fn duration_serialize_preserves_1250ms_config_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  owned:\n    command: \"echo hi\"\n    stop_when_idle_for: 1250ms\n",
    )
    .expect("write");
    let cfg = Config::load(Some(&path)).expect("load 1250ms");
    let yaml = serde_yaml::to_string(&cfg).expect("serialize");
    assert!(
        yaml.contains("1250ms"),
        "as_secs truncation would emit 1s; got {yaml}"
    );
    assert!(
        !yaml.contains("stop_when_idle_for: 1s"),
        "original serializer maps 1250ms to 1s; got {yaml}"
    );
    write_owner_only(&path, &yaml).expect("rewrite");
    let again = Config::load(Some(&path)).expect("reload");
    std::assert_eq!(
        again
            .backends
            .get("owned")
            .expect("backend")
            .stop_when_idle_for,
        Some(std::time::Duration::from_millis(1250))
    );
}

#[test]
fn duration_serialize_keeps_whole_seconds_as_seconds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  owned:\n    command: \"echo hi\"\n    stop_when_idle_for: 30s\n",
    )
    .expect("write");
    let cfg = Config::load(Some(&path)).expect("load 30s");
    let yaml = serde_yaml::to_string(&cfg).expect("serialize");
    assert!(
        yaml.contains("30s"),
        "whole seconds must stay NNs; got {yaml}"
    );
    assert!(
        !yaml.contains("30000ms"),
        "must not expand whole seconds to ms; got {yaml}"
    );
    write_owner_only(&path, &yaml).expect("rewrite");
    let again = Config::load(Some(&path)).expect("reload");
    std::assert_eq!(
        again
            .backends
            .get("owned")
            .expect("backend")
            .stop_when_idle_for,
        Some(std::time::Duration::from_secs(30))
    );
}

#[test]
fn duration_serialize_zero_and_max_whole_seconds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  owned:\n    command: \"echo hi\"\n    stop_when_idle_for: 0s\n",
    )
    .expect("write");
    let mut cfg = Config::load(Some(&path)).expect("load 0s");
    let yaml = serde_yaml::to_string(&cfg).expect("serialize 0s");
    assert!(
        yaml.contains("0s"),
        "zero whole seconds encode as 0s; got {yaml}"
    );
    cfg.backends
        .get_mut("owned")
        .expect("backend")
        .stop_when_idle_for = Some(crate::duration_bound::MAX_DURATION);
    let yaml = serde_yaml::to_string(&cfg).expect("serialize the longest duration");
    assert!(
        yaml.contains("3155760000s"),
        "the longest duration stays whole seconds; got {yaml}"
    );
    // MIK-8207: one second more would not load again, so it is not written.
    cfg.backends
        .get_mut("owned")
        .expect("backend")
        .stop_when_idle_for =
        Some(crate::duration_bound::MAX_DURATION + std::time::Duration::from_secs(1));
    assert!(serde_yaml::to_string(&cfg).is_err());
}

#[test]
fn duration_serialize_rejects_sub_ms_and_over_u64_millis() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  owned:\n    command: \"echo hi\"\n    stop_when_idle_for: 1s\n",
    )
    .expect("write");
    let mut cfg = Config::load(Some(&path)).expect("load");
    cfg.backends
        .get_mut("owned")
        .expect("backend")
        .stop_when_idle_for = Some(std::time::Duration::from_nanos(500));
    assert!(
        serde_yaml::to_string(&cfg).is_err(),
        "sub-millisecond precision must be a serde error"
    );
    cfg.backends
        .get_mut("owned")
        .expect("backend")
        .stop_when_idle_for = Some(
        std::time::Duration::from_secs(u64::MAX)
            .checked_add(std::time::Duration::from_millis(1))
            .expect("Duration can hold max secs + 1ms"),
    );
    assert!(
        serde_yaml::to_string(&cfg).is_err(),
        "a duration no load accepts must be a serde error"
    );
}

/// CWE-532: `ServerConfig`'s `Debug` must not print the `/metrics` scrape token.
#[test]
fn server_config_debug_redacts_metrics_token() {
    const SENTINEL: &str = "scrape-token-sentinel-c7";
    let cfg = ServerConfig {
        metrics_token: Some(SENTINEL.to_string()),
        ..ServerConfig::default()
    };
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains(SENTINEL), "leaked metrics_token: {dbg}");
    assert!(
        dbg.contains("<redacted>"),
        "missing redaction marker: {dbg}"
    );
}
