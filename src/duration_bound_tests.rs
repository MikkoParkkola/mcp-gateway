// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8207: every duration taken from input is bounded before it reaches
//! arithmetic that panics, and a token answer above the bound is refused.

use std::time::Duration;

use super::{MAX_DURATION, expiry_from_expires_in};
use crate::config::Config;

const MAX_SECS: u64 = MAX_DURATION.as_secs();

/// The config `text` loads as, before validation.
fn load(text: &str) -> crate::Result<Config> {
    Config::from_file_text(text)
}

#[test]
fn an_expires_in_above_the_bound_is_refused() {
    assert_eq!(expiry_from_expires_in(1_000, 3_600), Some(4_600));
    assert_eq!(
        expiry_from_expires_in(1_000, MAX_SECS),
        Some(1_000 + MAX_SECS)
    );
    assert_eq!(expiry_from_expires_in(1_000, MAX_SECS + 1), None);
    assert_eq!(expiry_from_expires_in(1_000, u64::MAX), None);
    assert_eq!(
        expiry_from_expires_in(u64::MAX, 1),
        None,
        "the sum overflows"
    );
}

#[test]
fn a_human_duration_above_the_bound_is_refused_at_load() {
    // Each of these wrapped, unchecked, to a few seconds or minutes.
    for value in ["5124095576030432h", "307445734561825861m", "3155760001s"] {
        let text = format!("cache:\n  default_ttl: {value}\n");
        assert!(load(&text).is_err(), "{value} must be refused");
    }
    let nested = "backends:\n  x:\n    command: echo\n    timeout: 307445734561825861m\n";
    assert!(
        load(nested).is_err(),
        "a backend's own timeout is bounded too"
    );
    for (value, want) in [
        ("100ms", Duration::from_millis(100)),
        ("5m", Duration::from_secs(300)),
        ("3155760000s", MAX_DURATION),
    ] {
        let text = format!("cache:\n  default_ttl: {value}\n");
        assert_eq!(load(&text).expect(value).cache.default_ttl, want);
    }
}

/// What is written must load again: a duration the parser would refuse is
/// never written (a dashboard edit, say, would leave an unloadable file).
#[test]
fn a_duration_above_the_bound_is_never_written() {
    let mut cache = Config::default().cache;
    cache.default_ttl = MAX_DURATION + Duration::from_secs(1);
    assert!(serde_yaml::to_string(&cache).is_err());
    cache.default_ttl = MAX_DURATION;
    let written = serde_yaml::to_string(&cache).expect("at the bound");
    assert!(written.contains("3155760000s"), "{written}");
}

#[test]
fn an_integer_duration_above_the_bound_is_refused_at_load() {
    let over = MAX_SECS + 1;
    #[cfg(feature = "firewall")]
    {
        let text =
            format!("security:\n  firewall:\n    tenant_guard:\n      window_secs: {over}\n");
        assert!(load(&text).is_err(), "{text}");
    }
    for text in [
        format!("auth:\n  dashboard_session:\n    idle_timeout_secs: {over}\n"),
        format!("key_server:\n  token_ttl_secs: {over}\n"),
        format!(
            "backends:\n  x:\n    command: echo\n    oauth:\n      token_refresh_buffer_secs: {over}\n"
        ),
        format!("tasks:\n  default_ttl_ms: {}\n", (MAX_SECS + 1) * 1_000),
    ] {
        assert!(load(&text).is_err(), "{text}");
    }
    let at_max = format!(
        "auth:\n  dashboard_session:\n    idle_timeout_secs: {MAX_SECS}\n    absolute_timeout_secs: {MAX_SECS}\n"
    );
    assert_eq!(
        load(&at_max)
            .expect("at the bound")
            .auth
            .dashboard_session
            .idle_timeout_secs,
        MAX_SECS
    );
    let forty_days = "tasks:\n  default_ttl_ms: 3456000000\n";
    assert_eq!(
        load(forty_days).expect("40 days").tasks.default_ttl_ms,
        3_456_000_000
    );
}

/// `config` fails validation, and the error names `key`.
fn refuses(config: &Config, key: &str) {
    let refused = config.validate().expect_err(key).to_string();
    assert!(refused.contains(key), "{refused}");
}

#[test]
fn a_zero_interval_is_refused() {
    let mut config = Config::default();
    config.key_server.cleanup_interval_secs = 0;
    config
        .validate()
        .expect("its timer never starts with the key server off");
    config.key_server.enabled = true;
    refuses(&config, "key_server.cleanup_interval_secs");
    let mut config = Config::default();
    config.streaming.session_reaper_interval = Duration::ZERO;
    refuses(&config, "streaming.session_reaper_interval");
    let mut config = Config::default();
    config.failsafe.health_check.interval = Duration::ZERO;
    config.failsafe.health_check.enabled = true;
    refuses(&config, "failsafe.health_check.interval");
    Config::default()
        .validate()
        .expect("the defaults stay valid");
}

#[test]
fn a_capability_duration_above_the_bound_is_refused() {
    let with = |extra: &str| {
        format!(
            "name: c\ndescription: d\nproviders:\n  primary:\n    service: rest\n{extra}    config:\n      base_url: https://api.example.com\n      path: /x\n"
        )
    };
    let parse = crate::capability::parse_capability;
    assert!(parse(&with(&format!("    timeout: {}\n", MAX_SECS + 1))).is_err());
    assert!(parse(&with("    timeout: 0\n")).is_err(), "a zero timeout");
    let cached = format!(
        "{}cache:\n  strategy: exact\n  ttl: {}\n",
        with(""),
        MAX_SECS + 1
    );
    assert!(parse(&cached).is_err(), "cache.ttl");
    parse(&with("    timeout: 60\n")).expect("a real timeout");
}

/// Every integer duration on a struct read from config, a capability or a
/// runtime profile (one that derives `Deserialize`) carries the load-time
/// bound. Names alone decide which
/// fields are durations, so a new `*_secs` field fails here until bounded.
#[test]
fn every_integer_duration_read_from_input_is_bounded() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let surfaces = [
        "config",
        "capability/definition",
        "security/firewall/tenant_guard.rs",
        "security/firewall/budget_guard.rs",
        "security/firewall/collusion_gate.rs",
        "security/audit_rotation_config.rs",
        "control_plane/export.rs",
        "personal_accounts/config.rs",
        "personal_accounts/config",
        "runtime/provider.rs",
        "runtime/descriptor.rs",
    ];
    let mut files = Vec::new();
    for surface in surfaces {
        collect_rs(&root.join(surface), &mut files);
    }
    let field = regex::Regex::new(
        r"^\s*(?:pub(?:\([a-z]+\))? )?([a-z_]*(?:_secs|_seconds|_ms|_millis)|timeout|ttl): (?:Option<)?(?:u64|u32|i64)\b",
    )
    .expect("pattern");
    let mut unbounded = Vec::new();
    for file in &files {
        if file.to_string_lossy().contains("test") {
            continue;
        }
        let text = std::fs::read_to_string(file).expect("read");
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            if !field.is_match(line) {
                continue;
            }
            // Only a struct read from input: one whose derive lists Deserialize.
            let derive = lines[..at]
                .iter()
                .rev()
                .find(|l| l.trim_start().starts_with("#[derive("));
            if !derive.is_some_and(|d| d.contains("Deserialize")) {
                continue;
            }
            // The field's attributes and docs: every line up to the previous
            // field or the struct's opening brace, so an attribute rustfmt
            // splits over several lines is read whole.
            let attributes = lines[..at].iter().rev().take_while(|l| {
                let l = l.trim();
                let previous_field = l.ends_with(',')
                    && l.contains(':')
                    && !l.contains('=')
                    && !l.starts_with('#')
                    && !l.starts_with("//");
                !(l.ends_with('{') || l == "}" || previous_field)
            });
            if !attributes
                .into_iter()
                .any(|l| l.contains("crate::duration_bound::"))
            {
                unbounded.push(format!("{}:{}: {}", file.display(), at + 1, line.trim()));
            }
        }
    }
    assert!(
        unbounded.is_empty(),
        "unbounded duration fields:\n{}",
        unbounded.join("\n")
    );
}

fn collect_rs(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    if path.is_file() {
        out.push(path.to_path_buf());
    } else if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() || path.extension().is_some_and(|e| e == "rs") {
                collect_rs(&path, out);
            }
        }
    }
}

/// MIK-8207: each `delta!` arm builds its own unit, the value its `try_*`
/// constructor gives.
#[test]
fn delta_builds_each_unit() {
    use chrono::TimeDelta;
    let one = |d: Option<TimeDelta>| d.expect("in range");
    assert_eq!(
        crate::duration_bound::delta!(weeks, 2),
        one(TimeDelta::try_weeks(2))
    );
    assert_eq!(
        crate::duration_bound::delta!(days, 3),
        one(TimeDelta::try_days(3))
    );
    assert_eq!(
        crate::duration_bound::delta!(hours, 4),
        one(TimeDelta::try_hours(4))
    );
    assert_eq!(
        crate::duration_bound::delta!(minutes, 5),
        one(TimeDelta::try_minutes(5))
    );
    assert_eq!(
        crate::duration_bound::delta!(seconds, 6),
        one(TimeDelta::try_seconds(6))
    );
    assert_eq!(
        crate::duration_bound::delta!(milliseconds, 7),
        one(TimeDelta::try_milliseconds(7))
    );
    assert_eq!(
        crate::duration_bound::delta!(seconds, -6),
        -one(TimeDelta::try_seconds(6))
    );
}
