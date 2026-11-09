// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Policies read model's relay section: each action with its effect,
//! the lists and the gate's inferred classes, and the four live fields as
//! the file has them and as the gate enforces them across reloads.

use serde_json::{Value, json};

use super::policies_test_support::{FW, read_model, reloaded, setting, switch};
use crate::config::Config;

const RELAY: &str = "security.firewall.collusion";

fn relay_config(f: impl FnOnce(&mut crate::security::firewall::CollusionConfig)) -> Config {
    let mut config = Config::default();
    f(&mut config.security.firewall.collusion);
    config
}

fn flows(pairs: &[(&str, &str)]) -> Vec<crate::security::firewall::AllowedFlow> {
    pairs
        .iter()
        .map(|(s, e)| crate::security::firewall::AllowedFlow {
            source: (*s).to_owned(),
            egress: (*e).to_owned(),
        })
        .collect()
}

/// R7a: each action with what it does.
#[test]
fn r7a_each_relay_action_with_its_effect() {
    use crate::security::firewall::CollusionAction;
    for (action, name, effect) in [
        (CollusionAction::Off, "off", "checks_nothing"),
        (CollusionAction::Observe, "observe", "records_and_allows"),
        (
            CollusionAction::Block,
            "block",
            "refuses_relays_and_unkeyed_egress",
        ),
    ] {
        let model = read_model(&relay_config(|c| c.action = action));
        let relay = &model["relay"];
        assert_eq!(
            relay["action"],
            setting(&format!("{RELAY}.action"), json!(name), json!(name))
        );
        assert_eq!(relay["effect"], json!(effect), "{name}");
    }
}

/// R7b, R7e: the lists with their paths, the gate's own inferred classes,
/// read-only; the firewall precondition and the detector settings.
#[test]
fn r7b_the_relay_lists_classes_and_precondition() {
    let model = read_model(&relay_config(|c| {
        c.sources = vec!["crm:*".to_owned()];
        c.non_egress = vec!["notes:read_*".to_owned()];
        c.allowed_flows = flows(&[("docs:read", "mail:send_*")]);
    }));
    let relay = &model["relay"];
    let same = |name: &str, v: Value| setting(&format!("{RELAY}.{name}"), v.clone(), v);
    assert_eq!(relay["sources"], same("sources", json!(["crm:*"])));
    assert_eq!(
        relay["non_egress"],
        same("non_egress", json!(["notes:read_*"]))
    );
    assert_eq!(
        relay["allowed_flows"],
        same(
            "allowed_flows",
            json!([{ "source": "docs:read", "egress": "mail:send_*" }])
        )
    );
    assert_eq!(
        relay["inferred_classes"],
        json!(crate::security::firewall::SENSITIVE_CLASSES)
    );
    assert_eq!(relay["read_only"], json!(true));
    assert_eq!(
        relay["firewall"],
        switch(&format!("{FW}.enabled"), true, true)
    );
    assert_eq!(
        relay["detector"],
        json!([
            same("window_secs", json!(600)),
            same("min_matches", json!(2)),
            same("common_principals", json!(5)),
        ])
    );

    let mut config = Config::default();
    config.security.firewall.enabled = false;
    let model = read_model(&config);
    assert_eq!(
        model["relay"]["firewall"],
        switch(&format!("{FW}.enabled"), false, false)
    );
}

/// The relay's four live fields, each as `setting` with file and enforced.
fn relay_fields(model: &Value) -> [&Value; 4] {
    let r = &model["relay"];
    [
        &r["action"],
        &r["sources"],
        &r["non_egress"],
        &r["allowed_flows"],
    ]
}

/// A reload that sets every live relay field.
fn relay_edit(
    base: &Config,
    action: crate::security::firewall::CollusionAction,
    tag: &str,
) -> Config {
    let mut next = base.clone();
    let c = &mut next.security.firewall.collusion;
    c.action = action;
    c.sources = vec![format!("{tag}:src")];
    c.non_egress = vec![format!("{tag}:ne")];
    c.allowed_flows = flows(&[(&format!("{tag}:a"), &format!("{tag}:b"))]);
    next
}

/// The four live fields as a config with them would report, file = enforced.
fn applied_fields(action: &str, tag: &str) -> [Value; 4] {
    let same = |name: &str, v: Value| setting(&format!("{RELAY}.{name}"), v.clone(), v);
    [
        same("action", json!(action)),
        same("sources", json!([format!("{tag}:src")])),
        same("non_egress", json!([format!("{tag}:ne")])),
        same(
            "allowed_flows",
            json!([{ "source": format!("{tag}:a"), "egress": format!("{tag}:b") }]),
        ),
    ]
}

/// R7c: a reload of the four live fields alone applies at once.
#[test]
fn r7c_a_live_relay_edit_applies() {
    use crate::security::firewall::CollusionAction;
    let startup = Config::default();
    let next = relay_edit(&startup, CollusionAction::Observe, "one");
    let model = reloaded(&startup, &[&next]);
    let expected = applied_fields("observe", "one");
    assert_eq!(relay_fields(&model), expected.each_ref());
    assert_eq!(model["relay"]["effect"], json!("records_and_allows"));
}

/// R7d, R7d2: a reload that also changes a detector setting waits for a
/// restart, and the gate keeps the view applied last, which after a first
/// live edit is that edit's, not the startup config's.
#[test]
fn r7d_a_detector_change_keeps_the_applied_view() {
    use crate::security::firewall::CollusionAction;
    let startup = Config::default();
    let first = relay_edit(&startup, CollusionAction::Observe, "one");
    let mut second = relay_edit(&first, CollusionAction::Block, "two");
    second.security.firewall.collusion.window_secs = 900;
    let model = reloaded(&startup, &[&first, &second]);
    let file = applied_fields("block", "two");
    let enforced = applied_fields("observe", "one");
    for ((got, f), e) in relay_fields(&model).iter().zip(&file).zip(&enforced) {
        assert_eq!(got["file"], f["file"], "{got}");
        assert_eq!(got["enforced"], e["enforced"], "{got}");
        assert_eq!(got["pending_restart"], json!(true), "{got}");
    }
    assert_eq!(
        model["relay"]["effect"],
        json!("records_and_allows"),
        "the enforced action"
    );
    assert_eq!(
        model["relay"]["detector"][0],
        setting(&format!("{RELAY}.window_secs"), json!(900), json!(600))
    );
}

/// R7f: with the firewall off at startup no live relay edit applies.
#[test]
fn r7f_no_live_relay_edit_without_a_running_firewall() {
    let mut startup = Config::default();
    startup.security.firewall.enabled = false;
    let mut next = startup.clone();
    next.security.firewall.collusion.sources = vec!["late:*".to_owned()];
    let model = reloaded(&startup, &[&next]);
    assert_eq!(
        model["relay"]["sources"],
        setting(&format!("{RELAY}.sources"), json!(["late:*"]), json!([]))
    );
}

/// R7g: `off` loads lists the gate cannot compile (an invalid glob, more
/// than 64 flows); once applied they are not reported as waiting for a
/// restart, since the enforced view is what compiling them gives.
#[test]
fn r7g_uncompilable_entries_are_not_pending() {
    let startup = Config::default();
    let mut next = startup.clone();
    let c = &mut next.security.firewall.collusion;
    c.sources = vec!["[".to_owned(), "ok:*".to_owned()];
    c.non_egress = vec!["[".to_owned()];
    let many: Vec<(String, String)> = (0..65)
        .map(|i| (format!("s{i}"), format!("e{i}")))
        .collect();
    let pairs: Vec<(&str, &str)> = many.iter().map(|(s, e)| (s.as_str(), e.as_str())).collect();
    c.allowed_flows = flows(&pairs);
    let model = reloaded(&startup, &[&next]);
    let relay = &model["relay"];
    assert_eq!(relay["sources"]["file"], json!(["[", "ok:*"]));
    assert_eq!(relay["sources"]["enforced"], json!(["ok:*"]));
    assert_eq!(relay["non_egress"]["enforced"], json!([]));
    assert_eq!(
        relay["allowed_flows"]["file"].as_array().map(Vec::len),
        Some(65)
    );
    assert_eq!(
        relay["allowed_flows"]["enforced"].as_array().map(Vec::len),
        Some(64)
    );
    // The first 64, in order: entry 64 (`s64`) is the one dropped.
    assert_eq!(
        relay["allowed_flows"]["enforced"][0],
        json!({ "source": "s0", "egress": "e0" })
    );
    assert_eq!(
        relay["allowed_flows"]["enforced"][63],
        json!({ "source": "s63", "egress": "e63" })
    );
    for field in relay_fields(&model) {
        assert_eq!(field["pending_restart"], json!(false), "{field}");
    }
}

/// R7h: each detector setting, changed alone by a reload, waits for a
/// restart, and keeps the relay's live fields from applying.
#[test]
fn r7h_each_detector_setting_waits_for_a_restart() {
    for (i, field) in ["window_secs", "min_matches", "common_principals"]
        .into_iter()
        .enumerate()
    {
        let startup = Config::default();
        let mut next = startup.clone();
        let c = &mut next.security.firewall.collusion;
        let (file, enforced) = match field {
            "window_secs" => {
                c.window_secs = 900;
                (json!(900), json!(600))
            }
            "min_matches" => {
                c.min_matches = 3;
                (json!(3), json!(2))
            }
            _ => {
                c.common_principals = 4;
                (json!(4), json!(5))
            }
        };
        c.sources = vec!["late:*".to_owned()];
        let model = reloaded(&startup, &[&next]);
        assert_eq!(
            model["relay"]["detector"][i],
            setting(&format!("{RELAY}.{field}"), file, enforced),
            "{field}"
        );
        assert_eq!(model["relay"]["sources"]["enforced"], json!([]), "{field}");
        assert_eq!(
            model["relay"]["sources"]["pending_restart"],
            json!(true),
            "{field}"
        );
    }
}
