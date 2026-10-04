// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

fn def(method: &str, input: &serde_json::Value) -> CapabilityDefinition {
    named_def("create_webhook", method, input)
}

fn named_def(name: &str, method: &str, input: &serde_json::Value) -> CapabilityDefinition {
    // A read capability declares itself read-only, as the shipped ones do.
    // Leaving the flag at its default means "unknown", which is treated as
    // mutating: the safe direction for a rule about registering a
    // destination somebody else will deliver to.
    let read_only = method.eq_ignore_ascii_case("GET");
    let yaml = format!(
        "fulcrum: \"1.0\"\nname: {name}\ndescription: d\nschema:\n  input: {}\nproviders:\n  primary:\n    service: s\n    config:\n      endpoint: https://example.com/x\n      method: {method}\nauth:\n  required: false\n  type: none\nmetadata:\n  read_only: {read_only}\n",
        serde_json::to_string(input).unwrap()
    );
    serde_yaml::from_str(&yaml).expect("definition parses")
}

#[test]
fn the_shipped_capabilities_classify_as_expected() {
    // Run against the real files, not synthetic ones: the hand count that
    // justified deferring this was wrong, so the classifier has to be shown
    // against what actually ships.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    if !root.exists() {
        return;
    }
    let mut flagged = Vec::new();
    let mut walked = 0usize;
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "yaml") {
                walked += 1;
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                if let Ok(def) = serde_yaml::from_str::<CapabilityDefinition>(&text)
                    && creates_caller_addressed_external_state(&def)
                {
                    flagged.push(def.name);
                }
            }
        }
    }
    assert!(
        walked > 100,
        "expected the full capability set, walked {walked}"
    );
    flagged.sort();
    // Every shipped registration, not only the one that prompted this.
    // `gws_gmail_watch` registers a Pub/Sub topic: no "webhook" in the name
    // and no URL in the schema, and the first version missed it.
    for expected in ["linear_create_webhook", "gws_gmail_watch"] {
        assert!(
            flagged.contains(&expected.to_string()),
            "{expected} registers a delivery destination and must be caught: {flagged:?}"
        );
    }
    // Sending a URL as DATA is not registering a destination: nothing calls
    // back, and requiring a credential would take ordinary tools away.
    for ordinary in [
        "wayback_availability",
        "wayback_save",
        "linear_attach_url",
        "notion_create_page",
        // Named for a subscription, but its body returns a timestamp and
        // registers nothing. A name is a hint, never the evidence.
        "bus_subscribe",
    ] {
        assert!(
            !flagged.contains(&ordinary.to_string()),
            "{ordinary} posts a URL as data and must stay open: {flagged:?}"
        );
    }
}

#[test]
fn a_posted_caller_url_creates_external_state() {
    let d = def(
        "POST",
        &serde_json::json!({"properties": {"url": {"type": "string"}}}),
    );
    assert!(creates_caller_addressed_external_state(&d));
}

#[test]
fn a_read_of_a_caller_url_does_not() {
    // wayback_availability asks a third party ABOUT a URL. Nothing is
    // created and nothing calls back.
    let d = def(
        "GET",
        &serde_json::json!({"properties": {"url": {"type": "string"}}}),
    );
    assert!(!creates_caller_addressed_external_state(&d));
}

#[test]
fn posting_a_url_as_data_is_not_registering_an_address() {
    // wayback_save posts a URL to be archived. Nothing calls back, and
    // requiring admin would take an ordinary tool away from a single-user
    // client for no gain.
    let d = named_def(
        "wayback_save",
        "POST",
        &serde_json::json!({"properties": {"url": {"type": "string"}}}),
    );
    assert!(!creates_caller_addressed_external_state(&d));
}

#[test]
fn a_post_without_a_destination_does_not() {
    let d = def(
        "POST",
        &serde_json::json!({"properties": {"title": {"type": "string"}}}),
    );
    assert!(!creates_caller_addressed_external_state(&d));
}
#[test]
fn a_declared_registration_wins_over_the_name_heuristic() {
    // MIK-7262. `gws_gmail_watch` registers a Pub/Sub topic: the destination
    // is not a URL and the name carries no keyword, so inference alone
    // misses it. A capability author saying so must beat the heuristic, or
    // the declaration is decoration.
    let mut d = named_def(
        "notion_create_page",
        "POST",
        &serde_json::json!({"properties": {"title": {"type": "string"}}}),
    );
    assert!(
        !creates_caller_addressed_external_state(&d),
        "inference alone must not flag this, or the test proves nothing"
    );
    d.metadata.registers_external_callback = Some(true);
    assert!(creates_caller_addressed_external_state(&d));
}

#[test]
fn a_declared_non_registration_wins_over_the_name_heuristic() {
    // The other direction, and the one that costs a user a tool: a name and
    // a schema that both read as a webhook, on a capability whose author
    // says it registers nothing.
    let mut d = named_def(
        "linear_create_webhook",
        "POST",
        &serde_json::json!({"properties": {"url": {"type": "string"}}}),
    );
    assert!(
        creates_caller_addressed_external_state(&d),
        "inference alone must flag this, or the test proves nothing"
    );
    d.metadata.registers_external_callback = Some(false);
    assert!(!creates_caller_addressed_external_state(&d));
}

#[test]
fn a_declared_registration_survives_a_non_mutating_method() {
    // MIK-7262. The declaration used to be read AFTER the method inference
    // had already returned, so an author who said "this registers a
    // callback" on a GET-reached capability was silently overruled by the
    // heuristic the declaration exists to beat.
    let mut d = named_def(
        "gws_gmail_watch",
        "GET",
        &serde_json::json!({"properties": {"topic": {"type": "string"}}}),
    );
    d.metadata.read_only = false;
    d.metadata.registers_external_callback = Some(true);
    assert!(creates_caller_addressed_external_state(&d));
}

#[test]
fn a_declared_registration_survives_a_schema_without_properties() {
    // The second short-circuit: a definition whose input carries no
    // `properties` map bailed out before the declaration was read.
    let mut d = named_def("gws_gmail_watch", "POST", &serde_json::json!({}));
    d.metadata.registers_external_callback = Some(true);
    assert!(creates_caller_addressed_external_state(&d));
}

#[test]
fn read_only_still_beats_a_declared_registration() {
    // Precedence pin (design event, MIK-7262): `read_only` is ALSO an author
    // declaration, and the older one. Two explicit declarations in conflict
    // resolve to read-only, so the fix above cannot quietly reverse the
    // ruling recorded at the top of the function. Without this test the next
    // refactor re-hoists the callback check and nothing fails.
    let mut d = named_def(
        "linear_create_webhook",
        "POST",
        &serde_json::json!({"properties": {"url": {"type": "string"}}}),
    );
    d.metadata.read_only = true;
    d.metadata.registers_external_callback = Some(true);
    assert!(!creates_caller_addressed_external_state(&d));
}
