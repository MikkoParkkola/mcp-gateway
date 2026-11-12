// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The secret check a deferred task's query runs before its poll and on its
//! terminal answer: only a stored fingerprint equal to what the backend's
//! rules resolve to now lets the query on, and nothing else does.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::{WITHHELD, withheld};
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::task_service::{UpstreamAnswer, UpstreamHandle};
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget};
use crate::secrets::SecretResolver;
use crate::security::dispatched::{Dispatched, MISSING};

const VALUE: &str = "check-side-secret-5c21";
/// A rule value naming a variable no test sets: it cannot resolve.
const UNSET: &str = "{env.ECHO_CHECK_NEVER_SET_5c21}";

fn rule(value: &str) -> CredentialRule {
    CredentialRule {
        name: "api".to_owned(),
        credential_type: CredentialType::ApiKey,
        value: value.to_owned(),
        inject_as: InjectTarget::Header,
        inject_key: "X-Api-Key".to_owned(),
        tools: vec!["*".to_owned()],
    }
}

fn backend(rules: Vec<CredentialRule>) -> Backend {
    let backend = Backend::new(
        "svc",
        BackendConfig {
            secrets: rules,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    backend.stamp_secret_resolver(Arc::new(SecretResolver::new()));
    backend
}

fn handle(fingerprint: Option<String>) -> UpstreamHandle {
    UpstreamHandle {
        backend: "svc".to_owned(),
        handle: "peer-task-1".to_owned(),
        tool: "read".to_owned(),
        arguments: json!({}),
        fingerprint,
    }
}

/// What `VALUE` under `rule` fingerprints to at a dispatch.
fn dispatched() -> String {
    Dispatched::of("svc", &[("api".to_owned(), VALUE.to_owned())]).stored()
}

fn assert_withheld(answer: Option<UpstreamAnswer>, why: &str) {
    match answer {
        Some(UpstreamAnswer::Substituted(error)) => assert_eq!(error.message, WITHHELD, "{why}"),
        Some(_) => panic!("{why}: another answer than the withheld one"),
        None => panic!("{why}: the query was let on"),
    }
}

#[test]
fn an_unchanged_secret_or_no_rules_lets_the_query_on() {
    assert!(withheld(&backend(vec![rule(VALUE)]), &handle(Some(dispatched()))).is_none());
    assert!(withheld(&backend(Vec::new()), &handle(Some("none".to_owned()))).is_none());
}

#[test]
fn every_other_stored_state_is_withheld() {
    let rules = || backend(vec![rule(VALUE)]);
    assert_withheld(withheld(&rules(), &handle(None)), "a legacy row");
    assert_withheld(
        withheld(&rules(), &handle(Some(MISSING.to_owned()))),
        "a missing marker",
    );
    assert_withheld(
        withheld(&rules(), &handle(Some("none".to_owned()))),
        "rules added after a none dispatch",
    );
    assert_withheld(
        withheld(
            &backend(vec![rule("rotated-secret-5c21")]),
            &handle(Some(dispatched())),
        ),
        "a rotated value",
    );
    assert_withheld(
        withheld(&backend(Vec::new()), &handle(Some(dispatched()))),
        "rules removed",
    );
    assert_withheld(
        withheld(&backend(Vec::new()), &handle(None)),
        "a legacy row on a backend with no rules",
    );
}

/// A rule that cannot resolve at the check withholds whatever was stored:
/// neither the fingerprint nor the renewal can be taken.
#[test]
fn a_rule_that_cannot_resolve_at_the_check_is_withheld() {
    for stored in [
        Some(dispatched()),
        Some("none".to_owned()),
        Some(MISSING.to_owned()),
    ] {
        assert_withheld(
            withheld(&backend(vec![rule(UNSET)]), &handle(stored.clone())),
            &format!("stored {stored:?}"),
        );
    }
}

/// Two rules writing the same argument: the call sends only the later one,
/// but the check renews every resolved value, so a value overwritten in
/// this order and sent in another (the rules reordered since the dispatch,
/// which leaves the fingerprint as it was) is still redacted.
#[test]
fn a_matched_check_renews_every_resolved_value_not_only_the_one_sent() {
    use crate::security::needles::{NeedleSet, scrub_text};
    const FIRST: &str = "overwritten-secret-3a19";
    const SECOND: &str = "winning-secret-3a19";
    let mut first = rule(FIRST);
    first.inject_as = InjectTarget::Argument;
    first.inject_key = "api_key".to_owned();
    let mut second = first.clone();
    second.name = "api2".to_owned();
    second.value = SECOND.to_owned();
    let backend = backend(vec![first, second]);
    let needles = Arc::new(NeedleSet::default());
    backend.stamp_needles(Arc::clone(&needles));
    let stored = Dispatched::of(
        "svc",
        &[
            ("api".to_owned(), FIRST.to_owned()),
            ("api2".to_owned(), SECOND.to_owned()),
        ],
    )
    .stored();
    assert!(
        withheld(&backend, &handle(Some(stored))).is_none(),
        "premise: it matches"
    );
    for value in [FIRST, SECOND] {
        let mut text = format!("echo {value}");
        scrub_text(&needles, &mut text);
        assert!(!text.contains(value), "{value} was not renewed: {text}");
    }
}

/// One check resolves the backend's rules once: the fingerprint it compares
/// and the values it renews are the same resolution, so a rotation between
/// two lookups cannot match one value and renew another.
#[test]
fn a_check_resolves_the_rules_once() {
    let backend = backend(vec![rule(VALUE)]);
    let before = crate::secrets::lookup_probe::calls();
    assert!(withheld(&backend, &handle(Some(dispatched()))).is_none());
    assert_eq!(crate::secrets::lookup_probe::calls() - before, 1);
}
