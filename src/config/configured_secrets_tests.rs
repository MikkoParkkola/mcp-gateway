// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which configured `headers:` and `env:` values load records as secret,
//! and how sure it is, for each way a value can be written.

use std::collections::HashMap;
use std::path::PathBuf;

use super::{ConfiguredByBackend, ConfiguredSecret, SecretOrigin};
use crate::config::{BackendConfig, EnvOverlay, secret_ref::evaluate_backends};

/// Long enough that no length gate applies.
const TOKEN: &str = "tok-0c9b4e7a21f35d68";

/// What load records for one backend whose `headers:` and `env:` are the
/// given written values, with `env_body` as its env file.
/// One recorded entry: field, value and how sure load is.
type Row = (String, String, SecretOrigin);

/// Written `(key, value)` pairs.
type Pairs<'a> = &'a [(&'a str, &'a str)];

fn recorded(headers: Pairs<'_>, env: Pairs<'_>, env_body: &str) -> Vec<Row> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.env");
    crate::gateway::test_helpers::write_owner_only(&path, env_body).expect("write the env file");
    let overlay = EnvOverlay::from_paths(&[PathBuf::from(&path)]);
    let to_map = |pairs: &[(&str, &str)]| {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<HashMap<_, _>>()
    };
    let mut backends = HashMap::from([(
        "b".to_owned(),
        BackendConfig {
            headers: to_map(headers),
            env: to_map(env),
            ..BackendConfig::default()
        },
    )]);
    let mut unresolved = Vec::new();
    let mut configured = ConfiguredByBackend::new();
    evaluate_backends(&mut backends, &overlay, &mut unresolved, &mut configured);
    assert!(
        unresolved.is_empty(),
        "premise: everything resolves: {unresolved:?}"
    );
    let mut out: Vec<_> = configured["b"]
        .iter()
        .map(
            |ConfiguredSecret {
                 field,
                 value,
                 origin,
             }| (field.clone(), value.clone(), *origin),
        )
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    out
}

fn row(field: &str, value: &str, origin: SecretOrigin) -> Row {
    (field.to_owned(), value.to_owned(), origin)
}

/// Decision 2, row by row: an explicit reference counts at any length, a
/// header's substituted variable is explicit, an env value written as
/// nothing but `${VAR}` references is inferred, and a mixed template, a used
/// default or a literal is never recorded.
#[test]
fn each_written_form_is_recorded_as_the_ruling_says() {
    let env_body = format!("T={TOKEN}\nONE=1\nA=first-part-77\nB=second-part-88\nH=/home/u\n");
    let explicit = SecretOrigin::Explicit;
    let inferred = SecretOrigin::Inferred;
    let cases: [(&str, Pairs<'_>, Pairs<'_>, Vec<Row>); 9] = [
        (
            "env: reference in env",
            &[],
            &[("K", "env:T")],
            vec![row("env.K", TOKEN, explicit)],
        ),
        (
            "a 1-byte env: reference is explicit",
            &[],
            &[("K", "env:ONE")],
            vec![row("env.K", "1", explicit)],
        ),
        (
            "env: reference in a header",
            &[("Authorization", "env:T")],
            &[],
            vec![row("headers.Authorization", TOKEN, explicit)],
        ),
        (
            "a substituted header variable",
            &[("Authorization", "Bearer ${T}")],
            &[],
            vec![row("headers.Authorization", TOKEN, explicit)],
        ),
        (
            "whole-value ${VAR} in env",
            &[],
            &[("K", "${T}")],
            vec![row("env.K", TOKEN, inferred)],
        ),
        (
            "adjacent templates in env, each part",
            &[],
            &[("K", "${A}${B}")],
            vec![
                row("env.K", "first-part-77", inferred),
                row("env.K", "second-part-88", inferred),
            ],
        ),
        (
            "a mixed template in env is a path",
            &[],
            &[("PATH", "${H}/bin")],
            vec![],
        ),
        (
            "a used default is config text",
            &[("X", "${UNSET_9105:-fallback}")],
            &[("K", "${UNSET_9105:-fallback}")],
            vec![],
        ),
        (
            "literals are plain",
            &[("X", "plain")],
            &[("LOG_LEVEL", "debug"), ("DEBUG", "1")],
            vec![],
        ),
    ];
    for (name, headers, env, want) in cases {
        assert_eq!(recorded(headers, env, &env_body), want, "{name}");
    }
}

/// `${VAR:-default}` with the variable set records the variable's value
/// under the field's rule.
#[test]
fn a_default_template_with_its_variable_set_records_the_variable() {
    let env_body = format!("T={TOKEN}\n");
    assert_eq!(
        recorded(
            &[("X", "${T:-fallback}")],
            &[("K", "${T:-fallback}")],
            &env_body
        ),
        vec![
            row("env.K", TOKEN, SecretOrigin::Inferred),
            row("headers.X", TOKEN, SecretOrigin::Explicit),
        ]
    );
}

/// The record prints its count, never a value.
#[test]
fn the_record_never_prints_a_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.env");
    crate::gateway::test_helpers::write_owner_only(&path, format!("T={TOKEN}\n"))
        .expect("write the env file");
    let overlay = EnvOverlay::from_paths(&[path]);
    let mut backends = HashMap::from([(
        "b".to_owned(),
        BackendConfig {
            env: HashMap::from([("K".to_owned(), "env:T".to_owned())]),
            ..BackendConfig::default()
        },
    )]);
    let mut configured = ConfiguredByBackend::new();
    evaluate_backends(&mut backends, &overlay, &mut Vec::new(), &mut configured);
    let backend = &backends["b"];
    let printed = format!("{backend:?} {:?}", configured["b"]);
    assert_eq!(configured["b"].iter().count(), 1, "premise: one recorded");
    assert!(!printed.contains(TOKEN), "{printed}");
}

/// The load refusals for one backend `b` whose headers are `env:` references
/// to the given env-file variables.
fn refused(headers: Pairs<'_>, env_body: &str) -> Vec<String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.env");
    crate::gateway::test_helpers::write_owner_only(&path, env_body).expect("write the env file");
    let overlay = EnvOverlay::from_paths(&[PathBuf::from(&path)]);
    let mut backends = HashMap::from([(
        "b".to_owned(),
        BackendConfig {
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            ..BackendConfig::default()
        },
    )]);
    let mut unresolved = Vec::new();
    evaluate_backends(
        &mut backends,
        &overlay,
        &mut unresolved,
        &mut ConfiguredByBackend::new(),
    );
    unresolved
}

/// `count` header references, each to its own variable, and the env file
/// that defines them.
fn many(count: usize) -> (Vec<(String, String)>, String) {
    let headers = (0..count)
        .map(|i| (format!("X-Key-{i}"), format!("env:KEY_{i}")))
        .collect();
    let mut body = String::new();
    for i in 0..count {
        use std::fmt::Write as _;
        let _ = writeln!(body, "KEY_{i}=configured-secret-{i:04}");
    }
    (headers, body)
}

/// A backend may configure at most `MAX_CONFIGURED` secret values: one more
/// is refused at load, naming the backend and the count, never a value.
#[test]
fn a_backend_configuring_too_many_secrets_is_refused_at_load() {
    let at_cap = many(super::MAX_CONFIGURED);
    let pairs: Vec<(&str, &str)> = at_cap
        .0
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert!(
        refused(&pairs, &at_cap.1).is_empty(),
        "the cap itself was refused"
    );
    let over = many(super::MAX_CONFIGURED + 1);
    let pairs: Vec<(&str, &str)> = over
        .0
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let refusals = refused(&pairs, &over.1);
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(
        refusals[0].contains("backends.b:") && refusals[0].contains("65"),
        "{refusals:?}"
    );
    assert!(
        !refusals[0].contains("configured-secret-"),
        "a refusal printed a value: {refusals:?}"
    );
}

/// Load's refusal of a secret value holding `marker`: one message, naming
/// the field and never the value. A redaction next to such a value could
/// complete it.
fn assert_marker_refused(marker: &str) {
    let body = format!("MARKED=abc{marker}xyz-secret\n");
    let refusals = refused(&[("X-Key", "env:MARKED")], &body);
    assert_eq!(refusals.len(), 1, "{marker}: {refusals:?}");
    assert!(
        refusals[0].contains("backends.b.headers.X-Key"),
        "{refusals:?}"
    );
    assert!(
        !refusals[0].contains("xyz-secret"),
        "a refusal printed the value: {refusals:?}"
    );
}

#[test]
fn a_secret_value_holding_the_redacted_marker_is_refused_at_load() {
    assert_marker_refused("[redacted]");
}

#[test]
fn a_secret_value_holding_the_removed_marker_is_refused_at_load() {
    assert_marker_refused("<removed>");
}

#[test]
fn a_secret_value_holding_the_hidden_marker_is_refused_at_load() {
    assert_marker_refused("{hidden}");
}
