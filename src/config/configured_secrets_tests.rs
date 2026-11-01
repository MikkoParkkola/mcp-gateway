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
fn recorded(
    headers: &[(&str, &str)],
    env: &[(&str, &str)],
    env_body: &str,
) -> Vec<(String, String, SecretOrigin)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.env");
    std::fs::write(&path, env_body).expect("write the env file");
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

fn row(field: &str, value: &str, origin: SecretOrigin) -> (String, String, SecretOrigin) {
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
    let cases: [(&str, &[(&str, &str)], &[(&str, &str)], Vec<_>); 9] = [
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
    std::fs::write(&path, format!("T={TOKEN}\n")).expect("write the env file");
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
