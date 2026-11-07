// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! CLI `add`'s store step: the literals of the backend just added that the
//! shared rule stores go to the secret store and only references reach the
//! config; everything else is written as typed.

use std::cell::Cell;

use super::store_backend_with;
use super::tests::{entries, opened, read_reference};
use crate::config::Config;

/// A config holding backend `tool` with `env` and `headers`.
fn with_backend(env: &[(&str, &str)], headers: &[(&str, &str)]) -> Config {
    let mut backend: crate::config::BackendConfig =
        crate::yaml::from_str("command: x\n").expect("backend");
    for (k, v) in env {
        backend.env.insert((*k).to_string(), (*v).to_string());
    }
    for (k, v) in headers {
        backend.headers.insert((*k).to_string(), (*v).to_string());
    }
    let mut config = Config::default();
    config.backends.insert("tool".to_string(), backend);
    config
}

/// A1: a credential-named env literal is stored; the config holds its
/// reference and the answer names the field and that reference.
#[test]
fn a1_a_credential_literal_is_stored_and_named() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = with_backend(&[("API_KEY", "sk-live-0123456789")], &[]);

    let (adoption, stored) =
        store_backend_with(&mut config, &["tool"], &[], || Ok(opened(dir.path()))).expect("stores");
    adoption.settle(&Ok(()));

    let written = config.backends["tool"].env["API_KEY"].clone();
    assert_eq!(read_reference(&written), "sk-live-0123456789");
    assert_eq!(
        stored,
        vec![("backends.tool.env.API_KEY".to_string(), written)]
    );
    assert_eq!(entries(dir.path()), 1);
    let yaml = crate::yaml::to_string(&config).expect("yaml");
    assert!(!yaml.contains("sk-live-0123456789"), "{yaml}");
}

/// A2: a header value is stored whole, one entry.
#[test]
fn a2_a_header_is_stored_whole() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = with_backend(&[], &[("Authorization", "Bearer sk-header-123")]);

    let (adoption, stored) =
        store_backend_with(&mut config, &["tool"], &[], || Ok(opened(dir.path()))).expect("stores");
    adoption.settle(&Ok(()));

    let written = &config.backends["tool"].headers["Authorization"];
    assert_eq!(read_reference(written), "Bearer sk-header-123");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].0, "backends.tool.headers.Authorization");
    assert_eq!(entries(dir.path()), 1);
}

/// A3: short, non-credential, reference and template values are written as
/// typed and no store is opened (an unavailable store does not fail them).
#[test]
fn a3_values_the_rule_keeps_open_no_store() {
    let kept: [(&str, &str); 5] = [
        ("API_TOKEN", "sk-sev7"),
        ("LOG_LEVEL", "debug-verbose"),
        ("API_KEY", "env:MY_KEY"),
        ("GH_TOKEN", "keychain:gh"),
        ("DB_PASSWORD", "${DB_PASSWORD}"),
    ];
    let mut config = with_backend(&kept, &[("X-Auth", "Bearer ${T}")]);
    let opens = Cell::new(0);

    let (adoption, stored) = store_backend_with(&mut config, &["tool"], &[], || {
        opens.set(opens.get() + 1);
        Err("no store".to_string())
    })
    .expect("nothing to store");
    adoption.settle(&Ok(()));

    assert_eq!(opens.get(), 0, "a store was opened with nothing to save");
    assert!(stored.is_empty(), "{stored:?}");
    let backend = &config.backends["tool"];
    for (k, v) in kept {
        assert_eq!(backend.env[k], v, "{k}");
    }
    assert_eq!(backend.headers["X-Auth"], "Bearer ${T}");
}

/// A4: a field listed to keep as text is written as typed; the others still
/// go to the store.
#[test]
fn a4_keep_as_text_keeps_only_its_field() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = with_backend(
        &[
            ("API_KEY", "sk-live-0123456789"),
            ("OTHER_TOKEN", "tok-0123456789"),
        ],
        &[("Authorization", "Bearer sk-header-123")],
    );
    let keep = [
        "env.API_KEY".to_string(),
        "headers.Authorization".to_string(),
    ];

    let (adoption, stored) =
        store_backend_with(&mut config, &["tool"], &keep, || Ok(opened(dir.path())))
            .expect("stores");
    adoption.settle(&Ok(()));

    let backend = &config.backends["tool"];
    assert_eq!(backend.env["API_KEY"], "sk-live-0123456789");
    assert_eq!(backend.headers["Authorization"], "Bearer sk-header-123");
    assert_eq!(
        read_reference(&backend.env["OTHER_TOKEN"]),
        "tok-0123456789"
    );
    let fields: Vec<&str> = stored.iter().map(|(f, _)| f.as_str()).collect();
    assert_eq!(fields, ["backends.tool.env.OTHER_TOKEN"]);
}

/// A4b: a keep-as-text field the backend does not have is an error, so a
/// typo never silently stores what the operator asked to keep.
#[test]
fn a4b_an_unknown_keep_field_is_refused() {
    let mut config = with_backend(&[("API_KEY", "sk-live-0123456789")], &[]);
    let keep = ["env.API_KEYY".to_string()];

    let error = store_backend_with(&mut config, &["tool"], &keep, || {
        panic!("no store is opened for a refused request")
    })
    .err()
    .expect("refused");

    assert!(error.contains("env.API_KEYY"), "{error}");
    assert_eq!(config.backends["tool"].env["API_KEY"], "sk-live-0123456789");
}

/// A5: the entries exist after the store step; a failed write removes them,
/// a saved one keeps them.
#[test]
fn a5_settle_follows_the_write() {
    for (saved, kept) in [(Err("Not saved".to_string()), 0), (Ok(()), 1)] {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = with_backend(&[("API_KEY", "sk-live-0123456789")], &[]);

        let (adoption, _) =
            store_backend_with(&mut config, &["tool"], &[], || Ok(opened(dir.path())))
                .expect("stores");
        // The entry exists before the write: its reference reads back the value
        // (counting entries would wait on the vault lock the pending save holds).
        assert_eq!(
            read_reference(&config.backends["tool"].env["API_KEY"]),
            "sk-live-0123456789"
        );
        adoption.settle(&saved);

        assert_eq!(entries(dir.path()), kept, "{saved:?}");
    }
}

/// A6: a store that cannot be opened fails the step and leaves the backend
/// as it was.
#[test]
fn a6_an_unopenable_store_changes_nothing() {
    let mut config = with_backend(&[("API_KEY", "sk-live-0123456789")], &[]);

    let error = store_backend_with(&mut config, &["tool"], &[], || {
        Err("secrets.store (keychain) refused: locked".to_string())
    })
    .err()
    .expect("refused");

    assert!(error.contains("secrets.store"), "{error}");
    assert_eq!(config.backends["tool"].env["API_KEY"], "sk-live-0123456789");
}

/// A7: a missing backend is an error, never a silent no-op.
#[test]
fn a7_a_missing_backend_is_an_error() {
    let mut config = Config::default();

    let error = store_backend_with(&mut config, &["ghost"], &[], || {
        panic!("no store is opened for a missing backend")
    })
    .err()
    .expect("refused");

    assert!(error.contains("ghost"), "{error}");
}

/// A8 (setup's batch): two backends' literals go in one save, with one store
/// opening, so one vault lock covers them all.
#[test]
fn a8_several_backends_store_in_one_save() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = with_backend(&[("API_KEY", "sk-live-0123456789")], &[]);
    let mut second = config.backends["tool"].clone();
    second
        .env
        .insert("API_KEY".to_string(), "sk-live-9876543210".to_string());
    config.backends.insert("other".to_string(), second);
    let opens = Cell::new(0);

    let (adoption, stored) = store_backend_with(&mut config, &["tool", "other"], &[], || {
        opens.set(opens.get() + 1);
        Ok(opened(dir.path()))
    })
    .expect("stores");
    adoption.settle(&Ok(()));

    assert_eq!(opens.get(), 1);
    assert_eq!(stored.len(), 2);
    assert_eq!(entries(dir.path()), 2);
    assert_eq!(
        read_reference(&config.backends["other"].env["API_KEY"]),
        "sk-live-9876543210"
    );
}

/// A9 (code review r1, gpt): a value the shared rule refuses (a literal
/// default) is refused by field and code before any store opens; the config
/// is unchanged and the value is never named.
#[test]
fn a9_a_refused_value_fails_before_any_store() {
    let mut config = with_backend(&[("API_KEY", "${MISSING:-sk-live-0123456789}")], &[]);

    let error = store_backend_with(&mut config, &["tool"], &[], || {
        panic!("no store is opened for a refused value")
    })
    .err()
    .expect("refused");

    assert!(error.contains("literal_default (env.API_KEY)"), "{error}");
    assert!(!error.contains("sk-live"), "{error}");
    assert_eq!(
        config.backends["tool"].env["API_KEY"],
        "${MISSING:-sk-live-0123456789}"
    );
}

/// A10 (code review r1, gpt): a backend named twice is refused before any
/// store opens, so no entry is made twice.
#[test]
fn a10_a_name_given_twice_is_refused() {
    let mut config = with_backend(&[("API_KEY", "sk-live-0123456789")], &[]);

    let error = store_backend_with(&mut config, &["tool", "tool"], &[], || {
        panic!("no store is opened for a repeated name")
    })
    .err()
    .expect("refused");

    assert!(error.contains("named twice"), "{error}");
}
