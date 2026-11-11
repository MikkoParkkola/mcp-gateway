// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! One WARN per identity provider whose subjects are email addresses. Each
//! row uses its own issuer: the set of providers already warned about is per
//! process.

use std::sync::{Arc, Barrier};

use super::email_hash::EmailHashKey;
use super::oidc::VerifiedIdentity;
use super::{KeyServer, is_email_shaped};
use crate::config::KeyServerConfig;

fn server() -> KeyServer {
    KeyServer::new(KeyServerConfig::default(), EmailHashKey::for_test())
}

fn identity(issuer: &str, subject: &str) -> VerifiedIdentity {
    VerifiedIdentity::checked(
        issuer.to_owned(),
        subject.to_owned(),
        String::new(),
        None,
        Vec::new(),
    )
    .expect("names someone")
}

#[test]
fn an_email_shape_is_one_at_a_local_part_and_a_dotted_domain() {
    for yes in ["ada@x.org", "Ada.Lovelace+Audit@Mail.Example.Test"] {
        assert!(is_email_shaped(yes), "{yes}");
    }
    for no in [
        "opaque-7f3a",
        "ada@localhost",
        "@x.org",
        "ada@",
        "a@b@x.org",
        "ada@.org",
        "ada@x.",
    ] {
        assert!(!is_email_shaped(no), "{no}");
    }
}

#[test]
fn an_opaque_subject_never_warns() {
    assert!(!server().note_email_subject(&identity("https://opaque.warn.test", "user-7f3a")));
}

#[test]
fn one_provider_warns_once_whatever_its_subjects() {
    let ks = server();
    let iss = "https://once.warn.test";
    assert!(ks.note_email_subject(&identity(iss, "ada@x.org")));
    assert!(
        !ks.note_email_subject(&identity(iss, "ada@x.org")),
        "the same subject again"
    );
    assert!(
        !ks.note_email_subject(&identity(iss, "grace@y.org")),
        "another subject, same provider"
    );
}

#[test]
fn two_providers_warn_once_each() {
    let ks = server();
    assert!(ks.note_email_subject(&identity("https://a.two.warn.test", "ada@x.org")));
    assert!(ks.note_email_subject(&identity("https://b.two.warn.test", "ada@x.org")));
}

/// Eight first sightings of one provider at once: exactly one warns.
#[test]
fn concurrent_first_sightings_warn_exactly_once() {
    let ks = Arc::new(server());
    let barrier = Arc::new(Barrier::new(8));
    let warned: usize = (0..8)
        .map(|n| {
            let (ks, barrier) = (Arc::clone(&ks), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                ks.note_email_subject(&identity("https://race.warn.test", &format!("u{n}@x.org")))
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| usize::from(h.join().expect("thread")))
        .sum();
    assert_eq!(warned, 1);
}
