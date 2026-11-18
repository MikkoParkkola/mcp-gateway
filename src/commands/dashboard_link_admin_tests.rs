// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The TLS classifier's chain walk (design delta 5), on injected chains shaped like the real one: a Spark probe of a
//! certificate from another CA (tls-probe-1.log) showed hyper's `Connect` error wrapping `io::Error(Other)` wrapping
//! `io::Error(InvalidData)` wrapping rustls `InvalidCertificate(UnknownIssuer)`.

use super::tls_in_chain;

/// Stands in for hyper's `Connect` error: its source is the `io::Error` it carries.
#[derive(Debug)]
struct Connect(std::io::Error);

impl std::fmt::Display for Connect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connect")
    }
}

impl std::error::Error for Connect {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

fn unknown_issuer() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
}

fn io(
    kind: std::io::ErrorKind,
    inner: impl Into<Box<dyn std::error::Error + Send + Sync>>,
) -> std::io::Error {
    std::io::Error::new(kind, inner)
}

#[test]
fn the_walk_finds_rustls_however_deep_the_io_errors_nest() {
    use std::io::ErrorKind::{ConnectionRefused, InvalidData, Other};
    let real = Connect(io(Other, io(InvalidData, unknown_issuer())));
    let one_level = Connect(io(InvalidData, unknown_issuer()));
    let bare = unknown_issuer();
    let refused = Connect(io(ConnectionRefused, "refused"));
    let nested_plain = Connect(io(Other, io(InvalidData, "not tls")));
    let cases: [(&str, Option<&(dyn std::error::Error + 'static)>, bool); 6] = [
        ("the probed shape", Some(&real), true),
        ("one io::Error", Some(&one_level), true),
        ("rustls itself", Some(&bare), true),
        ("a refused connection", Some(&refused), false),
        (
            "nested io::Errors without rustls",
            Some(&nested_plain),
            false,
        ),
        ("no cause", None, false),
    ];
    for (case, chain, tls) in cases {
        assert_eq!(tls_in_chain(chain), tls, "{case}");
    }
}

/// An error whose source is itself: a looping chain.
#[derive(Debug)]
struct Loop;

impl std::fmt::Display for Loop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("loop")
    }
}

impl std::error::Error for Loop {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self)
    }
}

/// The walk is one path, each node once: forty alternating `Connect` and `io::Error` wrappers still reach rustls, and
/// a chain whose source loops ends (false) instead of spinning.
#[test]
fn the_walk_is_linear_and_bounded() {
    let mut deep: Box<dyn std::error::Error + Send + Sync> = Box::new(unknown_issuer());
    for _ in 0..40 {
        deep = Box::new(Connect(io(std::io::ErrorKind::Other, deep)));
    }
    let deep: &(dyn std::error::Error + 'static) = deep.as_ref();
    assert!(tls_in_chain(Some(deep)), "forty wrappers deep");
    assert!(!tls_in_chain(Some(&Loop)), "a looping chain");
}
