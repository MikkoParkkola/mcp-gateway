// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows for the browser-session cookie rules: what counts as presenting a
//! session, and which cookie lines yield a usable token.

use axum::http::{HeaderMap, HeaderValue, header};

use super::{Session, presents_session, sole_cookie};

const NAME: &str = "token";

fn session() -> Session {
    Session {
        installation_id: "desk".into(),
        user_endpoint: "http://127.0.0.1:9/api/v1/auths/".into(),
        cookie_name: NAME.into(),
    }
}

fn headers(lines: &[&str]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for line in lines {
        map.append(header::COOKIE, HeaderValue::from_str(line).unwrap());
    }
    map
}

/// Mutant: a request offering the session cookie in any spelling is classified
/// as offering none (and so falls through to the API path), or the name is
/// matched loosely.
#[test]
fn presenting_a_session_means_naming_the_cookie_valid_or_not() {
    let session = session();
    for lines in [
        vec!["token=abc"],
        vec!["token="],
        vec!["a=1; token=abc"],
        vec!["token=a; token=b"],
        vec!["a=1", "token=abc"],
    ] {
        assert!(presents_session(&session, &headers(&lines)), "{lines:?}");
    }
    for lines in [
        vec![],
        vec!["a=1"],
        vec!["tokens=abc"],
        vec!["xtoken=abc"],
        vec!["token"],
    ] {
        assert!(!presents_session(&session, &headers(&lines)), "{lines:?}");
    }
    let mut opaque = HeaderMap::new();
    opaque.append(
        header::COOKIE,
        HeaderValue::from_bytes(b"token=\xff").unwrap(),
    );
    assert!(
        !presents_session(&session, &opaque),
        "a line that is not text is skipped"
    );
}

/// Mutant: a duplicated, empty or unreadable session cookie yields a token.
#[test]
fn only_one_nonempty_session_cookie_yields_a_token() {
    assert_eq!(sole_cookie(&headers(&["token=abc"]), NAME), Some("abc"));
    assert_eq!(
        sole_cookie(&headers(&["a=1; token=abc", "b=2"]), NAME),
        Some("abc")
    );
    assert_eq!(
        sole_cookie(&headers(&["a=1", "token=abc"]), NAME),
        Some("abc")
    );
    assert_eq!(
        sole_cookie(&headers(&["flag; token=abc"]), NAME),
        Some("abc"),
        "a pair with no `=` is skipped, not fatal"
    );
    for lines in [
        vec!["token=a; token=b"],
        vec!["token=a", "token=b"],
        vec!["token="],
        vec!["a=1"],
        vec![],
    ] {
        assert_eq!(sole_cookie(&headers(&lines), NAME), None, "{lines:?}");
    }
    let mut opaque = HeaderMap::new();
    opaque.append(
        header::COOKIE,
        HeaderValue::from_bytes(b"token=\xff").unwrap(),
    );
    assert_eq!(sole_cookie(&opaque, NAME), None);
    // An unreadable line refuses even beside a valid one, in either order.
    let (unreadable, valid) = (&b"token=\xff"[..], &b"token=abc"[..]);
    for (first, second) in [(unreadable, valid), (valid, unreadable)] {
        let mut mixed = HeaderMap::new();
        mixed.append(header::COOKIE, HeaderValue::from_bytes(first).unwrap());
        mixed.append(header::COOKIE, HeaderValue::from_bytes(second).unwrap());
        assert_eq!(sole_cookie(&mixed, NAME), None);
    }
    assert_eq!(
        sole_cookie(&headers(&["token=; token=abc"]), NAME),
        None,
        "an empty cookie still counts as a duplicate"
    );
}
