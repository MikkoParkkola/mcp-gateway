// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

fn secret(bytes: usize) -> String {
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode(vec![7_u8; bytes])
    )
}

#[test]
fn whsec_bounds_are_24_to_64_decoded_bytes() {
    assert!(decode_whsec(&secret(23)).is_none());
    assert_eq!(decode_whsec(&secret(24)).map(|k| k.len()), Some(24));
    assert_eq!(decode_whsec(&secret(64)).map(|k| k.len()), Some(64));
    assert!(decode_whsec(&secret(65)).is_none());
    assert!(decode_whsec(&secret(32).replace("whsec_", "whsek_")).is_none());
    assert!(decode_whsec("whsec_%%%").is_none());
}

#[test]
fn signature_is_hmac_over_id_timestamp_body_newest_first() {
    let (new, old) = (b"new-key".as_slice(), b"old-key".as_slice());
    let header = sign(&[new, old], "msg_1", "1700000000", b"{}");
    let parts: Vec<&str> = header.split(' ').collect();
    assert_eq!(parts.len(), 2);
    for (part, key) in parts.iter().zip([new, old]) {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(part.strip_prefix("v1,").expect("v1 prefix"))
            .expect("base64");
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("key");
        mac.update(b"msg_1.1700000000.{}");
        mac.verify_slice(&raw)
            .expect("signature verifies under its key");
    }
}

#[test]
fn literals_are_refused_unless_allowed() {
    let open = CallbackClient::new(Vec::new()).expect("client");
    let loopback = url::Url::parse("https://127.0.0.1:9/h").expect("url");
    assert_eq!(
        open.check_literal(&loopback),
        Err(CallbackFailure::ConnectionRefused)
    );
    for refused in [
        "https://[::1]/h",
        "https://10.0.0.1/h",
        "https://169.254.169.254/h",
    ] {
        let url = url::Url::parse(refused).expect("url");
        assert!(open.check_literal(&url).is_err(), "{refused}");
    }
    assert!(
        open.check_literal(&url::Url::parse("https://8.8.8.8/h").expect("url"))
            .is_ok()
    );
    let allowed = CallbackClient::new(vec![("127.0.0.0".parse().expect("ip"), 8)]).expect("client");
    assert!(allowed.check_literal(&loopback).is_ok());
    let outside = url::Url::parse("https://10.0.0.1/h").expect("url");
    assert!(
        allowed.check_literal(&outside).is_err(),
        "only the listed range"
    );
}

#[test]
fn an_allowlist_never_exempts_link_local_or_its_encodings() {
    let everything_v6 = CallbackClient::new(vec![("::".parse().expect("ip"), 0)]).expect("client");
    for refused in [
        "https://[fe80::1]/h",
        "https://[::ffff:169.254.169.254]/h",
        "https://[2002:a9fe:a9fe::]/h",
    ] {
        let url = url::Url::parse(refused).expect("url");
        assert!(everything_v6.check_literal(&url).is_err(), "{refused}");
    }
    let ula = url::Url::parse("https://[fd00::1]/h").expect("url");
    assert!(
        everything_v6.check_literal(&ula).is_ok(),
        "unique-local is exemptable"
    );
    let everything_v4 =
        CallbackClient::new(vec![("0.0.0.0".parse().expect("ip"), 0)]).expect("client");
    let metadata = url::Url::parse("https://169.254.169.254/h").expect("url");
    assert!(everything_v4.check_literal(&metadata).is_err());
}

#[test]
fn retry_after_reads_seconds_and_http_dates() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-10-02T12:00:00Z")
        .expect("time")
        .with_timezone(&chrono::Utc);
    assert_eq!(retry_after(" 120 ", now), Some(Duration::from_secs(120)));
    assert_eq!(
        retry_after("Fri, 02 Oct 2026 12:01:30 GMT", now),
        Some(Duration::from_secs(90))
    );
    assert_eq!(
        retry_after("Fri, 02 Oct 2026 11:00:00 GMT", now),
        Some(Duration::ZERO),
        "a past date waits nothing"
    );
    assert_eq!(retry_after("soon", now), None);
}

/// A body that never left the process is reported as unsent, so the read
/// verdict releases its reservation: a refused literal and a refused connect.
#[tokio::test]
async fn failures_before_a_byte_is_written_are_reported_unsent() {
    let keys: [&[u8]; 1] = [b"k"];
    let client = CallbackClient::new(vec![("127.0.0.0".parse().expect("ip"), 8)]).expect("client");
    let refused_literal = url::Url::parse("https://10.0.0.1:9/h").expect("url");
    let closed_port = url::Url::parse("https://127.0.0.1:1/h").expect("url");
    for url in [&refused_literal, &closed_port] {
        let outcome = client
            .post_tracked(url, "sub", "evt", &keys, b"{}".to_vec(), ReadBody::Discard)
            .await;
        assert!(
            matches!(outcome, Err((CallbackFailure::ConnectionRefused, true))),
            "{url}: {outcome:?}"
        );
    }
}
