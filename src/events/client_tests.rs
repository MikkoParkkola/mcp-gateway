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
