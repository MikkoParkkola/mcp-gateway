// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Network rows on what the registry answers and how the request travels:
//! a non-200 answer, a redirect, an endless or compressed body, invalid JSON
//! and hostile text are each silent or sanitized, and an HTTPS proxy, NO_PROXY
//! and an unusable proxy are honoured through the production builder. Moved
//! from `npm_pin_wire_tests.rs` for the file-size ceiling.

use super::*;

#[tokio::test]
async fn a_non_200_answer_is_silent_even_with_a_valid_document() {
    for code in [404u16, 500, 203] {
        let fake = Fake::start(&[(MEMORY_PATH, Reply::Status(code, memory_doc()))]).await;
        let rows = check(
            &config_of(&[("memory", memory_on("2026.8.31"))]),
            &fake.cfg(&[]),
            Lookup::On,
        )
        .await;
        assert!(rows.is_empty(), "HTTP {code}: {rows:?}");
    }
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let fake = Fake::start(&[
        (MEMORY_PATH, Reply::Redirect("/elsewhere".to_string())),
        ("/elsewhere", Reply::Json(memory_doc())),
    ])
    .await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert!(rows.is_empty(), "{rows:?}");
    let targets: Vec<String> = fake.requests().into_iter().map(|r| r.target).collect();
    assert_eq!(
        targets,
        [MEMORY_PATH],
        "the redirect target was never asked"
    );
}

#[tokio::test]
async fn an_endless_body_is_cut_early_and_silent() {
    let fake = Fake::start(&[(
        MEMORY_PATH,
        Reply::Drip {
            chunk: 64 * 1024,
            total: 8 * MAX_DOC_BYTES,
        },
    )])
    .await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert!(rows.is_empty(), "{rows:?}");
    let written = fake.dripped.load(Ordering::SeqCst);
    assert!(
        written < 4 * MAX_DOC_BYTES,
        "the client kept reading: {written} bytes"
    );
}

#[tokio::test]
async fn a_compressed_body_counts_its_decoded_size() {
    // A deprecated pin padded past the cap once decoded, tiny on the wire.
    let mut body = memory_doc();
    body.pop(); // the closing brace
    body.extend_from_slice(br#","padding":""#);
    body.extend(std::iter::repeat_n(b'a', 2 * MAX_DOC_BYTES));
    body.extend_from_slice(br#""}"#);
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Gzip(body))]).await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert!(
        rows.is_empty(),
        "the decoded size is over the cap: {rows:?}"
    );

    // The same document under the cap, compressed, is read.
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Gzip(memory_doc()))]).await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert_eq!(warns(&rows).len(), 1, "{rows:?}");
}

#[tokio::test]
async fn invalid_json_is_silent() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(b"{not json".to_vec()))]).await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert!(rows.is_empty(), "{rows:?}");
}

#[tokio::test]
async fn hostile_text_prints_sanitized() {
    let hostile = "\u{1b}[2J\u{1b}[31mPWNED\u{1b}[0m\nfake\u{202e}line";
    let body = super::super::doc(&[("2026.8.31", Some(hostile))]);
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(body))]).await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    let detail = &warns(&rows)[0].detail;
    assert!(detail.contains("npm says: \"PWNED fakeline\""), "{detail}");
    assert!(
        !detail.chars().any(|c| c.is_control() || c == '\u{202e}'),
        "{detail:?}"
    );
}

// ── proxy: through the production builder, never bypassed ──────────────────

#[tokio::test]
async fn https_proxy_carries_the_lookup_through_connect() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let proxy = Proxy::start().await;
    let url = proxy.url();
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[("HTTPS_PROXY", url.as_str()), ("REQUEST_METHOD", "GET")]),
        Lookup::On,
    )
    .await;
    assert_eq!(
        warns(&rows).len(),
        1,
        "the lookup went through the proxy: {rows:?}"
    );
    assert_eq!(proxy.connects(), [format!("CONNECT {}", fake.addr)]);
}

#[tokio::test]
async fn no_proxy_covering_the_host_goes_direct() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let proxy = Proxy::start().await;
    let url = proxy.url();
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[("HTTPS_PROXY", url.as_str()), ("NO_PROXY", "127.0.0.1")]),
        Lookup::On,
    )
    .await;
    assert_eq!(warns(&rows).len(), 1, "{rows:?}");
    assert!(proxy.connects().is_empty(), "{:?}", proxy.connects());

    // A NO_PROXY that does not cover the host keeps the proxy.
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let _ = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[("HTTPS_PROXY", url.as_str()), ("NO_PROXY", "other.example")]),
        Lookup::On,
    )
    .await;
    assert_eq!(proxy.connects().len(), 1);
}

#[tokio::test]
async fn an_unusable_proxy_sends_nothing_anywhere() {
    let proxy = Proxy::start().await;
    let with_userinfo = format!("http://user:pass@{}", proxy.addr);
    let socks = format!("socks5://{}", proxy.addr);
    let broken = format!("http://proxy{{typo}}:{}", proxy.addr.port());
    let cases: [&[(&str, &str)]; 4] = [
        &[("HTTPS_PROXY", with_userinfo.as_str())],
        &[("ALL_PROXY", socks.as_str())],
        &[("HTTPS_PROXY", broken.as_str())],
        &[("HTTPS_PROXY", "::not a url::")],
    ];
    for pairs in cases {
        let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
        let rows = check(
            &config_of(&[("memory", memory_on("2026.8.31"))]),
            &fake.cfg(pairs),
            Lookup::On,
        )
        .await;
        assert!(rows.is_empty(), "{pairs:?}: {rows:?}");
        assert_eq!(fake.requests().len(), 0, "{pairs:?}: went direct");
        assert_eq!(
            fake.handshakes_failed.load(Ordering::SeqCst),
            0,
            "{pairs:?}: reached the fake"
        );
    }
    assert!(proxy.connects().is_empty(), "{:?}", proxy.connects());
}
