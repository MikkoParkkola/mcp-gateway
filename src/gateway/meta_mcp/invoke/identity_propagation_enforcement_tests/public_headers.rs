// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The two public credential calls hand an embedder a value that is wiped
//! when dropped and never prints its contents. The free scan
//! looks for the exact header value the call returned: a signed assertion
//! encodes its claims, so a marker placed in the caller's identity would
//! never appear in memory and a scan for it would pass on anything.

use super::*;
use crate::gateway::alloc_meter::{MIN_MARKER, Scanned, isolate, scan_frees, scan_frees_watching};

fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

/// The heap buffer of the minted `Authorization` value: the block the drop
/// must free.
fn value_buffer(headers: &[(String, String)]) -> *const u8 {
    headers
        .iter()
        .find(|(name, _)| name == "Authorization")
        .map(|(_, value)| value.as_ptr())
        .expect("premise: the call returned a minted credential")
}

/// The minted `Authorization` value, copied once into a buffer that is never
/// freed, so the scan's needle is not itself a freed copy.
fn minted_value(headers: &[(String, String)]) -> &'static [u8] {
    let (_, value) = headers
        .iter()
        .find(|(name, _)| name == "Authorization")
        .expect("premise: the call returned a minted credential");
    assert!(
        value.len() >= MIN_MARKER,
        "premise: the minted value is long enough to scan for"
    );
    Box::leak(value.as_bytes().to_vec().into_boxed_slice())
}

fn assert_wiped(call: &str, scanned: Scanned) {
    assert!(
        scanned.watched_freed,
        "{call}: the credential's own buffer was not freed, so a zero proves nothing: {scanned:?}"
    );
    assert_eq!(
        scanned.hits, 0,
        "{call}: a block was freed still holding the credential: {scanned:?}"
    );
}

/// `resolve_propagation_headers`: dropping the returned value frees no block
/// still holding the credential. A plain copy the caller makes with
/// `.to_vec()` is the caller's, and the scan sees it freed unwiped: the
/// positive control, so a scan that sees nothing cannot pass.
#[tokio::test]
async fn the_headers_call_hands_out_a_value_wiped_on_drop() {
    if isolate(&test_path(
        "the_headers_call_hands_out_a_value_wiped_on_drop",
    )) {
        return;
    }
    let (m, _captured) = meta_with_capturing_backend();
    let headers = m
        .resolve_propagation_headers("mem", Some(&identity()))
        .await
        .expect("resolve ok");
    let marker = minted_value(&headers);

    let copy: Vec<(String, String)> = headers.iter().cloned().collect();
    let ((), control) = scan_frees(marker, || drop(copy));
    assert!(
        control.hits >= 1,
        "positive control: a plain copy freed unwiped was not seen: {control:?}"
    );

    let watched = value_buffer(&headers);
    let ((), scanned) = scan_frees_watching(marker, watched, || drop(headers));
    assert_wiped("resolve_propagation_headers", scanned);
}

/// `resolve_propagation_credential`: dropping the whole returned tuple, its
/// binding included, frees no block still holding the credential.
#[tokio::test]
async fn the_credential_call_hands_out_a_value_wiped_on_drop() {
    if isolate(&test_path(
        "the_credential_call_hands_out_a_value_wiped_on_drop",
    )) {
        return;
    }
    let (m, _captured) = meta_with_capturing_backend();
    let returned = m
        .resolve_propagation_credential("mem", Some(&identity()))
        .await
        .expect("resolve ok");
    let marker = minted_value(&returned.0);

    let watched = value_buffer(&returned.0);
    let ((), scanned) = scan_frees_watching(marker, watched, || drop(returned));
    assert_wiped("resolve_propagation_credential", scanned);
}

/// The returned value never prints its contents: plain and pretty `Debug`
/// name the header and carry none of the credential, and so does the whole
/// tuple the credential call returns. The bindings' types pin both calls'
/// return types: a change back to a plain vector fails to build.
#[tokio::test]
async fn a_returned_credential_never_prints_its_value() {
    let (m, _captured) = meta_with_capturing_backend();
    let headers: crate::identity_propagation::PropagatedHeaders = m
        .resolve_propagation_headers("mem", Some(&identity()))
        .await
        .expect("resolve ok");
    let returned: (
        crate::identity_propagation::PropagatedHeaders,
        Option<String>,
    ) = m
        .resolve_propagation_credential("mem", Some(&identity()))
        .await
        .expect("resolve ok");
    let token = |headers: &[(String, String)]| {
        headers
            .iter()
            .find(|(name, _)| name == "Authorization")
            .map(|(_, value)| value.trim_start_matches("Bearer ").to_owned())
            .expect("premise: a minted credential")
    };
    let cases = [
        ("headers {:?}", format!("{headers:?}"), token(&headers)),
        ("headers {:#?}", format!("{headers:#?}"), token(&headers)),
        (
            "credential tuple {:?}",
            format!("{returned:?}"),
            token(&returned.0),
        ),
    ];
    for (case, printed, secret) in cases {
        assert!(
            printed.contains("Authorization"),
            "{case}: the header name is shown"
        );
        assert!(
            !printed.contains(&secret),
            "{case}: Debug printed the credential ({} bytes of output)",
            printed.len()
        );
    }
}
