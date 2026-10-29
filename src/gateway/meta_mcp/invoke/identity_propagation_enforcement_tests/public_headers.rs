// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The two public credential calls hand an embedder a value that is wiped
//! when dropped and never prints its contents (MIK-9070 A). The free scan
//! looks for the exact header value the call returned: a signed assertion
//! encodes its claims, so a marker placed in the caller's identity would
//! never appear in memory and a scan for it would pass on anything.

use super::*;
use crate::gateway::alloc_meter::{MIN_MARKER, Scanned, isolate, scan_frees};

fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
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
        scanned.searched >= 1,
        "{call}: no block was freed, so a zero proves nothing: {scanned:?}"
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

    let copy = headers.to_vec();
    let ((), control) = scan_frees(marker, || drop(copy));
    assert!(
        control.hits >= 1,
        "positive control: a plain copy freed unwiped was not seen: {control:?}"
    );

    let ((), scanned) = scan_frees(marker, || drop(headers));
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

    let ((), scanned) = scan_frees(marker, || drop(returned));
    assert_wiped("resolve_propagation_credential", scanned);
}

/// The returned value never prints its contents: `{:?}` names the header and
/// carries none of the credential.
#[tokio::test]
async fn a_returned_credential_never_prints_its_value() {
    let (m, _captured) = meta_with_capturing_backend();
    let headers = m
        .resolve_propagation_headers("mem", Some(&identity()))
        .await
        .expect("resolve ok");
    let (_, value) = headers
        .iter()
        .find(|(name, _)| name == "Authorization")
        .expect("premise: a minted credential");
    let printed = format!("{headers:?}");
    assert!(
        printed.contains("Authorization"),
        "the header name is shown: {}",
        printed.len()
    );
    let token = value.trim_start_matches("Bearer ");
    assert!(
        !printed.contains(token),
        "Debug printed the credential ({} bytes of output)",
        printed.len()
    );
}
