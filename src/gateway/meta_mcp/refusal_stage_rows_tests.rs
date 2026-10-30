// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Both gateway refusals are raised before anything is sent, at the reviewed
//! sites the pre-send scan holds, so both read as never sent. The composite
//! rows (a late refusal keeps its code and its run's key) are on the route:
//! `router/late_refusal_lease_tests.rs`.

#[test]
fn the_gateway_refusals_read_as_never_sent() {
    let denial = crate::Error::Forbidden {
        code: -32003,
        status: 403,
        message: "refused".into(),
    };
    assert!(denial.is_pre_dispatch(), "a denial reads as may have run");
    let refusal = crate::Error::gateway_refused(-32000, "switched off by the operator");
    assert!(
        refusal.is_pre_dispatch(),
        "a gateway refusal reads as may have run"
    );
}
