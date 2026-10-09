// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202: the clock module's own rows.

use serde_json::json;

use super::test_clock;
use super::*;

#[test]
fn a_clock_before_the_epoch_is_an_error_in_every_form() {
    let _clock = test_clock::before_epoch();
    assert_eq!(unix_secs(), Err(ClockBeforeEpoch));
    assert_eq!(unix_millis(), Err(ClockBeforeEpoch));
    assert_eq!(utc_now(), Err(ClockBeforeEpoch));
}

#[test]
fn an_access_check_on_an_unreadable_clock_is_expired_whatever_it_compares() {
    let _clock = test_clock::before_epoch();
    assert_eq!(expired_by(|_| Validity::Live), Validity::Expired);
    assert_eq!(expired_by_utc(|_| Validity::Live), Validity::Expired);
}

#[test]
fn a_readable_clock_runs_the_sites_own_comparison() {
    let _clock = test_clock::at_secs(1_000);
    assert_eq!(unix_secs(), Ok(1_000));
    let expiry = |exp: u64| {
        expired_by(|now| {
            if now >= exp {
                Validity::Expired
            } else {
                Validity::Live
            }
        })
    };
    assert_eq!(expiry(1_001), Validity::Live);
    assert_eq!(expiry(1_000), Validity::Expired);
    assert_eq!(
        utc_now().map(|now| now.timestamp()),
        Ok(1_000),
        "the chrono form reads the same clock"
    );
}

#[test]
fn the_guard_restores_the_real_clock() {
    {
        let _clock = test_clock::before_epoch();
    }
    assert!(unix_secs().is_ok());
}

fn at(secs: u64) -> JwtClaimTime {
    JwtClaimTime::At(secs)
}

#[test]
fn the_jwt_window_near_the_epoch_neither_underflows_nor_admits_the_expired() {
    let _clock = test_clock::at_secs(100);
    // 30 + 60 < 100: expired. 50 + 60 >= 100: within the leeway.
    assert_eq!(
        jwt_window(at(30), JwtClaimTime::Absent, 60),
        Validity::Expired
    );
    assert_eq!(jwt_window(at(50), JwtClaimTime::Absent, 60), Validity::Live);
    // Closer than the leeway to the epoch: nothing subtracts, nothing wraps.
    let _clock = test_clock::at_secs(10);
    assert_eq!(jwt_window(at(0), JwtClaimTime::Absent, 60), Validity::Live);
}

#[test]
fn the_jwt_window_boundaries_and_malformed_claims() {
    let _clock = test_clock::at_secs(1_000);
    assert_eq!(
        jwt_window(at(940), JwtClaimTime::Absent, 60),
        Validity::Live,
        "exp + leeway == now"
    );
    assert_eq!(
        jwt_window(at(939), JwtClaimTime::Absent, 60),
        Validity::Expired
    );
    assert_eq!(
        jwt_window(at(2_000), at(1_060), 60),
        Validity::Live,
        "nbf == now + leeway"
    );
    assert_eq!(
        jwt_window(at(2_000), at(1_061), 60),
        Validity::Expired,
        "immature"
    );
    assert_eq!(
        jwt_window(at(u64::MAX), JwtClaimTime::Absent, 60),
        Validity::Expired,
        "overflow"
    );
    assert_eq!(
        jwt_window(at(2_000), JwtClaimTime::Malformed, 60),
        Validity::Expired
    );
    assert_eq!(
        jwt_window(JwtClaimTime::Malformed, JwtClaimTime::Absent, 60),
        Validity::Expired
    );
}

#[test]
fn the_jwt_window_on_an_unreadable_clock_is_expired() {
    let _clock = test_clock::before_epoch();
    assert_eq!(
        jwt_window(at(u64::MAX - 1), JwtClaimTime::Absent, 0),
        Validity::Expired
    );
}

#[test]
fn claim_times_decode_as_the_decoder_read_them() {
    let claims = json!({"exp": 1_700_000_000, "nbf": 1_699_999_999.75, "bad": "soon", "neg": -5});
    assert_eq!(JwtClaimTime::of(&claims, "exp"), at(1_700_000_000));
    assert_eq!(JwtClaimTime::of(&claims, "nbf"), at(1_699_999_999));
    assert_eq!(JwtClaimTime::of(&claims, "bad"), JwtClaimTime::Malformed);
    assert_eq!(JwtClaimTime::of(&claims, "neg"), JwtClaimTime::Malformed);
    assert_eq!(JwtClaimTime::of(&claims, "missing"), JwtClaimTime::Absent);
}
