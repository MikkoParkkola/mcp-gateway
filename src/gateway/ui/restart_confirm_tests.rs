// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the restart confirmation registry (`restart_confirm`), written
//! before the code. Each names its test-plan row (mik-9447 test plan r3).
//!
//! A missing presented value maps to its binding's kind (principal `None` ->
//! `PrincipalChanged`, invocation `None` -> `InvocationChanged`, target `None`
//! or `Err` -> `TargetChanged`, sample `None` -> `SampleMissing`): the
//! design's kind list has no separate "missing" kinds except the sample's.
//!
//! The registry compares `FileId` values only. That a real rename or an
//! in-place rewrite yields a different `FileId` is slice 4's row INV-20
//! (`inv20_target_file_id`); here one synthetic field at a time stands in.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::restart_confirm::{Clock, Fill, Live, Presented, Refusal, RestartConfirm, SampleSource};
use crate::gateway::recent_writes::{RecentWrites, WriteSample};
use crate::gateway::router::{ProcessFacts, ProcessStart};
use crate::restart::invocation::{FileId, InvocationDigest};

const LIFETIME: Duration = Duration::from_secs(120);
/// `LIFETIME` less one nanosecond: the last instant a confirmation is good.
const LAST_GOOD: Duration = Duration::new(119, 999_999_999);

/// A clock a row moves by hand.
#[derive(Clone)]
struct TestClock(Arc<Mutex<Instant>>);

impl TestClock {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Instant::now())))
    }
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
    fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }
    fn source(&self) -> Clock {
        let me = self.clone();
        Arc::new(move || me.now())
    }
}

/// A random source that counts up, fails, or hands out scripted fills, and
/// records how many bytes each fill asked for.
#[derive(Clone)]
struct TestRng {
    script: Arc<Mutex<VecDeque<[u8; 32]>>>,
    /// Fills that succeed before every later one fails.
    ok_fills: usize,
    next: Arc<Mutex<u8>>,
    requested: Arc<Mutex<Vec<usize>>>,
}

impl TestRng {
    fn counting() -> Self {
        Self {
            script: Arc::default(),
            ok_fills: usize::MAX,
            next: Arc::default(),
            requested: Arc::default(),
        }
    }
    fn failing() -> Self {
        Self::failing_after(0)
    }
    fn failing_after(ok_fills: usize) -> Self {
        Self {
            ok_fills,
            ..Self::counting()
        }
    }
    fn script<const N: usize>(fills: [[u8; 32]; N]) -> Self {
        Self {
            script: Arc::new(Mutex::new(fills.into())),
            ..Self::counting()
        }
    }
    fn requested(&self) -> Vec<usize> {
        self.requested.lock().unwrap().clone()
    }
    fn source(&self) -> Fill {
        let me = self.clone();
        Arc::new(move |bytes: &mut [u8]| {
            let mut requested = me.requested.lock().unwrap();
            requested.push(bytes.len());
            if requested.len() > me.ok_fills {
                return Err(());
            }
            if let Some(fill) = me.script.lock().unwrap().pop_front() {
                bytes.copy_from_slice(&fill[..bytes.len()]);
            } else {
                let mut next = me.next.lock().unwrap();
                *next = next.wrapping_add(1);
                bytes.fill(*next);
            }
            Ok(())
        })
    }
}

fn file_id() -> FileId {
    FileId {
        dev: 1,
        ino: 2,
        size: 3,
        ctime_sec: 4,
        ctime_nsec: 5,
    }
}

fn sample(at: Instant, count: u64, writes_total: u64) -> WriteSample {
    WriteSample {
        count,
        complete_secs: 60,
        taken_at_mono: at,
        writes_total,
    }
}

fn live(principal: &str, at: Instant) -> Live {
    Live {
        principal: principal.to_owned(),
        boot: 7,
        invocation: InvocationDigest::for_test([9; 32]),
        target: file_id(),
        sample: sample(at, 1, 100),
    }
}

/// What a POST presents when nothing changed since the mint.
fn same(live: &Live) -> Presented {
    Presented {
        principal: Some(live.principal.clone()),
        boot: live.boot,
        invocation: Some(live.invocation),
        target: Some(Ok(live.target)),
        sample: Some(live.sample),
    }
}

/// A registry on a test clock whose random source yields fresh bytes per mint.
fn registry() -> (RestartConfirm, TestClock, Instant) {
    let clock = TestClock::new();
    let now = clock.now();
    (
        RestartConfirm::for_test(clock.source(), TestRng::counting().source()),
        clock,
        now,
    )
}

fn key(token: &str) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(token.as_bytes()).into()
}

// T-DEFAULT-OFF: off by default, and an instance that is off mints nothing.
#[test]
fn restart_confirmation_ships_switched_off() {
    assert!(
        !RestartConfirm::new().enabled(),
        "the shipped default must be off"
    );
    assert_eq!(
        RestartConfirm::new().mint(live("p", Instant::now())),
        None,
        "an instance that is off mints nothing, whatever its caller checked"
    );
    let facts = ProcessFacts::new(ProcessStart::now(), None);
    assert!(
        !facts.restart_confirm().enabled(),
        "the process's own registry is off"
    );
}

// T-MINT-LIMITS
#[test]
fn a_second_mint_by_one_principal_replaces_the_first() {
    let (rc, _clock, now) = registry();
    let first = rc.mint(live("p", now)).expect("first mint");
    let second = rc.mint(live("p", now)).expect("second mint");
    assert_ne!(first, second);
    assert_eq!(rc.entry_count(), 1, "one entry per principal");
    assert_eq!(
        rc.consume(&first, &same(&live("p", now))).err(),
        Some(Refusal::Invalid)
    );
    assert!(rc.consume(&second, &same(&live("p", now))).is_ok());
}

#[test]
fn the_sixty_fifth_principal_is_refused_while_sixty_four_are_live() {
    let (rc, clock, now) = registry();
    for i in 0..64 {
        assert!(rc.mint(live(&format!("p{i}"), now)).is_some(), "mint {i}");
    }
    assert_eq!(
        rc.mint(live("p64", now)),
        None,
        "64 live entries of others: refused"
    );
    assert_eq!(rc.entry_count(), 64);
    // One tick before they expire, the 64 are still live.
    clock.advance(LAST_GOOD);
    assert_eq!(
        rc.mint(live("p64", clock.now())),
        None,
        "not yet expired: still refused"
    );
    // A principal that already holds one of the 64 replaces, never refused.
    assert!(rc.mint(live("p3", clock.now())).is_some());
    assert_eq!(rc.entry_count(), 64);
}

#[test]
fn sixty_four_expired_entries_admit_a_sixty_fifth_principal() {
    let (rc, clock, now) = registry();
    for i in 0..64 {
        rc.mint(live(&format!("p{i}"), now)).expect("mint");
    }
    clock.advance(LIFETIME);
    assert!(
        rc.mint(live("p64", clock.now())).is_some(),
        "expired entries are pruned first"
    );
    assert_eq!(rc.entry_count(), 1);
}

// T-RNG
#[test]
fn a_failing_random_source_mints_nothing() {
    let clock = TestClock::new();
    let rc = RestartConfirm::for_test(clock.source(), TestRng::failing().source());
    assert_eq!(rc.mint(live("p", clock.now())), None);
    assert_eq!(rc.entry_count(), 0);
}

#[test]
fn a_failed_re_mint_keeps_the_principals_earlier_token() {
    let clock = TestClock::new();
    let rc = RestartConfirm::for_test(clock.source(), TestRng::failing_after(1).source());
    let first = rc.mint(live("p", clock.now())).expect("first mint");
    assert_eq!(
        rc.mint(live("p", clock.now())),
        None,
        "the second fill fails"
    );
    assert!(
        rc.consume(&first, &same(&live("p", clock.now()))).is_ok(),
        "a mint that failed replaced nothing"
    );
}

// T-EXPIRY: the entry lives while now < minted + 120 s.
#[test]
fn a_token_expires_at_exactly_its_lifetime_and_after_but_not_one_tick_before() {
    let (rc, clock, now) = registry();
    let token = rc.mint(live("p", now)).expect("mint");
    clock.advance(LAST_GOOD);
    assert!(
        rc.consume(&token, &same(&live("p", now))).is_ok(),
        "one tick before: good"
    );
    for past in [Duration::ZERO, Duration::from_nanos(1)] {
        let (rc, clock, now) = registry();
        let token = rc.mint(live("p", now)).expect("mint");
        clock.advance(LIFETIME + past);
        assert_eq!(
            rc.consume(&token, &same(&live("p", now))).err(),
            Some(Refusal::Expired)
        );
        assert_eq!(
            rc.consume(&token, &same(&live("p", now))).err(),
            Some(Refusal::Invalid),
            "burnt"
        );
    }
}

/// Mint for `p`, consume once with `presented`, then show the token is burnt.
fn consume_once(presented: impl FnOnce(&Live) -> Presented) -> Result<(), Refusal> {
    let (rc, _clock, now) = registry();
    let bound = live("p", now);
    let token = rc.mint(bound.clone()).expect("mint");
    let first = rc.consume(&token, &presented(&bound)).map(|_| ());
    assert_eq!(
        rc.consume(&token, &same(&bound)).err(),
        Some(Refusal::Invalid),
        "whatever the outcome, the token is gone after one consume"
    );
    first
}

// T-PRESENTED: each missing value is its own refusal, and the token burns.
#[test]
fn each_missing_presented_value_is_refused_and_burns_the_token() {
    type Case = (&'static str, fn(&Live) -> Presented, Refusal);
    let cases: [Case; 5] = [
        (
            "principal None",
            |l| Presented {
                principal: None,
                ..same(l)
            },
            Refusal::PrincipalChanged,
        ),
        (
            "invocation None",
            |l| Presented {
                invocation: None,
                ..same(l)
            },
            Refusal::InvocationChanged,
        ),
        (
            "target None",
            |l| Presented {
                target: None,
                ..same(l)
            },
            Refusal::TargetChanged,
        ),
        (
            "target Err",
            |l| Presented {
                target: Some(Err(std::io::ErrorKind::NotFound.into())),
                ..same(l)
            },
            Refusal::TargetChanged,
        ),
        (
            "sample None",
            |l| Presented {
                sample: None,
                ..same(l)
            },
            Refusal::SampleMissing,
        ),
    ];
    for (name, presented, want) in cases {
        assert_eq!(consume_once(presented), Err(want), "{name}");
    }
}

// T-BINDINGS: each changed value is its own refusal, and the token burns.
#[test]
fn each_changed_binding_is_refused_and_burns_the_token() {
    type Case = (&'static str, Box<dyn Fn(&Live) -> Presented>, Refusal);
    fn target(change: fn(&mut FileId)) -> Box<dyn Fn(&Live) -> Presented> {
        Box::new(move |l| {
            let mut id = l.target;
            change(&mut id);
            Presented {
                target: Some(Ok(id)),
                ..same(l)
            }
        })
    }
    let cases: Vec<Case> = vec![
        (
            "a second dashboard session",
            Box::new(|l| Presented {
                principal: Some(format!("{}-other", l.principal)),
                ..same(l)
            }),
            Refusal::PrincipalChanged,
        ),
        (
            "boot",
            Box::new(|l| Presented {
                boot: l.boot + 1,
                ..same(l)
            }),
            Refusal::BootChanged,
        ),
        (
            "invocation digest",
            Box::new(|l| Presented {
                invocation: Some(InvocationDigest::for_test([8; 32])),
                ..same(l)
            }),
            Refusal::InvocationChanged,
        ),
        // One synthetic FileId per field, every other field equal: a compare
        // that skips any single field leaves its case accepted.
        ("dev only", target(|id| id.dev += 1), Refusal::TargetChanged),
        (
            "ino only (renamed over)",
            target(|id| id.ino += 1),
            Refusal::TargetChanged,
        ),
        (
            "size only (rewritten in place)",
            target(|id| id.size += 1),
            Refusal::TargetChanged,
        ),
        (
            "ctime_sec only",
            target(|id| id.ctime_sec += 1),
            Refusal::TargetChanged,
        ),
        (
            "ctime_nsec only",
            target(|id| id.ctime_nsec += 1),
            Refusal::TargetChanged,
        ),
    ];
    for (name, presented, want) in cases {
        assert_eq!(consume_once(|l| presented(l)), Err(want), "{name}");
    }
}

#[test]
fn nothing_changed_is_accepted() {
    assert_eq!(consume_once(same), Ok(()));
}

// T-TOKEN-SHAPE
#[test]
fn malformed_unminted_and_replayed_tokens_are_invalid() {
    let (rc, _clock, now) = registry();
    let bound = live("p", now);
    let token = rc.mint(bound.clone()).expect("mint");
    let body = token.strip_prefix("rc1.").expect("rc1. prefix");
    for bad in [
        format!("rc2.{body}"),                     // wrong prefix, right length
        format!("{token}A"),                       // one character long
        token[..token.len() - 1].to_owned(),       // one character short
        format!("rc1.{}", "A".repeat(body.len())), // right shape, never minted
    ] {
        assert_eq!(
            rc.consume(&bad, &same(&bound)).err(),
            Some(Refusal::Invalid),
            "{bad:?}"
        );
    }
    assert_eq!(
        rc.entry_count(),
        1,
        "no malformed token touched the real entry"
    );
    assert!(rc.consume(&token, &same(&bound)).is_ok());
    assert_eq!(
        rc.consume(&token, &same(&bound)).err(),
        Some(Refusal::Invalid),
        "replay"
    );
}

#[test]
fn a_wrong_length_or_unprefixed_token_is_refused_before_it_is_hashed() {
    // An entry planted under the digest of a malformed string: a consume that
    // hashed and looked it up would remove it.
    let (rc, _clock, now) = registry();
    let bound = live("p", now);
    let long = format!("rc1.{}", "A".repeat(44));
    let unprefixed = format!("xx1.{}", "A".repeat(43));
    for bad in [long, unprefixed] {
        rc.plant(key(&bad), bound.clone());
        assert_eq!(
            rc.consume(&bad, &same(&bound)).err(),
            Some(Refusal::Invalid),
            "{bad:?}"
        );
        assert!(rc.has_key(&key(&bad)), "{bad:?} was hashed and looked up");
    }
}

#[test]
fn a_token_is_rc1_and_the_base64url_of_thirty_two_random_bytes() {
    let clock = TestClock::new();
    let bytes: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).expect("under 32"));
    let rng = TestRng::script([bytes]);
    let rc = RestartConfirm::for_test(clock.source(), rng.source());
    let token = rc.mint(live("p", clock.now())).expect("mint");
    assert_eq!(rng.requested(), vec![32], "one fill of exactly 32 bytes");
    assert_eq!(token, format!("rc1.{}", URL_SAFE_NO_PAD.encode(bytes)));
    assert_eq!(token.len(), 4 + 43);
}

#[test]
fn the_registry_keys_by_the_digest_of_the_exact_string() {
    let (rc, _clock, now) = registry();
    let bound = live("p", now);
    let token = rc.mint(bound.clone()).expect("mint");
    assert!(
        rc.has_key(&key(&token)),
        "key = SHA-256 of the exact token string"
    );
    // The same 32 bytes, spelled differently: the last character's two unused
    // bits set. A registry that decoded before hashing would accept it.
    let last = token.chars().last().expect("non-empty");
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let pos = alphabet.find(last).expect("base64url character");
    let variant = format!(
        "{}{}",
        &token[..token.len() - 1],
        &alphabet[(pos | 3)..=(pos | 3)]
    );
    assert_ne!(
        variant, token,
        "the generated bytes left the unused bits clear"
    );
    assert_eq!(
        rc.consume(&variant, &same(&bound)).err(),
        Some(Refusal::Invalid)
    );
    assert!(rc.has_key(&key(&token)), "the real entry is untouched");
}

// T-SAMPLE: mint with a bound sample, present a fresh one.
fn with_counts(
    bound_count: u64,
    fresh_count: u64,
    bound_total: u64,
    fresh_total: u64,
) -> Result<u64, Refusal> {
    let (rc, _clock, now) = registry();
    let mut bound = live("p", now);
    bound.sample = sample(now, bound_count, bound_total);
    let token = rc.mint(bound.clone()).expect("mint");
    let fresh = sample(now, fresh_count, fresh_total);
    rc.consume(
        &token,
        &Presented {
            sample: Some(fresh),
            ..same(&bound)
        },
    )
    .map(|accepted| accepted.writes_since)
}

fn with_samples(bound_count: u64, bound_total: u64, fresh_total: u64) -> Result<u64, Refusal> {
    with_counts(bound_count, bound_count, bound_total, fresh_total)
}

#[test]
fn a_regressed_write_total_is_refused_never_wrapped() {
    assert_eq!(with_samples(1, 100, 99), Err(Refusal::SampleInvalid));
    assert_eq!(with_samples(0, 100, 0), Err(Refusal::SampleInvalid));
}

#[test]
fn writes_after_a_quiet_preview_are_refused() {
    // The admin confirmed "nothing is writing"; that is no longer true.
    assert_eq!(with_samples(0, 100, 101), Err(Refusal::WritesSincePreview));
}

#[test]
fn writes_after_a_busy_preview_are_accepted_and_counted() {
    assert_eq!(with_samples(3, 100, 105), Ok(5));
    assert_eq!(
        with_samples(0, 100, 100),
        Ok(0),
        "a quiet preview with no writes since"
    );
}

// REG.3: the sample source lives on the instance.
#[test]
fn the_sample_comes_from_the_instances_source() {
    let clock = TestClock::new();
    let start = clock.now();
    let counter = RecentWrites::new(start);
    clock.advance(Duration::from_secs(5));
    let rc = RestartConfirm::for_test(clock.source(), TestRng::counting().source());
    assert_eq!(
        rc.sample(&counter),
        Some(counter.sample(clock.now())),
        "production: the gateway's counter, read at the instance's clock"
    );
    let scripted = sample(start, 4, 40);
    let rc = rc.with_samples(SampleSource::Scripted(Arc::new(Mutex::new(
        [Some(scripted), None].into(),
    ))));
    assert_eq!(rc.sample(&counter), Some(scripted));
    assert_eq!(rc.sample(&counter), None, "a scripted missing sample");
    assert_eq!(rc.sample(&counter), None, "an empty script is no sample");
}

// T-SLOT-CONTRACT is a 7c row: it needs shutdown's real RestartSlot.

#[test]
fn the_warning_rule_reads_the_count_the_admin_was_shown() {
    // Shown quiet, busy now: still the quiet decision, refused.
    assert_eq!(
        with_counts(0, 5, 100, 101),
        Err(Refusal::WritesSincePreview)
    );
    // Shown busy, quiet now: the admin confirmed writes, accepted.
    assert_eq!(with_counts(3, 0, 100, 105), Ok(5));
}
