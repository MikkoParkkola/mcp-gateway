// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows L1.1-L1.11, P1, L2.7 and L2.8 of the CLI login test plan. Draws are
//! scripted and time is passed in, so no row sleeps or depends on chance
//! (except L1.11's interleaving, see there).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use super::attempts::{
    AttemptStore, CODE_ALPHABET, Draws, PollRefused, PollState, StartRefused, Started, UserCode,
};

// The design's numbers, written out on purpose: a row
// that read the constant it checks would move with a changed constant and
// stay green.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const HELD: usize = 256;
const CODE_DRAWS: usize = 8;
const TEN_MINUTES: Duration = Duration::from_secs(600);
const MAX_POLLS: u32 = 120;

/// How often each draw ran.
#[derive(Default)]
struct Calls {
    code: AtomicUsize,
    id: AtomicUsize,
    secret: AtomicUsize,
}

fn next<T>(queue: &Mutex<VecDeque<T>>, what: &str) -> T {
    queue
        .lock()
        .expect("script lock")
        .pop_front()
        .unwrap_or_else(|| panic!("{what} draw script exhausted"))
}

/// Draws that hand out the given values in order.
fn scripted(
    codes: Vec<[u8; 10]>,
    ids: Vec<uuid::Uuid>,
    secrets: Vec<String>,
) -> (Draws, Arc<Calls>) {
    let calls = Arc::new(Calls::default());
    let (codes, ids, secrets) = (
        Arc::new(Mutex::new(VecDeque::from(codes))),
        Arc::new(Mutex::new(VecDeque::from(ids))),
        Arc::new(Mutex::new(VecDeque::from(secrets))),
    );
    let (c1, c2, c3) = (Arc::clone(&calls), Arc::clone(&calls), Arc::clone(&calls));
    let draws = Draws {
        code: Box::new(move || {
            c1.code.fetch_add(1, Ordering::SeqCst);
            next(&codes, "code")
        }),
        id: Box::new(move || {
            c2.id.fetch_add(1, Ordering::SeqCst);
            next(&ids, "id")
        }),
        secret: Box::new(move || {
            c3.secret.fetch_add(1, Ordering::SeqCst);
            next(&secrets, "secret")
        }),
    };
    (draws, calls)
}

fn id(n: usize) -> uuid::Uuid {
    uuid::Uuid::from_u128(u128::try_from(n).unwrap_or(u128::MAX))
}

fn secret(n: usize) -> String {
    format!("secret-{n:043}")
}

/// A store scripted for `count` starts with distinct codes, ids and secrets.
fn store_for(count: usize) -> (AttemptStore, Arc<Calls>) {
    let codes = (0..count).map(distinct_code).collect();
    let ids = (1..=count).map(id).collect();
    let secrets = (1..=count).map(secret).collect();
    let (draws, calls) = scripted(codes, ids, secrets);
    (AttemptStore::new(draws), calls)
}

/// Distinct codes for `n` below 1024: the last two symbols carry `n`.
fn distinct_code(n: usize) -> [u8; 10] {
    let hi = u8::try_from(n / 32 % 32).unwrap_or(0);
    let lo = u8::try_from(n % 32).unwrap_or(0);
    [7, 7, 7, 7, 7, 7, 7, 7, hi, lo]
}

/// L1.1: a code is ten symbols from the 32-symbol alphabet, shown as two
/// groups of five joined by one hyphen.
#[test]
fn a_code_is_ten_symbols_from_the_alphabet() {
    let indices = [0, 1, 2, 3, 4, 27, 28, 29, 30, 31];
    let (draws, _) = scripted(vec![indices], vec![id(1)], vec![secret(1)]);
    let store = AttemptStore::new(draws);
    let started = store
        .start(Instant::now())
        .expect("a start into an empty store");
    let shown = started.code.display();
    assert_eq!(
        shown, "01234-VWXYZ",
        "the drawn symbols, hyphen after the fifth"
    );
    assert_eq!(CODE_ALPHABET, ALPHABET, "the design's 32 symbols, in order");
    assert!(
        shown
            .bytes()
            .filter(|b| *b != b'-')
            .all(|b| CODE_ALPHABET.contains(&b)),
        "every symbol from the alphabet: {shown}"
    );
}

/// L1.2: either case, with or without the one hyphen; nothing else. The
/// hyphen-less form is J9 L1's "case/display-hyphen variants" (j9 test plan
/// r3:252); design :15's "that one hyphen only" bars any other hyphen.
#[test]
fn a_code_parses_in_either_case_with_one_hyphen() {
    let (draws, _) = scripted(
        vec![[10, 11, 12, 13, 14, 15, 16, 17, 18, 19]],
        vec![id(1)],
        vec![secret(1)],
    );
    let store = AttemptStore::new(draws);
    let t0 = Instant::now();
    let started = store.start(t0).expect("a start into an empty store");
    let shown = started.code.display();
    assert_eq!(shown, "ABCDE-FGHJK");
    for typed in [
        shown.clone(),
        shown.to_lowercase(),
        "aBcDe-FgHjK".to_owned(),
        shown.replace('-', ""),
    ] {
        let parsed = UserCode::parse(&typed).unwrap_or_else(|| panic!("{typed:?} parses"));
        assert_eq!(
            store.lookup(&parsed, t0),
            Some(started.id),
            "{typed:?} finds the attempt"
        );
    }
    for typed in [
        "ABCDE--FGHJK",
        "ABCDE FGHJK",
        "ABCDI-FGHJK",
        "ABCDL-FGHJK",
        "ABCDO-FGHJK",
        "ABCDU-FGHJK",
        "ABCD-EFGHJK",
        "ABCDE-FGHJKM",
        "ABCDE-FGHJ",
        "",
    ] {
        assert_eq!(UserCode::parse(typed), None, "{typed:?} is refused");
    }
}

/// L1.3: the id and the polling secret are their own draws, used as drawn.
#[test]
fn id_and_secret_are_separate_draws() {
    let (draws, calls) = scripted(vec![distinct_code(1)], vec![id(7)], vec![secret(9)]);
    let store = AttemptStore::new(draws);
    let started = store
        .start(Instant::now())
        .expect("a start into an empty store");
    assert_eq!(started.id, id(7));
    assert_eq!(started.secret, secret(9));
    assert_eq!(started.code.display(), "77777-77701");
    for (what, n) in [
        ("code", &calls.code),
        ("id", &calls.id),
        ("secret", &calls.secret),
    ] {
        assert_eq!(n.load(Ordering::SeqCst), 1, "{what} drawn once");
    }
}

/// L1.4: one collision, then a fresh code: one attempt under the fresh code.
#[test]
fn one_collision_then_a_fresh_code_succeeds() {
    let held = distinct_code(1);
    let (draws, _) = scripted(
        vec![held, held, distinct_code(2)],
        vec![id(1), id(2)],
        vec![secret(1), secret(2)],
    );
    let store = AttemptStore::new(draws);
    let t0 = Instant::now();
    store.start(t0).expect("A");
    let b = store.start(t0).expect("B after one collision");
    assert_eq!(b.code.display(), "77777-77702");
    assert_eq!(store.retained(t0), 2);
}

/// L1.5: eight colliding draws refuse without inserting; seven then a fresh
/// one inserts once.
#[test]
fn eight_collisions_refuse_without_insertion() {
    let held = distinct_code(1);
    let mut codes = vec![held; 1 + CODE_DRAWS];
    codes.extend(vec![held; CODE_DRAWS - 1]);
    codes.push(distinct_code(2));
    let (draws, calls) = scripted(
        codes,
        vec![id(1), id(2), id(3)],
        vec![secret(1), secret(2), secret(3)],
    );
    let store = AttemptStore::new(draws);
    let t0 = Instant::now();
    store.start(t0).expect("A");
    assert_eq!(
        store.start(t0).err(),
        Some(StartRefused::Collision),
        "eight collisions"
    );
    assert_eq!(store.retained(t0), 1, "nothing inserted");
    assert_eq!(
        calls.code.load(Ordering::SeqCst),
        1 + CODE_DRAWS,
        "exactly eight draws for B"
    );
    let c = store.start(t0).expect("seven collisions then a fresh code");
    assert_eq!(c.code.display(), "77777-77702");
    assert_eq!(store.retained(t0), 2);
}

/// L1.6: an id draw equal to a held id never aliases it: B is refused, or
/// held as a second attempt of its own that answers only to B's secret
/// (J9 L1, "without aliasing").
#[test]
fn an_id_collision_never_aliases() {
    let (draws, _) = scripted(
        vec![distinct_code(1), distinct_code(2), distinct_code(3)],
        vec![id(1), id(1), id(2)],
        vec![secret(1), secret(2), secret(3)],
    );
    let store = AttemptStore::new(draws);
    let t0 = Instant::now();
    let a = store.start(t0).expect("A");
    match store.start(t0) {
        Ok(b) => {
            assert_ne!(b.id, a.id, "B must not alias A's id");
            assert_eq!(store.retained(t0), 2, "B is held as a second attempt");
            assert_eq!(store.lookup(&b.code, t0), Some(b.id), "B's code names B");
            assert_eq!(
                store.poll(b.id, &b.secret, t0),
                Ok(PollState::Pending),
                "B answers to its own secret"
            );
            assert_eq!(
                store.poll(b.id, &a.secret, t0),
                Err(PollRefused::Invalid),
                "A's secret does not open B"
            );
        }
        Err(refused) => {
            assert_eq!(refused, StartRefused::Collision);
            assert_eq!(store.retained(t0), 1, "a refused start inserts nothing");
        }
    }
    assert_eq!(
        store.lookup(&a.code, t0),
        Some(a.id),
        "A's code still names A"
    );
    assert_eq!(
        store.poll(a.id, &a.secret, t0),
        Ok(PollState::Pending),
        "A still answers to its own secret"
    );
}

/// L1.7: 256 attempts are held, the 257th start is refused, and no held
/// attempt is evicted for it. The store itself applies no rate limit.
#[test]
fn capacity_is_256() {
    let (store, _) = store_for(HELD + 1);
    let t0 = Instant::now();
    let held: Vec<_> = (1..=HELD)
        .map(|k| {
            store
                .start(t0)
                .unwrap_or_else(|e| panic!("start {k}: {e:?}"))
        })
        .collect();
    assert_eq!(store.retained(t0), HELD);
    assert_eq!(
        store.start(t0).err(),
        Some(StartRefused::Full),
        "the 257th start"
    );
    assert_eq!(store.retained(t0), HELD);
    for a in &held {
        assert_eq!(
            store.poll(a.id, &a.secret, t0),
            Ok(PollState::Pending),
            "{} still held",
            a.id
        );
    }
}

/// L1.8: a consumed attempt keeps its place and its code until its deadline.
#[test]
fn a_consumed_attempt_keeps_its_place_until_its_deadline() {
    let t0 = Instant::now();
    // (a) its place in a full store.
    let (store, _) = store_for(HELD + 1);
    let held: Vec<_> = (0..HELD).map(|_| store.start(t0).expect("fill")).collect();
    assert!(store.consume(held[0].id, t0), "consume a held attempt");
    assert_eq!(store.retained(t0), HELD, "consumed still counts");
    assert_eq!(store.start(t0).err(), Some(StartRefused::Full));
    // (b) its code, in a fresh store.
    let mine = distinct_code(5);
    let mut codes = vec![mine; 1 + CODE_DRAWS];
    codes.push(mine);
    let (draws, _) = scripted(
        codes,
        vec![id(1), id(2), id(3)],
        vec![secret(1), secret(2), secret(3)],
    );
    let store = AttemptStore::new(draws);
    let a = store.start(t0).expect("A");
    assert!(store.consume(a.id, t0));
    assert_eq!(
        store.lookup(&a.code, t0),
        None,
        "a consumed code is not found"
    );
    let late = t0 + Duration::from_secs(599);
    assert_eq!(
        store.start(late).err(),
        Some(StartRefused::Collision),
        "the code is still held at 599 s"
    );
    assert_eq!(store.retained(t0 + TEN_MINUTES), 0, "gone at 600 s");
    let b = store
        .start(t0 + TEN_MINUTES)
        .expect("the code is free at 600 s");
    assert_eq!(b.code, a.code);
}

/// L1.9: an attempt ends exactly 600 s after its start; use does not extend it.
#[test]
fn the_deadline_is_600_seconds_and_never_moves() {
    let (store, _) = store_for(1);
    let t0 = Instant::now();
    let a = store.start(t0).expect("A");
    assert_eq!(a.deadline, t0 + TEN_MINUTES);
    let secs = Duration::from_secs;
    assert_eq!(
        store.poll(a.id, &a.secret, t0 + secs(5)),
        Ok(PollState::Pending)
    );
    assert_eq!(
        store.poll(a.id, &a.secret, t0 + secs(10)),
        Ok(PollState::Pending)
    );
    assert_eq!(store.lookup(&a.code, t0 + secs(590)), Some(a.id));
    assert_eq!(
        store.lookup(&a.code, t0 + secs(599)),
        Some(a.id),
        "alive at 599 s"
    );
    assert_eq!(
        store.poll(a.id, &a.secret, t0 + secs(599)),
        Ok(PollState::Pending)
    );
    assert_eq!(
        store.poll(a.id, &a.secret, t0 + TEN_MINUTES),
        Err(PollRefused::Invalid),
        "gone at 600 s"
    );
    assert_eq!(store.lookup(&a.code, t0 + TEN_MINUTES), None);
    assert_eq!(store.retained(t0 + TEN_MINUTES), 0);
}

/// L1.10: a new store (a restart) knows no attempt of an old one.
#[test]
fn a_new_store_knows_no_old_attempt() {
    let t0 = Instant::now();
    let (old, _) = store_for(1);
    let a = old.start(t0).expect("A");
    assert_eq!(
        old.poll(a.id, &a.secret, t0),
        Ok(PollState::Pending),
        "the old store holds A"
    );
    let (new, _) = store_for(1);
    assert_eq!(new.poll(a.id, &a.secret, t0), Err(PollRefused::Invalid));
    assert_eq!(new.lookup(&a.code, t0), None);
    assert_eq!(new.retained(t0), 0);
}

/// P1: unknown, expired and wrong-secret polls get one and the same refusal,
/// which names no id, code or secret.
#[test]
fn unknown_expired_and_wrong_secret_polls_look_the_same() {
    let (store, _) = store_for(1);
    let t0 = Instant::now();
    let a = store.start(t0).expect("A");
    assert_eq!(
        store.poll(a.id, &a.secret, t0),
        Ok(PollState::Pending),
        "A answers its own secret"
    );
    // At the same instant: a wrong secret must not hear TooSoon, which would
    // tell a stranger the attempt exists.
    let wrong = store
        .poll(a.id, "secret-wrong", t0)
        .expect_err("wrong secret");
    let unknown = store.poll(id(999), &a.secret, t0).expect_err("unknown id");
    let expired = store
        .poll(a.id, &a.secret, t0 + TEN_MINUTES)
        .expect_err("expired");
    assert_eq!(wrong, PollRefused::Invalid);
    assert_eq!(wrong, unknown);
    assert_eq!(wrong, expired);
    let shown = [
        format!("{wrong:?}"),
        format!("{unknown:?}"),
        format!("{expired:?}"),
    ];
    assert!(shown.iter().all(|s| *s == shown[0]), "{shown:?}");
    for leak in [a.id.to_string(), a.code.display(), a.secret.clone()] {
        assert!(!shown[0].contains(&leak), "{shown:?} names {leak}");
    }
}

/// L2.7: the rightful poller waits five seconds between polls.
#[test]
fn legitimate_polls_are_five_seconds_apart() {
    let (store, _) = store_for(1);
    let t0 = Instant::now();
    let a = store.start(t0).expect("A");
    assert_eq!(store.poll(a.id, &a.secret, t0), Ok(PollState::Pending));
    assert_eq!(
        store.poll(a.id, &a.secret, t0 + Duration::from_millis(4900)),
        Err(PollRefused::TooSoon)
    );
    assert_eq!(
        store.poll(a.id, &a.secret, t0 + Duration::from_secs(5)),
        Ok(PollState::Pending)
    );
}

/// L2.8: an attempt answers at most 120 polls, and refuses the 121st while
/// still before its deadline (so the deadline cannot hide a missing count).
#[test]
fn an_attempt_takes_at_most_120_polls() {
    let (store, _) = store_for(1);
    let t0 = Instant::now();
    let a = store.start(t0).expect("A");
    store.set_polls_for_test(a.id, MAX_POLLS - 1);
    assert_eq!(
        store.poll(a.id, &a.secret, t0),
        Ok(PollState::Pending),
        "the 120th poll"
    );
    let later = t0 + Duration::from_secs(5);
    assert!(later < a.deadline);
    assert_eq!(
        store.poll(a.id, &a.secret, later),
        Err(PollRefused::Exhausted),
        "the 121st poll"
    );
}

/// Where L1.11's two starts meet: each start thread calls `launch` just
/// before `start`; the store's test-only pause calls `wait`.
#[derive(Default)]
struct Gate {
    counts: Mutex<Counts>,
    changed: std::sync::Condvar,
}

#[derive(Default)]
struct Counts {
    launched: usize,
    arrived: usize,
}

/// Starts in each L1.11 race.
const RACERS: usize = 2;

impl Gate {
    fn launch(&self) {
        self.counts.lock().expect("gate lock").launched += 1;
        self.changed.notify_all();
    }

    /// In the pause: first until both threads have launched, so a thread
    /// scheduled late cannot reach its check after the first insert and
    /// pass a split lock; then at most two seconds for the other start to
    /// arrive here too. Under one lock it never arrives (it waits for the
    /// lock this start holds), so the green path spends those two seconds.
    fn wait(&self) {
        let mut counts = self.counts.lock().expect("gate lock");
        counts.arrived += 1;
        self.changed.notify_all();
        let (counts, _) = self
            .changed
            .wait_timeout_while(counts, Duration::from_secs(30), |c| c.launched < RACERS)
            .expect("gate wait");
        let _ = self
            .changed
            .wait_timeout_while(counts, Duration::from_secs(2), |c| c.arrived < RACERS)
            .expect("gate wait");
    }
}

/// Two starts at once on a store paused by a `Gate`; the scripts hand out
/// codes and ids in order, whichever start draws first. Returns both
/// outcomes and the count held after.
fn race(codes: Vec<[u8; 10]>, ids: Vec<uuid::Uuid>) -> (Vec<Result<Started, StartRefused>>, usize) {
    let secrets = (1..=ids.len()).map(secret).collect();
    let (draws, _) = scripted(codes, ids, secrets);
    let gate = Arc::new(Gate::default());
    let in_pause = Arc::clone(&gate);
    let store = Arc::new(AttemptStore::with_pause(
        draws,
        Box::new(move || in_pause.wait()),
    ));
    let t0 = Instant::now();
    let both = Arc::new(Barrier::new(RACERS));
    let runs: Vec<_> = (0..RACERS)
        .map(|_| {
            let (store, both, gate) = (Arc::clone(&store), Arc::clone(&both), Arc::clone(&gate));
            std::thread::spawn(move || {
                both.wait();
                gate.launch();
                store.start(t0)
            })
        })
        .collect();
    let outcomes = runs
        .into_iter()
        .map(|run| run.join().expect("start thread"))
        .collect();
    (outcomes, store.retained(t0))
}

/// L1.11: two starts racing on one code, or on one id, hold it once
/// (design :15, "one map lock atomically reserves canonical code/ID").
///
/// Honesty note: the store's test-only pause (`AttemptStore::with_pause`)
/// runs after `start` finds its code and its id free and before it inserts.
/// Each start waits there for the other. If a check and the insert are not
/// under one lock, both starts find the same value free, meet in the pause
/// and both insert it: the round fails by construction. Under one lock the
/// second start cannot reach its checks while the first waits in the pause,
/// which gives up after two seconds; the first inserts and the second finds
/// the value taken. A pause placed after the insert is invisible here; code
/// review checks its placement against the comment on the store's `pause`
/// field.
#[test]
fn racing_starts_hold_a_code_and_an_id_once() {
    // Round 1: both first draw one code; the loser redraws its code.
    let same = distinct_code(1);
    let (outcomes, held) = race(
        vec![same, same, distinct_code(2), distinct_code(3)],
        (1..=4).map(id).collect(),
    );
    let started: Vec<_> = outcomes
        .into_iter()
        .map(|outcome| outcome.expect("a code collision is redrawn"))
        .collect();
    assert_ne!(started[0].code, started[1].code, "one code held twice");
    assert_ne!(started[0].id, started[1].id, "round 1: one id held twice");
    assert_eq!(held, 2, "round 1");

    // Round 2: distinct codes, both first draw one id; the
    // loser redraws its id or is refused, never shares it.
    let (outcomes, held) = race(
        (1..=4).map(distinct_code).collect(),
        vec![id(1), id(1), id(2), id(3)],
    );
    match outcomes.as_slice() {
        [Ok(a), Ok(b)] => {
            assert_ne!(a.id, b.id, "round 2: one id held twice");
            assert_eq!(held, 2, "round 2: both held");
        }
        [Ok(_), Err(refused)] | [Err(refused), Ok(_)] => {
            assert_eq!(*refused, StartRefused::Collision, "round 2");
            assert_eq!(held, 1, "round 2: the refused start inserted nothing");
        }
        [Err(_), Err(_)] => panic!("round 2: both starts refused; one must hold the id"),
        _ => panic!("round 2: {RACERS} starts, other than 2 outcomes"),
    }
}
