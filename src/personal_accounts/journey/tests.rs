// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Store-level contract of the journey table (design §11.2, slice 2). Every
//! test drives a real store in a temp dir and reads `journeys.json` back
//! through its own decryption, never through an in-memory copy.

use std::collections::BTreeMap;

use super::super::super::{AccountKey, GrantRecord, PersonalAccountStore, StoreConfig};
use super::{
    CALLBACK_WINDOW, ConsentExpectation, DigestKind, JourneyError, JourneyLimits, JourneyRecord,
    JourneyRefusal, JourneyStatus, JourneyTable, NewJourney, PER_USER_WINDOW, RECORD_MAX,
    START_WINDOW, StartSecrets, digest_comparisons, read_journeys,
};

const T0: u64 = 1_800_000_000;
const K1: [u8; 32] = [7; 32];
const K2: [u8; 32] = [9; 32];

fn limits() -> JourneyLimits {
    JourneyLimits {
        journeys_total: 1024,
        journeys_per_user: 8,
        starts_per_minute_per_user: 10,
        journeys_created_per_minute: 120,
    }
}

fn raised(journeys_total: usize) -> JourneyLimits {
    JourneyLimits {
        journeys_total,
        journeys_per_user: 1000,
        starts_per_minute_per_user: 1000,
        journeys_created_per_minute: 1000,
    }
}

/// A store config whose current key and retained keys are chosen per test.
fn settings(root: &std::path::Path, current: &str, keys: &[(&str, [u8; 32])]) -> StoreConfig {
    let root = root.canonicalize().expect("temp root exists");
    StoreConfig {
        instance_id: "gateway-instance".into(),
        store_dir: root.join("records"),
        authority_dir: root.join("authority"),
        current_key_id: current.into(),
        keys: keys
            .iter()
            .map(|(id, key)| ((*id).to_owned(), key.to_vec()))
            .collect::<BTreeMap<_, _>>(),
        max_entries: 10_000,
        max_authority_bytes: 16_777_216,
    }
}

fn fresh() -> (tempfile::TempDir, StoreConfig, PersonalAccountStore) {
    let root = tempfile::tempdir().unwrap();
    let config = settings(root.path(), "k1", &[("k1", K1)]);
    let store = PersonalAccountStore::initialize(config.clone()).expect("initialize");
    (root, config, store)
}

fn owner(subject: &str, account: &str) -> AccountKey {
    AccountKey {
        principal_authority: "openwebui-adapter:4:inst".into(),
        principal_subject: subject.into(),
        backend_id: account.into(),
        resource: "https://www.googleapis.com/drive/v3".into(),
        oauth_issuer: "https://accounts.google.com".into(),
    }
}

fn request(subject: &str, account: &str) -> NewJourney {
    NewJourney {
        owner: owner(subject, account),
        descriptor_revision: "0".repeat(64),
        expected: ConsentExpectation::Absent,
        return_path: "/settings/accounts".into(),
    }
}

fn create(store: &PersonalAccountStore, now: u64, limits: &JourneyLimits, who: &str) -> String {
    let id = store
        .create_journey(now, limits, request(who, "google"))
        .expect("creation succeeds");
    assert_eq!(id.len(), 32, "a journey id is 32 lowercase hex");
    id
}

fn start(
    store: &PersonalAccountStore,
    now: u64,
    limits: &JourneyLimits,
    id: &str,
    who: &str,
) -> StartSecrets {
    store
        .start_journey(now, limits, id, &owner(who, "google"))
        .expect("the owner starts its own pending journey")
}

fn epoch(store: &PersonalAccountStore) -> String {
    let guard = store.lock_authority();
    guard
        .as_ref()
        .expect("authority present")
        .store_epoch
        .clone()
}

/// The decrypted table on disk, through the production reader.
fn on_disk(
    store: &PersonalAccountStore,
    config: &StoreConfig,
    limits: &JourneyLimits,
) -> JourneyTable {
    read_journeys(config, &epoch(store), limits).expect("journeys.json decrypts")
}

fn refused(result: Result<impl Sized, JourneyError>) -> JourneyRefusal {
    match result.err() {
        Some(JourneyError::Refused(refusal)) => refusal,
        Some(other) => panic!("expected a refusal, got {other:?}"),
        None => panic!("expected a refusal, got success"),
    }
}

#[test]
fn t_c06a_per_user_creation_is_a_sliding_ten_minute_rate() {
    // GIVEN: one principal creates 8 journeys for one account, each superseding.
    let (_root, _config, store) = fresh();
    let limits = limits();
    for i in 0..8 {
        create(&store, T0 + i, &limits, "alice");
    }
    // WHEN: the 9th arrives inside the window.
    let ninth = store.create_journey(T0 + 8, &limits, request("alice", "google"));
    // THEN: 429 until the 1st creation leaves the window, then success.
    assert_eq!(
        refused(ninth),
        JourneyRefusal::RateLimited {
            retry_after: T0 + PER_USER_WINDOW - (T0 + 8)
        }
    );
    create(&store, T0 + 8, &limits, "bob");
    create(&store, T0 + PER_USER_WINDOW + 1, &limits, "alice");
}

#[test]
fn t_c06b_active_journeys_are_bounded_gateway_wide() {
    let (_root, _config, store) = fresh();
    let limits = JourneyLimits {
        journeys_total: 2,
        ..limits()
    };
    create(&store, T0, &limits, "alice");
    create(&store, T0 + 1, &limits, "bob");
    let third = store.create_journey(T0 + 2, &limits, request("carol", "google"));
    assert_eq!(
        refused(third),
        JourneyRefusal::CapacityExceeded {
            retry_after: START_WINDOW - 2
        },
        "Retry-After is the seconds until the earliest active deadline"
    );
}

#[test]
fn t_c06c_supersede_is_keyed_on_principal_and_account() {
    let (_root, _config, store) = fresh();
    let limits = limits();
    let a_x = store
        .create_journey(T0, &limits, request("alice", "x"))
        .unwrap();
    let a_y = store
        .create_journey(T0, &limits, request("alice", "y"))
        .unwrap();
    let b_x = store
        .create_journey(T0, &limits, request("bob", "x"))
        .unwrap();
    store
        .create_journey(T0 + 1, &limits, request("alice", "x"))
        .unwrap();
    let status = |id: &str| store.journey_status(T0 + 1, &limits, id).unwrap().status;
    assert_eq!(status(&a_x), JourneyStatus::Superseded);
    assert_eq!(status(&a_y), JourneyStatus::Pending);
    assert_eq!(status(&b_x), JourneyStatus::Pending);
}

fn file_len(config: &StoreConfig) -> usize {
    let bytes = std::fs::read(config.authority_dir.join(super::JOURNEYS_FILE)).unwrap();
    bytes.len()
}

#[test]
fn t_flood_record_bound_evicts_oldest_terminal_and_never_refuses_callbacks() {
    // GIVEN: journeys_total = 4, so records_max = 16, and 3 started journeys.
    let (_root, config, store) = fresh();
    let limits = raised(4);
    assert_eq!(limits.records_max(), 16);
    let started: Vec<(String, StartSecrets)> = (0..3)
        .map(|i| {
            let who = format!("started-{i}");
            let id = create(&store, T0, &limits, &who);
            let secrets = start(&store, T0, &limits, &id, &who);
            (id, secrets)
        })
        .collect();
    // WHEN: 40 journeys are created and terminated across principals.
    let mut churned = Vec::new();
    for i in 0..40 {
        let who = format!("churn-{i}");
        let id = create(&store, T0 + 1 + i, &limits, &who);
        store
            .finish_journey(T0 + 1 + i, &limits, &id, JourneyStatus::Cancelled, None)
            .expect("a terminal transition never needs capacity");
        churned.push(id);
        let table = on_disk(&store, &config, &limits);
        assert!(
            table.journeys.len() <= 16,
            "record count exceeded records_max"
        );
        assert!(
            file_len(&config) <= limits.byte_cap(),
            "sealed file over its cap"
        );
    }
    // THEN: the oldest terminal records went first; the newest 13 remain.
    let table = on_disk(&store, &config, &limits);
    for (index, id) in churned.iter().enumerate() {
        assert_eq!(
            table.journeys.contains_key(id),
            index >= 27,
            "journey {index}"
        );
    }
    // AND: every started journey still completes through its callback.
    for (id, secrets) in &started {
        let consumed = store
            .consume_callback(T0 + 60, &limits, &secrets.state, Some(&secrets.binding))
            .expect("callbacks are never refused for capacity");
        assert_eq!(&consumed.journey_id, id);
    }
}

#[test]
fn t_flood_default_global_creation_rate_refuses_with_retry_after() {
    let (_root, _config, store) = fresh();
    let limits = JourneyLimits {
        journeys_per_user: 1000,
        ..limits()
    };
    for i in 0..120 {
        let id = create(&store, T0, &limits, &format!("p{i}"));
        store
            .finish_journey(T0, &limits, &id, JourneyStatus::Cancelled, None)
            .unwrap();
    }
    let over = store.create_journey(T0 + 1, &limits, request("late", "google"));
    assert_eq!(
        refused(over),
        JourneyRefusal::CapacityExceeded { retry_after: 59 }
    );
}

#[test]
fn t_c04c_every_terminal_record_holds_no_secret_and_stays_queryable() {
    // GIVEN: four started journeys, ended by connect, cancel, error and expiry.
    let (_root, config, store) = fresh();
    let limits = limits();
    let ends = [
        ("connect", Some(JourneyStatus::Connected)),
        ("cancel", Some(JourneyStatus::Cancelled)),
        ("error", Some(JourneyStatus::Failed)),
        ("expiry", None),
    ];
    let mut minted = Vec::new();
    for (who, end) in ends {
        let id = create(&store, T0, &limits, who);
        let secrets = start(&store, T0, &limits, &id, who);
        if let Some(status) = end {
            let consumed = store
                .consume_callback(T0 + 1, &limits, &secrets.state, Some(&secrets.binding))
                .unwrap();
            assert_eq!(consumed.verifier, secrets.verifier);
            store
                .finish_journey(T0 + 2, &limits, &id, status, None)
                .unwrap();
        }
        minted.push((id, secrets));
    }
    // WHEN: the expiry journey passes callback_by and the sweep runs.
    let late = T0 + CALLBACK_WINDOW + 1;
    let (expiry_id, _) = &minted[3];
    assert_eq!(
        store
            .journey_status(late, &limits, expiry_id)
            .unwrap()
            .status,
        JourneyStatus::Expired
    );
    store
        .create_journey(late, &limits, request("sweep", "google"))
        .unwrap();
    // THEN: on disk, no terminal record keeps a binding or verifier, and no
    // raw state, binding or verifier byte appears anywhere in the plaintext.
    let table = on_disk(&store, &config, &limits);
    let plaintext = serde_json::to_string(&table).unwrap();
    for (id, secrets) in &minted {
        let record = &table.journeys[id];
        assert!(record.binding_digest.is_none() && record.pkce_verifier.is_none());
        for raw in [&secrets.state, &secrets.binding, &secrets.verifier] {
            assert!(!plaintext.contains(raw.as_str()), "raw secret persisted");
        }
        assert!(
            store.journey_status(late, &limits, id).is_ok(),
            "still queryable"
        );
    }
}

#[test]
fn t_ct_state_binding_and_owner_comparisons_are_constant_time() {
    let (_root, _config, store) = fresh();
    let limits = limits();
    let before =
        [DigestKind::State, DigestKind::Binding, DigestKind::Owner].map(digest_comparisons);
    let id = create(&store, T0, &limits, "alice");
    let secrets = start(&store, T0, &limits, &id, "alice");
    store
        .consume_callback(T0 + 1, &limits, &secrets.state, Some(&secrets.binding))
        .unwrap();
    let after = [DigestKind::State, DigestKind::Binding, DigestKind::Owner].map(digest_comparisons);
    for (kind, (was, now)) in ["state", "binding", "owner"]
        .iter()
        .zip(before.iter().zip(after))
    {
        assert!(now > *was, "{kind} comparison bypassed ConstantTimeEq");
    }
}

fn maximal_record() -> JourneyRecord {
    let hex = |n: usize| "f".repeat(n);
    JourneyRecord {
        owner_digest: hex(64),
        account_id: "a".repeat(super::ACCOUNT_ID_MAX),
        descriptor_revision: hex(64),
        issuer: "i".repeat(super::ISSUER_MAX),
        expected: ConsentExpectation::ReconnectRequired(super::super::super::GrantVersion {
            generation: hex(32),
            token_revision: u64::MAX,
            authorization_epoch: u64::MAX,
            descriptor_revision: hex(64),
        }),
        return_path: "/".repeat(super::RETURN_PATH_MAX),
        status: JourneyStatus::Superseded,
        reason: Some(super::JourneyReason::UnexpectedTokenForm),
        consumed: true,
        state_digest: Some(hex(64)),
        binding_digest: Some(hex(64)),
        principal_digest: hex(64),
        digest_key_id: "k".repeat(super::KEY_ID_MAX),
        pkce_verifier: Some("v".repeat(43)),
        created_at: u64::MAX,
        start_by: u64::MAX,
        started_at: Some(u64::MAX),
        callback_by: Some(u64::MAX),
        terminal_at: Some(u64::MAX),
        replay_refusals: u32::MAX,
    }
}

#[test]
fn t_r2_5_over_cap_fields_are_refused_before_any_store_access() {
    let (_root, config, store) = fresh();
    let limits = limits();
    let long_account = request("alice", &"a".repeat(super::ACCOUNT_ID_MAX + 1));
    let mut long_path = request("alice", "google");
    long_path.return_path = format!("/{}", "p".repeat(super::RETURN_PATH_MAX));
    for new in [long_account, long_path] {
        assert_eq!(
            refused(store.create_journey(T0, &limits, new)),
            JourneyRefusal::InvalidRequest
        );
    }
    assert!(
        !config.authority_dir.join(super::JOURNEYS_FILE).exists(),
        "a refused POST must not have written the table"
    );
}

#[test]
fn t_r2_5_a_maximal_record_fits_record_max_rounded_to_256() {
    let serialized = serde_json::to_vec(&maximal_record()).unwrap();
    let expected = serde_json::to_vec(&maximal_record().expected).unwrap();
    assert!(
        expected.len() <= super::EXPECTATION_MAX,
        "serialized expectation over its EXPECTATION_MAX cap"
    );
    assert!(
        serialized.len() <= RECORD_MAX,
        "{} > RECORD_MAX",
        serialized.len()
    );
    assert_eq!(RECORD_MAX % 256, 0, "RECORD_MAX is rounded to 256 bytes");
    assert!(
        RECORD_MAX - serialized.len() < 256,
        "RECORD_MAX is not the rounded maximum"
    );
}

/// Drop the store (releasing its lifetime locks) and reopen it with new keys.
fn reload(
    store: PersonalAccountStore,
    config: &StoreConfig,
    current: &str,
    keys: &[(&str, [u8; 32])],
) -> (StoreConfig, PersonalAccountStore) {
    drop(store);
    let mut next = config.clone();
    next.current_key_id = current.into();
    next.keys = keys
        .iter()
        .map(|(id, key)| ((*id).to_owned(), key.to_vec()))
        .collect();
    let store = PersonalAccountStore::open(next.clone()).expect("reopen after reload");
    (next, store)
}

fn digest_key_of(store: &PersonalAccountStore, config: &StoreConfig, id: &str) -> String {
    on_disk(store, config, &limits()).journeys[id]
        .digest_key_id
        .clone()
}

#[test]
fn t_keyrot_digests_follow_the_recorded_key_not_the_current_one() {
    // GIVEN: two journeys started under k1.
    let (_root, config, store) = fresh();
    let limits = limits();
    let first = create(&store, T0, &limits, "alice");
    let first_secrets = start(&store, T0, &limits, &first, "alice");
    let second = create(&store, T0, &limits, "bob");
    let second_secrets = start(&store, T0, &limits, &second, "bob");
    // WHEN: the config reloads with current k2, keeping k1 readable.
    let (config, store) = reload(store, &config, "k2", &[("k1", K1), ("k2", K2)]);
    // THEN: the k1 callback validates, and new journeys record k2.
    let consumed = store
        .consume_callback(
            T0 + 1,
            &limits,
            &first_secrets.state,
            Some(&first_secrets.binding),
        )
        .expect("a k1 digest validates after rotation");
    assert_eq!(consumed.journey_id, first);
    let newer = create(&store, T0 + 1, &limits, "carol");
    start(&store, T0 + 1, &limits, &newer, "carol");
    assert_eq!(digest_key_of(&store, &config, &newer), "k2");
    // AND: with k1 removed (authority resealed under k2 first), the remaining
    // k1 journey fails closed as an unrecognised state.
    store
        .commit_grant(&owner("dave", "google"), &sealed_grant())
        .unwrap();
    let (_config, store) = reload(store, &config, "k2", &[("k2", K2)]);
    let refusal = store.consume_callback(
        T0 + 2,
        &limits,
        &second_secrets.state,
        Some(&second_secrets.binding),
    );
    assert_eq!(refused(refusal), JourneyRefusal::UnknownState);
}

#[test]
fn t_keyrot2_start_recaptures_the_digest_key_it_mints_under() {
    let (_root, config, store) = fresh();
    let limits = limits();
    let id = create(&store, T0, &limits, "alice");
    let (config, store) = reload(store, &config, "k2", &[("k1", K1), ("k2", K2)]);
    let secrets = start(&store, T0 + 1, &limits, &id, "alice");
    assert_eq!(
        digest_key_of(&store, &config, &id),
        "k2",
        "start re-captures the key"
    );
    store
        .consume_callback(T0 + 2, &limits, &secrets.state, Some(&secrets.binding))
        .expect("the callback validates under the re-captured key");
}

fn sealed_grant() -> GrantRecord {
    GrantRecord {
        generation: "fedcba9876543210fedcba9876543210".into(),
        token_revision: 1,
        authorization_epoch: 1,
        descriptor_revision: "0".repeat(64),
        scopes: vec!["https://www.googleapis.com/auth/drive.readonly".into()],
        access_token: "synthetic-access".into(),
        refresh_token: None,
        token_type: "Bearer".into(),
        expires_at: 0,
        provider_account_id: None,
        client_id: "synthetic-client".into(),
    }
}

#[test]
fn t_c03d_consumed_is_durable_so_a_replay_after_restart_is_refused() {
    // GIVEN: a consumed callback, then a crash before the exchange.
    let (_root, config, store) = fresh();
    let limits = limits();
    let id = create(&store, T0, &limits, "alice");
    let secrets = start(&store, T0, &limits, &id, "alice");
    store
        .consume_callback(T0 + 1, &limits, &secrets.state, Some(&secrets.binding))
        .unwrap();
    // WHEN: the store restarts and the same callback is replayed.
    let (config, store) = reload(store, &config, "k1", &[("k1", K1)]);
    let replay = store.consume_callback(T0 + 2, &limits, &secrets.state, Some(&secrets.binding));
    // THEN: refused as a replay, counted, and no verifier on disk.
    assert_eq!(refused(replay), JourneyRefusal::Replay);
    let record = &on_disk(&store, &config, &limits).journeys[&id];
    assert!(
        record.consumed,
        "consumed was persisted, not kept in memory"
    );
    assert!(
        record.pkce_verifier.is_none(),
        "the verifier left with the consume write"
    );
    assert_eq!(record.replay_refusals, 1);
}

#[test]
fn t_r3_2_a_late_first_callback_is_expiry_not_replay() {
    let (_root, _config, store) = fresh();
    let limits = limits();
    let id = create(&store, T0, &limits, "alice");
    let secrets = start(&store, T0, &limits, &id, "alice");
    let late = T0 + CALLBACK_WINDOW + 1;
    let first = store.consume_callback(late, &limits, &secrets.state, Some(&secrets.binding));
    assert_eq!(refused(first), JourneyRefusal::Expired);
    let view = store.journey_status(late, &limits, &id).unwrap();
    assert_eq!(view.status, JourneyStatus::Expired);
    assert_eq!(view.reason, Some(super::JourneyReason::Expired));
    assert!(!view.replay_refused);
    assert_eq!(view.replay_refusals, 0);
}
