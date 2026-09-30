// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2142: a collection of another schema version is refused, on read and write.

use super::*;

// #2142: a collection written in another format version is refused, naming
// the file and both versions, and a write leaves it untouched.
#[test]
fn a_collection_of_another_schema_version_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(dir.path());
    store
        .put_grant(grant("g1", ControlPlaneGrantStatus::Approved))
        .unwrap();
    store.put_policy(policy("p1", true)).unwrap();

    for name in ["grants.json", "policies.json"] {
        let path = dir.path().join("store").join(name);
        let good = std::fs::read(&path).unwrap();
        for version in [0_u32, 2] {
            let mut doc: serde_json::Value = serde_json::from_slice(&good).unwrap();
            doc["schema_version"] = version.into();
            let written = serde_json::to_vec(&doc).unwrap();
            std::fs::write(&path, &written).unwrap();

            let (read, write) = if name == "grants.json" {
                (
                    store.list_grants().map(drop),
                    store.put_grant(grant("g2", ControlPlaneGrantStatus::Requested)),
                )
            } else {
                (
                    store.list_policies().map(drop),
                    store.put_policy(policy("p2", false)),
                )
            };
            let message = match read {
                Err(StoreError::Corrupt(message)) => message,
                other => panic!("{name} at version {version}: {other:?}"),
            };
            for part in [
                name,
                format!("schema_version {version}").as_str(),
                "supports 1",
            ] {
                assert!(message.contains(part), "{part:?} missing: {message}");
            }
            assert!(
                matches!(write, Err(StoreError::Corrupt(_))),
                "{name} v{version}: {write:?}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), written, "{name} rewritten");
        }
        std::fs::write(&path, &good).unwrap();
    }
    assert_eq!(store.list_grants().unwrap().len(), 1);
    assert_eq!(store.list_policies().unwrap().len(), 1);
}

// #2142: the locked compare-and-swap re-reads through the same check, so a
// file swapped to another version at the caller's generation is not rewritten.
#[test]
fn a_compare_and_swap_refuses_a_collection_of_another_schema_version() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(dir.path());
    store
        .put_grant(grant("g1", ControlPlaneGrantStatus::Approved))
        .unwrap();
    let path = store.grants_file();
    let generation = FileControlPlaneStore::load::<ControlPlaneGrant>(&path)
        .unwrap()
        .generation;
    let mut doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    doc["schema_version"] = 2.into();
    let written = serde_json::to_vec(&doc).unwrap();
    std::fs::write(&path, &written).unwrap();

    let items = vec![grant("g2", ControlPlaneGrantStatus::Requested)];
    assert!(matches!(
        store.store_cas(&path, &items, generation, FaultPoint::None),
        Err(StoreError::Corrupt(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), written);
}

// #2142: the version is judged before the items, so a later format whose items
// do not parse as this build's is refused for its version, not as bad JSON.
#[test]
fn the_version_is_refused_before_the_items_are_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_store(dir.path());
    store.put_policy(policy("p1", true)).unwrap();
    let path = store.policies_file();
    std::fs::write(
        &path,
        br#"{"schema_version":2,"generation":1,"items":{"renamed":[]}}"#,
    )
    .unwrap();
    match store.list_policies() {
        Err(StoreError::Corrupt(message)) => {
            assert!(message.contains("schema_version 2"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}
