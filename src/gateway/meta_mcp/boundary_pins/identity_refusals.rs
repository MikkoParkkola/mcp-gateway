// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The unit-row proofs the identity evidence table cites (see
//! `identity_evidence`): the two identity types that cannot be deserialized,
//! `GrantSubject` refusing a pair that names no one in each bypass form, the
//! grants file's own read-back, and the journal entry that holds no identity.

use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;

/// Compile-time: neither `VerifiedIdentity` nor `CertIdentity` can be
/// deserialized. If either implemented `DeserializeOwned`, both impls of
/// [`AmbiguousIfDeserialize`] would apply and `some_item` would be ambiguous,
/// so this module (the lib test build) would not compile. It runs in the lib
/// shards, apart from rustdoc, and names the cause the H1-H6 pairs share.
trait AmbiguousIfDeserialize<A> {
    fn some_item() {}
}
impl<T: ?Sized> AmbiguousIfDeserialize<()> for T {}
impl<T: serde::de::DeserializeOwned> AmbiguousIfDeserialize<u8> for T {}
/// The ambiguity check as a named row: it compiles only while neither type
/// implements `DeserializeOwned`, so the evidence table can cite it.
#[test]
fn verified_and_cert_identities_cannot_be_deserialized() {
    let _ = <VerifiedIdentity as AmbiguousIfDeserialize<_>>::some_item;
    let _ = <CertIdentity as AmbiguousIfDeserialize<_>>::some_item;
}

/// A pair naming no one, and the same pair naming someone.
const NAMELESS: &str = r#"{"authority":"api_key","subject":""}"#;
const NAMED: &str = r#"{"authority":"api_key","subject":"alice"}"#;
/// What `GrantSubject`'s checked deserialization says about [`NAMELESS`].
const REFUSAL: &str = "the identity's subject is empty";

/// Asserts `read` refuses [`NAMELESS`] with the subject named as empty, and
/// reads [`NAMED`]: the shape deserializes, and only the empty part refuses.
fn refuses_only_the_nameless<T>(read: impl Fn(&str) -> serde_json::Result<T>) {
    let refused = read(NAMELESS).err().map(|e| e.to_string());
    assert!(
        refused.as_deref().is_some_and(|e| e.contains(REFUSAL)),
        "a pair naming no one must be refused as such: {refused:?}"
    );
    assert!(
        read(NAMED).is_ok(),
        "control: the same shape naming someone reads"
    );
}

/// H1: a struct deriving `Deserialize` under another name still reads its
/// `GrantSubject` through the checked path.
#[test]
fn h1_an_aliased_derive_refuses_a_grant_subject_naming_no_one() {
    use serde::Deserialize as D;
    #[derive(D)]
    struct Holder {
        _g: GrantSubject,
    }
    refuses_only_the_nameless(|pair| {
        serde_json::from_str::<Holder>(&format!(r#"{{"_g":{pair}}}"#))
    });
}

/// H2: an array field, the item boundary the scanner cut short.
#[test]
fn h2_an_array_of_grant_subjects_refuses_one_naming_no_one() {
    refuses_only_the_nameless(|pair| {
        serde_json::from_str::<[GrantSubject; 1]>(&format!("[{pair}]"))
    });
}

/// H4: a deserializer imported under another name.
#[test]
fn h4_an_aliased_deserializer_refuses_a_grant_subject_naming_no_one() {
    use serde_json::from_str as f;
    refuses_only_the_nameless(|pair| f::<GrantSubject>(pair));
}

/// H5: a read-back typed `Self` inside an impl of the carrier.
trait ReadBack: Sized {
    fn read_back(text: &str) -> serde_json::Result<Self>;
}
impl ReadBack for GrantSubject {
    fn read_back(text: &str) -> serde_json::Result<Self> {
        serde_json::from_str(text)
    }
}

#[test]
fn h5_a_self_read_back_refuses_a_grant_subject_naming_no_one() {
    refuses_only_the_nameless(GrantSubject::read_back);
}

/// H6: a block expression initializing a typed `let`.
#[test]
fn h6_a_block_initializer_refuses_a_grant_subject_naming_no_one() {
    refuses_only_the_nameless(|pair| {
        let read: serde_json::Result<GrantSubject> = { serde_json::from_str(pair) };
        read
    });
}

/// `parse_refusal`'s own read-back: a JSON grants file whose row names no one
/// is refused, the refusal built from the JSON re-read naming the empty part.
#[tokio::test]
async fn a_json_grants_file_naming_no_one_is_refused_by_parse_refusal() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("grants.json");
    let file = r#"{"schema_version":"identity_grants.v1","grants":[{"grant_id":"g-empty","subject":{"authority":"api_key","subject":""},"agent":"any","capability":"calendar_read","scope":"execute","owner":{"authority":"api_key","subject":"alice"},"provenance":"mcp-gateway identity grants grant","reason":"empty"}]}"#;
    crate::gateway::test_helpers::write_owner_only(&path, file).expect("write");
    let error = crate::identity_grants::read_identity_grants_file(&path)
        .await
        .expect_err("a row naming no one must not load");
    assert!(error.contains(&path.display().to_string()), "path: {error}");
    assert!(
        error.contains("1 row(s) name no one: grant 'g-empty' (empty subject)"),
        "the row and its empty part are named: {error}"
    );
    let named = file.replacen(r#""subject":"""#, r#""subject":"bob""#, 1);
    assert_ne!(named, file, "premise: the control names the subject");
    crate::gateway::test_helpers::write_owner_only(&path, &named).expect("write");
    crate::identity_grants::read_identity_grants_file(&path)
        .await
        .expect("control: the same file naming its subject loads");
}

/// `parse_journal` reads `JournalEntry`: grant ids and digests, no identity.
/// The scanner flags it only because its statement slice runs past the fn end
/// into the next fn's `IdentityGrant` signature. The closure below destructures
/// an entry exhaustively, with each field's type written out, and matches every
/// verb, so it stops compiling if an entry or a verb gains a field or a variant:
/// a journal that starts carrying an identity cannot build unnoticed.
#[test]
fn a_journal_entry_carries_no_identity() {
    use crate::identity_grants::journal::{JournalEntry, JournalVerb};
    use chrono::{DateTime, Utc};
    let fields_are_not_identities: fn(JournalEntry) = |entry| {
        let JournalEntry {
            v,
            entry_id,
            verb,
            grant_id,
            prev_digest,
            digest,
            expires_at,
            at,
            actor,
            os_account,
        } = entry;
        let _: u32 = v;
        let _: String = entry_id;
        let _: String = grant_id;
        let _: Option<String> = prev_digest;
        let _: String = digest;
        let _: Option<DateTime<Utc>> = expires_at;
        let _: DateTime<Utc> = at;
        let _: String = actor;
        let _: Option<String> = os_account;
        match verb {
            JournalVerb::Add | JournalVerb::Replace | JournalVerb::Revoke => {}
        }
    };
    let _ = fields_are_not_identities;
}
