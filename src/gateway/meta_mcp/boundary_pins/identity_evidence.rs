// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Evidence that the compiler, and the identity types' checked
//! deserialization, cover every case `scripts/release/check_identity_sources.py`
//! catches. [`CASES`] names the proofs for each case. The rows below keep the
//! table in step with the script, check that each named proof exists and has
//! the required shape, and hold the proofs that are unit rows.

use super::packaged::{PinnedFile, crate_root, read_or_skip, repo_file};
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;

/// The three identity leaf modules.
const LEAVES: [&str; 3] = [
    "src/identity_grants/subject.rs",
    "src/key_server/oidc/verified.rs",
    "src/mtls/identity/cert.rs",
];
/// The compile-time pairs: each a `compile_fail` block and its one-line twin.
const EVIDENCE: &str = "src/identity_evidence.rs";

/// `GrantSubject::new` is checked: a value only after its `Result` is handled,
/// and a pair naming no one is refused.
const NEW_IS_CHECKED: &[&str] = &[
    "doc:NEW-GS",
    "row:src/identity_grants_subject_tests.rs#new_refuses_a_subject_naming_no_one_and_names_the_empty_part",
];

/// One row per case the scanner catches: the case as the script keys it, then
/// its proofs. A proof is `doc:<ID>` (a pair in [`EVIDENCE`]) or
/// `row:<file>#<fn>` (a unit row).
const CASES: &[(&str, &[&str])] = &[
    (
        "ALLOWED src/key_server/oidc/verified.rs checked VerifiedIdentity {",
        &["doc:LIT-VI"],
    ),
    (
        "ALLOWED src/identity_grants/subject.rs new GrantSubject {",
        &["doc:LIT-GS"],
    ),
    (
        "ALLOWED src/mtls/identity/cert.rs parse CertIdentity {",
        &["doc:LIT-CI"],
    ),
    (
        "ALLOWED src/decisions/mod.rs access_key GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    (
        "ALLOWED src/decisions/mod.rs covered GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    (
        "ALLOWED src/decisions/mod.rs denial_from_record GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    (
        "ALLOWED src/gateway/meta_mcp/invoke/budget.rs grant_subject_from_api_key GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    (
        "ALLOWED src/gateway/router/identity.rs grant_subject_from_cert_identity GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    (
        "ALLOWED src/gateway/router/identity.rs grant_subject_from_oauth_agent GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    (
        "ALLOWED src/gateway/router/identity.rs grant_subject_from_verified_identity GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    (
        "ALLOWED src/gateway/router/identity.rs trusted_proxy_identity GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    (
        "ALLOWED src/gateway/ui/admin_audit.rs caller_who GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    (
        "ALLOWED src/gateway/ui/admin_audit.rs recorded GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    (
        "ALLOWED src/gateway/ui/events.rs admitted GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    (
        "ALLOWED src/gateway/ui/tool_call.rs via_label GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    (
        "ALLOWED src/identity_grants/subject.rs try_from GrantSubject::new(",
        NEW_IS_CHECKED,
    ),
    ("RULE_SITES src/commands/identity.rs", NEW_IS_CHECKED),
    (
        "READ_BACKS src/capability/parser.rs parse_capability",
        &["row:src/identity_grants_subject_tests.rs#a_capability_owner_naming_no_one_is_refused"],
    ),
    (
        "READ_BACKS src/capability/file_writer_headers.rs check",
        &[
            "row:src/capability/file_writer_headers.rs#an_owner_naming_no_one_is_refused_by_the_header_check",
        ],
    ),
    (
        "READ_BACKS src/identity_grants.rs read_identity_grants_file_with_bytes",
        &[
            "row:src/identity_grants_subject_tests.rs#a_grants_yaml_naming_no_one_is_refused_with_its_path_and_rule_id",
        ],
    ),
    (
        "READ_BACKS src/identity_grants/journal.rs parse_journal",
        &[
            "row:src/gateway/meta_mcp/boundary_pins/identity_evidence.rs#a_journal_entry_carries_no_identity",
        ],
    ),
    (
        "READ_BACKS src/identity_grants_matching.rs parse_refusal",
        &[
            "row:src/gateway/meta_mcp/boundary_pins/identity_evidence.rs#a_json_grants_file_naming_no_one_is_refused_by_parse_refusal",
        ],
    ),
    (
        "READ_BACKS src/identity_grants_matching.rs remainder_error",
        &[
            "row:src/identity_grants_subject_tests.rs#a_nameless_row_behind_a_bare_one_is_the_remainder_error",
        ],
    ),
    (
        "H1",
        &[
            "doc:H1",
            "row:src/gateway/meta_mcp/boundary_pins/identity_evidence.rs#h1_an_aliased_derive_refuses_a_grant_subject_naming_no_one",
        ],
    ),
    (
        "H2",
        &[
            "doc:H2",
            "row:src/gateway/meta_mcp/boundary_pins/identity_evidence.rs#h2_an_array_of_grant_subjects_refuses_one_naming_no_one",
        ],
    ),
    ("H3", &["doc:H3"]),
    (
        "H4",
        &[
            "doc:H4",
            "doc:H4-SPACED",
            "row:src/gateway/meta_mcp/boundary_pins/identity_evidence.rs#h4_an_aliased_deserializer_refuses_a_grant_subject_naming_no_one",
        ],
    ),
    (
        "H5",
        &[
            "doc:H5",
            "row:src/gateway/meta_mcp/boundary_pins/identity_evidence.rs#h5_a_self_read_back_refuses_a_grant_subject_naming_no_one",
        ],
    ),
    (
        "H6",
        &[
            "doc:H6",
            "row:src/gateway/meta_mcp/boundary_pins/identity_evidence.rs#h6_a_block_initializer_refuses_a_grant_subject_naming_no_one",
        ],
    ),
    ("H7", &["doc:H7"]),
    ("H8", &["doc:H8"]),
];

/// A source file of this crate (always packaged, so never a skip).
fn source(rel: &str) -> String {
    read_or_skip(crate_root(), rel, false).expect("a source file is read or the read panics")
}

/// The quoted strings of one Python literal line, in order: `("a", "b"): ...`
/// gives `["a", "b"]`.
fn quoted(line: &str) -> Vec<&str> {
    line.split('"').skip(1).step_by(2).collect()
}

/// The key lines of the script's `NAME = {` dict, up to its closing `}`.
fn dict_keys<'a>(script: &'a str, name: &str) -> Vec<Vec<&'a str>> {
    let open = format!("{name} = {{");
    let start = script
        .find(&open)
        .unwrap_or_else(|| panic!("the script defines {name}"));
    script[start + open.len()..]
        .lines()
        .take_while(|line| line.trim() != "}")
        .map(str::trim)
        .filter(|line| line.starts_with("(\""))
        .map(|line| quoted(line.split("):").next().unwrap_or(line)))
        .collect()
}

/// The case ids the scanner catches today, built from its own lists.
fn script_cases(script: &str) -> Vec<String> {
    let mut cases: Vec<String> = dict_keys(script, "ALLOWED")
        .into_iter()
        .map(|key| format!("ALLOWED {}", key.join(" ")))
        .chain(
            dict_keys(script, "READ_BACKS")
                .into_iter()
                .map(|key| format!("READ_BACKS {}", key.join(" "))),
        )
        .collect();
    let rule_sites = script
        .lines()
        .find(|line| line.starts_with("RULE_SITES = {"))
        .expect("the script defines RULE_SITES");
    cases.extend(
        quoted(rule_sites)
            .into_iter()
            .map(|site| format!("RULE_SITES {site}")),
    );
    cases.extend((1..=8).map(|n| format!("H{n}")));
    cases.sort();
    cases
}

/// The table's case ids equal the cases the script catches: `ALLOWED`, `READ_BACKS`
/// and `RULE_SITES` read from the script, plus H1-H8. A row added to or dropped
/// from the script fails here until the table follows.
#[test]
fn the_table_names_every_case_the_scanner_catches() {
    let Some(script) = repo_file(PinnedFile::IdentityScanner) else {
        return;
    };
    let mut table: Vec<String> = CASES.iter().map(|(case, _)| (*case).to_owned()).collect();
    table.sort();
    let script = script_cases(&script);
    assert_eq!(
        script.len(),
        31,
        "premise: 16 ALLOWED, 6 READ_BACKS, 1 RULE_SITES, H1-H8: {script:?}"
    );
    assert_eq!(table, script);
}

/// One evidence pair: its id, then each block's fence info and body lines.
struct Pair {
    id: String,
    fail_info: String,
    fail: Vec<String>,
    twin_info: String,
    twin: Vec<String>,
}

/// The `compile_fail` block and twin after each `evidence:` line, in order.
fn pairs(evidence: &str) -> Vec<Pair> {
    let lines: Vec<&str> = evidence.lines().collect();
    let mut out = Vec::new();
    let mut at = 0;
    while at < lines.len() {
        let Some(id) = lines[at].strip_prefix("//! evidence: ") else {
            at += 1;
            continue;
        };
        let mut blocks = Vec::new();
        let mut i = at + 1;
        while blocks.len() < 2 && i < lines.len() {
            if let Some(info) = lines[i].strip_prefix("//! ```") {
                let body: Vec<String> = lines[i + 1..]
                    .iter()
                    .take_while(|line| **line != "//! ```")
                    .map(|line| (*line).to_owned())
                    .collect();
                i += body.len() + 2;
                blocks.push((info.to_owned(), body));
            } else {
                i += 1;
            }
        }
        assert_eq!(
            blocks.len(),
            2,
            "evidence {id} has a compile_fail block and a twin"
        );
        let (twin_info, twin) = blocks.pop().expect("two blocks");
        let (fail_info, fail) = blocks.pop().expect("two blocks");
        out.push(Pair {
            id: id.to_owned(),
            fail_info,
            fail,
            twin_info,
            twin,
        });
        at = i;
    }
    out
}

/// Every pair is a `compile_fail` block then a plain (compiled and run) twin,
/// and the two differ in exactly one line, so the twin passing puts the
/// failure on that line. Stable rustdoc ignores a `compile_fail` error code,
/// so the twin is what names the cause.
#[test]
fn each_compile_fail_has_a_one_line_twin() {
    let found = pairs(&source(EVIDENCE));
    assert_eq!(found.len(), 13, "premise: the 13 pairs are read");
    for pair in found {
        let id = &pair.id;
        assert_eq!(
            pair.fail_info, "compile_fail",
            "{id}: the first block must fail to compile"
        );
        assert_eq!(
            pair.twin_info, "",
            "{id}: the twin must be compiled and run, not ignored"
        );
        assert_eq!(
            pair.fail.len(),
            pair.twin.len(),
            "{id}: same number of lines"
        );
        let differing = pair
            .fail
            .iter()
            .zip(&pair.twin)
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(differing, 1, "{id}: exactly one line differs");
    }
}

/// The names of the test fns in `text` (`#[test]` or an attribute ending in
/// `::test`, such as `#[tokio::test]`), at any depth.
fn test_fns(text: &str) -> Vec<String> {
    struct Tests(Vec<String>);
    impl<'ast> syn::visit::Visit<'ast> for Tests {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            let is_test = item.attrs.iter().any(|attr| {
                attr.path()
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "test")
            });
            if is_test {
                self.0.push(item.sig.ident.to_string());
            }
            syn::visit::visit_item_fn(self, item);
        }
    }
    let file = syn::parse_file(text).expect("the file parses");
    let mut tests = Tests(Vec::new());
    syn::visit::Visit::visit_file(&mut tests, &file);
    tests.0
}

/// Every proof the table names exists: each `doc:` id is a pair in the
/// evidence module, each `row:` names a fn in its file, and every pair in the
/// module is named by some case.
#[test]
fn every_proof_the_table_names_exists() {
    let ids: Vec<String> = pairs(&source(EVIDENCE))
        .into_iter()
        .map(|pair| pair.id)
        .collect();
    let mut named = Vec::new();
    for (case, proofs) in CASES {
        assert!(!proofs.is_empty(), "{case}: at least one proof");
        for proof in *proofs {
            if let Some(id) = proof.strip_prefix("doc:") {
                assert!(ids.iter().any(|known| known == id), "{case}: no pair {id}");
                named.push(id);
            } else if let Some(row) = proof.strip_prefix("row:") {
                let (file, name) = row.split_once('#').expect("row:<file>#<fn>");
                assert!(
                    test_fns(&source(file)).iter().any(|test| test == name),
                    "{case}: {file} has no test fn {name}"
                );
            } else {
                panic!("{case}: unknown proof {proof}");
            }
        }
    }
    for id in &ids {
        assert!(
            named.contains(&id.as_str()),
            "pair {id} is named by no case"
        );
    }
}

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
const _: fn() = || {
    let _ = <VerifiedIdentity as AmbiguousIfDeserialize<_>>::some_item;
    let _ = <CertIdentity as AmbiguousIfDeserialize<_>>::some_item;
};

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
        let _: (
            u32,
            String,
            String,
            Option<String>,
            String,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
            String,
            Option<String>,
        ) = (
            v,
            entry_id,
            grant_id,
            prev_digest,
            digest,
            expires_at,
            at,
            actor,
            os_account,
        );
        match verb {
            JournalVerb::Add | JournalVerb::Replace | JournalVerb::Revoke => {}
        }
    };
    let _ = fields_are_not_identities;
}

/// Every `mod` item in `text`, at any depth (inside an inline module or a fn
/// body too), whatever its visibility: each would see its ancestors' private
/// fields.
fn child_modules(text: &str) -> Vec<String> {
    struct Mods(Vec<String>);
    impl<'ast> syn::visit::Visit<'ast> for Mods {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            self.0.push(item.ident.to_string());
            syn::visit::visit_item_mod(self, item);
        }
    }
    let file = syn::parse_file(text).expect("the text parses");
    let mut mods = Mods(Vec::new());
    syn::visit::Visit::visit_file(&mut mods, &file);
    mods.0
}

/// The child scan sees every declaration form a production child could take.
#[test]
fn the_child_scan_sees_every_module_form() {
    let forms = "mod a; pub mod b; pub(crate) mod c; pub(self) mod d; pub(super) mod e; \
                 pub(in crate::x) mod f; mod g {} fn h() { mod i {} }";
    assert_eq!(
        child_modules(forms),
        ["a", "b", "c", "d", "e", "f", "g", "i"]
    );
}

/// EV.3: the three identity leaf modules declare no child module
/// outside test code. A child would see the private fields, so a literal or a
/// field write there would compile.
#[test]
fn identity_leaf_modules_declare_no_production_children() {
    assert_eq!(
        child_modules(&source("src/key_server/oidc/verified.rs")),
        ["tests"],
        "premise: the raw text shows verified.rs's test child, so blanking it is what passes"
    );
    for leaf in LEAVES {
        let production = crate::test_source_text::production_text(&source(leaf));
        let children = child_modules(&production);
        assert!(
            children.is_empty(),
            "{leaf} declares a production child: {children:?}"
        );
    }
}

/// The identity types' fields stay private to their leaf module. The literal
/// pairs run as an outside crate, so they cannot show that code in this crate
/// is refused too; private fields show it for every module but the leaf's own.
#[test]
fn the_identity_types_fields_stay_private_to_their_leaf() {
    for (leaf, ty) in LEAVES
        .iter()
        .zip(["GrantSubject", "VerifiedIdentity", "CertIdentity"])
    {
        let file = syn::parse_file(&source(leaf)).expect("the leaf parses");
        let fields = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == ty => Some(&item.fields),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{leaf} defines {ty}"));
        assert!(!fields.is_empty(), "premise: {ty} has fields");
        for field in fields {
            assert!(
                matches!(field.vis, syn::Visibility::Inherited),
                "{leaf}: a field of {ty} is visible outside its module"
            );
        }
    }
}
