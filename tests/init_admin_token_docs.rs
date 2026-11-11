// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Custody documentation follows the existing upgrading document-content rows.

/// ADMINTOK.3 / design 8: security, upgrading and (once the privacy statement
/// exists) privacy describe init's store/reference custody and remove the old
/// plaintext-init claims. The privacy statement is another change's document:
/// when it is absent from the tree, only the two existing documents are judged.
#[test]
fn admintok_3_documents_describe_init_store_references_without_plaintext_claims() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (file, obsolete) in [
        ("SECURITY.md", "the config with its admin token"),
        (
            "docs/UPGRADING-4.0.md",
            "`auth.bearer_token` and `key_server.admin_token` are unchanged and still plaintext",
        ),
        ("docs/PRIVACY.md", "the config with its admin token"),
    ] {
        let Ok(doc) = std::fs::read_to_string(root.join(file)) else {
            assert_eq!(file, "docs/PRIVACY.md", "{file} must exist");
            continue;
        };
        let doc = doc.replace("\r\n", "\n");
        assert!(
            !doc.contains(obsolete),
            "{file} still claims plaintext custody"
        );
        assert!(
            doc.split("\n\n").any(|paragraph| paragraph.contains("init")
                && paragraph.contains("reference")
                && paragraph.contains("secrets.store")),
            "{file} must explain init's store and reference in one paragraph"
        );
    }
}
