// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The settings save: stale revisions, all or nothing across the file and the
//! secret store, the owner field, and nothing lost.

use crate::config_reload::reload_context::replace::RefusalClass;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{SaveEdit, SaveValue, SecretTarget, UiSaved, ui_save};
use crate::config_persistence::keyedit::Scalar;
use crate::config_reload::ReloadContext;
use crate::config_reload::reload_context::replace::ui_diff::{Shown, UiRefused, ui_diff};
use crate::config_reload::reload_context::replace::{AuditPosture, FileRevision, GatewayAuth};
use crate::config_reload::replace_test_support::{WAIT, context, read, refusing_context};
use crate::config_reload::ui_fields::{FieldId, Param, PreviewEdit, PreviewValue};
use crate::gateway::test_helpers::write_owner_only;
use crate::secret_store::{FilesStore, SecretStore, StoreError, StoreKind, Vault, unused_entries};
use crate::wiped_bytes::WipedBytes;

const BASE: &str = "# operator's note\nenvironment: \"dev\" # where\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\" # first\n";
const TOKEN: &[u8] = b"zq-ui-save-bearer-one";

/// The files store, counting creates; `fail` refuses every create.
struct Counting {
    inner: FilesStore,
    creates: AtomicUsize,
    fail: bool,
}

impl SecretStore for Counting {
    fn kind(&self) -> StoreKind {
        self.inner.kind()
    }
    fn limit(&self) -> usize {
        self.inner.limit()
    }
    fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe()
    }
    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        self.inner.exists(name)
    }
    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        self.creates.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(StoreError::Unavailable("refused (test)".to_owned()));
        }
        self.inner.create(name, value)
    }
    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.inner.delete(name)
    }
}

struct Gw {
    dir: std::sync::Arc<tempfile::TempDir>,
    path: std::path::PathBuf,
    ctx: Arc<ReloadContext>,
    store: Arc<Counting>,
}

fn gw_with(text: &str, refusing: bool, fail: bool) -> Gw {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, text).expect("write");
    let ctx = if refusing {
        refusing_context(&path)
    } else {
        context(&path)
    };
    let store = Arc::new(Counting {
        inner: FilesStore::new(dir.path()),
        creates: AtomicUsize::new(0),
        fail,
    });
    Gw {
        dir,
        path,
        ctx,
        store,
    }
}

fn gw(text: &str) -> Gw {
    gw_with(text, false, false)
}

impl Gw {
    fn base(&self) -> FileRevision {
        FileRevision::of(read(&self.path).as_bytes())
    }
    fn creates(&self) -> usize {
        self.store.creates.load(Ordering::SeqCst)
    }
    /// Every live entry in the store, named or not.
    fn entries(&self) -> Vec<String> {
        let vault = Vault::with_lock(self.dir.path(), self.dir.path().join("vault.lock"));
        unused_entries(&vault, &[&self.store.inner], &BTreeSet::new())
            .expect("list entries")
            .into_iter()
            .map(|e| e.name)
            .collect()
    }
    async fn save(
        &self,
        base: FileRevision,
        fields: Vec<(&str, SaveValue)>,
    ) -> Result<UiSaved, UiRefused> {
        let fields = fields
            .into_iter()
            .map(|(id, value)| (field(id), Param::default(), value))
            .collect();
        self.save_as(AuditPosture::of(None, GatewayAuth::Off), base, fields)
            .await
    }

    async fn save_as(
        &self,
        posture: AuditPosture,
        base: FileRevision,
        fields: Vec<(FieldId, Param, SaveValue)>,
    ) -> Result<UiSaved, UiRefused> {
        let target = SecretTarget {
            vault: Vault::with_lock(self.dir.path(), self.dir.path().join("vault.lock")),
            store: Arc::clone(&self.store) as Arc<dyn SecretStore + Send + Sync>,
        };
        ui_save(
            Arc::clone(&self.ctx),
            posture,
            base,
            SaveEdit { fields },
            Some(target),
            WAIT,
        )
        .await
    }
}

fn field(id: &str) -> FieldId {
    FieldId::of(id).expect("in FIELDS")
}

fn s(text: &str) -> SaveValue {
    SaveValue::Set(Scalar::Str(text.to_owned()))
}

fn secret(value: &[u8]) -> SaveValue {
    SaveValue::Secret(WipedBytes::new(value.to_vec()))
}

/// SAVE.1: a save whose preview predates a hand edit writes nothing, makes
/// no entry, and answers with the preview of the file as it is now.
#[tokio::test]
async fn a_save_after_a_hand_edit_writes_nothing_and_returns_a_fresh_preview() {
    let gw = gw(BASE);
    let base = gw.base();
    let edited = BASE.replace("dev", "staging");
    write_owner_only(&gw.path, &edited).expect("hand edit");

    let refused = gw
        .save(
            base,
            vec![
                ("environment", s("prod")),
                ("auth.bearer_token", secret(TOKEN)),
            ],
        )
        .await
        .expect_err("SAVE.1: the file changed since the preview");

    assert_eq!(read(&gw.path), edited, "SAVE.1: the save wrote");
    assert_eq!(gw.creates(), 0, "SAVE.1: an entry was created");
    let UiRefused::Stale(fresh) = refused else {
        panic!("SAVE.1: not a fresh preview: {refused:?}");
    };
    assert_eq!(fresh.revision, FileRevision::of(edited.as_bytes()));
}

/// SAVE.2: a refused save leaves the file and the store as they were.
#[tokio::test]
async fn a_refused_save_leaves_store_and_file_unchanged() {
    let gw = gw(BASE);
    let refusals = [
        // A field every feature set has, given a value of the wrong kind.
        vec![("auth.enabled", SaveValue::Set(Scalar::Int(1)))],
        vec![
            ("auth.bearer_token", s("plain")),
            ("environment", s("prod")),
        ],
    ];
    for fields in refusals {
        gw.save(gw.base(), fields)
            .await
            .expect_err("SAVE.2: refused");
        assert_eq!(read(&gw.path), BASE, "SAVE.2: the file changed");
        assert_eq!(gw.creates(), 0, "SAVE.2: an entry was created");
    }
}

/// SAVE.2: a new secret goes to a fresh entry; the entry the file named
/// before stays, and the file names only the new one.
#[tokio::test]
async fn a_secret_save_keeps_the_old_entry_and_names_the_new_one() {
    let gw = gw(BASE);
    gw.save(gw.base(), vec![("auth.bearer_token", secret(TOKEN))])
        .await
        .expect("the first bearer saves");
    let first = gw.entries();
    assert_eq!(first.len(), 1, "{first:?}");
    assert!(read(&gw.path).contains(&first[0]), "{}", read(&gw.path));

    gw.save(
        gw.base(),
        vec![("auth.bearer_token", secret(b"zq-ui-save-bearer-two"))],
    )
    .await
    .expect("the second bearer saves");

    let now = gw.entries();
    assert_eq!(now.len(), 2, "SAVE.2: the old entry was removed: {now:?}");
    let new: Vec<_> = now.iter().filter(|e| !first.contains(e)).collect();
    let text = read(&gw.path);
    assert!(
        text.contains(new[0].as_str()) && !text.contains(&first[0]),
        "SAVE.2: the file does not name only the new entry: {text}"
    );
}

/// SAVE.2: a store that refuses the entry leaves no file change.
#[tokio::test]
async fn a_store_refusal_writes_no_config() {
    let gw = gw_with(BASE, false, true);
    let refused = gw
        .save(
            gw.base(),
            vec![
                ("auth.bearer_token", secret(TOKEN)),
                ("environment", s("prod")),
            ],
        )
        .await
        .expect_err("SAVE.2: the store refused");
    assert!(
        matches!(refused, UiRefused::SecretsRefused { .. }),
        "{refused:?}"
    );
    assert_eq!(read(&gw.path), BASE, "SAVE.2: the file changed");
    assert_eq!(gw.entries(), Vec::<String>::new());
}

/// SAVE.2: a commit the reload refuses is rolled back: the old file is
/// restored and still loads, and the new entry is removed.
#[tokio::test]
async fn a_commit_the_reload_refuses_restores_the_config_and_removes_the_entry() {
    let gw = gw_with(BASE, true, false);
    gw.save(
        gw.base(),
        vec![
            ("auth.bearer_token", secret(TOKEN)),
            ("environment", s("prod")),
        ],
    )
    .await
    .expect_err("SAVE.2: the reload refused");
    assert_eq!(read(&gw.path), BASE, "SAVE.2: the old file is not back");
    crate::config::Config::load(Some(&gw.path)).expect("SAVE.2: the old file loads");
    assert_eq!(
        gw.creates(),
        1,
        "premise: the entry was created before the commit"
    );
    assert_eq!(
        gw.entries(),
        Vec::<String>::new(),
        "SAVE.2: the new entry is left"
    );
}

/// SAVE.2: a save of a secret alone changes only that secret's lines.
#[tokio::test]
async fn a_secret_only_save_changes_only_its_line() {
    let gw = gw(BASE);
    gw.save(gw.base(), vec![("auth.bearer_token", secret(TOKEN))])
        .await
        .expect("the secret saves");
    let text = read(&gw.path);
    let added: Vec<&str> = text
        .lines()
        .filter(|l| !BASE.lines().any(|b| b == *l))
        .collect();
    assert!(
        BASE.lines().all(|b| text.lines().any(|l| l == b)),
        "a line was lost:\n{text}"
    );
    assert!(
        added
            .iter()
            .all(|l| l.trim() == "auth:" || l.trim_start().starts_with("bearer_token:")),
        "SAVE.2: more than the secret changed: {added:?}"
    );
}

/// SAVE.3: the owner is saved through the same path; an empty one removes
/// the key.
#[tokio::test]
async fn an_empty_owner_removes_the_key_through_the_save() {
    let gw = gw(BASE);
    let on_a = Param {
        backend: Some("a".to_owned()),
        index: None,
    };
    let owner = |value: &str| vec![(field("backends.owner"), on_a.clone(), s(value))];
    let off = || AuditPosture::of(None, GatewayAuth::Off);

    gw.save_as(off(), gw.base(), owner("team-a"))
        .await
        .expect("SAVE.3: the owner saves");
    assert!(
        read(&gw.path).contains("owner: \"team-a\""),
        "{}",
        read(&gw.path)
    );

    gw.save_as(off(), gw.base(), owner("  "))
        .await
        .expect("SAVE.3: the empty owner saves");
    assert_eq!(read(&gw.path), BASE, "SAVE.3: the owner key is not removed");

    // An explicit removal of an absent owner changes nothing.
    let remove = vec![(field("backends.owner"), on_a.clone(), SaveValue::Remove)];
    let saved = gw
        .save_as(off(), gw.base(), remove)
        .await
        .expect("SAVE.3: removal saves");
    assert!(!saved.changed, "{saved:?}");
}

/// A save of the value already there writes nothing and reports the base.
#[tokio::test]
async fn a_save_of_the_current_value_reports_the_base_unchanged() {
    let gw = gw(BASE);
    let base = gw.base();
    let saved = gw
        .save(base.clone(), vec![("environment", s("dev"))])
        .await
        .expect("saves");
    assert!(!saved.changed, "{saved:?}");
    assert_eq!(saved.revision, base);
    assert!(!saved.reload.restart_required, "{saved:?}");
    assert_eq!(read(&gw.path), BASE);
}

/// With auth on and no audit log, a save is refused before anything.
#[tokio::test]
async fn a_save_without_an_audit_log_under_auth_is_refused() {
    let gw = gw(BASE);
    let refused = gw
        .save_as(
            AuditPosture::of(None, GatewayAuth::On),
            gw.base(),
            vec![(field("auth.bearer_token"), Param::default(), secret(TOKEN))],
        )
        .await
        .expect_err("refused");
    assert_eq!(refused, UiRefused::NoAuditLog);
    assert_eq!(read(&gw.path), BASE);
    assert_eq!(gw.creates(), 0);
}

/// SAVE.8: a save keeps every comment and untouched line byte for byte,
/// a trailing comment on the edited line and CRLF endings included.
#[tokio::test]
async fn a_save_keeps_every_comment_and_untouched_line() {
    for text in [BASE.to_owned(), BASE.replace('\n', "\r\n")] {
        let gw = gw(&text);
        gw.save(gw.base(), vec![("environment", s("prod"))])
            .await
            .expect("SAVE.8: the edit is proven in place");
        assert_eq!(
            read(&gw.path),
            text.replace("environment: \"dev\"", "environment: \"prod\""),
            "SAVE.8: more than the edited value changed"
        );
    }
}

/// SAVE.8: an edit the in-place editor cannot prove (an anchor on the key)
/// answers with the preview's patch; nothing is written, no entry made.
#[tokio::test]
async fn an_anchored_key_returns_the_validated_patch_and_writes_nothing() {
    let anchored = BASE.replace("environment: \"dev\"", "environment: &env \"dev\"");
    let gw = gw(&anchored);
    let refused = gw
        .save(
            gw.base(),
            vec![
                ("environment", s("prod")),
                ("auth.bearer_token", secret(TOKEN)),
            ],
        )
        .await
        .expect_err("SAVE.8: not provable in place");

    let preview = ui_diff(
        &gw.ctx,
        &PreviewEdit {
            fields: vec![
                (
                    field("environment"),
                    Param::default(),
                    PreviewValue::Set(Scalar::Str("prod".to_owned())),
                ),
                (
                    field("auth.bearer_token"),
                    Param::default(),
                    PreviewValue::Secret,
                ),
            ],
        },
    )
    .await
    .expect("the preview of the same edit");
    let Shown::Patch(patch) = preview.shown else {
        panic!("premise: the preview is a patch");
    };
    assert_eq!(
        refused,
        UiRefused::Unprovable(patch),
        "SAVE.8: not the preview's patch"
    );
    assert_eq!(read(&gw.path), anchored, "SAVE.8: the file changed");
    assert_eq!(gw.creates(), 0, "SAVE.8: an entry was created");
}

/// The save's intent names the fields it edits, never a value (design R1.1).
#[tokio::test]
async fn a_save_names_its_fields_in_the_intent() {
    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;

    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("audit.jsonl");
    let logger = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "test".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("logger opens"),
    );
    logger.keep_test_dir(Arc::clone(&dir));
    let gw = gw(BASE);
    gw.save_as(
        AuditPosture::of(Some(logger), GatewayAuth::Off),
        gw.base(),
        vec![
            (field("environment"), Param::default(), s("prod")),
            (field("auth.bearer_token"), Param::default(), secret(TOKEN)),
        ],
    )
    .await
    .expect("the save stands");

    let records = std::fs::read_to_string(&path).expect("the log");
    let intent = records
        .lines()
        .find(|l| l.contains("config_save_intent"))
        .unwrap_or_else(|| panic!("no save intent in:\n{records}"));
    assert!(
        intent.contains(r#""fields":["environment","auth.bearer_token"]"#),
        "the intent does not name its fields: {intent}"
    );
    let token = String::from_utf8_lossy(TOKEN);
    assert!(!records.contains(token.as_ref()), "a value reached the log");
}

/// Every writer result has one answer; a failure after the write began
/// answers fixed text.
#[test]
fn every_writer_result_maps_to_one_refusal() {
    use super::{Halt, Mapped, map_error};
    use crate::config_reload::reload_context::replace::ReplaceError;
    use crate::config_reload::reload_context::replace::ui_diff::PreviewRefused;
    use crate::secret_store::SaveError;

    let rows = [
        (ReplaceError::Busy, None, Mapped::Refusal(UiRefused::Busy)),
        (
            ReplaceError::Stale {
                current: FileRevision::of(b"x"),
            },
            None,
            Mapped::Repreview { stale: true },
        ),
        (
            ReplaceError::Refused("r".into()),
            Some(Halt::Unprovable),
            Mapped::Repreview { stale: false },
        ),
        (
            ReplaceError::Refused("r".into()),
            Some(Halt::SlotMismatch),
            Mapped::Refusal(UiRefused::Unsupported(
                "the edit's secret slots do not match".into(),
            )),
        ),
        (
            // The writer's own refusal text never leaves: fixed text instead.
            ReplaceError::Refused("r".into()),
            None,
            Mapped::Refusal(UiRefused::Invalid(super::LOADER_REFUSED.to_owned())),
        ),
        (
            // The reload's class rides out typed; its text stays behind.
            ReplaceError::ReloadRefused {
                class: RefusalClass::Internal,
                reason: "l".into(),
            },
            None,
            Mapped::Refusal(UiRefused::ReloadRefused {
                class: RefusalClass::Internal,
            }),
        ),
        (
            ReplaceError::NoAuditLog,
            None,
            Mapped::Refusal(UiRefused::NoAuditLog),
        ),
        (
            ReplaceError::AuditRefused("a".into()),
            None,
            Mapped::Refusal(UiRefused::NoAuditLog),
        ),
        (
            ReplaceError::Secrets(SaveError::Refused(StoreError::Unavailable("u".into()))),
            None,
            Mapped::Refusal(UiRefused::SecretsRefused { timeout: false }),
        ),
        (
            ReplaceError::Secrets(SaveError::Store(StoreError::TimedOut)),
            None,
            Mapped::Refusal(UiRefused::SecretsRefused { timeout: true }),
        ),
        (
            ReplaceError::NoConfigFile,
            None,
            Mapped::Refusal(UiRefused::Preview(PreviewRefused::NoConfigFile)),
        ),
        (
            ReplaceError::ConfigRefused("c".into()),
            None,
            Mapped::Refusal(UiRefused::Preview(PreviewRefused::Unread("c".into()))),
        ),
        (
            ReplaceError::Unsupported("t".into()),
            None,
            Mapped::Refusal(UiRefused::Preview(PreviewRefused::Untrusted("t".into()))),
        ),
    ];
    for (error, halt, want) in rows {
        let what = format!("{error:?} {halt:?}");
        assert_eq!(map_error(error, halt), want, "{what}");
    }
}

#[test]
fn writer_failures_map_to_fixed_text() {
    use super::{Mapped, map_error};
    use crate::config_reload::reload_context::replace::ReplaceError;

    let failed = || Mapped::Refusal(UiRefused::Failed(super::FAILED.to_owned()));
    let journal = || std::path::PathBuf::from("j");
    let rows = [
        (ReplaceError::Stage("s".into()), None, failed()),
        (ReplaceError::Write("w".into()), None, failed()),
        (ReplaceError::Failed("f".into()), None, failed()),
        (
            ReplaceError::RollbackFailed {
                journal: journal(),
                error: "e".into(),
            },
            None,
            failed(),
        ),
        (
            ReplaceError::Unconfirmed {
                journal: journal(),
                error: "e".into(),
            },
            None,
            failed(),
        ),
    ];
    for (error, halt, want) in rows {
        let what = format!("{error:?} {halt:?}");
        assert_eq!(map_error(error, halt), want, "{what}");
    }
}

/// K7: red oracle is Failed for an operational secret-store failure.
#[test]
fn k7_store_failure_is_failed() {
    let mapped = super::map_error(
        super::ReplaceError::Secrets(crate::secret_store::SaveError::Store(StoreError::Failed(
            "store-canary".to_owned(),
        ))),
        None,
    );
    assert!(matches!(
        mapped,
        super::Mapped::Refusal(UiRefused::Failed(_))
    ));
}

/// K7: oracle is a timed-out secret refusal; this control passes the stub.
#[test]
fn k7_store_timeout_stays_timeout() {
    let mapped = super::map_error(
        super::ReplaceError::Secrets(crate::secret_store::SaveError::Store(StoreError::TimedOut)),
        None,
    );
    assert!(matches!(
        mapped,
        super::Mapped::Refusal(UiRefused::SecretsRefused { timeout: true })
    ));
}
