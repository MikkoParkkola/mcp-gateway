// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Grant-change journal cells (MIK-7570.AUDIT.4), CLI half.
//!
//! Plan: `docs/design/2026-09-28-grant-change-journal-test-plan.md`, cells
//! T1a-T1f and the journal reader. The gateway half lives with the auditor.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::journal::{
    ChangeError, GrantChange, Hooks, JOURNAL_VERSION, JournalEntry, JournalVerb, UNKNOWN_ACTOR,
    apply_change_with, grant_digest, journal_path, lock_path, parse_journal,
};
use super::{
    GrantAgent, GrantScope, GrantSubject, IdentityGrant, IdentityGrantFile,
    read_identity_grants_file,
};

fn row(grant_id: &str, reason: &str) -> IdentityGrant {
    IdentityGrant {
        grant_id: grant_id.to_string(),
        subject: GrantSubject::new("api_key".to_string(), "alice".to_string(), None),
        agent: GrantAgent::Any,
        capability: "cap".to_string(),
        tool: None,
        scope: GrantScope::Read,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "p".to_string(),
        reason: reason.to_string(),
    }
}

/// Upsert `row` the way the CLI does: refuse a duplicate unless `replace`.
fn upsert(new: IdentityGrant, replace: bool) -> GrantChange {
    Box::new(move |file: &mut IdentityGrantFile| {
        let existed = file.grants.iter().any(|g| g.grant_id == new.grant_id);
        if existed && !replace {
            return Err(format!("grant id '{}' already exists", new.grant_id));
        }
        file.grants.retain(|g| g.grant_id != new.grant_id);
        let id = new.grant_id.clone();
        file.grants.push(new);
        Ok((
            if existed {
                JournalVerb::Replace
            } else {
                JournalVerb::Add
            },
            id,
        ))
    })
}

fn revoke(grant_id: &str) -> GrantChange {
    let grant_id = grant_id.to_string();
    Box::new(move |file: &mut IdentityGrantFile| {
        let row = file
            .grants
            .iter_mut()
            .find(|g| g.grant_id == grant_id)
            .ok_or_else(|| format!("grant id '{grant_id}' was not found"))?;
        row.revoked_at = Some("2026-06-29T14:00:00Z".parse().unwrap());
        Ok((JournalVerb::Revoke, grant_id))
    })
}

async fn change(path: &Path, c: GrantChange) -> Result<IdentityGrant, ChangeError> {
    apply_change_with(
        path,
        true,
        c,
        Some("alice-os".to_string()),
        &Hooks::default(),
    )
    .await
}

fn entries(path: &Path) -> Vec<JournalEntry> {
    let bytes = std::fs::read(journal_path(path)).unwrap_or_default();
    parse_journal(&bytes).entries
}

fn journal_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(journal_path(path)).unwrap_or_default()
}

#[test]
fn journal_and_lock_sit_beside_the_grant_file() {
    let grants = Path::new("/srv/gw/grants.yaml");
    assert_eq!(
        journal_path(grants),
        Path::new("/srv/gw/grants.yaml.journal.jsonl")
    );
    assert_eq!(
        lock_path(grants),
        Path::new("/srv/gw/.grants.yaml.journal.lock")
    );
}

/// MIK-7715: the gateway configured with a symlink to the grant file and the
/// CLI editing the real path share one journal and one lock, so the CLI's
/// change reaches the gateway as an `add`, not as an out-of-band edit.
// Unix-only: plants a file symlink, which Windows gates behind a privilege.
#[cfg(unix)]
#[tokio::test]
async fn two_spellings_of_one_grant_file_share_journal_and_lock() {
    use crate::config_reload::grant_audit::JournalRead;
    let dir = tempfile::tempdir().unwrap();
    let real_dir = dir.path().join("data");
    let link_dir = dir.path().join("etc");
    std::fs::create_dir_all(&real_dir).unwrap();
    std::fs::create_dir_all(&link_dir).unwrap();
    let real = real_dir.join("grants.yaml");
    let link = link_dir.join("grants.yaml");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    change(&real, upsert(row("g1", "r"), false)).await.unwrap();

    assert_eq!(lock_path(&link), lock_path(&real), "one lock for both");
    let read = super::journal::read_locked(&link, std::time::Duration::from_secs(5))
        .await
        .expect("lock taken");
    let JournalRead::Bytes(bytes) = read.journal else {
        panic!("gateway saw no journal through the symlink");
    };
    let verbs: Vec<_> = parse_journal(&bytes)
        .entries
        .into_iter()
        .map(|e| (e.verb, e.grant_id))
        .collect();
    assert_eq!(verbs, vec![(JournalVerb::Add, "g1".to_string())]);
}

/// T1c: pinned bytes. A new serialised field on `IdentityGrant` changes every
/// digest, and every grant would then read as edited out-of-band; it must be
/// skipped when default.
#[test]
fn t1c_digest_is_sha256_of_the_serialised_row() {
    assert_eq!(
        grant_digest(&row("g1", "r")),
        "sha256:0231855e2a31a21765ad5776324622ddf380b69e6d2910c301c321f0b57dd0bf"
    );
}

/// T1a: add, replace and revoke each append one entry with the row's
/// digests before and after, the expiry, the clock, `unknown` and the OS hint.
#[tokio::test]
async fn t1a_each_change_appends_one_entry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    let mut first = row("g1", "first");
    first.expires_at = Some("2030-01-01T00:00:00Z".parse().unwrap());
    let d1 = grant_digest(&first);
    change(&path, upsert(first, false)).await.unwrap();
    let second = row("g1", "second");
    let d2 = grant_digest(&second);
    change(&path, upsert(second, true)).await.unwrap();
    let revoked = change(&path, revoke("g1")).await.unwrap();
    let d3 = grant_digest(&revoked);

    let got = entries(&path);
    let shape: Vec<_> = got
        .iter()
        .map(|e| (e.verb, e.prev_digest.clone(), e.digest.clone()))
        .collect();
    assert_eq!(
        shape,
        vec![
            (JournalVerb::Add, None, d1.clone()),
            (JournalVerb::Replace, Some(d1), d2.clone()),
            (JournalVerb::Revoke, Some(d2), d3),
        ]
    );
    assert_eq!(
        got[0].expires_at,
        Some("2030-01-01T00:00:00Z".parse().unwrap())
    );
    for e in &got {
        assert_eq!(e.v, 1);
        assert_eq!(e.grant_id, "g1");
        assert_eq!(e.actor, UNKNOWN_ACTOR);
        assert_eq!(e.os_account.as_deref(), Some("alice-os"));
        assert!(!e.entry_id.is_empty());
    }
    let ids: std::collections::BTreeSet<_> = got.iter().map(|e| &e.entry_id).collect();
    assert_eq!(ids.len(), 3, "entry ids must be distinct");
}

/// T1b: a refused change writes neither file.
#[tokio::test]
async fn t1b_a_refused_change_appends_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    change(&path, upsert(row("g1", "r"), false)).await.unwrap();
    assert_eq!(entries(&path).len(), 1);

    let dup = change(&path, upsert(row("g1", "other"), false)).await;
    assert!(matches!(dup, Err(ChangeError::Refused(_))), "{dup:?}");
    let missing = change(&path, revoke("g9")).await;
    assert!(
        matches!(missing, Err(ChangeError::Refused(_))),
        "{missing:?}"
    );
    assert_eq!(entries(&path).len(), 1);
    assert_eq!(
        read_identity_grants_file(&path).await.unwrap().grants.len(),
        1
    );
}

/// T1d: the journal is created owner-only.
// Unix-only: asserts POSIX mode bits; Windows has no mode bits (owner-only comes from DACLs).
#[cfg(unix)]
#[tokio::test]
async fn t1d_journal_is_created_0600() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    change(&path, upsert(row("g1", "r"), false)).await.unwrap();
    let mode = std::fs::metadata(journal_path(&path))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// T1e: a failed grant-file write appends nothing; a failed append after the
/// write reports the change as unjournalled and leaves the file changed.
#[tokio::test]
async fn t1e_write_and_append_failures() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    let hooks = Hooks {
        fail_grant_write: true,
        ..Hooks::default()
    };
    let r = apply_change_with(&path, true, upsert(row("g1", "r"), false), None, &hooks).await;
    assert!(matches!(r, Err(ChangeError::Refused(_))), "{r:?}");
    assert!(journal_bytes(&path).is_empty());
    assert!(!path.exists());

    let hooks = Hooks {
        fail_append: true,
        ..Hooks::default()
    };
    let r = apply_change_with(&path, true, upsert(row("g1", "r"), false), None, &hooks).await;
    let Err(ChangeError::Unjournalled(reason)) = &r else {
        panic!("expected Unjournalled, got {r:?}");
    };
    assert!(
        r.as_ref()
            .unwrap_err()
            .to_string()
            .contains("may have no journal entry"),
        "{reason}"
    );
    assert!(journal_bytes(&path).is_empty());
    assert_eq!(
        read_identity_grants_file(&path).await.unwrap().grants.len(),
        1
    );
}

/// T1f: an existing journal left group-readable is tightened to 0600, and a
/// journal whose last line has no newline (a torn append) gets one before the
/// next entry, so the new entry parses.
#[tokio::test]
async fn t1f_existing_journal_is_repaired() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    change(&path, upsert(row("g1", "r"), false)).await.unwrap();
    let journal = journal_path(&path);
    let mut bytes = std::fs::read(&journal).unwrap();
    bytes.extend_from_slice(b"{\"torn\":");
    std::fs::write(&journal, &bytes).unwrap();
    // Unix-only: POSIX mode bits; Windows has none (owner-only comes from DACLs).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    change(&path, upsert(row("g2", "r"), false)).await.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&journal).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let parsed = parse_journal(&std::fs::read(&journal).unwrap());
    let ids: Vec<_> = parsed.entries.iter().map(|e| e.grant_id.as_str()).collect();
    assert_eq!(ids, vec!["g1", "g2"]);
    assert_eq!(parsed.torn.len(), 1, "the torn fragment is one torn line");
}

/// T10a, CLI half: the lock is held from before the grant-file write until
/// after the append. The hook runs between the two and must find it taken.
#[tokio::test]
async fn t10a_the_lock_spans_the_write_and_the_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    let lock = lock_path(&path);
    let saw_held = Arc::new(AtomicBool::new(false));
    let probe = Arc::clone(&saw_held);
    let hooks = Hooks {
        after_grant_write: Some(Box::new(move || {
            let free = crate::fs_lock::ExclusiveFileLock::try_lease(&lock)
                .expect("lock file usable")
                .is_some();
            probe.store(!free, Ordering::SeqCst);
        })),
        ..Hooks::default()
    };
    apply_change_with(&path, true, upsert(row("g1", "r"), false), None, &hooks)
        .await
        .unwrap();
    assert!(
        saw_held.load(Ordering::SeqCst),
        "the journal lock was free between the grant-file write and the append"
    );
    assert_eq!(entries(&path).len(), 1);
}

/// A hand-edited file with a duplicate id is refused: which row is in force
/// is ambiguous, so no `prev_digest` could be right.
#[tokio::test]
async fn duplicate_ids_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    let first = row("g1", "first");
    let file = IdentityGrantFile::new(vec![first.clone(), row("g1", "second")]);
    super::write_identity_grants_file(&path, &file)
        .await
        .unwrap();

    let r = change(&path, revoke("g1")).await;

    assert!(matches!(r, Err(ChangeError::Refused(_))), "{r:?}");
    assert!(entries(&path).is_empty());
    assert_eq!(
        read_identity_grants_file(&path).await.unwrap().grants[0],
        first
    );
}

/// A change refused because the grant file is absent leaves nothing behind,
/// not even the lock file.
#[tokio::test]
async fn a_refused_change_on_a_missing_file_leaves_no_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    let r = apply_change_with(&path, false, revoke("g1"), None, &Hooks::default()).await;
    assert!(matches!(r, Err(ChangeError::Refused(_))), "{r:?}");
    assert!(!lock_path(&path).exists());
    assert!(!journal_path(&path).exists());
}

/// A journal path planted as a symlink is refused: the append must not land
/// on, or chmod, the file it points at.
// Unix-only: asserts POSIX mode bits on the planted target; the Windows symlink refusal runs in journal_windows_tests.rs:75.
#[cfg(unix)]
#[tokio::test]
async fn a_symlinked_journal_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    let victim = dir.path().join("victim.txt");
    std::fs::write(&victim, b"keep").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink(&victim, journal_path(&path)).unwrap();

    let r = change(&path, upsert(row("g1", "r"), false)).await;

    assert!(matches!(r, Err(ChangeError::Unjournalled(_))), "{r:?}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    let mode = std::fs::metadata(&victim).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o644);
}

/// A journal another local account can write to is refused, not repaired: a
/// group/world-writable journal may already carry entries this process never
/// wrote, and chmod-ing it to 0600 would launder that history for the next
/// reader. T1f's 0o644 (read-only exposure) still gets tightened.
// Unix-only: asserts POSIX mode bits; Windows has no mode bits (owner-only comes from DACLs).
#[cfg(unix)]
#[tokio::test]
async fn a_writable_by_others_journal_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    change(&path, upsert(row("g1", "r"), false)).await.unwrap();
    let journal = journal_path(&path);
    let before = std::fs::read(&journal).unwrap();
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o646)).unwrap();

    let grants_before = std::fs::read(&path).unwrap();

    let r = change(&path, upsert(row("g2", "r"), false)).await;

    assert!(matches!(r, Err(ChangeError::Refused(_))), "{r:?}");
    assert_eq!(std::fs::read(&journal).unwrap(), before, "no line appended");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        grants_before,
        "the grant file is untouched"
    );
    let mode = std::fs::metadata(&journal).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o646,
        "mode is refused, not laundered to 0600"
    );
}

#[test]
fn reader_leaves_an_unterminated_tail_for_later() {
    let line = serde_json::to_string(&sample_entry("e1")).unwrap();
    let bytes = format!("{line}\n{{\"v\":1,\"entry_id\":\"e2\"");
    let parsed = parse_journal(bytes.as_bytes());
    assert_eq!(parsed.entries.len(), 1);
    assert!(
        parsed.torn.is_empty(),
        "an unterminated tail is not torn yet"
    );
}

/// A line in a journal format this build does not know is refused like a
/// damaged line: never read as a change, always reported.
#[test]
fn reader_refuses_a_future_journal_version() {
    let mut future = sample_entry("e2");
    future.v = JOURNAL_VERSION + 1;
    let a = serde_json::to_string(&sample_entry("e1")).unwrap();
    let b = serde_json::to_string(&future).unwrap();
    let bytes = format!("{a}\n{b}\n");
    let parsed = parse_journal(bytes.as_bytes());
    let ids: Vec<_> = parsed.entries.iter().map(|e| e.entry_id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["e1"],
        "a v{} entry was read as a change",
        future.v
    );
    assert_eq!(parsed.torn.len(), 1, "the future-version line is reported");
}

#[test]
fn reader_reports_a_bad_complete_line_as_torn_and_keeps_going() {
    let a = serde_json::to_string(&sample_entry("e1")).unwrap();
    let b = serde_json::to_string(&sample_entry("e2")).unwrap();
    let bytes = format!("{a}\nnot json\n{b}\n");
    let parsed = parse_journal(bytes.as_bytes());
    let ids: Vec<_> = parsed.entries.iter().map(|e| e.entry_id.as_str()).collect();
    assert_eq!(ids, vec!["e1", "e2"]);
    assert_eq!(parsed.torn.len(), 1);
    assert!(parsed.torn[0].starts_with("sha256:"));
}

fn sample_entry(entry_id: &str) -> JournalEntry {
    JournalEntry {
        v: 1,
        entry_id: entry_id.to_string(),
        verb: JournalVerb::Add,
        grant_id: "g1".to_string(),
        prev_digest: None,
        digest: grant_digest(&row("g1", "r")),
        expires_at: None,
        at: "2026-09-28T00:00:00Z".parse().unwrap(),
        actor: UNKNOWN_ACTOR.to_string(),
        os_account: None,
    }
}
