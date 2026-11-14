// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Windows keychain backend over real Credential Manager entries.

use std::time::{Duration, Instant};

use super::keychain::{CONFIRM_ATTEMPTS, KeychainError, KeychainRead};
use super::keychain_windows::WindowsKeychain;
use crate::win_cred;

const SENTINEL: &[u8] = b"kc-sentinel-7f3a";

fn fresh(tag: &str) -> String {
    format!("mcp-gateway-test.backend-{tag}.{}", std::process::id())
}

#[test]
fn an_entry_reads_back_and_a_missing_one_is_missing() {
    use crate::secret_store::SecretStore;
    let name = fresh("read");
    win_cred::create(&name, SENTINEL).expect("create");
    let read = WindowsKeychain::new().read(&name);
    // The store's delete returns only once the entry is seen gone, so the read
    // below cannot meet a credential Credential Manager still answers for.
    WindowsKeychain::new().delete(&name).expect("delete");
    let read = read.expect("read");
    assert_eq!(read.as_bytes(), SENTINEL);
    assert!(!format!("{read:?}").contains("kc-sentinel-7f3a"));
    assert_eq!(
        WindowsKeychain::new().read(&name).expect_err("deleted"),
        KeychainError::Missing
    );
}

#[test]
fn a_late_answer_times_out_and_leaks_nothing() {
    let name = fresh("late");
    win_cred::create(&name, SENTINEL).expect("create");
    let started = Instant::now();
    let err = WindowsKeychain::with_timing(Duration::from_millis(100), Duration::from_secs(30))
        .read(&name)
        .expect_err("late");
    win_cred::delete(&name).expect("delete");
    assert_eq!(err, KeychainError::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "waited for the late answer"
    );
    assert!(!format!("{err:?} {}", err.reason()).contains("kc-sentinel-7f3a"));
}

/// B15/A17: the writer's round trip, collision and existence check over
/// real credentials; an existence check zeroes the blob before its free.
#[test]
fn the_writer_round_trips_refuses_a_taken_name_and_wipes_on_exists() {
    use crate::secret_store::{SecretStore, StoreError};
    let store = WindowsKeychain::new();
    store.probe().expect("Credential Manager answers");
    let name = fresh("writer");
    assert_eq!(store.exists(&name), Ok(false));
    assert_eq!(store.create(&name, b" a\n"), Ok(format!("keychain:{name}")));
    let _ = win_cred::FREED.with(|f| std::mem::take(&mut *f.borrow_mut()));
    assert_eq!(store.exists(&name), Ok(true));
    // `exists` runs on the bounded call's own thread, so its guard records
    // there; read the oracle directly on this one.
    assert_eq!(win_cred::exists(&name), Ok(true));
    assert_eq!(
        win_cred::FREED.with(|f| std::mem::take(&mut *f.borrow_mut())),
        vec![true]
    );
    assert_eq!(store.create(&name, b"other"), Err(StoreError::Exists));
    assert_eq!(store.read(&name).expect("kept").as_bytes(), b" a\n");
    store.delete(&name).expect("delete");
    assert_eq!(store.exists(&name), Ok(false));
    assert_eq!(store.delete(&name), Ok(()), "already gone is gone");
}

/// A probe that times out reports Credential Manager unavailable, not a
/// pending write: a probe writes nothing.
#[test]
fn a_probe_that_times_out_is_unavailable() {
    use crate::secret_store::{SecretStore, StoreError};
    let store = WindowsKeychain::with_timing(Duration::from_millis(100), Duration::from_secs(30));
    assert!(matches!(store.probe(), Err(StoreError::Unavailable(_))));
}

// The call site, through fake Credential Manager calls: the store's delete
// must carry the confirmation's answer, whatever the real entry does.

#[test]
fn the_store_delete_fails_while_the_entry_stays_readable() {
    use crate::secret_store::{SecretStore, StoreError};
    let err = WindowsKeychain::with_cred(|_| Ok(()), |_| Ok(true))
        .delete("call-site")
        .expect_err("an entry that stays readable is not removed");
    // The whole production budget was asked, not a smaller one.
    let checks = format!("still readable after {CONFIRM_ATTEMPTS} checks");
    assert!(
        matches!(&err, StoreError::Unavailable(why) if why.contains(&checks)),
        "{err:?}"
    );
}

#[test]
fn the_store_delete_fails_when_the_ask_errors() {
    use crate::secret_store::{SecretStore, StoreError};
    let err = WindowsKeychain::with_cred(|_| Ok(()), |_| Err(win_cred::CredError::Win32(5)))
        .delete("call-site")
        .expect_err("an entry whose state cannot be read is not removed");
    assert!(
        matches!(&err, StoreError::Unavailable(why) if why.contains("Win32(5)")),
        "{err:?}"
    );
}

#[test]
fn the_store_delete_fails_when_the_os_delete_fails() {
    use crate::secret_store::{SecretStore, StoreError};
    let err = WindowsKeychain::with_cred(|_| Err(win_cred::CredError::Win32(5)), |_| Ok(false))
        .delete("call-site")
        .expect_err("a failed OS delete is not removed");
    assert!(
        matches!(&err, StoreError::Unavailable(why) if why.contains("Win32(5)")),
        "{err:?}"
    );
}

#[test]
fn the_store_delete_succeeds_once_the_entry_is_gone() {
    use crate::secret_store::SecretStore;
    // Each fake also checks it was handed the entry being deleted: a fake that
    // panics fails the delete, so wrong-name wiring fails this row.
    let delete = |name: &str| {
        assert_eq!(name, "call-site");
        Ok(())
    };
    let gone = |name: &str| {
        assert_eq!(name, "call-site");
        Ok(false)
    };
    WindowsKeychain::with_cred(delete, gone)
        .delete("call-site")
        .expect("a deleted entry seen gone");
    let absent = |name: &str| {
        assert_eq!(name, "call-site");
        Err(win_cred::CredError::NotFound)
    };
    WindowsKeychain::with_cred(absent, gone)
        .delete("call-site")
        .expect("an entry already absent");
}
