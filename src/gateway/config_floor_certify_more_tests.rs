// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Certify rows C6 to C9: secret references, a newer file, a lost worker and a
//! symlink repointed between the read and the re-check.

use std::sync::Arc;

use tokio::time::Instant;

use super::seams::{CheckHook, CheckStep, LockHook, LockVerdict};
use super::support::{BASE, BOUND, Booted, sha256_hex};
use super::{ConfigFloor, FloorAdapter, FloorFault};
use crate::config::keychain::{FakeKeychain, KeychainError, with_test_keychain};
use crate::gateway::test_helpers::write_owner_only;

const BEARER: &str = "kc-bearer-0123456789abcdef0123456789abcdef";

/// Pause, then checkpoint, both under one real deadline; the checkpoint result.
async fn certify(row: &str, floor: &mut ConfigFloor) -> Result<(), FloorFault> {
    let deadline = Instant::now() + BOUND;
    floor
        .pause(deadline)
        .await
        .unwrap_or_else(|f| panic!("{row} pause faulted: {f:?}"));
    floor.checkpoint(deadline).await
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

/// Certify a booted file that was rewritten to `text` after boot, with the
/// keychain fake installed on this thread (the keychain seam is thread-local).
fn certify_text(
    row: &str,
    text: &str,
    fake: Arc<FakeKeychain>,
) -> (Result<(), FloorFault>, Option<String>) {
    with_test_keychain(fake, || {
        let booted = Booted::new(BASE);
        booted.cfg.rewrite(text);
        let mut floor = booted.floor();
        let result = runtime().block_on(certify(row, &mut floor));
        (result, floor.certification().map(|c| c.sha256.clone()))
    })
}

fn bearer_yaml(enabled: bool, reference: &str) -> String {
    format!("{BASE}auth:\n  enabled: {enabled}\n  bearer_token: {reference}\n")
}

fn assert_certified(row: &str, got: (Result<(), FloorFault>, Option<String>), text: &str) {
    assert_eq!(got.0, Ok(()), "{row} the file certifies");
    let want = sha256_hex(text.as_bytes());
    assert_eq!(got.1.as_deref(), Some(want.as_str()), "{row} literal hash");
}

fn assert_refused(row: &str, got: (Result<(), FloorFault>, Option<String>)) {
    assert_eq!(got.0, Err(FloorFault::SaveFailed), "{row} refuses");
    assert_eq!(got.1, None, "{row} no certification recorded");
}

#[test]
fn c6_keychain_read_that_times_out_refuses() {
    const ROW: &str = "C6 timed-out keychain read";
    let fake = Arc::new(FakeKeychain::default());
    fake.fail("gw.bearer", KeychainError::Timeout);
    let text = bearer_yaml(false, "keychain:gw.bearer");
    assert_refused(ROW, certify_text(ROW, &text, fake));
}

#[test]
fn c6_keychain_reference_that_resolves_certifies() {
    const ROW: &str = "C6 resolving keychain reference";
    let fake = Arc::new(FakeKeychain::default());
    fake.insert("gw.bearer", BEARER.as_bytes());
    let text = bearer_yaml(false, "keychain:gw.bearer");
    assert_certified(ROW, certify_text(ROW, &text, fake), &text);
}

#[test]
fn c6_description_text_naming_a_keychain_reference_certifies() {
    const ROW: &str = "C6 description holding keychain:x";
    let text = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    description: \"keychain:x\"\n";
    let got = certify_text(ROW, text, Arc::new(FakeKeychain::default()));
    assert_certified(ROW, got, text);
}

#[test]
fn c6_failing_env_reference_refuses() {
    const ROW: &str = "C6 failing env reference";
    let text = bearer_yaml(true, "env:CFG_FLOOR_C6_NEVER_SET_VARIABLE");
    assert_refused(ROW, certify_text(ROW, &text, Arc::default()));
}

#[test]
fn c6_failing_file_reference_refuses() {
    const ROW: &str = "C6 failing file reference";
    let text = bearer_yaml(true, "file:/nonexistent-cfg-floor-c6/secret");
    assert_refused(ROW, certify_text(ROW, &text, Arc::default()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c7_newer_file_certifies_without_reloading() {
    const ROW: &str = "C7 newer file";
    let booted = Booted::new(&format!("{BASE}environment: old\n"));
    let newer = format!("{BASE}environment: newer\n");
    booted.cfg.rewrite(&newer);
    let mut floor = booted.floor();
    assert_eq!(certify(ROW, &mut floor).await, Ok(()), "{ROW} certifies");
    let want = sha256_hex(newer.as_bytes());
    let got = floor.certification().map(|c| c.sha256.clone());
    assert_eq!(got.as_deref(), Some(want.as_str()), "{ROW} newer hash");
    let running = booted.running_environment();
    assert_eq!(running.as_deref(), Some("old"), "{ROW} running config kept");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c8_check_hook_panic_is_worker_lost() {
    const ROW: &str = "C8 check panic";
    let booted = Booted::new(BASE);
    let mut floor = booted.floor();
    let hook: CheckHook = Arc::new(|_, step| {
        assert_ne!(step, CheckStep::Start, "row-injected check panic");
    });
    floor.set_check_hook(Some(hook));
    let got = certify(ROW, &mut floor).await;
    assert_eq!(got, Err(FloorFault::WorkerLost), "{ROW} worker lost");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c8_lock_hook_panic_is_worker_lost() {
    const ROW: &str = "C8 lock panic";
    let booted = Booted::new(BASE);
    let mut floor = booted.floor();
    let hook: LockHook = Arc::new(|_| -> LockVerdict { panic!("row-injected lock panic") });
    floor.set_lock_hook(Some(hook));
    let got = certify(ROW, &mut floor).await;
    assert_eq!(got, Err(FloorFault::WorkerLost), "{ROW} worker lost");
}

/// The configured path as a symlink to `real.yaml` (BASE) beside `other.yaml`
/// (a different valid file); a hook repoints it after the trusted read.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c9_symlink_repointed_after_the_read_refuses() {
    const ROW: &str = "C9 symlink repointed";
    let booted = Booted::new(BASE);
    let (link, dir) = (booted.cfg.path.clone(), booted.cfg.dir.path().to_path_buf());
    write_owner_only(&dir.join("real.yaml"), BASE).expect("real target");
    write_owner_only(&dir.join("other.yaml"), format!("{BASE}environment: x\n")).expect("other");
    std::fs::remove_file(&link).expect("unlink");
    std::os::unix::fs::symlink(dir.join("real.yaml"), &link).expect("link");
    let mut floor = booted.floor();
    let hook: CheckHook = Arc::new(move |_, step| {
        if step == CheckStep::AfterRead {
            std::fs::remove_file(&link).expect("unlink in hook");
            std::os::unix::fs::symlink(dir.join("other.yaml"), &link).expect("relink");
        }
    });
    floor.set_check_hook(Some(hook));
    let got = certify(ROW, &mut floor).await;
    assert_eq!(
        got,
        Err(FloorFault::SaveFailed),
        "{ROW} refused at the re-check"
    );
}
