// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A login cancelled before it registers.

use super::*;

/// A login cancelled before it registers (a restart or shutdown of
/// the backend) ends as cancelled and opens no browser.
#[tokio::test]
async fn a_login_cancelled_before_registration_opens_no_browser() {
    let dir = tempfile::tempdir().unwrap();
    let mut client = client(dir.path(), Some("https://as.example"));
    let opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::clone(&opened);
    client.open_browser = Box::new(move |_| {
        seen.store(true, std::sync::atomic::Ordering::SeqCst);
        true
    });
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();

    let ended = tokio::time::timeout(
        Duration::from_secs(10),
        client.authorize_until(&cancel, None),
    )
    .await
    .expect("a cancelled login ends at once");

    assert!(
        matches!(ended, Err(crate::Error::AuthorizationCancelled { ref backend }) if backend == BACKEND),
        "{ended:?}"
    );
    assert!(
        !opened.load(std::sync::atomic::Ordering::SeqCst),
        "no browser opens for a cancelled login"
    );
}
