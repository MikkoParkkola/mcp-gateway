// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A minted listener run is fixed on the grant its first mint released: a
//! mint under another grant ends the run before its request goes out, and
//! so does the run's own read when the grant moved or gives no view. A busy
//! custody keeps the run.

use std::sync::atomic::{AtomicUsize, Ordering};

use futures::FutureExt;
use parking_lot::Mutex;

use super::*;

/// A mint whose grant can be rotated, and whose fence read can be scripted.
struct Scripted {
    grant: Mutex<String>,
    read: Mutex<Option<Result<Option<String>, FenceRead>>>,
    refuse: Mutex<bool>,
}

impl Scripted {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            grant: Mutex::new("acct:fence:v1:u1:1".to_owned()),
            read: Mutex::new(None),
            refuse: Mutex::new(false),
        })
    }

    fn rotate(&self) {
        self.grant.lock().push_str(":rotated");
    }
}

#[async_trait::async_trait]
impl ListenerMint for Scripted {
    async fn mint(
        &self,
        _backend: &str,
        _identity: &VerifiedIdentity,
    ) -> crate::Result<ListenerGrant> {
        if *self.refuse.lock() {
            return Err(crate::Error::Config("the grant was revoked".to_owned()));
        }
        Ok(ListenerGrant {
            headers: vec![("authorization".to_owned(), "Bearer at.u1".to_owned())],
            fence: Some(self.grant.lock().clone()),
        })
    }

    async fn fence_binding(
        &self,
        _backend: &str,
        _identity: &VerifiedIdentity,
    ) -> Result<Option<String>, FenceRead> {
        self.read
            .lock()
            .clone()
            .unwrap_or_else(|| Ok(Some(self.grant.lock().clone())))
    }
}

fn run_on(mint: &Arc<Scripted>) -> Arc<RunFence> {
    Arc::new(RunFence {
        mint: Arc::clone(mint) as Arc<dyn ListenerMint>,
        backend: "managed".to_owned(),
        identity: VerifiedIdentity {
            subject: "u1".into(),
            email: "u1@example.com".into(),
            name: None,
            groups: Vec::new(),
            issuer: "https://idp".into(),
        },
        binding: OnceLock::new(),
        ended: AtomicBool::new(false),
    })
}

/// One request through `minted`; `sent` counts the requests that went out.
async fn request(minted: &Minted, sent: &Arc<AtomicUsize>) -> bool {
    let sent = Arc::clone(sent);
    let outcome = minted
        .with_credential(Box::new(move |_headers| {
            async move {
                sent.fetch_add(1, Ordering::SeqCst);
                Err::<reqwest::Response, _>(crate::Error::Transport(
                    "no peer in this row".to_owned(),
                ))
            }
            .boxed()
        }))
        .await;
    !outcome
        .as_ref()
        .is_err_and(|e| e.to_string().contains("grant moved"))
}

#[tokio::test]
async fn a_mint_under_another_grant_ends_the_run_before_its_request() {
    let mint = Scripted::new();
    let run = run_on(&mint);
    let minted = Minted {
        run: Arc::clone(&run),
        obs: "obs".to_owned(),
    };
    let sent = Arc::new(AtomicUsize::new(0));
    assert!(
        request(&minted, &sent).await,
        "the first mint fixes the run"
    );
    let fixed = run.binding();
    mint.rotate();

    assert!(
        !request(&minted, &sent).await,
        "refused under the new grant"
    );
    assert_eq!(sent.load(Ordering::SeqCst), 1, "its request never went out");
    assert!(run.ended());
    assert_eq!(
        run.binding(),
        fixed,
        "what the old run emits keeps the old binding"
    );
}

#[tokio::test]
async fn a_mint_under_the_same_grant_keeps_the_run() {
    let mint = Scripted::new();
    let run = run_on(&mint);
    let minted = Minted {
        run: Arc::clone(&run),
        obs: "obs".to_owned(),
    };
    let sent = Arc::new(AtomicUsize::new(0));
    assert!(request(&minted, &sent).await);
    assert!(request(&minted, &sent).await);
    assert_eq!(sent.load(Ordering::SeqCst), 2);
    assert!(!run.ended());
}

#[tokio::test]
async fn the_runs_own_read_ends_a_quiet_run() {
    // Moved: a re-grant.
    let mint = Scripted::new();
    let run = run_on(&mint);
    assert!(run.admits(Some("acct:fence:v1:u1:1")));
    mint.rotate();
    run.recheck().await;
    assert!(run.ended(), "a moved grant ends the run");

    // No view: a revocation.
    let mint = Scripted::new();
    let run = run_on(&mint);
    assert!(run.admits(Some("acct:fence:v1:u1:1")));
    *mint.read.lock() = Some(Err(FenceRead::Closed));
    run.recheck().await;
    assert!(run.ended(), "no view of the grant ends the run");
}

#[tokio::test]
async fn a_busy_custody_or_an_unchanged_grant_keeps_the_run() {
    let mint = Scripted::new();
    let run = run_on(&mint);
    assert!(run.admits(Some("acct:fence:v1:u1:1")));
    run.recheck().await;
    assert!(!run.ended(), "an unchanged grant");
    *mint.read.lock() = Some(Err(FenceRead::Busy));
    run.recheck().await;
    assert!(!run.ended(), "a busy custody decides nothing");
}

#[tokio::test]
async fn a_read_before_any_mint_fixes_nothing() {
    let mint = Scripted::new();
    let run = run_on(&mint);
    mint.rotate();
    run.recheck().await;
    assert!(!run.ended());
    assert_eq!(run.binding(), None);
}

#[tokio::test]
async fn a_refused_mint_on_a_grant_with_no_view_ends_the_run() {
    let mint = Scripted::new();
    let run = run_on(&mint);
    let minted = Minted {
        run: Arc::clone(&run),
        obs: "obs".to_owned(),
    };
    let sent = Arc::new(AtomicUsize::new(0));
    assert!(
        request(&minted, &sent).await,
        "the first mint fixes the run"
    );
    *mint.refuse.lock() = true;
    *mint.read.lock() = Some(Err(FenceRead::Busy));
    let _ = request(&minted, &sent).await;
    assert!(!run.ended(), "a busy custody decides nothing");
    *mint.read.lock() = Some(Err(FenceRead::Closed));
    let _ = request(&minted, &sent).await;
    assert!(
        run.ended(),
        "a revoked grant ends the run at its refused mint"
    );
    assert_eq!(
        sent.load(Ordering::SeqCst),
        1,
        "nothing sent after the refusals"
    );
}

/// A mint that answers with no credential at all, against the
/// [`ListenerMint`] contract.
struct MintsNothing;

#[async_trait::async_trait]
impl ListenerMint for MintsNothing {
    async fn mint(
        &self,
        _backend: &str,
        _identity: &VerifiedIdentity,
    ) -> crate::Result<ListenerGrant> {
        Ok(ListenerGrant {
            headers: Vec::new(),
            fence: None,
        })
    }

    async fn fence_binding(
        &self,
        _backend: &str,
        _identity: &VerifiedIdentity,
    ) -> Result<Option<String>, FenceRead> {
        Ok(None)
    }
}

/// A minted source lends a credential or refuses: a mint that yields none
/// sends nothing. A per-user slot of a required binding takes a source-lent
/// send as the subscriber's own, so this source is where "never lend empty"
/// is held.
#[tokio::test]
async fn a_mint_with_no_credential_sends_nothing() {
    let run = run_on(&Scripted::new());
    let run = Arc::new(RunFence {
        mint: Arc::new(MintsNothing) as Arc<dyn ListenerMint>,
        backend: run.backend.clone(),
        identity: run.identity.clone(),
        binding: OnceLock::new(),
        ended: AtomicBool::new(false),
    });
    let minted = Minted {
        run,
        obs: "u1".to_owned(),
    };
    let sent = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&sent);
    let outcome = minted
        .with_credential(Box::new(move |_headers| {
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                Err::<reqwest::Response, _>(crate::Error::Transport("no peer".to_owned()))
            }
            .boxed()
        }))
        .await;
    assert_eq!(
        sent.load(Ordering::SeqCst),
        0,
        "a send ran with no credential"
    );
    assert!(outcome.is_err());
}
