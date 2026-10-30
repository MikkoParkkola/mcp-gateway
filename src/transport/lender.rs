// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A per-user pool slot's lender (ADR-007 IDP.7): the credentials
//! the dispatches now in flight on the slot lend to its transport. A
//! lent-only transport sends only what is lent here, so a send with no
//! dispatch in flight (a session DELETE on close, a reconnect between calls)
//! has nothing to send as and is not sent.
//!
//! Every loan on one slot is its one principal's (the slot is keyed by that
//! principal's binding), and none outlives the dispatch that made it: the
//! [`Loan`] ends it when dropped, zeroing its copy.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::future::BoxFuture;
use zeroize::Zeroizing;

use crate::Error;
use crate::Result;
use crate::protocol::param_headers::is_param_header;

/// Why a lent credential's per-send check refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Revoked, unreleasable or past its published expiry: the slot is
    /// evicted, and no later send under this loan is tried.
    Definitive,
    /// Refused for this send only (a dispatch-scoped credential whose own
    /// `exp` passed): no later send under this loan is tried, the slot stays.
    ThisLoan,
    /// A fault that says nothing about the credential (a busy custody, a
    /// network or storage error): this send fails, the loan is not marked.
    Transient,
}

/// Whether a lent credential may be sent now; run before every send.
pub(crate) type SendCheck =
    Arc<dyn Fn() -> BoxFuture<'static, std::result::Result<(), Refusal>> + Send + Sync>;

/// A dispatch's credential and the check every send of it runs first. Only
/// the mint core attaches a check; headers from anywhere else carry none,
/// and a lent-only slot refuses a loan without one.
#[derive(Clone, Default)]
pub(crate) struct LentCredential {
    /// Wiped on drop, as the lender's own copy and the resolved
    /// `CallerCredential` are. The per-send header lists built from a loan
    /// are plain vectors.
    pub(crate) headers: Zeroizing<Vec<(String, String)>>,
    pub(crate) check: Option<SendCheck>,
}

/// Header names only: a value is the subscriber's credential and is never
/// printed.
impl std::fmt::Debug for LentCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LentCredential")
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("checked", &self.check.is_some())
            .finish()
    }
}

impl LentCredential {
    /// A loan with no send check, for headers no mint produced: a shared
    /// slot's call, a call with no identity, a backend's own gate headers. A
    /// lent-only slot refuses it. The only way to build one without a check,
    /// so every such loan is named where it is made; there is deliberately no
    /// `From` conversion that could make one silently.
    pub(crate) fn unchecked(headers: &[(String, String)]) -> Self {
        Self {
            headers: headers.to_vec().into(),
            check: None,
        }
    }
}

/// One loan: its zeroed-on-drop headers, its check, and whether a check
/// refused it.
struct Lent {
    id: u64,
    headers: Zeroizing<Vec<(String, String)>>,
    check: Option<SendCheck>,
    refused: Option<Refusal>,
}

/// What a send needs of one loan, cloned out under the lock so nothing is
/// held across the check's await.
pub(crate) struct Snapshot {
    pub(crate) id: u64,
    pub(crate) headers: Zeroizing<Vec<(String, String)>>,
    pub(crate) check: Option<SendCheck>,
    pub(crate) refused: Option<Refusal>,
}

/// The name of the [`Lender::start_call`] marker: a slot start's own send,
/// resolved to the starter at each send. Never sent.
const START_MARKER: &str = "x-mcp-gateway-slot-start";

/// The loans of one slot, newest last.
#[derive(Default)]
pub(crate) struct Lender {
    loans: parking_lot::Mutex<Vec<Lent>>,
    next: AtomicU64,
    /// The loans of the dispatches waiting on this slot's start, oldest
    /// first: the oldest still waiting is the starter, so a cancelled first
    /// caller hands the start to the next rather than leaving it loanless.
    starter: parking_lot::Mutex<Vec<u64>>,
    /// Run once a loan is refused definitively: the slot that owns this
    /// lender evicts itself, whether or not its dispatch is still awaited.
    evict: parking_lot::Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl Lender {
    /// Lend `credential` until the returned [`Loan`] drops. Plain headers
    /// lend with no check, which a lent-only slot refuses to send.
    pub(crate) fn lend(self: &Arc<Self>, credential: LentCredential) -> Loan {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.loans.lock().push(Lent {
            id,
            headers: Zeroizing::new(credential_part(&credential.headers)),
            check: credential.check,
            refused: None,
        });
        Loan {
            lender: Arc::clone(self),
            id,
        }
    }

    /// Every loan whose headers are exactly the call's credential headers: the
    /// call's headers less the gateway-owned `Mcp-Param-*` mirrors, compared as
    /// sets of (lowercased name, value). Never a subset, never "contains"; a
    /// call with no credential headers matches nothing.
    ///
    /// Identical bytes in a credential header set are the same grant. Every
    /// strategy derives a credential from one principal's grant, and an equal
    /// bearer value is one bearer: whoever holds the bytes holds the grant. So
    /// when several loans match, each one's check is a check on that same grant.
    pub(crate) fn matching_all(&self, call: &[(String, String)]) -> Vec<Snapshot> {
        let credential = credential_part(call);
        let wanted = canonical(&credential);
        if wanted.is_empty() {
            return Vec::new();
        }
        self.loans
            .lock()
            .iter()
            .filter(|lent| canonical(&lent.headers) == wanted)
            .map(Self::snapshot)
            .collect()
    }

    /// Queue `loan_id` as a dispatch waiting on this slot's start. The oldest
    /// one still queued is the starter; the guard leaves the queue when
    /// dropped.
    pub(crate) fn starting(self: &Arc<Self>, loan_id: u64) -> StartGuard {
        self.starter.lock().push(loan_id);
        StartGuard {
            lender: Arc::clone(self),
            id: loan_id,
        }
    }

    /// The live loan of the oldest dispatch waiting on this slot's start, if
    /// any.
    pub(crate) fn starter(&self) -> Option<Snapshot> {
        let waiting = self.starter.lock().clone();
        waiting.into_iter().find_map(|id| self.loan(id))
    }

    /// The call a slot start's own sends carry (connect, era probe,
    /// handshake, the A2A card fetch) while a dispatch waits on the start; an
    /// empty call when none does. It names no credential: [`Self::lent_for`]
    /// resolves it at each send to the oldest dispatch still waiting, so a
    /// starter cancelled mid-start hands the remaining sends to the next one.
    /// Only a lent-only slot lends, so any other slot's start gets an empty
    /// call. The marker never reaches the wire: a lent-only send carries only
    /// its loan's headers and the call's `Mcp-Param-*` mirrors.
    pub(crate) fn start_call(&self) -> Vec<(String, String)> {
        if self.starter().is_some() {
            vec![(START_MARKER.to_owned(), String::new())]
        } else {
            Vec::new()
        }
    }

    /// The live loan `id`, if its dispatch still runs.
    pub(crate) fn loan(&self, id: u64) -> Option<Snapshot> {
        self.loans
            .lock()
            .iter()
            .find(|lent| lent.id == id)
            .map(Self::snapshot)
    }

    /// The headers a lent-only send carries: the loan the call's own
    /// credential headers select, after every loan matching them passes its
    /// check. A call with no credential headers is refused: a slot start's own
    /// sends carry [`Self::start_call`] explicitly, so no other send can
    /// borrow the starting dispatch's loan. Snapshots are owned, so no lock is
    /// held across a check. Every transport that sends on a lent-only slot
    /// picks its loan here.
    ///
    /// # Errors
    ///
    /// A refusal when no loan matches, a matching loan has no check or was
    /// refused, or a check refuses now. One refusal refuses the send.
    pub(crate) async fn lent_for(
        &self,
        call: &[(String, String)],
    ) -> Result<Vec<(String, String)>> {
        let start = matches!(call, [(name, _)] if name == START_MARKER);
        // A start's starter can end while its check runs; the start then
        // sends as the next dispatch still waiting, never as the ended one.
        // Each pass follows a loan that has ended, which `starter` skips,
        // so the passes end.
        loop {
            let loans = if start {
                self.starter().into_iter().collect()
            } else {
                self.matching_all(call)
            };
            let Some(first) = loans.first() else {
                return Err(counted_refusal(
                    "unlent",
                    "the call's credential is not lent on this slot",
                ));
            };
            for loan in &loans {
                if loan.refused.is_some() {
                    return Err(counted_refusal("marked", "this credential was refused"));
                }
                let Some(check) = loan.check.as_ref() else {
                    return Err(counted_refusal(
                        "unchecked",
                        "no recheck is attached to this credential",
                    ));
                };
                if let Err(refusal) = check().await {
                    self.refuse(loan.id, refusal);
                    // No credential and no backend text: the refusal kind only.
                    tracing::warn!(?refusal, "a per-user send's credential recheck refused it");
                    let reason = match refusal {
                        Refusal::Definitive => "recheck_definitive",
                        Refusal::ThisLoan => "recheck_this_loan",
                        Refusal::Transient => "recheck_transient",
                    };
                    return Err(counted_refusal(
                        reason,
                        "this credential's recheck refused it",
                    ));
                }
            }
            if start && self.loan(first.id).is_none() {
                continue;
            }
            return Ok(first.headers.to_vec());
        }
    }

    fn snapshot(lent: &Lent) -> Snapshot {
        Snapshot {
            id: lent.id,
            headers: lent.headers.clone(),
            check: lent.check.clone(),
            refused: lent.refused,
        }
    }

    /// Record that loan `id`'s check refused. A definitive refusal runs the
    /// eviction hook once, at the refusal, so a dispatch dropped right after
    /// cannot skip it.
    pub(crate) fn refuse(&self, id: u64, refusal: Refusal) {
        if refusal == Refusal::Transient {
            return;
        }
        // The mark only escalates: a later ThisLoan never hides a Definitive,
        // and the first Definitive evicts even over an earlier ThisLoan.
        let newly_definitive = {
            let mut loans = self.loans.lock();
            loans
                .iter_mut()
                .find(|lent| lent.id == id)
                .is_some_and(|lent| {
                    let was = lent.refused;
                    if was != Some(Refusal::Definitive) {
                        lent.refused = Some(refusal);
                    }
                    refusal == Refusal::Definitive && was != Some(Refusal::Definitive)
                })
        };
        if newly_definitive && let Some(evict) = self.evict.lock().as_ref() {
            evict();
        }
    }

    /// Set what a definitive refusal runs: the owning slot's eviction.
    pub(crate) fn on_definitive_refusal(&self, evict: Box<dyn Fn() + Send + Sync>) {
        *self.evict.lock() = Some(evict);
    }
}

/// [`send_refused`], counted under `reason`: every lent-only send the
/// gateway refuses is one increment of
/// `mcp_gateway_per_user_send_refused_total`.
pub(crate) fn counted_refusal(reason: &'static str, why: &str) -> Error {
    count_refusal(reason);
    send_refused(why)
}

/// One refused per-user send, or deferred send, under `reason`.
pub(crate) fn count_refusal(reason: &'static str) {
    telemetry_metrics::counter!(
        "mcp_gateway_per_user_send_refused_total",
        "reason" => reason
    )
    .increment(1);
}

/// The refusal of a lent-only send: nothing reached the wire.
pub(crate) fn send_refused(why: &str) -> Error {
    Error::Forbidden {
        code: -32001,
        status: 403,
        message: format!("per-user send refused: {why}"),
    }
}

/// The headers of `headers` that are credential: all but the gateway-owned
/// `Mcp-Param-*` mirrors, which a call carries beside its credential.
fn credential_part(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !is_param_header(name))
        .cloned()
        .collect()
}

/// `headers` as a sorted list of (lowercased name, value).
fn canonical(headers: &[(String, String)]) -> Vec<(String, &str)> {
    let mut sorted: Vec<_> = headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.as_str()))
        .collect();
    sorted.sort_unstable();
    sorted
}

/// Holds a loan's place as the slot's starter; clears it when dropped, only
/// if the mark is still its own.
pub(crate) struct StartGuard {
    lender: Arc<Lender>,
    id: u64,
}

impl Drop for StartGuard {
    fn drop(&mut self) {
        let mut waiting = self.lender.starter.lock();
        if let Some(at) = waiting.iter().position(|&id| id == self.id) {
            waiting.remove(at);
        }
    }
}

/// One dispatch's loan; ends when dropped.
pub(crate) struct Loan {
    lender: Arc<Lender>,
    id: u64,
}

impl Loan {
    /// This loan's id within its lender.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// Whether a check refused this loan, and how.
    pub(crate) fn refused(&self) -> Option<Refusal> {
        self.lender.loan(self.id).and_then(|lent| lent.refused)
    }
}

impl Drop for Loan {
    fn drop(&mut self) {
        self.lender.loans.lock().retain(|lent| lent.id != self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> Vec<(String, String)> {
        vec![("Authorization".to_owned(), value.to_owned())]
    }

    #[test]
    fn a_send_finds_its_own_loan_by_its_headers() {
        let lender = Arc::new(Lender::default());
        let first = lender.lend(LentCredential::unchecked(&headers("one")));
        let _second = lender.lend(LentCredential::unchecked(&headers("two")));
        let mine = lender.matching_all(&headers("one"));
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].id, first.id(), "never the newest loan: its own");
        assert!(
            lender.matching_all(&headers("three")).is_empty(),
            "no loan: nothing to send as"
        );
    }

    #[test]
    fn a_strict_subset_of_a_loans_credential_matches_nothing() {
        let lender = Arc::new(Lender::default());
        let mut both = headers("one");
        both.push(("X-Api-Key".to_owned(), "key".to_owned()));
        let _loan = lender.lend(LentCredential::unchecked(&both));
        assert!(lender.matching_all(&headers("one")).is_empty());
        assert!(lender.matching_all(&[]).is_empty(), "empty matches nothing");
    }

    #[test]
    fn mcp_param_mirrors_on_the_call_are_ignored_for_matching() {
        let lender = Arc::new(Lender::default());
        let loan = lender.lend(LentCredential::unchecked(&headers("one")));
        let mut call = headers("one");
        call.push(("Mcp-Param-Region".to_owned(), "eu".to_owned()));
        let found = lender.matching_all(&call);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, loan.id());
    }

    #[test]
    fn the_first_starter_wins_and_only_its_own_guard_clears_it() {
        let lender = Arc::new(Lender::default());
        let first = lender.lend(LentCredential::unchecked(&headers("one")));
        let second = lender.lend(LentCredential::unchecked(&headers("two")));
        let held = lender.starting(first.id());
        let ignored = lender.starting(second.id());
        assert_eq!(lender.starter().map(|s| s.id), Some(first.id()));
        drop(ignored);
        assert_eq!(lender.starter().map(|s| s.id), Some(first.id()));
        drop(held);
        assert!(lender.starter().is_none());
    }

    /// While a start runs, a send that carries no credential is refused: only
    /// the start's own sends, passing [`Lender::start_call`] explicitly,
    /// go out as the starting dispatch.
    #[test]
    fn a_send_without_a_credential_never_borrows_the_starting_loan() {
        let lender = Arc::new(Lender::default());
        let loan = lender.lend(LentCredential {
            headers: headers("one").into(),
            check: Some(Arc::new(|| Box::pin(async { Ok(()) }))),
        });
        let _starting = lender.starting(loan.id());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");

        runtime.block_on(async {
            assert!(
                lender.lent_for(&[]).await.is_err(),
                "an empty call borrowed the starting dispatch's loan"
            );
            let mirror_only = vec![("Mcp-Param-Region".to_owned(), "eu".to_owned())];
            assert!(
                lender.lent_for(&mirror_only).await.is_err(),
                "a mirror-only call borrowed the starting dispatch's loan"
            );
            assert_eq!(
                lender.lent_for(&lender.start_call()).await.ok(),
                Some(headers("one")),
                "the start's own send, carrying the starter explicitly, goes out"
            );
        });
    }

    /// A start's call is resolved at each send: captured while the first
    /// dispatch was the starter, it sends as the next one once the first is
    /// cancelled mid-start, never as the ended loan.
    #[test]
    fn a_start_call_follows_the_starter_cancelled_mid_start() {
        let lender = Arc::new(Lender::default());
        let checked = |value: &str| LentCredential {
            headers: headers(value).into(),
            check: Some(Arc::new(|| Box::pin(async { Ok(()) }))),
        };
        let first = lender.lend(checked("one"));
        let second = lender.lend(checked("two"));
        let first_waits = lender.starting(first.id());
        let _second_waits = lender.starting(second.id());
        let call = lender.start_call();
        drop(first_waits);
        drop(first);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");

        let sent = runtime.block_on(lender.lent_for(&call)).ok();

        assert_eq!(
            sent,
            Some(headers("two")),
            "the start sent as the next waiter"
        );
    }

    /// A start send whose starter's dispatch ends while that loan's check
    /// runs is sent as the next dispatch still waiting, not as the ended one.
    /// With no waiter left, the captured start call is refused.
    #[test]
    fn a_start_send_whose_starter_ends_during_its_check_sends_as_the_next() {
        let lender = Arc::new(Lender::default());
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let (in_check, resume) = (Arc::clone(&entered), Arc::clone(&release));
        let first = lender.lend(LentCredential {
            headers: headers("one").into(),
            check: Some(Arc::new(move || {
                let (in_check, resume) = (Arc::clone(&in_check), Arc::clone(&resume));
                Box::pin(async move {
                    in_check.notify_one();
                    resume.notified().await;
                    Ok(())
                })
            })),
        });
        let second = lender.lend(LentCredential {
            headers: headers("two").into(),
            check: Some(Arc::new(|| Box::pin(async { Ok(()) }))),
        });
        let first_waits = lender.starting(first.id());
        let second_waits = lender.starting(second.id());
        let call = lender.start_call();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");

        let sent = runtime.block_on(async {
            let cancel = async move {
                entered.notified().await;
                drop(first_waits);
                drop(first);
                release.notify_one();
            };
            tokio::join!(lender.lent_for(&call), cancel).0
        });
        assert_eq!(sent.ok(), Some(headers("two")), "sent as the next waiter");

        drop(second_waits);
        drop(second);
        let after = runtime.block_on(lender.lent_for(&call));
        assert!(after.is_err(), "a start call with no waiter left was sent");
    }

    /// A lent credential's headers are the zeroizing type the lender stores,
    /// so no copy of a caller's credential outlives its holder unwiped.
    #[test]
    fn a_lent_credentials_headers_are_wiped_on_drop() {
        let credential = LentCredential::unchecked(&headers("one"));
        let wiped: &Zeroizing<Vec<(String, String)>> = &credential.headers;
        assert_eq!(wiped.as_slice(), headers("one").as_slice());
    }

    /// A refusal mark only escalates: `ThisLoan` then `Definitive` evicts once,
    /// and a `ThisLoan` after a `Definitive` leaves it `Definitive`.
    /// The first starter cancelled, the next dispatch waiting on the start
    /// becomes its starter: the start is never left with no loan to send as.
    #[test]
    fn a_cancelled_first_starter_hands_the_start_to_the_next() {
        let lender = Arc::new(Lender::default());
        let first = lender.lend(LentCredential::unchecked(&headers("one")));
        let second = lender.lend(LentCredential::unchecked(&headers("two")));
        let first_waits = lender.starting(first.id());
        let _second_waits = lender.starting(second.id());
        drop(first_waits);
        assert_eq!(lender.starter().map(|s| s.id), Some(second.id()));
    }

    #[test]
    fn a_refusal_mark_only_escalates() {
        let lender = Arc::new(Lender::default());
        let evicted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&evicted);
        lender.on_definitive_refusal(Box::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        }));
        let loan = lender.lend(LentCredential::unchecked(&headers("one")));
        lender.refuse(loan.id(), Refusal::ThisLoan);
        lender.refuse(loan.id(), Refusal::Definitive);
        assert_eq!(evicted.load(Ordering::SeqCst), 1, "the upgrade evicts");
        lender.refuse(loan.id(), Refusal::ThisLoan);
        assert_eq!(
            loan.refused(),
            Some(Refusal::Definitive),
            "never downgraded"
        );
        assert_eq!(evicted.load(Ordering::SeqCst), 1, "evicted once");
    }

    #[test]
    fn a_definitive_refusal_evicts_once_and_a_transient_one_marks_nothing() {
        let lender = Arc::new(Lender::default());
        let evicted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&evicted);
        lender.on_definitive_refusal(Box::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        }));
        let loan = lender.lend(LentCredential::unchecked(&headers("one")));
        lender.refuse(loan.id(), Refusal::Transient);
        assert_eq!(loan.refused(), None, "a transient fault marks nothing");
        lender.refuse(loan.id(), Refusal::Definitive);
        lender.refuse(loan.id(), Refusal::Definitive);
        assert_eq!(loan.refused(), Some(Refusal::Definitive));
        assert_eq!(
            evicted.load(Ordering::SeqCst),
            1,
            "evicted once, at the refusal"
        );
        let other = lender.lend(LentCredential::unchecked(&headers("two")));
        lender.refuse(other.id(), Refusal::ThisLoan);
        assert_eq!(other.refused(), Some(Refusal::ThisLoan));
        assert_eq!(
            evicted.load(Ordering::SeqCst),
            1,
            "a this-loan refusal does not evict"
        );
    }

    /// A refused recheck is counted by how it refused, and so is a call
    /// whose credential is not lent.
    #[cfg(feature = "metrics")]
    #[test]
    fn every_refused_send_is_counted_by_its_reason() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let lender = Arc::new(Lender::default());
        let _loan = lender.lend(LentCredential {
            headers: headers("one").into(),
            check: Some(Arc::new(|| Box::pin(async { Err(Refusal::ThisLoan) }))),
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");

        telemetry_metrics::with_local_recorder(&recorder, || {
            runtime.block_on(async {
                assert!(lender.lent_for(&headers("one")).await.is_err());
                assert!(lender.lent_for(&headers("two")).await.is_err());
            });
        });

        let rendered = handle.render();
        for reason in ["recheck_this_loan", "unlent"] {
            let series = format!("mcp_gateway_per_user_send_refused_total{{reason=\"{reason}\"}}");
            assert!(
                rendered
                    .lines()
                    .any(|line| line.starts_with(&series) && line.ends_with(" 1")),
                "{series} not counted once:\n{rendered}"
            );
        }
    }

    /// No conversion builds a loan: one would make a loan with no send check
    /// at a call site that never says so. Every unchecked loan is made by
    /// `LentCredential::unchecked`, by name. Scans every source file for an
    /// impl header that converts into the type.
    #[test]
    fn no_conversion_builds_a_loan() {
        fn scan(dir: &std::path::Path, hits: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).expect("src is readable") {
                let path = entry.expect("a directory entry").path();
                if path.is_dir() {
                    scan(&path, hits);
                    continue;
                }
                if path.extension().is_none_or(|ext| ext != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("a source file");
                // One space between tokens, none before a `<`, so spacing
                // cannot hide a header.
                let flat = text
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .replace(" <", "<");
                // Built at run time, so this row's own text never matches.
                let target = format!("{}{}", "Lent", "Credential");
                let conversions = [concat!("From", "<"), concat!("Into", "<")];
                for (at, _) in flat.match_indices(&target) {
                    let Some(start) = flat[..at].rfind("impl") else {
                        continue;
                    };
                    // The impl header up to the type, path prefix included.
                    let header = &flat[start..at];
                    if header.contains(['{', '}']) {
                        continue;
                    }
                    // `From<..> for` the type, or `Into<` the type for another.
                    let from = header.contains(" for ") && header.contains(conversions[0]);
                    let into = header.contains(conversions[1]);
                    if from || into {
                        hits.push(format!("{}: {header}", path.display()));
                    }
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut hits = Vec::new();
        scan(&src, &mut hits);
        assert!(hits.is_empty(), "a conversion builds a loan: {hits:?}");
    }
}
