// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Single-use enforcement: the consumed ledger, in-flight claims and the state that owns them.

use ring::rand::{SecureRandom as _, SystemRandom};

use super::{Keyring, Payload, expiry_for};

/// The continuations already spent.
///
/// Encryption makes an envelope unforgeable; it does nothing about how many
/// times an unforgeable envelope is presented. This is the other half, and the
/// specification asks for it in as many words: a state that must be consumed at
/// most once **MUST** have that invariant enforced server-side.
///
/// Three properties, and each has a way of being quietly absent:
///
/// * **Atomic.** Check-and-consume in one operation. As two steps, two retries
///   of a destructive continuation both see it unspent and both proceed.
/// * **Bounded.** A client may abandon a continuation — the spec says a server
///   MUST NOT assume otherwise — so entries arrive at a rate the client chooses
///   and eviction on a deadline alone is not a bound.
/// * **Retained at least as long as the envelope.** Forgetting a spent `jti`
///   while its envelope still opens is a replay window with extra steps.
///
/// Process-local, and correct that way rather than pending a shared store. Key
/// material is generated per process and never shared ([`ContinuationState`]),
/// so an envelope opens on exactly one replica and only that replica can spend
/// it — leaving no second ledger for a partition or a stale read to disagree
/// with. Sharing the keys without sharing this table is what would break it,
/// which is the invariant [`ContinuationState`] carries.
#[derive(Debug)]
pub struct ConsumedLedger {
    capacity: usize,
    /// `jti` -> the deadline of the envelope it came from. A `tokio` lock, so
    /// check-and-consume stays one operation for concurrent callers.
    spent: tokio::sync::Mutex<std::collections::HashMap<String, u64>>,
}

impl ConsumedLedger {
    /// A ledger holding at most `capacity` unexpired entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            spent: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Spend a continuation. `true` if this caller won, `false` if it was
    /// already spent or the ledger is full.
    ///
    /// One operation under one lock: the check and the write cannot be
    /// separated by a scheduler, which is the whole point.
    ///
    /// At capacity it **refuses** rather than evicting. Both stay bounded, and
    /// the difference is who pays: forgetting an entry whose envelope still
    /// opens re-opens a replay window on a continuation already spent, which is
    /// the single property this ledger exists to hold. Refusing costs a caller
    /// one retry of an elicitation. An entry is only ever reclaimed once its
    /// own deadline has passed, at which point its envelope no longer opens and
    /// remembering it buys nothing.
    ///
    /// So capacity is a deployment decision about availability, never about
    /// safety — which is the right way round.
    ///
    /// `now` is passed rather than read from a clock, as everywhere else in
    /// this module: reclamation must agree with [`Self::evict_expired`] and
    /// with the deadline [`Keyring::open`] enforced, and three components
    /// reading three clocks is how they come to disagree.
    pub async fn consume(&self, jti: &str, expires_at: u64, now: u64) -> bool {
        let mut spent = self.spent.lock().await;
        if spent.contains_key(jti) {
            return false;
        }
        if spent.len() >= self.capacity {
            // Reclaim only what is genuinely dead — an entry whose own deadline
            // has passed, whose envelope therefore no longer opens. Refusing
            // while holding entries nobody can replay would be a denial of
            // service dressed as caution.
            spent.retain(|_, deadline| now <= *deadline);
            if spent.len() >= self.capacity {
                return false;
            }
        }
        spent.insert(jti.to_string(), expires_at);
        true
    }

    /// Drop entries whose continuations have expired.
    ///
    /// An entry is kept until `now` passes its deadline, never before: the
    /// envelope opens until then, so the memory of it being spent must last at
    /// least as long.
    pub async fn evict_expired(&self, now: u64) {
        self.spent
            .lock()
            .await
            .retain(|_, expires_at| now <= *expires_at);
    }

    /// How many entries are held.
    pub async fn len(&self) -> usize {
        self.spent.lock().await.len()
    }

    /// Whether the ledger holds nothing.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

/// Where a retry must be handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Routing {
    /// This replica holds the exchange.
    Here,
    /// Nobody holds it: evicted, expired, or the holder is gone.
    Gone,
}

/// The in-flight table: key -> (replica holding it, deadline, quota key).
type Held = std::collections::HashMap<String, (String, u64, super::QuotaKey)>;

/// Exchanges this gateway is holding open on behalf of a legacy backend.
///
/// This is the one place the gateway is permitted to hold state, and the reason
/// is not convenience. A **legacy** backend that elicits does so by keeping its
/// RPC open and waiting; there is no continuation it can hand back, because the
/// revision that invented continuations is the one it does not speak. So the
/// gateway absorbs that statefulness and presents the modern client a
/// continuation anyway. That is the bridge earning its keep.
///
/// The open RPC lives on exactly one replica, and a stateless client's retry
/// may land on any of them — which is why `origin_replica` travels inside the
/// sealed envelope. A retry that arrives anywhere but the minting replica
/// **fails explicitly**; there is no affinity to send it home with. Starting a
/// second exchange
/// instead would leave the first hanging and ask the user the same question
/// twice; for a destructive tool, the second answer would authorise a call the
/// first one already authorised.
#[derive(Debug)]
pub struct InFlight {
    replica: String,
    capacity: usize,
    /// key -> (replica holding it, deadline, the caller it is charged to).
    held: tokio::sync::Mutex<Held>,
    /// A lower bound on the earliest deadline held (`u64::MAX` when none), so
    /// a reader skips the walk when nothing can have expired (`MIK-8060`).
    /// Written only under `held`'s lock: `hold` lowers it, a walk sets it to
    /// the exact minimum, and `complete` leaves it, which keeps it a bound.
    earliest: std::sync::atomic::AtomicU64,
    /// How many times a reader walked the whole table to reclaim (`MIK-8060`).
    #[cfg(test)]
    walks: std::sync::atomic::AtomicUsize,
    /// key -> the request digest of the chain step paused on that exchange
    /// (MIK-8168). Crate-internal, and never longer-lived than its hold.
    steps: parking_lot::Mutex<std::collections::HashMap<String, String>>,
}

/// Drop exchanges whose deadline has passed, returning the earliest deadline
/// left (`u64::MAX` when none).
///
/// A free function rather than a method because [`InFlight::guard`] calls it
/// while already holding the lock.
pub(super) fn reclaim_abandoned(held: &mut Held, now: u64) -> u64 {
    let before = held.len();
    let mut earliest = u64::MAX;
    held.retain(|_, (_, deadline, _)| {
        let live = now <= *deadline;
        if live {
            earliest = earliest.min(*deadline);
        }
        live
    });
    let evicted = before - held.len();
    if evicted > 0 {
        // The only trace this event leaves. A client refused for presenting a
        // stale envelope is counted at its own call site with
        // `reason="deadline_passed"`; a client that simply stops calling makes
        // no call to be counted in, so without this an operator cannot see it
        // at all (NFR.OBS.4). Counted here rather than at the caller because
        // this is where the eviction is decided, and the emission is pinned
        // end-to-end by `tests/continuation_expiry_metric_test.rs`.
        telemetry_metrics::counter!("continuation_expiry_total", "reason" => "hold_evicted")
            .increment(evicted as u64);
    }
    earliest
}

impl InFlight {
    /// A table for this replica, holding at most `capacity` exchanges.
    #[must_use]
    pub fn new(replica: &str, capacity: usize) -> Self {
        Self {
            replica: replica.to_string(),
            capacity,
            held: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            earliest: std::sync::atomic::AtomicU64::new(u64::MAX),
            #[cfg(test)]
            walks: std::sync::atomic::AtomicUsize::new(0),
            steps: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Record that this replica is holding an exchange open, returning its key.
    ///
    /// `None` at capacity — a refusal the caller turns into an error the client
    /// can see. Growing instead would make the table a memory-exhaustion vector
    /// reachable by any client that starts elicitations and walks away, which
    /// the specification explicitly permits it to do.
    ///
    /// Also `None` when `quota` already holds its share of the table
    /// ([`super::PRINCIPAL_SLOTS`], MIK-8293), and refused the same way: one
    /// caller filling the pool would otherwise refuse every other caller's
    /// questions until its holds expired. Nothing is evicted.
    pub async fn hold(
        &self,
        backend_id: &str,
        quota: &super::QuotaKey,
        expires_at: u64,
        now: u64,
    ) -> Option<String> {
        // `guard` has already reclaimed against `now`, so the count this
        // refusal reads is of exchanges that are still live. Reclaiming in the
        // capacity branch instead would make the bound the only thing that
        // ever collected an abandoned slot, and every reader below would then
        // be able to observe one.
        let mut held = self.guard(now).await;
        if held.len() >= self.capacity {
            return None;
        }
        // Counted, never stored: every path that frees a slot (complete,
        // try_complete, the expiry reclaim) frees the caller's share with it,
        // so there is no count to fall out of step with the table.
        // ponytail: a scan of at most `capacity` entries, under a lock the mint
        // already holds; keep a per-key count map if mints ever become hot.
        let share = super::PRINCIPAL_SLOTS.min(self.capacity);
        if held
            .values()
            .filter(|(_, _, held_by)| held_by == quota)
            .count()
            >= share
        {
            tracing::warn!("a caller holds its share of the in-flight table; refusing a new slot");
            return None;
        }
        // Named by the gateway, never by the client: two exchanges against one
        // backend must not collide, and no caller may name another's.
        let key = format!("{backend_id}:{}", uuid::Uuid::new_v4());
        held.insert(
            key.clone(),
            (self.replica.clone(), expires_at, quota.clone()),
        );
        self.earliest
            .fetch_min(expires_at, std::sync::atomic::Ordering::Relaxed);
        Some(key)
    }

    /// Take the lock and reclaim against `now` before anything reads the map.
    ///
    /// Every reader below goes through here, which is what makes "an expired
    /// hold is retained" and "an expired hold routes `Here`" unstateable about
    /// this type. Teaching `route` alone to compare deadlines would leave both
    /// findings stateable about `len`, and about the next reader someone adds.
    ///
    /// **The guarantee is relative to the supplied `now`, and that is the whole
    /// contract.** The table holds no record whose deadline is strictly before the
    /// `now` most recently passed in. It does *not* hold that the table is free
    /// of records expired against the wall clock at the instant a caller reads
    /// the result: `invoke.rs` captures `now` once and reuses it for both the
    /// route and the completion, so an exchange expiring inside that window
    /// survives the reclaim and still routes. That is correct — a dispatch
    /// decided against a single consistent instant is the property the call
    /// path wants, and re-reading the clock per call would make one request
    /// observe two different presents. Said here so that a future call site
    /// cannot inherit the absolute reading.
    async fn guard(&self, now: u64) -> tokio::sync::MutexGuard<'_, Held> {
        let mut held = self.held.lock().await;
        // Nothing held expires before the bound, so nothing can be reclaimed:
        // a full table would otherwise cost a walk of every hold per call.
        let earliest = &self.earliest;
        if earliest.load(std::sync::atomic::Ordering::Relaxed) < now {
            #[cfg(test)]
            self.walks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let left = reclaim_abandoned(&mut held, now);
            earliest.store(left, std::sync::atomic::Ordering::Relaxed);
            // A paused chain's step digest lives exactly as long as its hold, so
            // an abandoned chain (its hold expired) leaves nothing behind either.
            // Only a walk removes holds here; `complete` drops its own step.
            self.steps.lock().retain(|key, _| held.contains_key(key));
        }
        held
    }

    /// Whether this replica still holds the exchange for `key`.
    ///
    /// There is no third answer. The holder recorded in the table is always
    /// this replica, because `hold` is the only thing that writes one, so a
    /// retry that reaches the wrong process asks a table that never knew the
    /// key and is told `Gone`. That is the design's own bargain
    /// (`docs/design/2026-08-30-shared-continuation-state.md:116`): the
    /// cross-replica guarantee holds cryptographically, with no shared store
    /// and **no affinity**, and MRTR.6's second arm — fail explicitly — is
    /// what serves the criterion.
    ///
    /// Waits for the lock rather than answering under contention. `Gone` means
    /// the exchange no longer exists and a caller acts on it by failing the
    /// retry, so reporting it for a lock a concurrent reaper happens to hold
    /// would turn ordinary contention into a lost elicitation — the outcome
    /// this table exists to prevent. The wait is bounded by the map operations
    /// the other holders are performing, all of which are O(1) or a retain over
    /// a table with a capacity.
    pub async fn route(&self, key: &str, now: u64) -> Routing {
        let held = self.guard(now).await;
        match held.get(key) {
            Some(_) => Routing::Here,
            None => Routing::Gone,
        }
    }

    /// Release an exchange that has finished, reporting whether it held a slot.
    ///
    /// Without this, capacity counts every exchange ever *started* until its
    /// deadline passes, so a busy gateway refuses new elicitations on behalf of
    /// ones that completed long ago. Reaping is the backstop for abandonment,
    /// not the ordinary path — the ordinary path is that an exchange ends.
    pub async fn complete(&self, key: &str, now: u64) -> bool {
        let removed = self.guard(now).await.remove(key).is_some();
        self.steps.lock().remove(key);
        removed
    }

    /// [`Self::complete`] without waiting or blocking: `None` when the table is
    /// locked, so a caller that cannot await (a `Drop`) can fall back to the
    /// async path. A busy step map keeps the key's step entry, which the next
    /// reclaim drops with every entry whose hold is gone.
    pub(crate) fn try_complete(&self, key: &str) -> Option<bool> {
        let removed = self.held.try_lock().ok()?.remove(key).is_some();
        if let Some(mut steps) = self.steps.try_lock() {
            steps.remove(key);
        }
        Some(removed)
    }

    /// Remember the chain step paused on its exchange (MIK-8168): its request
    /// digest, which binds the backend instance that asked. Synchronous
    /// because the chain driver seals a stop synchronously; the entry goes
    /// with its hold, on completion or on the next reclaim after expiry.
    pub(crate) fn bind_step(&self, step: &Payload) {
        let digest = step.original_request_digest.clone();
        self.steps.lock().insert(step.hold_key.clone(), digest);
    }

    /// The step digest [`Self::bind_step`] recorded, while its exchange is
    /// still held.
    pub(crate) async fn step_digest(&self, key: &str, now: u64) -> Option<String> {
        // Checked against the table, not left to the reclaim pass: a skipped
        // walk (`MIK-8060`) must not let a step outlive its hold.
        let held = self.guard(now).await;
        if !held.contains_key(key) {
            return None;
        }
        self.steps.lock().get(key).cloned()
    }

    /// How many exchanges are held, as of `now`.
    pub async fn len(&self, now: u64) -> usize {
        self.guard(now).await.len()
    }
}

/// The three pieces of continuation state, with one owner and one lifetime.
///
/// They are separable types and are deliberately not separable fields. A
/// keyring that outlives its ledger is a replay window: envelopes minted before
/// the ledger was replaced still open, and the memory of them being spent is
/// gone. Constructing all three together, and replacing them only together, is
/// what closes it.
///
/// **The invariant this type carries, because a future change could break it
/// while looking like a configuration convenience:**
///
/// > Continuation key material is never shared between processes unless the
/// > consumed-ledger is shared in the same change.
///
/// That is not a caveat, it is the enforcement mechanism for MRTR.5. Key
/// material is generated here, per process, and written nowhere. So an envelope
/// sealed by one replica is `NotAuthentic` on every other one, the set of
/// replicas that can spend it twice is empty, and the one replica that can
/// spend it at all does so atomically under [`ConsumedLedger`]'s own mutex —
/// no shared store, no session affinity, no consensus. A configured shared key
/// without a shared ledger is exactly the deployment the requirement forbids.
///
/// See `docs/design/2026-08-30-shared-continuation-state.md`.
#[derive(Debug)]
pub struct ContinuationState {
    replica: String,
    keyring: Keyring,
    ledger: ConsumedLedger,
    in_flight: InFlight,
    holds: HoldCounts,
}

/// What became of the sealed holds the gateway registered against this state
/// (MIK-8176, family continuation-slot-release). Per state, not per process,
/// so a test reads its own fixture's counts.
#[derive(Debug, Default)]
pub(crate) struct HoldCounts {
    /// Mints registered under an open request scope.
    pub(crate) registered: std::sync::atomic::AtomicU64,
    /// Mints made outside any request scope: a route boundary opened none.
    pub(crate) unscoped: std::sync::atomic::AtomicU64,
    /// Holds whose last copy dropped without reaching a transport.
    pub(crate) unhanded_drops: std::sync::atomic::AtomicU64,
}

/// How many spent continuations one process remembers at once.
///
/// An availability figure, never a safety one: at capacity the ledger refuses a
/// redemption rather than forgetting one, so the cost of it being too small is
/// a client retrying an elicitation, not a replay. Sized for a busy gateway's
/// unexpired continuations, which live minutes rather than hours.
pub(super) const CONSUMED_LEDGER_CAPACITY: usize = 65_536;

/// How many legacy exchanges one process holds open at once.
///
/// Also availability, and also a refusal rather than growth: a client may start
/// an elicitation and never retry, so this table's occupants arrive at a rate
/// the client chooses. Smaller than the ledger because each entry is a live RPC
/// against a backend, not a remembered string.
pub(super) const IN_FLIGHT_CAPACITY: usize = 4_096;

impl ContinuationState {
    /// Build the state for this process, generating its key material.
    ///
    /// # Panics
    ///
    /// Panics if the platform RNG cannot produce a key. A process that cannot
    /// generate one cannot seal a continuation, so it cannot serve the modern
    /// protocol path — failing at startup says that once, where an operator
    /// sees it, rather than on the first elicitation a user reaches.
    #[must_use]
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key)
            .expect("platform RNG must produce a continuation key");
        // Named by the process, for the process: `origin_replica` is sealed
        // inside the envelope and read only by the replica that minted it, so
        // any per-process value works and a generated one cannot collide with
        // a restarted predecessor's.
        let replica = uuid::Uuid::new_v4().to_string();
        Self {
            keyring: Keyring::new(&[(1, key)]).expect("a single 32-byte key is a valid keyring"),
            ledger: ConsumedLedger::new(CONSUMED_LEDGER_CAPACITY),
            in_flight: InFlight::new(&replica, IN_FLIGHT_CAPACITY),
            replica,
            holds: HoldCounts::default(),
        }
    }

    /// Test-only: a store whose in-flight table holds nothing, so every mint
    /// is refused for want of a slot (MIK-8078).
    #[cfg(test)]
    pub(crate) fn full_for_test() -> Self {
        let mut state = Self::new();
        state.in_flight = InFlight::new(&state.replica, 0);
        state
    }

    /// Test-only: a store that grants slots but whose keyring refuses every
    /// envelope (a mint budget of zero), so a site's mint-failure path is
    /// reached with its slot already taken (MIK-8311).
    #[cfg(test)]
    pub(crate) fn mint_refusing_for_test() -> Self {
        let mut key = [0u8; 32];
        SystemRandom::new()
            .fill(&mut key)
            .expect("platform RNG must produce a continuation key");
        let mut state = Self::new();
        state.keyring = Keyring::new(&[(1, key)])
            .expect("a single 32-byte key is a valid keyring")
            .with_mint_budget(0);
        state
    }

    /// Open an exchange on this replica and seal a continuation for it
    /// (MRTR.8).
    ///
    /// The hold and the mint are one operation because the criterion is about
    /// their agreement: an envelope naming an exchange nobody holds is
    /// redeemable against nothing, and a held slot no envelope names is a leak
    /// that only the reaper ever closes. Taking the slot first also puts the
    /// capacity refusal before the mint, so a gateway at its limit declines the
    /// question rather than answering it with a handle it cannot honour.
    ///
    /// `None` when the table is full, or when `quota` (the caller, never the
    /// sealed `principal_fingerprint`, which is finer) holds its share of it
    /// (MIK-8293). The caller turns that into the same refusal it gives an
    /// unbindable caller: both are properties of this gateway's state that a
    /// client can do nothing about.
    pub async fn begin_exchange(
        &self,
        backend_id: String,
        backend_request_state: Option<String>,
        principal_fingerprint: String,
        quota: &super::QuotaKey,
        original_request_digest: String,
        now: u64,
    ) -> Option<Payload> {
        let hold_key = self
            .in_flight
            .hold(&backend_id, quota, expiry_for(now), now)
            .await?;
        Some(Payload::mint(
            backend_id,
            backend_request_state,
            principal_fingerprint,
            original_request_digest,
            self.replica.clone(),
            hold_key,
            now,
        ))
    }

    /// Open a confirmation exchange on this replica and seal a
    /// [`ContinuationPurpose::DestructiveConfirm`](super::ContinuationPurpose::DestructiveConfirm)
    /// continuation for it.
    ///
    /// Same hold-then-mint pairing as [`Self::begin_exchange`]: the envelope
    /// names a slot this process is holding, and a full table declines rather
    /// than answering with a handle it cannot honour.
    pub async fn begin_confirmation_exchange(
        &self,
        backend_id: String,
        backend_request_state: Option<String>,
        principal_fingerprint: String,
        quota: &super::QuotaKey,
        original_request_digest: String,
        now: u64,
    ) -> Option<Payload> {
        let hold_key = self
            .in_flight
            .hold(&backend_id, quota, expiry_for(now), now)
            .await?;
        Some(Payload::mint_confirmation(
            backend_id,
            backend_request_state,
            principal_fingerprint,
            original_request_digest,
            self.replica.clone(),
            hold_key,
            now,
        ))
    }

    /// The keys this process mints and opens with.
    #[must_use]
    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// The continuations this process has already spent.
    #[must_use]
    pub fn ledger(&self) -> &ConsumedLedger {
        &self.ledger
    }

    /// The legacy exchanges this process is holding open.
    #[must_use]
    pub fn in_flight(&self) -> &InFlight {
        &self.in_flight
    }

    /// What became of the sealed holds registered against this state.
    pub(crate) fn hold_counts(&self) -> &HoldCounts {
        &self.holds
    }

    /// What this process calls itself in a minted `origin_replica`.
    #[must_use]
    pub fn replica(&self) -> &str {
        &self.replica
    }
}

impl Default for ContinuationState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod in_flight_lifetime;
#[cfg(test)]
mod quota_tests;
