// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The CLI login attempts: one per `login`, held in memory for ten minutes.
//!
//! An attempt has three random values, each from its own draw: the code a
//! person types on the approval page, an id that names the attempt, and the
//! polling secret only the CLI holds. Time is the caller's `now`, so rows set
//! it exactly; the draws are the caller's too (`Draws`), so rows script them.

use std::time::{Duration, Instant};

/// The 32 code symbols: digits and capitals without I, L, O and U.
pub(crate) const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Symbols in a code: 10 x 5 bits = 50 bits.
pub(crate) const CODE_LEN: usize = 10;
/// Attempts held at once, consumed ones included.
pub(crate) const CAPACITY: usize = 256;
/// From start to the deadline; nothing extends it.
pub(crate) const LIFETIME: Duration = Duration::from_secs(600);
/// Code draws before a start gives up on collisions.
pub(crate) const MAX_CODE_DRAWS: usize = 8;
/// The least time between two polls of one attempt.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Polls one attempt answers.
pub(crate) const MAX_POLLS: u32 = 120;

/// A code in canonical form: ten indices into `CODE_ALPHABET`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct UserCode([u8; CODE_LEN]);

impl UserCode {
    /// From ten drawn values, each taken mod 32.
    pub(crate) fn from_indices(indices: [u8; CODE_LEN]) -> Self {
        Self(indices.map(|i| i % 32))
    }

    /// As shown to a person: `XXXXX-XXXXX`.
    pub(crate) fn display(&self) -> String {
        let mut shown = String::with_capacity(CODE_LEN + 1);
        for (at, index) in self.0.iter().enumerate() {
            if at == CODE_LEN / 2 {
                shown.push('-');
            }
            shown.push(char::from(CODE_ALPHABET[usize::from(*index)]));
        }
        shown
    }

    /// A typed code: either case, with or without the one hyphen after the
    /// fifth symbol; anything else is `None`.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        // SCAFFOLD: refuses until the implementation commit.
        let _ = text;
        None
    }
}

/// Never shows the symbols: a code in a log would help a guesser.
impl std::fmt::Debug for UserCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserCode(..)")
    }
}

/// Where an attempt's random values come from.
pub(crate) struct Draws {
    pub(crate) code: Box<dyn Fn() -> [u8; CODE_LEN] + Send + Sync>,
    pub(crate) id: Box<dyn Fn() -> uuid::Uuid + Send + Sync>,
    pub(crate) secret: Box<dyn Fn() -> String + Send + Sync>,
}

impl Draws {
    /// The live sources: the code from the thread RNG, the id from
    /// `crate::ids` (a v4 UUID), the polling secret from the
    /// shared credential generator (256 bits).
    pub(crate) fn production() -> Self {
        Self {
            code: Box::new(draw_code),
            id: Box::new(crate::ids::new_v4),
            secret: Box::new(|| crate::random_secret::random_secret("")),
        }
    }
}

/// Ten uniform symbols: 256 is a multiple of 32, so `% 32` adds no bias.
fn draw_code() -> [u8; CODE_LEN] {
    use rand::RngExt as _;
    #[allow(
        clippy::disallowed_methods,
        reason = "user code: the CLI login code a person types; 50 bits for 600 s, and approving it also needs an admin session"
    )]
    let bytes: [u8; CODE_LEN] = rand::rng().random();
    bytes.map(|b| b % 32)
}

/// What a start hands the CLI.
pub(crate) struct Started {
    pub(crate) id: uuid::Uuid,
    pub(crate) code: UserCode,
    pub(crate) secret: String,
    pub(crate) deadline: Instant,
}

/// Why a start was refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StartRefused {
    /// `CAPACITY` attempts are held.
    Full,
    /// `MAX_CODE_DRAWS` draws all hit a held code, or the id draw hit a held id.
    Collision,
}

/// A poll's answer while the attempt waits.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PollState {
    Pending,
}

/// Why a poll was refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PollRefused {
    /// Unknown id, past the deadline, or the wrong secret: one answer for all
    /// three, so a poller learns nothing about attempts it does not hold.
    Invalid,
    /// The rightful poller came back within `POLL_INTERVAL`.
    TooSoon,
    /// The attempt has answered `MAX_POLLS` polls.
    Exhausted,
}

/// The attempts held now. A new store holds none: a restart ends them all.
pub(crate) struct AttemptStore {
    draws: Draws,
    /// Test only: `start` calls it after finding a code free and before
    /// inserting the attempt, inside the one lock that covers both.
    #[cfg(test)]
    pause: Option<Box<dyn Fn() + Send + Sync>>,
}

impl AttemptStore {
    pub(crate) fn new(draws: Draws) -> Self {
        Self {
            draws,
            #[cfg(test)]
            pause: None,
        }
    }

    /// A store whose `start` stops in `pause` between its uniqueness check
    /// and its insert, so a row can line two starts up inside that gap.
    #[cfg(test)]
    pub(crate) fn with_pause(draws: Draws, pause: Box<dyn Fn() + Send + Sync>) -> Self {
        Self {
            draws,
            pause: Some(pause),
        }
    }

    /// Holds a new attempt until `now + LIFETIME`.
    pub(crate) fn start(&self, now: Instant) -> Result<Started, StartRefused> {
        // SCAFFOLD: refuses until the implementation commit.
        let _ = (&self.draws, now);
        Err(StartRefused::Full)
    }

    /// The id of the live, unconsumed attempt holding `code`.
    pub(crate) fn lookup(&self, code: &UserCode, now: Instant) -> Option<uuid::Uuid> {
        // SCAFFOLD: refuses until the implementation commit.
        let _ = (code, now);
        None
    }

    /// Marks a live attempt consumed; its code and its place stay held until
    /// its deadline.
    pub(crate) fn consume(&self, id: uuid::Uuid, now: Instant) -> bool {
        // SCAFFOLD: refuses until the implementation commit.
        let _ = (id, now);
        false
    }

    /// The poller's view of its attempt. The secret is checked before the
    /// interval and the count, so a stranger only ever sees `Invalid`.
    pub(crate) fn poll(
        &self,
        id: uuid::Uuid,
        secret: &str,
        now: Instant,
    ) -> Result<PollState, PollRefused> {
        // SCAFFOLD: refuses until the implementation commit.
        let _ = (id, secret, now);
        Err(PollRefused::Invalid)
    }

    /// Attempts held at `now`, live or consumed.
    pub(crate) fn retained(&self, now: Instant) -> usize {
        // SCAFFOLD: counts nothing until the implementation commit.
        let _ = now;
        0
    }

    /// Sets a held attempt's poll count, so a row can reach `MAX_POLLS`
    /// before the deadline.
    #[cfg(test)]
    pub(crate) fn set_polls_for_test(&self, id: uuid::Uuid, polls: u32) {
        // SCAFFOLD: does nothing until the implementation commit.
        let _ = (id, polls);
    }
}
