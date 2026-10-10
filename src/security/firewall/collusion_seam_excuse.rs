// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8205`: a caller's own subset forward is excused (design r3.3, closed).
//!
//! A window W is a seam of caller C from source S when W is a k-gram of the
//! normalised run-together of one run S delivered to C, after omitting one
//! contiguous span of its pieces, and W overlaps the created boundary. Every
//! such window is text C received from S with at most one gap, so excusing it
//! reveals nothing C did not hold.
//!
//! Seam fingerprints are excuse only: they live in [`SeamExcuses`], apart
//! from the evidence entries, never witness, never count toward `Common`, and
//! never take evidence capacity.
//!
//! Work per delivery is O(P + S x B): P pieces counted and indexed (capped at
//! [`MAX_SEAM_PIECES`] before any per-piece work), S spans attempted (capped
//! at [`MAX_SEAM_SPANS`], generated lazily), B bytes read per span
//! (2 x [`SEAM_SIDE_BYTES`]).

use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasher;
use std::time::{Duration, Instant};

use super::super::{CAPACITY_METRIC, CollusionDetector, K, RelayAction, key, sample};
use super::leading;

/// Pieces per delivery that may take part in seams, counted round-robin
/// across runs, empty pieces included.
pub(in super::super) const MAX_SEAM_PIECES: usize = 4_096;
/// Omitted spans attempted per delivery, shortest first.
pub(in super::super) const MAX_SEAM_SPANS: usize = 1_024;
/// Raw bytes read on each side of a span's boundary.
pub(in super::super) const SEAM_SIDE_BYTES: usize = 1_024;
/// Seam fingerprints stored per delivery.
pub(in super::super) const SEAM_EXCUSE_FINGERPRINTS: usize = 4_096;
/// Seam fingerprints held in all; the oldest are evicted first, and only
/// seams.
pub(in super::super) const MAX_SEAM_EXCUSES: usize = 65_536;

#[cfg(test)]
thread_local! {
    // Work counters for the bound rows (tests only): counted, never timed.
    pub(in super::super) static COUNTERS: std::cell::RefCell<Counters> =
        std::cell::RefCell::new(Counters::default());
    // The start offset (in normalised chars of the joined slice) of each
    // window hashed, and the left side's normalised length (tests only).
    pub(in super::super) static HASHED_AT: std::cell::RefCell<Vec<(usize, usize)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// The work one seam pass did (tests only).
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Counters {
    pub index_visits: usize,
    pub candidates: usize,
    pub spans_attempted: usize,
    pub walk_visits: usize,
    pub walk_empty_visits: usize,
    pub bytes_read: usize,
    pub hashes: usize,
    pub scanned: usize,
}

/// Add `$n` to the test counter `$field`; nothing in production.
macro_rules! count {
    ($field:ident, $n:expr) => {
        #[cfg(test)]
        COUNTERS.with(|c| c.borrow_mut().$field += $n);
    };
}

/// Seam fingerprints by (source, principal, fingerprint): excuse only, read
/// by the same-source excuse check alone. Nothing here touches the evidence
/// entries, `Common` or evidence capacity, so a seam can change no other
/// caller's outcome.
#[derive(Default)]
pub(in super::super) struct SeamExcuses {
    /// Each seam's last delivery and its place in `order`.
    held: HashMap<(u64, u64, u64), (Instant, u64)>,
    /// Oldest first, for expiry and the global cap.
    order: BTreeMap<(Instant, u64), (u64, u64, u64)>,
    next_seq: u64,
}

impl SeamExcuses {
    /// Record `fps` as seams of (`source`, `principal`) delivered `now`.
    /// Returns how many older seams the global cap evicted.
    pub(in super::super) fn record(
        &mut self,
        (source, principal): (u64, u64),
        fps: &[u64],
        now: Instant,
    ) -> usize {
        for &fp in fps {
            let key = (source, principal, fp);
            if let Some((at, seq)) = self.held.remove(&key) {
                self.order.remove(&(at, seq));
            }
            let seq = self.next_seq;
            self.next_seq += 1;
            self.held.insert(key, (now, seq));
            self.order.insert((now, seq), key);
        }
        let mut evicted = 0;
        while self.held.len() > MAX_SEAM_EXCUSES {
            let Some((_, key)) = self.order.pop_first() else {
                break;
            };
            self.held.remove(&key);
            evicted += 1;
        }
        evicted
    }

    /// Whether `fp` is a live seam of (`source`, `principal`).
    pub(in super::super) fn holds(
        &self,
        (source, principal): (u64, u64),
        fp: u64,
        now: Instant,
        window: Duration,
    ) -> bool {
        self.held
            .get(&(source, principal, fp))
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) <= window)
    }

    /// Drop seams older than `window`.
    pub(in super::super) fn sweep(&mut self, now: Instant, window: Duration) {
        while let Some((&(at, seq), _)) = self.order.first_key_value() {
            if now.saturating_duration_since(at) <= window {
                break;
            }
            if let Some(key) = self.order.remove(&(at, seq)) {
                self.held.remove(&key);
            }
        }
    }

    /// Seams held now (tests only).
    #[cfg(test)]
    pub(in super::super) fn len(&self) -> usize {
        self.held.len()
    }
}

/// A run's eligible pieces, as indices of its non-empty ones: a boundary's
/// neighbours are found without visiting the empty pieces between.
struct Indexed<'r> {
    pieces: &'r [&'r str],
    /// Indices into `pieces` of the eligible non-empty pieces, in run order.
    nonempty: Vec<usize>,
    /// Whether every piece of the run was eligible (its end is the run's).
    whole: bool,
}

/// Index `runs` under [`MAX_SEAM_PIECES`], taking pieces round-robin across
/// runs so a long run cannot take the whole quota. Counting is the only
/// per-piece work done before the cap. Returns the indexed runs and whether
/// any piece fell outside the cap.
fn index<'r>(runs: &'r [Vec<&'r str>]) -> (Vec<Indexed<'r>>, bool) {
    let mut taken = vec![0usize; runs.len()];
    let mut total = 0;
    let mut active: Vec<usize> = (0..runs.len()).filter(|&r| !runs[r].is_empty()).collect();
    while total < MAX_SEAM_PIECES && !active.is_empty() {
        active.retain(|&r| {
            if total >= MAX_SEAM_PIECES || taken[r] >= runs[r].len() {
                return false;
            }
            taken[r] += 1;
            total += 1;
            count!(index_visits, 1);
            taken[r] < runs[r].len()
        });
    }
    let cut = runs.iter().zip(&taken).any(|(run, &t)| t < run.len());
    let indexed = runs
        .iter()
        .zip(&taken)
        .map(|(run, &t)| Indexed {
            pieces: &run[..t],
            nonempty: (0..t).filter(|&k| !run[k].is_empty()).collect(),
            whole: t == run.len(),
        })
        .collect();
    (indexed, cut)
}

/// The spans to attempt, generated lazily: omitted length 1, 2, ... (in
/// non-empty pieces), and within a length round-robin over the runs long
/// enough, longest first. Yields (run, left boundary, right boundary) as
/// positions in the run's `nonempty` list. Every step yields a candidate, so
/// the work is the candidates taken: the O(P²) list is never built.
fn spans<'a>(runs: &'a [Indexed<'_>]) -> impl Iterator<Item = (usize, usize, usize)> + 'a {
    let mut by_len: Vec<usize> = (0..runs.len()).collect();
    by_len.sort_by_key(|&r| std::cmp::Reverse(runs[r].nonempty.len()));
    let by_len: std::rc::Rc<[usize]> = by_len.into();
    let len = move |r: usize| runs[r].nonempty.len();
    let longest = by_len.first().map_or(0, |&r| len(r));
    (1..longest.saturating_sub(1)).flat_map(move |omit| {
        let by_len = std::rc::Rc::clone(&by_len);
        (0..longest - omit - 1).flat_map(move |a| {
            let b = a + omit + 1;
            let by_len = std::rc::Rc::clone(&by_len);
            (0..by_len.len()).map_while(move |i| (b < len(by_len[i])).then_some((by_len[i], a, b)))
        })
    })
}

/// The normaliser and character data for the compose-safe cut.
struct Props<'a> {
    nfc: icu_normalizer::ComposingNormalizerBorrowed<'a>,
    ccc: icu_normalizer::properties::CanonicalCombiningClassMapBorrowed<'a>,
    dec: icu_normalizer::properties::CanonicalDecompositionBorrowed<'a>,
}

/// Whether matching keeps `c` (it drops unsafe controls before NFC).
fn visible(c: char) -> bool {
    !crate::security::sanitize::is_unsafe_control(c)
}

/// Raw chars any one context scan may read: a run of controls cannot make a
/// scan unbounded.
const RAW_SCAN: usize = 32;

/// Up to `want` visible chars of `chars`, reading at most [`RAW_SCAN`] raw
/// chars. `None` when the budget runs out first: the context cannot be
/// established.
fn visible_run(chars: impl Iterator<Item = char>, want: usize) -> Option<Vec<char>> {
    let mut out = Vec::new();
    for (read, c) in chars.enumerate() {
        count!(scanned, 1);
        if out.len() == want {
            return Some(out);
        }
        if read == RAW_SCAN {
            return None;
        }
        if visible(c) {
            out.push(c);
        }
    }
    Some(out)
}

impl Props<'_> {
    fn new() -> Self {
        Props {
            nfc: icu_normalizer::ComposingNormalizerBorrowed::new_nfc(),
            ccc: icu_normalizer::properties::CanonicalCombiningClassMapBorrowed::new(),
            dec: icu_normalizer::properties::CanonicalDecompositionBorrowed::new(),
        }
    }

    /// Whether a cut between `before` and `after` is one NFC never reaches
    /// across, judged on the stream matching reads (unsafe controls
    /// dropped). The first visible char after the cut must be a
    /// non-whitespace starter: its full decomposition opens with combining
    /// class 0, so no mark is ever cut before (a mark can compose with a
    /// starter past any run of marks of a lower class). Then normalising up
    /// to three visible chars on each side apart must give what normalising
    /// them together gives: three covers the longest chain that crosses a
    /// cut before a starter (Hangul L+V+T, where LV+T is what a pairwise test
    /// misses). `before` and `after` must carry that context across piece
    /// boundaries; the callers pass neighbouring pieces' text.
    fn safe_cut(&self, before: [&str; 2], after: [&str; 2]) -> bool {
        let Some(head) = visible_run(after[0].chars().chain(after[1].chars()), 3) else {
            return false;
        };
        let Some(&first) = head.first() else {
            return false;
        };
        if first.is_whitespace() || self.ccc.get_u8(leading(&self.dec, first)) != 0 {
            return false;
        }
        let Some(mut tail) = visible_run(before[1].chars().rev().chain(before[0].chars().rev()), 3)
        else {
            return false;
        };
        tail.reverse();
        let a: String = tail.into_iter().collect();
        let b: String = head.into_iter().collect();
        let apart = format!("{}{}", self.nfc.normalize(&a), self.nfc.normalize(&b));
        apart == self.nfc.normalize(&format!("{a}{b}"))
    }
}

/// The raw text on one side of a boundary, and whether its far edge is a
/// cut the fill made (not the run's own end).
struct Side {
    text: String,
    artificial: bool,
}

/// Pieces read for cut context beyond the side, at most, each way.
const CONTEXT_PIECES: usize = 8;

/// Up to three visible chars of the run before `nonempty[j]`, read from at
/// most [`CONTEXT_PIECES`] pieces and [`RAW_SCAN`] raw chars. `None` when
/// fewer than three were found but the run goes on past what was read.
fn context_before(run: &Indexed<'_>, j: usize) -> Option<String> {
    let pieces = run.nonempty[..j].iter().rev().take(CONTEXT_PIECES);
    count!(walk_visits, j.min(CONTEXT_PIECES));
    let mut chars = visible_run(pieces.flat_map(|&k| run.pieces[k].chars().rev()), 3)?;
    if chars.len() < 3 && j > CONTEXT_PIECES {
        return None;
    }
    chars.reverse();
    Some(chars.into_iter().collect())
}

/// Up to three visible chars of the run after `nonempty[j]`: the mirror of
/// [`context_before`]. A run cut by the piece cap has no known end, so fewer
/// than three chars there is `None` too.
fn context_after(run: &Indexed<'_>, j: usize) -> Option<String> {
    let rest = &run.nonempty[j + 1..];
    count!(walk_visits, rest.len().min(CONTEXT_PIECES));
    let chars = visible_run(
        rest.iter()
            .take(CONTEXT_PIECES)
            .flat_map(|&k| run.pieces[k].chars()),
        3,
    )?;
    if chars.len() < 3 && (rest.len() > CONTEXT_PIECES || !run.whole) {
        return None;
    }
    Some(chars.into_iter().collect())
}

/// Fill the left side: walk back from `nonempty[a]` through non-empty
/// pieces, up to [`SEAM_SIDE_BYTES`]. An edge the cap made is moved right to
/// the first compose-safe point inside the piece the cap fell in, or to that
/// piece's end; each candidate is judged with the run's text on both sides,
/// across pieces. `None` (span skipped) when no point is safe.
fn left_side(run: &Indexed<'_>, a: usize, props: &Props<'_>) -> Option<Side> {
    let mut taken: Vec<&str> = Vec::new();
    let mut bytes = 0;
    let mut artificial = false;
    for j in (0..=a).rev() {
        let piece = run.pieces[run.nonempty[j]];
        count!(walk_visits, 1);
        if piece.is_empty() {
            count!(walk_empty_visits, 1);
        }
        if bytes + piece.len() <= SEAM_SIDE_BYTES {
            bytes += piece.len();
            taken.push(piece);
            continue;
        }
        artificial = true;
        let ctx = context_before(run, j)?;
        let after_ctx: String = taken
            .iter()
            .rev()
            .flat_map(|t| t.chars())
            .filter(|&c| visible(c))
            .take(3)
            .collect();
        let mut start = piece.len() - (SEAM_SIDE_BYTES - bytes);
        while !piece.is_char_boundary(start) {
            start += 1;
        }
        let cut = (start..=piece.len())
            .filter(|&i| piece.is_char_boundary(i))
            .find(|&i| props.safe_cut([&ctx, &piece[..i]], [&piece[i..], &after_ctx]))?;
        taken.push(&piece[cut..]);
        break;
    }
    count!(bytes_read, taken.iter().map(|t| t.len()).sum::<usize>());
    taken.reverse();
    Some(Side {
        text: taken.concat(),
        artificial,
    })
}

/// Fill the right side: walk forward from `nonempty[b]`, the mirror of
/// [`left_side`]; an edge the cap made is moved left to the last compose-safe
/// point inside the piece, or to that piece's start.
fn right_side(run: &Indexed<'_>, b: usize, props: &Props<'_>) -> Option<Side> {
    let mut text = String::new();
    let mut artificial = false;
    for j in b..run.nonempty.len() {
        let piece = run.pieces[run.nonempty[j]];
        count!(walk_visits, 1);
        if piece.is_empty() {
            count!(walk_empty_visits, 1);
        }
        if text.len() + piece.len() <= SEAM_SIDE_BYTES {
            text.push_str(piece);
            continue;
        }
        artificial = true;
        let ctx = context_after(run, j)?;
        let mut end = SEAM_SIDE_BYTES - text.len();
        while !piece.is_char_boundary(end) {
            end -= 1;
        }
        let cut = (0..=end)
            .rev()
            .filter(|&i| piece.is_char_boundary(i))
            .find(|&i| props.safe_cut([&text, &piece[..i]], [&piece[i..], &ctx]))?;
        text.push_str(&piece[..cut]);
        break;
    }
    // The walk reached the end of a run the piece cap cut short: what follows
    // is not known, so no cut there can be judged safe.
    if !artificial && !run.whole {
        return None;
    }
    count!(bytes_read, text.len());
    Some(Side { text, artificial })
}

/// Chars `a` and `b` share at the front.
fn common_prefix(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count()
}

/// Chars `a` and `b` share at the back.
fn common_suffix(a: &str, b: &str) -> usize {
    a.chars()
        .rev()
        .zip(b.chars().rev())
        .take_while(|(x, y)| x == y)
        .count()
}

impl CollusionDetector {
    /// The seam fingerprints of `runs` (each run's pieces in order, from
    /// `key_path_runs`), sampled as [`Self::fingerprints`] samples, and
    /// whether any cap cut the pass short. See the module docs for the rule
    /// and the work bound.
    pub(crate) fn seam_excuse_fingerprints(&self, runs: &[Vec<&str>]) -> (Vec<u64>, bool) {
        let (by_run, cut) = self.seam_excuses_by_run(runs);
        let mut seen = std::collections::HashSet::new();
        let fps = by_run
            .into_iter()
            .map(|(_, fp)| fp)
            .filter(|fp| seen.insert(*fp))
            .collect();
        (fps, cut)
    }

    /// [`Self::seam_excuse_fingerprints`], each fingerprint with the index of
    /// the run it came from, so a plan answer can attribute a run's seams to
    /// the step that produced it. One pass over all `runs`: the caps hold per
    /// call, never per run.
    pub(crate) fn seam_excuses_by_run(&self, runs: &[Vec<&str>]) -> (Vec<(usize, u64)>, bool) {
        let (indexed, mut cut) = index(runs);
        let props = Props::new();
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (attempted, (r, a, b)) in spans(&indexed).enumerate() {
            count!(candidates, 1);
            if attempted == MAX_SEAM_SPANS {
                cut = true;
                break;
            }
            count!(spans_attempted, 1);
            let run = &indexed[r];
            let (Some(left), Some(right)) = (left_side(run, a, &props), right_side(run, b, &props))
            else {
                cut = true;
                continue;
            };
            let Some(hashes) = self.boundary_hashes(&left, &right) else {
                cut = true;
                continue;
            };
            for h in sample(&hashes, self.sample) {
                if seen.insert((r, h)) {
                    if out.len() == SEAM_EXCUSE_FINGERPRINTS {
                        return (out, true);
                    }
                    out.push((r, h));
                }
            }
        }
        (out, cut)
    }

    /// Record `fps`, seams of a delivery from `source` to `principal`, as
    /// excuse only (`MIK-8205`). They never enter the evidence entries; an
    /// eviction past [`MAX_SEAM_EXCUSES`] drops only older seams, counted as
    /// `bound="seam_excuse_evicted"`.
    pub(crate) fn record_seam_excuses_at(
        &self,
        source: &str,
        principal: &str,
        fps: &[u64],
        now: Instant,
    ) {
        if self.params.action == RelayAction::Off || fps.is_empty() {
            return;
        }
        let pair = (self.digest(source), self.digest(principal));
        let evicted = self.state.lock().seams.record(pair, fps, now);
        if evicted > 0 {
            telemetry_metrics::counter!(CAPACITY_METRIC, "bound" => "seam_excuse_evicted")
                .increment(u64::try_from(evicted).unwrap_or(u64::MAX));
        }
    }

    /// The k-gram hashes of `left` + `right`, normalised as matching reads
    /// it, whose window overlaps the boundary: it holds a char the join
    /// changed (a composition, reordered marks, a collapsed space), or chars
    /// of both sides. Windows touching an artificial edge are dropped (one
    /// char of margin). `None` when an artificial side has fewer than K
    /// normalised chars, so no window can reach past it cleanly.
    fn boundary_hashes(&self, left: &Side, right: &Side) -> Option<Vec<u64>> {
        let joined = self.normalized(&format!("{}{}", left.text, right.text));
        let (nl, nr) = (self.normalized(&left.text), self.normalized(&right.text));
        if (left.artificial && nl.chars().count() < K)
            || (right.artificial && nr.chars().count() < K)
        {
            return None;
        }
        let bounds: Vec<usize> = joined
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(joined.len()))
            .collect();
        let n = bounds.len() - 1;
        if n < K {
            return Some(Vec::new());
        }
        let (pre, suf) = (common_prefix(&joined, &nl), common_suffix(&joined, &nr));
        let (lo, hi) = (pre.min(n - suf.min(n)), pre.max(n - suf.min(n)));
        let first = usize::from(left.artificial);
        let Some(last) = (n - K).checked_sub(usize::from(right.artificial)) else {
            return Some(Vec::new());
        };
        let mut hashes = Vec::new();
        for s in first..=last {
            let overlaps = if lo == hi {
                s < lo && s + K > lo
            } else {
                s < hi && s + K > lo
            };
            if overlaps {
                count!(hashes, 1);
                #[cfg(test)]
                HASHED_AT.with(|h| h.borrow_mut().push((s, nl.chars().count())));
                hashes.push(key().hash_one(&joined[bounds[s]..bounds[s + K]]));
            }
        }
        Some(hashes)
    }
}

#[cfg(test)]
#[path = "collusion_seam_excuse_tests.rs"]
mod tests;
