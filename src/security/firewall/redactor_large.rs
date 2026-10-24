// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! JSON text over [`B2_MAX_LEAF_BYTES`] (MIK-8774): the same projection as
//! under the cap, walked twice over the literals instead of collected, so the
//! memory added over base's whole-value path is one token's decoding and the
//! nesting stack, whatever the document's structure. Pass 1 sizes the output
//! and collects member findings; pass 2 writes the output into exactly that
//! capacity. No key is renamed here: where a key would be, and where a span
//! crosses an exempt value or the document is led by serde_json's raw-value
//! token, the walk replaces the spans unclipped (base's output) and still
//! redacts every member value.

use super::super::json_valid;
use std::borrow::Cow;

use super::json_literal::{self, Literal};
use super::{Family, Finding, JsonText, REDACTED, Redactor, Site, decoded, trimmed_content};

/// Where the walk puts a span's replacement.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// Inside each value literal the span covers, widened to whole escapes.
    Clip,
    /// Over the whole span, as base's whole-value path replaces it.
    Raw,
}

/// How a pass finds the member values it redacts whole.
#[derive(Clone, Copy)]
enum Members<'m> {
    /// Pair keys with values and classify them (pass 1).
    Classify,
    /// Take the starts pass 1 found, so pass 2 neither repeats the work nor
    /// reads an exemption that changed since (a continuation can expire).
    Replay(&'m [Member]),
}

/// A member value pass 1 redacts whole, and whether it adds a finding.
struct Member {
    start: usize,
    family: Family,
    reported: bool,
}

/// What one pass emitted.
struct Tally {
    ranges: usize,
    covered: usize,
    members: Vec<Member>,
}

/// Merges ranges that arrive by start, handing each finished one to `emit`.
struct Merger<'e> {
    pending: Option<(usize, usize)>,
    emit: &'e mut dyn FnMut(usize, usize),
}

impl Merger<'_> {
    fn push(&mut self, from: usize, to: usize) {
        match &mut self.pending {
            Some(last) if from <= last.1 => {
                last.0 = last.0.min(from);
                last.1 = last.1.max(to);
            }
            _ => {
                if let Some((a, b)) = self.pending.replace((from, to)) {
                    (self.emit)(a, b);
                }
            }
        }
    }

    fn finish(mut self) {
        if let Some((a, b)) = self.pending.take() {
            (self.emit)(a, b);
        }
    }
}

/// The escapes of one literal, read forward: positions are asked in order,
/// so each escape is parsed once and none is stored.
struct Escapes<'t> {
    text: &'t str,
    end: usize,
    at: usize,
    current: Option<(usize, usize)>,
}

impl<'t> Escapes<'t> {
    fn new(text: &'t str, lit: &Literal) -> Self {
        Self {
            text,
            end: lit.end,
            at: lit.start,
            current: None,
        }
    }

    /// The escape `at` falls strictly inside, as `escape_around` answers.
    fn around(&mut self, at: usize) -> Option<(usize, usize)> {
        loop {
            if let Some((start, end)) = self.current
                && at < end
            {
                return (start < at).then_some((start, end));
            }
            let from = self.at + self.text[self.at..self.end].find('\\')?;
            let (_, used) = json_literal::escape_at(&self.text[from..]);
            let to = (from + used.max(2)).min(self.end);
            self.current = Some((from, to));
            self.at = to;
        }
    }
}

impl Redactor {
    /// [`Redactor::redact_json_text`] for a leaf over the cap.
    pub(super) fn redact_large_json(
        &self,
        text: &str,
        exempt: &dyn Fn(&str) -> bool,
        findings: &mut Vec<Finding>,
    ) -> JsonText {
        let opens = matches!(
            text.trim_start().as_bytes().first(),
            Some(b'{' | b'[' | b'"')
        );
        let Some(doc) = opens
            .then(|| json_valid::check(text))
            .flatten()
            .filter(|doc| doc.walkable)
        else {
            return JsonText::NotJson;
        };
        let spans = self.credential_spans(text);
        let mut placement = if doc.raw_value_token {
            Placement::Raw
        } else {
            Placement::Clip
        };
        let plan = loop {
            let pass = self.walk(
                text,
                &spans,
                placement,
                Members::Classify,
                exempt,
                &mut |_, _| {},
            );
            if let Some(tally) = pass {
                break tally;
            }
            tracing::debug!(
                "a credential span over the size cap reaches a key or an exempt value; \
                 replacing spans whole"
            );
            placement = Placement::Raw;
        };
        if plan.ranges == 0 {
            return JsonText::Kept;
        }
        let len = text.len() - plan.covered + plan.ranges * REDACTED.len();
        let mut out = String::with_capacity(len);
        let mut cursor = 0;
        let mut write = |from: usize, to: usize| {
            out.push_str(&text[cursor..from]);
            out.push_str(REDACTED);
            cursor = to;
        };
        let replay = Members::Replay(&plan.members);
        let again = self.walk(text, &spans, placement, replay, exempt, &mut write);
        // Pass 2 reads only what pass 1 settled, so it emits the same ranges.
        if again.is_none_or(|tally| (tally.ranges, tally.covered) != (plan.ranges, plan.covered)) {
            tracing::warn!("the second redaction pass disagreed; redacting the leaf whole");
            return JsonText::Redacted(REDACTED.to_owned());
        }
        out.push_str(&text[cursor..]);
        let matched: Vec<usize> = self.set.matches(text).into_iter().collect();
        self.record_findings(&matched, &out, Site::Value, findings);
        findings.extend(
            (plan.members.iter())
                .filter(|member| member.reported)
                .map(|member| Self::member_finding(member.family)),
        );
        JsonText::Redacted(out)
    }

    /// One pass over `text`'s literals, handing every merged range to `emit`
    /// in order. `None`: under [`Placement::Clip`], a span starts outside a
    /// literal, a match starts in a key it covers, or it covers an exempt
    /// value; the caller walks again with [`Placement::Raw`], which never
    /// returns `None`.
    fn walk(
        &self,
        text: &str,
        spans: &[(usize, usize)],
        placement: Placement,
        known: Members<'_>,
        exempt: &dyn Fn(&str) -> bool,
        emit: &mut dyn FnMut(usize, usize),
    ) -> Option<Tally> {
        let (mut ranges, mut covered, mut replayed) = (0, 0, 0);
        let mut members = Vec::new();
        let mut counted = |from: usize, to: usize| {
            ranges += 1;
            covered += to - from;
            emit(from, to);
        };
        let mut merger = Merger {
            pending: None,
            emit: &mut counted,
        };
        // `first`: the first span not wholly before the current literal.
        // `checked`: under Clip, spans whose start is known to lie in a
        // literal; under Raw, spans already handed to the merger.
        let (mut first, mut checked) = (0, 0);
        let mut prev: Option<Literal> = None;
        for lit in json_literal::literals(text) {
            while checked < spans.len() && spans[checked].0 < lit.start {
                if placement == Placement::Raw {
                    merger.push(spans[checked].0, spans[checked].1);
                } else if !prev.as_ref().is_some_and(|p| spans[checked].0 < p.end) {
                    return None;
                }
                checked += 1;
            }
            while first < spans.len() && spans[first].1 <= lit.start {
                first += 1;
            }
            let overlapped = spans.get(first).is_some_and(|span| span.0 < lit.end);
            let clip = placement == Placement::Clip && overlapped;
            if lit.key {
                if clip && self.match_starts_in(text, &lit) {
                    return None;
                }
                prev = Some(lit);
                continue;
            }
            let member = match known {
                Members::Replay(found) => {
                    let hit = found.get(replayed).is_some_and(|m| m.start == lit.start);
                    replayed += usize::from(hit);
                    hit.then_some(None)
                }
                Members::Classify => {
                    // The pairing `member_values` reads: a key, then only `:`.
                    let paired = prev
                        .as_ref()
                        .filter(|key| key.key && text[key.end + 1..lit.start - 1].trim() == ":");
                    let value = (clip || paired.is_some())
                        .then(|| content(text, &lit))
                        .flatten();
                    let is_exempt = value.as_deref().is_some_and(exempt);
                    if is_exempt && clip {
                        return None;
                    }
                    match (paired, value.as_deref()) {
                        (Some(key), Some(value)) if !is_exempt => content(text, key)
                            .and_then(|key| self.credential_member(&key, value))
                            .map(Some),
                        _ => None,
                    }
                }
            };
            // The member's whole value goes first, so every range of this
            // literal after it starts inside it and the merge stays in order.
            if member.is_some() {
                merger.push(lit.start, lit.end);
            }
            let trimmed = trimmed_content(text, &lit);
            let contains = |(a, b): (usize, usize)| a <= trimmed.0 && trimmed.1 <= b;
            let mut is_covered = false;
            if clip {
                let mut escapes = Escapes::new(text, &lit);
                let mut local: Option<(usize, usize)> = None;
                for &(start, end) in spans[first..].iter().take_while(|span| span.0 < lit.end) {
                    let (mut from, mut to) = (start.max(lit.start), end.min(lit.end));
                    if from >= to {
                        continue; // an empty value: the span covers none of its bytes
                    }
                    if let Some(escape) = escapes.around(from) {
                        from = escape.0;
                    }
                    if let Some(escape) = escapes.around(to) {
                        to = escape.1;
                    }
                    merger.push(from, to);
                    match &mut local {
                        Some(last) if from <= last.1 => last.1 = last.1.max(to),
                        _ => is_covered |= local.replace((from, to)).is_some_and(contains),
                    }
                }
                is_covered |= local.is_some_and(contains);
            } else if member.is_some() {
                let after = spans.partition_point(|span| span.0 <= trimmed.0);
                is_covered = after.checked_sub(1).is_some_and(|i| contains(spans[i]));
            }
            // As under the cap: one secret, one finding, except family 1.
            if let Some(Some(family)) = member {
                members.push(Member {
                    start: lit.start,
                    family,
                    reported: family == Family::Generic || !is_covered,
                });
            }
            prev = Some(lit);
        }
        for &(start, end) in &spans[checked..] {
            if placement == Placement::Raw {
                merger.push(start, end);
            } else if !prev.as_ref().is_some_and(|p| start < p.end) {
                return None;
            }
        }
        merger.finish();
        Some(Tally {
            ranges,
            covered,
            members,
        })
    }
}

/// A literal's text decoded, borrowed when it holds no escape: most keys and
/// values, which the walk pairs on every leaf over the cap.
fn content<'t>(text: &'t str, lit: &Literal) -> Option<Cow<'t, str>> {
    let raw = &text[lit.start..lit.end];
    if raw.contains('\\') {
        decoded(text, lit).map(Cow::Owned)
    } else {
        Some(Cow::Borrowed(raw))
    }
}
