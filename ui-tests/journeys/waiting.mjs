// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The journeys that wait for a screen or route that has not landed, and the coverage check over them (part C design,
// decision D-W1; outcomes.mjs runs it over the titles of the tests that ran). A waiting journey is listed here, never
// skipped: a skip leaves the run green. The harness smoke must be one real test; each journey id is a real test or a
// waiting entry, never both and never neither. Halves of a journey that partly waits are counted on their own.

export const SMOKE = 'harness smoke';

export const JOURNEYS = Object.freeze(['J1', 'J2', 'J3', 'J4', 'J5a', 'J5b', 'J6', 'J7', 'J8a', 'J8b', 'J9a', 'J9b', 'J10', 'K1']);

/** What each waiting journey needs, in words, and the release that entry belongs to. Move an entry out when its journey lands. */
export const WAITING = Object.freeze([
  { id: 'J1', waitsFor: 'the first-run import, the server on/off save and the create-a-key screen', release: 'v4.0.0' },
  { id: 'J2', waitsFor: 'the connect-a-client screen and its route', release: 'v4.0.0' },
  { id: 'J3', waitsFor: 'the add-a-server screen', release: 'v4.0.0' },
  { id: 'J5a', waitsFor: 'the To do decision list and its read-only detail', release: 'v4.0.0' },
  { id: 'J5b', waitsFor: 'the To do decline and accept actions (moved to 4.0.1 by an operator decision)', release: 'v4.0.1' },
  { id: 'J6', waitsFor: 'the Policies status screen', release: 'v4.0.0' },
  { id: 'J7', waitsFor: 'the Activity export screen', release: 'v4.0.0' },
  { id: 'J8a', waitsFor: 'the Costs limits screen', release: 'v4.0.0' },
  { id: 'J8b', waitsFor: 'per-key limits and the at-limit action on the Costs page', release: 'v4.0.0' },
  { id: 'J9a', waitsFor: 'the revoke-a-key screen', release: 'v4.0.0' },
  { id: 'J9b', waitsFor: 'the rotate-a-key screen and its route', release: 'v4.0.0' },
  { id: 'J10', waitsFor: 'the Gateway Actions sign-in and the pending-restart banner', release: 'v4.0.0' },
  { id: 'K1', waitsFor: 'a refusal for an unrecognised key on a public path, once decided', release: 'v4.0.0' },
].map((w) => Object.freeze(w)));

/** The id a test title starts with: the smoke, or any journey-shaped id (known or not), each ended by a space or a colon. */
export function idOf(title) {
  if (/^harness smoke[: ]/.test(title)) return SMOKE;
  return title.match(/^((?:J|K)\d+[a-z]?)[: ]/)?.[1] ?? null;
}

/**
 * Every coverage problem, as a sentence naming its id or file; empty when covered. `titles`: the titles of the
 * tests that ran (outcomes.mjs reads them from the run's report); `waiting`: the entries.
 */
export function checkCoverage({ titles, waiting }) {
  const problems = [];
  const realIds = [];
  for (const title of titles) {
    const id = idOf(title);
    if (id === null) continue;
    if (id !== SMOKE && !JOURNEYS.includes(id)) problems.push(`${id}: a test "${title}" has an id that is not a journey`);
    realIds.push(id);
  }
  const count = (list, id) => list.filter((x) => x === id).length;
  const smokes = count(realIds, SMOKE);
  if (smokes !== 1) problems.push(`${SMOKE}: ${smokes} real tests, exactly 1 is required`);
  const waitIds = waiting.map((w) => w.id);
  if (waitIds.includes(SMOKE)) problems.push(`${SMOKE}: it can never wait`);
  for (const w of waiting) {
    if (w.id !== SMOKE && !JOURNEYS.includes(w.id)) problems.push(`${w.id}: waiting, but it is not a journey`);
    if (typeof w.waitsFor !== 'string' || w.waitsFor.trim() === '') problems.push(`${w.id}: waiting with no reason`);
    if (!/^v\d+\.\d+\.\d+$/.test(w.release ?? '')) problems.push(`${w.id}: release "${w.release}" is not vN.N.N`);
  }
  for (const id of JOURNEYS) {
    const r = count(realIds, id);
    const wt = count(waitIds, id);
    if (r + wt === 0) problems.push(`${id}: neither a real test nor waiting`);
    else if (r > 0 && wt > 0) problems.push(`${id}: both a real test and waiting`);
    else if (r > 1) problems.push(`${id}: ${r} real tests`);
    else if (wt > 1) problems.push(`${id}: ${wt} waiting entries`);
  }
  return problems;
}
