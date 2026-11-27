// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Copy and pure rules for the To do page. Nothing here touches the page, so a test can load the exact bytes the
// gateway serves and compare against them. The page draws no sentence that is not defined in this file.

/** Headline for each kind of pending decision. */
export const KIND_TITLE = Object.freeze({
  capability_changed: 'Capability changed since it was pinned',
  capability_unreadable: 'Capability file the gateway cannot read',
  access_request: 'Agent asking for access',
  adopt: 'Server found outside the gateway',
  client_config_unreadable: 'Client config file the gateway cannot read',
});
export const UNKNOWN_KIND_TITLE = 'Decision of a kind this page does not know';
export const kindTitle = (kind) => KIND_TITLE[kind] ?? UNKNOWN_KIND_TITLE;

/** Shown in place of a value the gateway left empty, keyed by the reason it gave. */
export const NULL_WORDS = Object.freeze({
  no_history: 'The gateway keeps no copy of the earlier version',
  not_linked: 'Calls are not tied to this decision yet',
  not_tracked: 'The gateway does not track this',
  not_recorded: 'Nothing was recorded for this',
  not_rated: 'The gateway gives this no rating',
  unparsed: 'Unknown: the file would not parse',
});
export const NULL_UNKNOWN = 'Not shown by the gateway';
export const nullWords = (reason) => NULL_WORDS[reason] ?? NULL_UNKNOWN;

/** Why a file could not be read, keyed by reason (used for capability files and client config files alike). */
export const UNREADABLE_REASON = Object.freeze({
  not_a_readable_file: 'Not a regular file, or bigger than any config the gateway reads',
  no_permission: 'The gateway lacks permission to open it',
  did_not_parse: 'Opened, but its contents would not parse',
});
export const UNREADABLE_UNKNOWN = 'Unreadable for a reason this page does not know';
export const unreadableWords = (reason) => UNREADABLE_REASON[reason] ?? UNREADABLE_UNKNOWN;

export const TOOL_STAND_IN = 'Stand-in name: the real one could not be trusted';
export const SCAN_INFERRED = 'estimated from the file, not measured';
export const EVERY_TOOL = 'All tools';
export const READS_ONLY = 'Read only';
export const READS_AND_WRITES = 'Read and write';

export const WAITS_ON = (n) => (n === 1 ? 'Blocked by 1 decision' : `Blocked by ${n} decisions`);
export const WAITS_ON_LINE = (n, title) => `Deciding this does nothing yet: decision ${n} (${title}) has to be settled first.`;
export const DECIDE_FIRST = (title) => `Open ${title}`;
export const WAITS_ON_MORE = (m) => (m === 1 ? 'One more decision blocks it too.' : `${m} more decisions block it too.`);
export const BACK_TO_LIST = (n) => `All decisions (${n})`;

/** When a decided item drops off the list: the two endings. */
export const CLEARS_ON_ITS_OWN = 'Once that is done, this item disappears by itself in under 30 seconds.';
export const LEAVES_AFTER_RELOAD = 'Once that is done, this item disappears when the gateway next reloads its configuration.';

/** How each kind is settled outside this page, with its ending. A kind missing here gets no such line. */
export const DECIDED_WHERE = Object.freeze({
  access_request: 'Grant it from a terminal with mcp-gateway identity grants grant. Until someone does, the agent keeps getting refused. '
    + LEAVES_AFTER_RELOAD,
  adopt: 'To take this server in, use Add a server on the Servers page, or write it into gateway.yaml yourself with the command or address above. '
    + CLEARS_ON_ITS_OWN,
  capability_changed: 'Settle it in the file itself, in the capabilities folder: restore what was there before, or keep the new content and pin it again with mcp-gateway cap pin. The tool stays switched off meanwhile. '
    + CLEARS_ON_ITS_OWN,
  capability_unreadable: 'Make the file readable again (permissions or syntax), or restore the content it was pinned with. The tool stays switched off meanwhile. '
    + CLEARS_ON_ITS_OWN + ' If the content still differs from its pin, a changed-capability item shows up instead.',
  client_config_unreadable: 'Repair the file so the gateway can read it: check its permissions and its syntax. ' + CLEARS_ON_ITS_OWN,
});

/** How each source's state reads in the not-available message. */
export const SOURCE_STATE_WORDS = Object.freeze({
  starting: 'has not finished starting',
  unreadable: 'failed to read',
  unavailable: 'is down',
});
export const SOURCE_STATE_UNKNOWN = 'is not ready yet';
export const SOURCES_UNKNOWN = 'The gateway gave no reason.';
export const sourceLine = ({ source, state }) => `${source} ${SOURCE_STATE_WORDS[state] ?? SOURCE_STATE_UNKNOWN}`;
export const UNAVAILABLE_TITLE = 'Pending decisions are not available right now';
export const RETRY = 'Try again';

export const EMPTY_TITLE = 'All caught up';
export const EMPTY_BODY = 'New decisions land here as soon as the gateway raises them.';
export const EMPTY_ACTION = 'See recent activity';
export const INCOMPLETE_KINDS = (titles) => `Some of the list may be missing; these could not be read in full: ${titles.join(', ')}.`;
export const EMPTY_INCOMPLETE = (titles) => `Nothing is listed, but the list may be incomplete; these could not be read in full: ${titles.join(', ')}.`;

/** The kinds the list could not fully read (missing and partial merged, each once, in served order) as headlines. */
export function incompleteTitles(view) {
  const kinds = [...(view.missing_kinds ?? []), ...(view.partial_kinds ?? [])];
  return [...new Set(kinds)].map(kindTitle);
}

/** The listed decisions an item is blocked by: each id once, in list order, as [{ position (1-based), item }]. */
export function waitedOn(item, list) {
  const wanted = new Set(Array.isArray(item.waits_on) ? item.waits_on : []);
  const found = [];
  list.forEach((other, i) => { if (wanted.has(other.id)) found.push({ position: i + 1, item: other }); });
  return found;
}

/** A row's one-line summary, built from served fields only. */
export const KIND_SUBLINE = Object.freeze({
  capability_changed: (d) => `${d.tool}, off since ${d.off_since ?? d.observed_at}`,
  capability_unreadable: (d) => `${d.tool} on ${d.backend}`,
  access_request: (d) => `${d.agent} wants ${(d.scope ?? []).map((s) => s.capability).join(', ')}`,
  adopt: (d) => `${d.server?.name}, found in ${d.server?.source}`,
  client_config_unreadable: (d) => `${d.file}, from ${d.source}`,
});
export const subline = (d) => (KIND_SUBLINE[d.kind] ? KIND_SUBLINE[d.kind](d) : '');

/** The row's severity mark for a kind that carries one; null otherwise. */
export function severityMark(d) {
  if (d.kind === 'capability_changed') return typeof d.scan === 'string' ? d.scan : null;
  if (d.kind === 'adopt') return typeof d.severity === 'string' ? d.severity : null;
  return null;
}
