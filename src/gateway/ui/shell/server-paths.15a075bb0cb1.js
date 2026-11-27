// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Every address and request path that carries a name. The one place a name is
// encoded: the shell's router and every screen that links to a server or a key,
// or sends a request about one, build the path here. It imports nothing and
// touches no page state, so a test can load it on its own.

/** A page address: `/ui/<page>[/<object>]/<tab>`, the object as one encoded segment. */
export function pathFor({ page, object, tab }) {
  return `/ui/${page}${object ? `/${encodeURIComponent(object)}` : ''}/${tab}`;
}

/** Names no address can carry: a browser folds `.` and `..` path segments before the page sees them. */
export const addressable = (name) => typeof name === 'string' && name !== '' && name !== '.' && name !== '..';

/** A server's page tab. */
export const serverPath = (name, tab) => pathFor({ page: 'servers', object: name, tab });

/** A key's page, under Access. */
export const keyPath = (name) => pathFor({ page: 'access', object: name, tab: 'status' });

/** A backend's API path, with an optional fixed suffix such as `revive` or `signin/confirm`. */
export const backendApi = (name, suffix = '') => `/ui/api/backends/${encodeURIComponent(name)}${suffix ? `/${suffix}` : ''}`;

/** Activity filtered by one server, the name as one encoded query value. */
export const activityHref = (server) => `/ui/activity?server=${encodeURIComponent(server)}`;
