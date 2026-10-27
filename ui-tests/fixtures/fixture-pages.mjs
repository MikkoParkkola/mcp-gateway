// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Test-only page registrations, served by the fixture server alone and
// injected into the shell document only when the request carries the cookie
// fixture-pages=1. It registers the way a real screen does: a module that
// runs before DOMContentLoaded, so the shell's cold start sees it. The
// server replaces __SHELL__ with the shell module's hashed name.
import { register, api } from '__SHELL__';

const PAGES = [
  ['overview', 'Overview'],
  ['to' + 'do', 'To do'],
  ['servers', 'Servers'],
  ['tools', 'Tools'],
  ['activity', 'Activity'],
  ['costs', 'Costs'],
  ['access', 'Access'],
  ['policies', 'Policies'],
  ['gateway', 'Gateway'],
];

const cookie = (name) => {
  const m = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return m ? decodeURIComponent(m[1]) : '';
};

const title = cookie('fixture-title');

for (const [id, label] of PAGES) {
  const tab = (name) => (el, ctx) => {
    el.textContent = `${id} ${ctx.object ?? '-'} ${name}`;
  };
  register(id, {
    title: title || label,
    subtitle: id === 'overview' ? '24 of 28 servers ready.' : undefined,
    tabs: {
      // Access › Status reads an API the tests can answer with 403.
      status: id === 'access' ? async (el) => { await api('/ui/api/forbidden-probe'); el.textContent = 'access - status'; } : tab('status'),
      actions: tab('actions'),
      settings: id === 'tools' ? null : tab('settings'),
    },
    entries: [id === 'tools'
      ? { label: `Try a ${label.toLowerCase()} call`, path: `/ui/${id}/actions#try`, kind: 'action' }
      : { label: `${label} limits`, path: `/ui/${id}/settings#limits`, kind: 'setting' }],
  });
}
