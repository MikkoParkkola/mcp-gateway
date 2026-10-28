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

// The page-error rows (shell-errors.spec.mjs) set fixture-probes=1: Policies ›
// Status then shows what /ui/api/page-probe answers for its object, with a
// link (and faults after writing it when the answer says fault), and Costs ›
// Status reads /ui/api/fault-probe and then faults in its own code.
const probes = cookie('fixture-probes') === '1';
const probed = {
  policies: async (el, ctx) => {
    const query = ctx.object ? `?object=${encodeURIComponent(ctx.object)}` : '';
    const { value, fault } = await api(`/ui/api/page-probe${query}`);
    const link = document.createElement('a');
    link.href = '/ui/servers';
    link.id = 'probe-link';
    link.textContent = 'servers';
    el.replaceChildren(`value ${value} `, link);
    // A render that has written part of the page and then faults.
    if (fault) null.call();
  },
  costs: async (el) => {
    const reply = await api('/ui/api/fault-probe');
    reply.missing.call();
  },
};

for (const [id, label] of PAGES) {
  const tab = (name) => (el, ctx) => {
    el.textContent = `${id} ${ctx.object ?? '-'} ${name}`;
  };
  register(id, {
    title: title || label,
    subtitle: id === 'overview' ? '24 of 28 servers ready.' : undefined,
    tabs: {
      // Access › Status reads an API the tests can answer with 403.
      status: (probes && probed[id])
        || (id === 'access' ? async (el) => { await api('/ui/api/forbidden-probe'); el.textContent = 'access - status'; } : tab('status')),
      actions: tab('actions'),
      settings: id === 'tools' ? null : tab('settings'),
    },
    entries: [id === 'tools'
      ? { label: `Try a ${label.toLowerCase()} call`, path: `/ui/${id}/actions#try`, kind: 'action' }
      : { label: `${label} limits`, path: `/ui/${id}/settings#limits`, kind: 'setting' }],
  });
}
