// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Test-only page registrations, served by the fixture server alone and
// injected into the shell document only when the request carries the cookie
// fixture-pages=1. It registers the way a real screen does: a module that
// runs before DOMContentLoaded, so the shell's cold start sees it. The
// server replaces __SHELL__ with the shell module's hashed name.
import { register, api, serverBanner } from '__SHELL__';

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
    if (value === 'empty') return; // G8: a completion that draws nothing
    const link = document.createElement('a');
    link.href = '/ui/servers';
    link.id = 'probe-link';
    link.textContent = 'servers';
    el.replaceChildren(`value ${value} `, link);
    // A render that has written part of the page and then faults.
    if (fault) null.call();
  },
  // F20 (shell-frame.spec.mjs): a screen sets its own header through its context.
  // F20b, F20c: while window.__fails > 0, an attempt keeps its setter (and, with
  // window.__headerThenFail, sets a header first) and fails.
  overview: (el, ctx) => {
    if (window.__fails > 0) {
      window.__fails -= 1;
      window.failedHeader = ctx.header;
      if (window.__headerThenFail) ctx.header({ title: 'From a failed attempt', subtitle: 'failed' });
      throw new Error('attempt fails');
    }
    el.textContent = `overview ${ctx.object ?? '-'} status`;
    window.overviewHeader = ctx.header;
  },
  // L7 (shell-live.spec.mjs): a screen announces through its render context.
  gateway: (el, ctx) => {
    el.textContent = 'gateway - status';
    ctx.announce('Gateway status read.');
    window.gatewayAnnounce = ctx.announce; // L15: kept past navigation
  },
  // T6 (shell-states.spec.mjs): stale data with its time, and a number to dim.
  tools: (el, ctx) => {
    const n = document.createElement('span');
    n.className = 'num';
    n.textContent = '42';
    const table = document.createElement('table');
    table.className = 't';
    table.innerHTML = '<tbody><tr><td class="n">7</td></tr></tbody>';
    el.replaceChildren('tools - status ', n, table);
    const since = new Date();
    since.setHours(14, 2, 0, 0); // today, so the title shows the time only
    ctx.show('stale', { since });
    window.toolsShow = ctx.show;
  },
  // T11: a screen shows a server's banner through its context, and takes it away.
  servers: (el, ctx) => {
    el.textContent = 'servers - status';
    ctx.show(serverBanner({ name: 'github', state: 'refused', reason: 'Refused by the runtime policy: shell_exec.' }));
    window.serversShow = ctx.show;
  },
  // L13: a screen marks its data stale, then clears it.
  activity: (el, ctx) => {
    el.textContent = 'activity - status';
    ctx.show('stale');
    ctx.show('stale'); // the same banner again is no news
    setTimeout(() => ctx.show(null), 50);
  },
  costs: async (el) => {
    const reply = await api('/ui/api/fault-probe');
    reply.missing.call();
  },
};

// The destructive-action rows (shell-destructive.spec.mjs) set fixture-probes=1:
// Gateway › Actions then has a "Remove probe…" row whose button calls ctx.confirm
// against /ui/api/destroy-probe. A test shapes the call through window.__confirm
// (set in an init script) and reads the outcome from window.__outcomes.
const confirmRow = (el, ctx) => {
  const opener = document.createElement('button');
  opener.type = 'button';
  opener.className = 'btn';
  opener.id = 'remove-probe';
  opener.textContent = 'Remove probe…';
  // Through the CSS object model: the shell's CSP refuses injected style elements.
  Object.assign(opener.style, window.__openerStyle ?? {});
  window.__outcomes = [];
  opener.addEventListener('click', () => {
    const extra = typeof window.__confirm === 'function' ? window.__confirm(opener) : (window.__confirm ?? {});
    const settled = ctx.confirm({
      opener,
      key: 'probe:one',
      verb: 'Remove',
      object: 'probe',
      progress: 'Removing probe…',
      consequences: ['3 tools disappear for 2 keys.', 'They called them 12 times today.'],
      run: () => api('/ui/api/destroy-probe', { method: 'DELETE' }),
      ...extra,
    });
    Promise.resolve(settled).then((r) => window.__outcomes.push(r), (e) => window.__outcomes.push({ thrown: String(e) }));
  });
  window.gatewayConfirm = ctx.confirm;
  el.replaceChildren('gateway - actions ', opener);
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
      actions: (probes && id === 'gateway') ? confirmRow : tab('actions'),
      settings: id === 'tools' ? null : tab('settings'),
    },
    entries: [id === 'tools'
      ? { label: `Try a ${label.toLowerCase()} call`, path: `/ui/${id}/actions#try`, kind: 'action' }
      : { label: `${label} limits`, path: `/ui/${id}/settings#limits`, kind: 'setting' }],
  });
}
