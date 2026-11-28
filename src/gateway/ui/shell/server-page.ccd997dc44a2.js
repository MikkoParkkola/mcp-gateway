// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// One server's own page: its Status and Actions tabs. The Servers module calls
// these when the address names a server; nothing here registers a page. Every
// path that carries the server's name comes from server-paths, and every served
// value goes in as text.
import { el, go, serverBadge, serverBanner, state } from '/ui/assets/shell.e63f1a7eeb83.js';
import { serverPath, backendApi, activityHref } from '/ui/assets/server-paths.15a075bb0cb1.js';

/** States whose `reason` is always one of the gateway's own sentences; never a refused server's. */
const SAYS_REASON = new Set(['needs_sign_in', 'unhealthy', 'slow']);

/** How long Remove waits for the keys read before its consequences say the keys could not be counted. */
const KEYS_MS = 15_000;

/** The live listener of the one render that owns it; any tab function run drops it. */
let dropListener = null;

/** Drop the page's status listener: called first by every tab function of the Servers module. */
export function leave() {
  dropListener?.();
  dropListener = null;
  owner = null;
}

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const known = (n) => typeof n === 'number' && Number.isFinite(n);

/** "2026-11-26 10:15 UTC" from an RFC 3339 string, or null when it is not a time. */
function utc(at) {
  const when = typeof at === 'string' ? new Date(at) : null;
  return when && !Number.isNaN(when.getTime()) ? `${when.toISOString().slice(0, 16).replace('T', ' ')} UTC` : null;
}

/**
 * Read the status and find this page's server. A key without the servers list
 * gets the forbidden state; a name no entry has gets the empty state. Either way
 * nothing else is read. Returns the entry, or null when the tab has drawn a state
 * or when `live()` says the user left before the answer came (then nothing is written).
 */
async function findServer(body, ctx, live = () => body.isConnected) {
  const answer = await ctx.api('/ui/api/status');
  if (!live()) return null; // answered after the user moved on: write nothing
  const servers = Array.isArray(answer?.servers) ? answer.servers : null;
  if (!servers) {
    ctx.show('forbidden');
    return null;
  }
  const found = servers.find((s) => s?.name === ctx.object) ?? null;
  if (!found) {
    body.append(notFound(ctx.object));
    return null;
  }
  ctx.header({ title: found.name });
  return found;
}

/** The empty state for a name no server has, with its way back to the list. */
function notFound(name) {
  return state('empty', {
    title: `No server named ${name}`,
    body: 'It may have been removed, or renamed in gateway.yaml.',
    action: el('p', {}, el('a', { class: 'lnk', href: '/ui/servers/status' }, 'Back to the servers')),
  });
}

/** One fact row of the Status tab's list. */
const fact = (term, value) => [el('dt', {}, term), el('dd', {}, value)];

/** The Status tab's parts for one entry: badge, reason, facts, cleartext line, Activity link. */
function statusParts(s) {
  const parts = [el('p', {}, serverBadge(s.state))];
  if (SAYS_REASON.has(s.state) && typeof s.reason === 'string' && s.reason) parts.push(el('p', { class: 'sp-reason' }, s.reason));
  parts.push(el('dl', { class: 'sp-facts' },
    ...fact('Transport', typeof s.transport === 'string' && s.transport ? s.transport : 'not known'),
    ...fact('Running', s.running === true ? 'Yes' : 'No'),
    ...fact('Tools', known(s.tools_cached) ? String(s.tools_cached) : 'not known'),
    ...fact('Calls, last 24 h', known(s.calls_24h) ? String(s.calls_24h) : 'not known')));
  if (s.cleartext_credentials_accepted === true) parts.push(el('p', { class: 'sp-warn' }, 'This server accepted credentials in cleartext.'));
  parts.push(el('p', {}, el('a', { class: 'lnk', href: activityHref(s.name) }, 'Its calls in Activity')));
  return parts;
}

/** The render that may still add a listener; any later tab run takes it over. */
let owner = null;

/**
 * Servers › <name> › Status. Drawn from the one status read, then from each
 * gateway-status event's own body with no new read. The listener belongs to
 * this render: leave() drops it, and so does the first event after the body
 * has left the document.
 */
export async function statusTab(body, ctx) {
  const mine = {};
  owner = mine;
  const found = await findServer(body, ctx, () => owner === mine && body.isConnected);
  if (!found) return;
  const root = el('div', { class: 'sp' });
  const draw = (s) => {
    ctx.show(serverBanner(s));
    // A redraw keeps keyboard focus: the Activity link is the one control here.
    const focused = root.contains(document.activeElement);
    root.replaceChildren(...statusParts(s));
    if (focused) root.querySelector('a.lnk')?.focus();
  };
  draw(found);
  body.append(root);
  const onStatus = (event) => {
    if (!body.isConnected) {
      leave();
      return;
    }
    const servers = event.detail?.servers;
    const now = Array.isArray(servers) ? servers.find((s) => s?.name === ctx.object) : null;
    if (now) draw(now);
    else if (Array.isArray(servers)) {
      // Gone from the gateway (removed elsewhere): say so instead of keeping stale facts, and stop following.
      leave();
      ctx.show(null);
      root.replaceWith(notFound(ctx.object));
    }
  };
  addEventListener('gateway-status', onStatus);
  dropListener = () => removeEventListener('gateway-status', onStatus);
}

/** A card: a heading, one sentence and its controls. */
const card = (title, sentence, ...rest) => el('section', { class: 'sp-card' }, el('h2', {}, title), el('p', {}, sentence), ...rest);

/** The keys whose `backends` name this server or hold `*`, in the read's order. */
const reaching = (keys, name) => keys.filter((k) => k && typeof k.name === 'string' && Array.isArray(k.backends)
  && (k.backends.includes(name) || k.backends.includes('*')));

/** Remove's consequences in numbers: tools, keys (up to three named), calls, and the after-effects. */
function removeConsequences(s, keys) {
  const tools = known(s.tools_cached) ? `${plural(s.tools_cached, 'tool', 'tools')} ${s.tools_cached === 1 ? 'disappears' : 'disappear'}.` : 'Its tools disappear.';
  let reach = 'The keys that reach it could not be counted.';
  if (keys) {
    const names = reaching(keys, s.name).map((k) => k.name);
    const rest = names.length - 3;
    reach = names.length === 0 ? 'No key reaches it.'
      : `${plural(names.length, 'key reaches', 'keys reach')} it: ${names.slice(0, 3).join(', ')}${rest > 0 ? ` and ${rest} more` : ''}.`;
  }
  const calls = known(s.calls_24h) ? [`It was called ${plural(s.calls_24h, 'time', 'times')} in the last 24 hours.`] : [];
  return [tools, reach, ...calls, 'Those keys get a tool-not-found answer on their next call.',
    'Its entry is deleted from gateway.yaml. It can be restored from the Gateway history, or added again.',
    'The removal is recorded under your name.'];
}

/** The gateway's own sentence for a refusal, or one built from its status. */
const refusalText = (err) => err?.serverMessage ?? (!err?.status
  ? 'The gateway did not answer. The sign-in may still be open: try again.'
  : err.unreadable
    // An ok status whose body would not parse: not a refusal, and the attempt may have gone through.
    ? "The gateway's answer could not be read. The sign-in may still be open: try again."
    : `The gateway refused the sign-in (HTTP ${err.status}).`);

/** The confirm refusals after which an attempt cannot go on (signin.rs): the start is offered again. */
const FINAL_REFUSALS = new Set(['no_sign_in', 'sign_in_save_failed']);

/** Link schemes, colon left off: shell row t6 refuses any asset spelling a web scheme. */
const WEB_SCHEMES = new Set(['http', 'https']);

/** A provider address the card may link: http or https only, else null. */
function providerUrl(raw) {
  try {
    const url = new URL(raw);
    return WEB_SCHEMES.has(url.protocol.slice(0, -1)) ? url.href : null;
  } catch {
    return null;
  }
}

/**
 * Sign in again. The start posts `{}`; its answer gives a new-tab link, the expiry,
 * and Finish or Cancel, which post the decision with that answer's attempt id,
 * again on a retry. A refusal shows the gateway's sentence; only a final refusal clears
 * the buttons so the start can be pressed again, and one decision runs at a time.
 * Any decision the gateway takes draws the tab again, which reads the status.
 */
function signInCard(s, ctx, again) {
  const start = el('button', { type: 'button', class: 'btn' }, 'Sign in again');
  const flow = el('div', { class: 'sp-flow' });
  const node = card('Sign in again', `${s.name} signs in with its provider.`, start, flow);
  const error = (err) => {
    node.querySelector('.sp-error')?.remove();
    if (err) {
      node.append(el('p', { class: 'sp-error' }, refusalText(err)));
      ctx.announce(refusalText(err));
    }
  };
  const post = (suffix, payload) => ctx.api(backendApi(s.name, suffix), {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  start.addEventListener('click', async () => {
    start.disabled = true;
    error(null);
    let answer;
    try {
      answer = await post('signin', {});
    } catch (err) {
      start.disabled = false;
      error(err);
      return;
    }
    // The user may have left while the start was answered: draw nothing on a page that is gone.
    if (!node.isConnected) return;
    const attempt = answer?.attempt_id;
    const href = providerUrl(answer?.authorization_url);
    const until = utc(answer?.expires_at);
    const decide = (decision) => async () => {
      if (finish.disabled) return; // one decision at a time: a late answer cannot undo a newer one
      finish.disabled = true;
      cancel.disabled = true;
      error(null);
      try {
        await post('signin/confirm', { decision, attempt_id: attempt });
      } catch (err) {
        error(err);
        // Only the gateway's final refusals end this attempt; anything else (not ready, no answer) keeps it.
        if (FINAL_REFUSALS.has(err?.code)) {
          flow.replaceChildren();
          start.disabled = false;
        } else {
          finish.disabled = false;
          cancel.disabled = false;
        }
        return;
      }
      if (node.isConnected) again();
    };
    const finish = el('button', { type: 'button', class: 'btn primary' }, 'Finish sign-in');
    const cancel = el('button', { type: 'button', class: 'btn' }, 'Cancel sign-in');
    finish.addEventListener('click', decide('confirm'));
    cancel.addEventListener('click', decide('cancel'));
    flow.replaceChildren(
      ...(href ? [el('p', {}, el('a', { class: 'lnk', href, target: '_blank', rel: 'noopener noreferrer' }, 'Open the sign-in page'))] : []),
      ...(until ? [el('p', {}, `The sign-in link expires at ${until}.`)] : []),
      el('p', { class: 'acts' }, finish, cancel));
    ctx.announce('Sign-in started.');
  });
  return node;
}

/**
 * Servers › <name> › Actions: Restart (Retry now while paused), Sign in again
 * when the entry has `sign_in`, and Remove. Restart and Remove go through the
 * shell's one confirm. The keys read starts with the tab; Remove waits for it.
 */
export async function actionsTab(body, ctx) {
  const s = await findServer(body, ctx);
  if (!s) return;
  const keysStop = new AbortController();
  const keysTimer = setTimeout(() => keysStop.abort(), KEYS_MS);
  const keysRead = ctx.api('/ui/api/keys', { signal: keysStop.signal }).then((b) => (Array.isArray(b?.keys) ? b.keys : null), () => null).finally(() => clearTimeout(keysTimer));
  const name = s.name;
  const verb = s.state === 'paused' ? 'Retry now' : 'Restart';
  const restart = el('button', { type: 'button', class: 'btn' }, `${verb} ${name}`);
  restart.addEventListener('click', () => ctx.confirm({
    opener: restart, key: `revive:${name}`, verb, object: name, replay: 'safe',
    progress: `${verb === 'Restart' ? 'Restarting' : 'Retrying'} ${name}…`,
    consequences: ['Calls in flight are cut.', 'The failure pause is reset.', 'Its tools stay listed.'],
    run: () => ctx.api(backendApi(name, 'revive'), { method: 'POST' }),
    done: (v) => (v?.status === 'revived'
      ? { path: serverPath(name, 'status'), notice: `${name} was restarted.` }
      : { path: serverPath(name, 'actions'), notice: `${name} did not restart: the gateway is shutting down.` }),
  }));
  const remove = el('button', { type: 'button', class: 'btn danger' }, `Remove ${name}`);
  remove.addEventListener('click', async () => {
    const keys = await keysRead;
    if (!remove.isConnected) return; // left while the keys were read
    ctx.confirm({
      opener: remove, key: `remove:${name}`, verb: 'Remove', object: name,
      progress: `Removing ${name}…`,
      consequences: removeConsequences(s, keys),
      run: () => ctx.api(backendApi(name), { method: 'DELETE' }),
      done: (v) => ({
        path: '/ui/servers/status',
        notice: `${name} was removed.${typeof v?.note === 'string' && v.note ? ` ${v.note}` : ''}`,
      }),
    });
  });
  const cards = [card(verb, verb === 'Restart' ? 'Restart its connection to the gateway.' : 'Try it now, without waiting out the pause.', restart)];
  if (s.sign_in) cards.push(signInCard(s, ctx, () => go(serverPath(name, 'actions'), { replace: true })));
  cards.push(card('Remove', 'Take it out of the gateway and its config file.', remove));
  const audit = el('p', { class: 'sp-audit t3' }, 'Actions on this page are recorded in Activity under your name.');
  body.append(el('div', { class: 'sp' }, ...cards, audit));
}
