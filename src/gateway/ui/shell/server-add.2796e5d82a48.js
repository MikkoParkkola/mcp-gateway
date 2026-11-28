// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The "Add a server" card on the Servers list's Settings tab, mode "Command or
// URL": one field, a name worked out from it, value rows sent as env for a
// command and as headers for a URL, a start-once preview (described, running,
// listed, failed), then the add. Every served string goes in as text.
import { el, segmented, ApiError, causeOf, sessionNow, sessionHolds, landWithNotice } from '/ui/assets/shell.3dea6c02b527.js';

/** Per-request limits (the route's own run limit is 30 s, its teardown follows; the confirm dialog stops at 30 s). */
const DESCRIBE_MS = 15_000;
const RUN_MS = 45_000;
export const ADD_MS = 25_000;

/** Programs that run a package: the server's name is the next word that is not a flag. */
const RUNNERS = new Set(['npx', 'uvx', 'pipx', 'bunx', 'pnpm', 'yarn', 'dlx', 'node', 'python', 'python3', 'deno']);

/** `url` when the text parses as an http, https, ws or wss URL; otherwise `command`. */
export function kindOf(text) {
  try {
    return ['http:', 'https:', 'ws:', 'wss:'].includes(new URL(text.trim()).protocol) ? 'url' : 'command';
  } catch {
    return 'command';
  }
}

/** The proposed name: a URL's first host label; a command's package or path segment without scope, version or affixes. */
export function proposeName(text) {
  const t = text.trim();
  if (!t) return '';
  if (kindOf(t) === 'url') return new URL(t).hostname.split('.')[0];
  const words = t.split(/\s+/);
  const word = words.find((w, i) => !w.startsWith('-') && !(i < words.length - 1 && RUNNERS.has(w))) ?? words[0];
  const seg = (word.split('/').filter(Boolean).pop() ?? word).replace(/(.)@.*$/, '$1');
  return seg.replace(/^mcp-server-?/, '').replace(/^server-/, '').replace(/-mcp$/, '') || seg;
}

/** Rows to the member they are sent as, or the first fault: `{index, words}`. Headers compare without letter case. */
export function rowValues(rows, kind) {
  const out = {};
  const seen = new Set();
  for (const [i, { name, value }] of rows.entries()) {
    const n = name.trim();
    if (!n && !value) continue;
    if (!n) return { fault: { index: i, words: 'Give this value a name.' } };
    const k = kind === 'url' ? n.toLowerCase() : n;
    if (seen.has(k)) return { fault: { index: i, words: 'This name is used twice.' } };
    seen.add(k);
    out[n] = value;
  }
  return { values: out };
}

// The card's own sentences, written once here; the tests import them (lead
// ruling 2026-11-27). FIELD_WORDS is rule 8: one sentence per by-field reason,
// since the gateway sends codes only, and a code is never printed.
export const FIELD_WORDS = {
  secret_in_url: 'Move the key from the address into a header.',
  secret_in_command: 'Move the secret from the command into an environment variable.',
  header_name: 'Header names use only letters, digits and dashes, each name once.',
  header_value: 'Header values must fit on one line.',
  headers_need_url: 'Only URL servers take headers.',
  url_invalid: 'This address is incomplete.',
};
export const OTHER_FIELD_WORDS = 'The gateway refused this value.';
export const WORDS = {
  hint: 'The gateway works out the name, transport and secrets when the server first starts.',
  rowsNote: 'Values that look like secrets go to the secret store, never into gateway.yaml.',
  ranWithout: 'A preview never sends what you typed in these rows, so a server that needs those values can refuse it.',
  /** Rule 7's confirm: what the button does, and the line while it runs. */
  overrideVerb: 'Send the key in plain text to',
  overrideProgress: (name) => `Adding ${name} without encryption…`,
  /** Rule 7's consequences of sending a key unencrypted; the first names the destination. */
  override: (host) => [
    `Your key travels readable on every call to ${host}.`,
    'Anyone who can watch the traffic between the gateway and that host can read the key.',
    'To stop it later, you replace the key at the server itself.',
    'The server keeps a warning on its row until its address uses https.',
    'It is recorded in Activity under your name.',
  ],
};

/** The by-field refusal, recognised from the parsed body only: `[{reason, field}]`, else null. */
export const fieldRefusals = (err) =>
  (err?.body?.error === 'literal_in_value' && Array.isArray(err.body.refusals) ? err.body.refusals : null);

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
let ids = 0;

/** Draw the card into `body`. */
export function addCard(body, ctx) {
  const uid = `add${++ids}`;
  const st = { text: '', name: '', manual: false, phase: 'input', withheld: null, confirm: null, tools: null };
  const title = el('h2', { id: `${uid}-title` }, 'Add a server');
  const modes = segmented({ label: 'How to add', options: [['command-url', 'Command or URL']], value: 'command-url' });
  const fieldErr = el('p', { class: 'add-err', id: `${uid}-field-err`, hidden: true });
  const field = el('input', { type: 'text', id: `${uid}-field`, autocomplete: 'off', spellcheck: 'false', 'aria-describedby': `${uid}-hint` });
  const hint = el('p', { class: 't3', id: `${uid}-hint` }, WORDS.hint);
  const nameLine = el('div', { class: 'add-name' });
  const nameErr = el('p', { class: 'add-err', id: `${uid}-name-err`, hidden: true });
  const legend = el('legend');
  const rowList = el('div', { class: 'add-rows-list' });
  const rowsErr = el('p', { class: 'add-err', id: `${uid}-rows-err`, hidden: true });
  const addRow = el('button', { type: 'button', class: 'btn quiet' }, 'Add a value');
  const rowsNote = el('p', { class: 't3' }, WORDS.rowsNote);
  const rowsSet = el('fieldset', { class: 'add-rows sp-card', 'aria-describedby': `${uid}-rows-err` }, legend, rowsErr, rowList, addRow, rowsNote);
  const stage = el('div', { class: 'add-stage' });
  const previewBtn = el('button', { type: 'button', class: 'btn primary' }, 'Start once to preview');
  const acts = el('div', { class: 'acts' }, previewBtn);
  const section = el('section', { class: 'add-server sp', role: 'region', 'aria-labelledby': `${uid}-title` },
    title, modes, el('label', { for: `${uid}-field` }, 'Command or URL'), field, fieldErr, hint, nameLine, nameErr, rowsSet, stage, acts);
  body.append(section);

  const rows = [];
  const kind = () => kindOf(st.text);

  const say = (node, words) => { node.textContent = words ?? ''; node.hidden = !words; };
  const clearErrors = () => {
    for (const n of [fieldErr, nameErr, rowsErr]) say(n, null);
    field.setAttribute('aria-describedby', `${uid}-hint`);
    for (const r of rows) { say(r.err, null); r.name.removeAttribute('aria-describedby'); }
  };

  // Rule 3: the operator's change to the field, the name or a row throws the preview away.
  const changed = () => { if (st.phase !== 'input') toInput(); };

  const drawName = () => {
    if (st.manual) return;
    const change = el('button', { type: 'button', class: 'btn link' }, 'Change');
    change.addEventListener('click', () => {
      st.manual = true;
      const input = el('input', { type: 'text', id: `${uid}-name`, autocomplete: 'off', spellcheck: 'false', value: st.name });
      input.addEventListener('input', () => { st.name = input.value.trim(); changed(); });
      nameLine.replaceChildren(el('label', { for: `${uid}-name` }, 'Name'), input);
      input.focus(); // opening is not a change; typing is (rule 3)
    });
    nameLine.replaceChildren('Name ', el('strong', {}, st.name), ' · Automatic · ', change);
    nameLine.hidden = !st.name;
  };

  // Row labels follow the kind too, so no row input shares the server's "Name" (one accessible name each).
  const rowWords = () => (kind() === 'url' ? ['Header name', 'Header value'] : ['Variable name', 'Variable value']);
  const drawLegend = () => {
    legend.textContent = kind() === 'url' ? 'Headers' : 'Environment variables';
    const [n, v] = rowWords();
    for (const r of rows) { r.nameLabel.textContent = n; r.valueLabel.textContent = v; }
  };
  const newRow = () => {
    const n = rows.length + 1;
    const r = {
      name: el('input', { type: 'text', id: `${uid}-r${n}-name`, autocomplete: 'off', spellcheck: 'false' }),
      value: el('input', { type: 'password', id: `${uid}-r${n}-value`, autocomplete: 'off' }),
      err: el('p', { class: 'add-err', id: `${uid}-r${n}-err`, hidden: true }),
    };
    const [nameWord, valueWord] = rowWords();
    r.nameLabel = el('label', { for: r.name.id }, nameWord);
    r.valueLabel = el('label', { for: r.value.id }, valueWord);
    r.node = el('div', { class: 'add-row' }, r.nameLabel, r.name, r.valueLabel, r.value, r.err);
    r.name.addEventListener('input', changed);
    r.value.addEventListener('input', changed);
    rows.push(r);
    rowList.append(r.node);
    r.name.focus();
  };
  addRow.addEventListener('click', newRow);
  field.addEventListener('input', () => {
    st.text = field.value;
    if (!st.manual) st.name = proposeName(st.text);
    drawName();
    drawLegend();
    clearErrors();
    changed();
  });
  drawName();
  drawLegend();

  // --- requests and states ---

  /** One request of this card: the session it started in, and its answer or error; `null` when that session is gone. */
  const post = async (path, payload, ms) => {
    const epoch = sessionNow();
    const stop = new AbortController();
    const timer = setTimeout(() => stop.abort(), ms);
    let out;
    try {
      out = { ok: await ctx.api(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload), signal: stop.signal }) };
    } catch (err) {
      out = { err };
    } finally {
      clearTimeout(timer);
    }
    return sessionHolds(epoch) ? { ...out, epoch } : null;
  };

  /** While a request is in flight nothing it was built from can change (rule 3). */
  const setBusy = (busy) => {
    for (const n of [field, addRow, previewBtn, ...rows.flatMap((r) => [r.name, r.value]), ...nameLine.querySelectorAll('input, button')]) n.disabled = busy;
  };

  const toInput = () => {
    st.phase = 'input';
    st.withheld = null;
    st.confirm = null;
    st.tools = null;
    stage.replaceChildren();
    acts.replaceChildren(previewBtn);
  };

  /** The request body from what is on screen, or null after a row fault was put at its row. */
  const request = () => {
    clearErrors();
    const { values, fault } = rowValues(rows.map((r) => ({ name: r.name.value, value: r.value.value })), kind());
    if (fault) {
      const r = rows[fault.index];
      say(r.err, fault.words);
      r.name.setAttribute('aria-describedby', r.err.id);
      r.name.focus();
      return null;
    }
    const out = { name: st.name, [kind()]: st.text.trim() };
    if (Object.keys(values).length) out[kind() === 'url' ? 'headers' : 'env'] = values;
    return out;
  };

  // --- describe, run, add ---

  /** A panel in the stage: a region whose heading takes focus when it appears (rule 10). */
  const panel = (heading, ...children) => {
    const h = el('h3', { id: `${uid}-panel`, tabindex: '-1' }, heading);
    const node = el('section', { class: 'add-panel sp-card', role: 'region', 'aria-labelledby': h.id }, h, ...children);
    stage.replaceChildren(node);
    h.focus({ preventScroll: true });
    return node;
  };

  /** The gateway's sentence, else the shell's words for the status, else "did not answer". */
  const failWords = (err) => {
    if (err instanceof ApiError && err.serverMessage && !fieldRefusals(err)) return err.serverMessage;
    if (err instanceof ApiError && err.status > 0) return causeOf(err).title;
    return 'The gateway did not answer.';
  };

  /** Rule 5's failed state. `ranWithout`: the run itself failed after this preview held typed values back. */
  const failed = (err, ranWithout) => {
    st.phase = 'failed';
    const retry = el('button', { type: 'button', class: 'btn primary' }, 'Retry');
    retry.addEventListener('click', () => describe());
    const buttons = [retry];
    const lines = [el('p', {}, failWords(err))];
    if (ranWithout) {
      lines.push(el('p', {}, WORDS.ranWithout));
      buttons.push(addWithout());
    }
    panel('The preview did not finish', ...lines, el('div', { class: 'acts' }, ...buttons));
    acts.replaceChildren();
  };

  /** Rule 8: each by-field refusal's sentence at the input its `field` names. */
  const putRefusals = (list) => {
    clearErrors();
    for (const { reason, field: at } of list) {
      const words = FIELD_WORDS[reason] ?? OTHER_FIELD_WORDS;
      const named = typeof at === 'string' && /^(env|headers)\./.test(at) ? at.slice(at.indexOf('.') + 1) : null;
      const row = named === null ? null
        : rows.find((r) => (kind() === 'url' ? r.name.value.trim().toLowerCase() === named.toLowerCase() : r.name.value.trim() === named));
      if (at === 'url' || at === 'command') { say(fieldErr, words); field.setAttribute('aria-describedby', `${fieldErr.id} ${uid}-hint`); }
      else if (row) { say(row.err, words); row.name.setAttribute('aria-describedby', row.err.id); }
      else say(rowsErr, words);
    }
  };

  /** Step 4: describe, nothing runs. */
  const describe = async () => {
    const payload = request();
    if (!payload) return;
    toInput();
    setBusy(true);
    const out = await post('/ui/api/previews', payload, DESCRIBE_MS);
    if (!out) return; // another session's answer: nothing on this screen changes
    setBusy(false);
    if (out.ok) return described(payload, out.ok);
    const { err } = out;
    const refusals = fieldRefusals(err);
    if (refusals) return putRefusals(refusals);
    if (err instanceof ApiError && err.status === 422) {
      const words = err.serverMessage ?? '';
      if (words.endsWith('You can still add this server.')) {
        st.phase = 'refused';
        panel('No preview', el('p', {}, words), el('div', { class: 'acts' }, addWithout()));
        acts.replaceChildren();
        return;
      }
      say(fieldErr, words);
      return;
    }
    failed(err, false);
  };

  // --- described, running, listed ---

  const fact = (label, value) => [el('dt', {}, label), el('dd', {}, value)];

  /** Step 4's 202: what a start would do; nothing has run. */
  const described = (payload, answer) => {
    const p = answer?.preview ?? {};
    st.phase = 'described';
    st.confirm = answer?.confirm ?? null;
    const held = [...(p.withheld?.env ?? []), ...(p.withheld?.headers ?? [])].filter((n) => typeof n === 'string');
    st.withheld = held.length > 0;
    const facts = el('dl', { class: 'sp-facts' },
      ...fact('Runs from', `${location.host}, the gateway's own host`),
      ...fact('Transport', String(p.transport ?? '')),
      ...(p.url ? fact('Address', String(p.url)) : []));
    const heldList = held.length
      ? [el('p', { id: `${uid}-held` }, 'Held back, not sent'), el('ul', { 'aria-labelledby': `${uid}-held` }, ...held.map((n) => el('li', {}, n)))]
      : [];
    const publisher = p.publisher?.verified === true ? [] : [el('p', { class: 'add-warn' }, '⚠ The publisher is not verified.')];
    const cancel = el('button', { type: 'button', class: 'btn' }, 'Cancel');
    cancel.addEventListener('click', () => { toInput(); field.focus(); });
    const start = el('button', { type: 'button', class: 'btn primary' }, 'Start once');
    start.addEventListener('click', () => run(payload, start));
    panel('Nothing has run yet', ...publisher, facts, ...heldList,
      el('p', {}, 'Stops after it lists its tools. No tool is called.'), el('div', { class: 'acts' }, cancel, start));
    acts.replaceChildren();
  };

  /** Step 5: start once with the one-use token. */
  const run = async (payload, start) => {
    const node = stage.firstElementChild;
    const words = `Starting ${st.name} to preview…`;
    st.phase = 'running';
    start.disabled = true;
    node.setAttribute('aria-busy', 'true');
    node.append(el('p', { class: 'add-progress' }, words));
    ctx.announce(words);
    setBusy(true);
    const withheld = st.withheld;
    const out = await post('/ui/api/previews', { ...payload, confirm: st.confirm }, RUN_MS);
    if (!out) return;
    setBusy(false);
    st.confirm = null; // a token is used once
    if (out.ok) return listed(payload, out.ok);
    const s = out.err instanceof ApiError ? out.err.status : 0;
    failed(out.err, withheld && (s === 502 || s === 504));
  };

  /** Step 5's 200: the tools, and the selection the add will send. */
  const listed = (payload, answer) => {
    const tools = Array.isArray(answer?.tools) ? answer.tools : [];
    const pkg = answer?.preview?.package?.name;
    if (!st.manual && typeof pkg === 'string' && pkg) { st.name = pkg; drawName(); } // not an operator's change
    st.phase = 'listed';
    st.tools = tools.filter((t) => t.class === 'read' && t.selectable === true).map((t) => t.name);
    const secs = (Number(answer?.preview?.elapsed_ms) || 0) / 1000;
    const items = tools.map((t) => el('li', {},
      el('strong', {}, String(t.name ?? '')), ` ${String(t.description ?? '')} · ${t.class === 'read' ? 'reads' : 'writes'}`,
      ...(st.tools.includes(t.name) ? [] : [' · ', el('span', { class: 'add-out' }, 'not included')])));
    const extra = [];
    if (answer?.preview?.truncated === true) extra.push(el('p', {}, 'The list was cut; more tools exist.'));
    if (Array.isArray(answer?.withheld_tools) && answer.withheld_tools.length) {
      extra.push(el('p', {}, `${plural(answer.withheld_tools.length, 'tool was', 'tools were')} held back for its issues.`));
    }
    panel(`Started once: ${plural(tools.length, 'tool', 'tools')} took ${secs.toFixed(1)} s`,
      el('ul', { class: 'add-tools' }, ...items), ...extra, el('div', { class: 'acts' }, addButton(payload)));
    acts.replaceChildren();
  };

  // --- add ---

  /** The landing notice of a 201: the count, then stored values, then the gateway's notes, each as text. */
  const noticeOf = (name, count, answer) => {
    const parts = [count === null ? `${name} added.` : `${name} added with ${plural(count, 'tool', 'tools')}.`];
    const stored = Array.isArray(answer?.secrets_stored) ? answer.secrets_stored.length : 0;
    if (stored) parts.push(stored === 1 ? '1 value is kept in the secret store.' : `${stored} values are kept in the secret store.`);
    for (const n of Array.isArray(answer?.notes) ? answer.notes : []) if (typeof n === 'string' && n) parts.push(n);
    return parts.join(' ');
  };

  /** Step 6: the add, with the tools a preview listed, or none after "Add without a preview". */
  const add = async (withTools) => {
    const payload = request();
    if (!payload) return;
    if (withTools && st.tools) payload.allowed_tools = st.tools;
    const count = withTools ? (st.tools?.length ?? 0) : null;
    for (const b of stage.querySelectorAll('button')) b.disabled = true;
    setBusy(true);
    const out = await post('/ui/api/backends', payload, ADD_MS);
    if (!out) return; // another session's answer: nothing lands, nothing changes
    setBusy(false);
    for (const b of stage.querySelectorAll('button')) b.disabled = false;
    if (out.ok) {
      for (const r of rows) r.value.value = ''; // no typed value stays on the page
      landWithNotice({ path: `/ui/servers/${encodeURIComponent(payload.name)}/status`, notice: noticeOf(payload.name, count, out.ok) }, out.epoch);
      return;
    }
    const { err } = out;
    const refusals = fieldRefusals(err);
    if (refusals) return putRefusals(refusals);
    const s = err instanceof ApiError ? err.status : 0;
    if (s === 422 && err.body?.error === 'cleartext_credentials') return refused(err.body, payload, count);
    if (s === 409) {
      say(nameErr, failWords(err));
      if (!st.manual) nameLine.querySelector('button')?.click();
      return;
    }
    if (s >= 400 && s < 500) { say(fieldErr, failWords(err)); return; }
    const retry = el('button', { type: 'button', class: 'btn primary' }, 'Retry');
    retry.addEventListener('click', () => add(withTools));
    st.phase = 'failed';
    panel('Not confirmed', el('p', {}, 'The gateway did not confirm the add.'), el('div', { class: 'acts' }, retry));
  };

  /** Rule 7: the add was refused for sending a key over plain http (or ws); the cause and fix are the gateway's. */
  const refused = (body, payload, count) => {
    st.phase = 'refused';
    let u = null;
    try { u = new URL(payload.url); } catch { /* the card still shows the cause */ }
    const secure = u?.protocol === 'ws:' ? 'wss:' : 'https:';
    const lines = [el('p', {}, typeof body.message === 'string' ? body.message : '')];
    if (typeof body.fix === 'string' && body.fix) lines.push(el('p', {}, 'Fix: ', body.fix));
    const tryBtn = el('button', { type: 'button', class: 'btn primary' }, `Try ${secure}//${u?.host ?? ''}`);
    tryBtn.addEventListener('click', () => {
      field.value = `${secure}//${st.text.trim().replace(/^[a-z]+:\/\//i, '')}`;
      field.dispatchEvent(new Event('input')); // the same as typing it: the card returns to its input state
      field.focus();
    });
    const override = el('button', { type: 'button', class: 'btn quiet' }, 'Send unencrypted anyway…');
    override.addEventListener('click', () => sendAnyway(override, payload, count, u?.host ?? ''));
    panel('Not added', ...lines, el('div', { class: 'acts' }, tryBtn),
      el('p', { class: 't3' }, 'A test network you control? ', override));
    acts.replaceChildren();
  };

  /** The Override: the add with `allow_cleartext_credentials`, only from inside the shell's confirm (rule 7). */
  const sendAnyway = async (opener, payload, count, host) => {
    const snapshot = { ...payload, allow_cleartext_credentials: true }; // the page behind the dialog is inert
    const name = snapshot.name;
    const epoch = sessionNow();
    const res = await ctx.confirm({
      opener, key: `add-cleartext:${name}`, verb: WORDS.overrideVerb, object: name,
      progress: WORDS.overrideProgress(name), consequences: WORDS.override(host),
      run: () => {
        const stop = new AbortController();
        const timer = setTimeout(() => stop.abort(), ADD_MS);
        return ctx.api('/ui/api/backends', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(snapshot), signal: stop.signal })
          .finally(() => clearTimeout(timer));
      },
      failed: (err) => (err instanceof ApiError && err.serverMessage && !fieldRefusals(err)
        ? { reason: err.serverMessage, next: 'Check the address and the values, then try again.' } : null),
      done: (v) => {
        for (const r of rows) r.value.value = ''; // no typed value stays on the page
        return { path: `/ui/servers/${encodeURIComponent(name)}/status`, notice: noticeOf(name, count, v) };
      },
    });
    if (!sessionHolds(epoch)) return;
    const refusals = res?.outcome === 'failed' ? fieldRefusals(res.error) : null;
    if (refusals) putRefusals(refusals);
  };

  const addWithout = () => {
    const b = el('button', { type: 'button', class: 'btn' }, 'Add without a preview');
    b.addEventListener('click', () => add(false));
    return b;
  };
  const addButton = () => {
    const b = el('button', { type: 'button', class: 'btn primary' }, `Add ${st.name} with ${plural(st.tools?.length ?? 0, 'tool', 'tools')}`);
    b.addEventListener('click', () => add(true));
    return b;
  };

  previewBtn.addEventListener('click', () => describe());
}
