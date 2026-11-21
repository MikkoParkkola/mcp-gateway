// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The shared Settings save flow: the change is reviewed on the page as the
// server's masked diff, then confirmed in the shell's dialog, then saved.
// One entry point, settingsSave; every settings tab calls it with the fields
// it built. The flow never renders a field value: only the server's masked
// diff or patch text reaches the page, and a secret travels in the save body
// alone (the preview sends `secret: true` in its place).
import { el, api, ApiError, announce, causeOf, confirmAction } from '/ui/assets/shell.d0963799aba0.js';

const DIFF_PATH = '/ui/api/settings/diff';
const SAVE_PATH = '/ui/api/settings';
const JSON_HEADERS = { 'content-type': 'application/json' };

const WORDS = {
  preparing: 'Preparing the change…',
  reviewTitle: 'Review before saving',
  caption: 'Proposed change to gateway.yaml',
  rest: 'Every other line and all comments in gateway.yaml stay as they are.',
  noInPlace: 'Nothing saved: this change cannot be made in place.',
  prepareFailed: 'Could not prepare the change.',
  saved: 'Saved.',
  unchanged: 'Nothing changed: gateway.yaml already had these values.',
  newer: 'gateway.yaml changed since you reviewed it; check this before saving again.',
  unconfirmed: 'The outcome is not confirmed. Reload the page to see what gateway.yaml holds now.',
  held: "An earlier save's outcome is not confirmed. Reload the page before saving again.",
  notStarted: 'Nothing was sent: the save could not start. Close any open dialog, sign in if asked, then try again.',
  next409: 'Close to keep this review; Reload page discards it.',
};

/** Set once any save's outcome is unconfirmed; only a page reload clears it. */
let held = false;
/** Hosts with a flow that has not ended: one flow per host. */
const open = new WeakSet();

/**
 * The gateway's own sentence for a refusal, or null when it gave none: its
 * message; "<field>: <reason>" for a field refusal; the named item for
 * unknown_field; a flat error only when it is a sentence. A bare code is
 * never a sentence.
 */
function sentenceOf(err, fields) {
  const body = err instanceof ApiError && err.body && typeof err.body === 'object' ? err.body : null;
  if (!body) return null;
  if (typeof body.message === 'string' && body.message.trim()) return body.message;
  if (typeof body.reason === 'string' && typeof body.field === 'string') return `${body.field}: ${body.reason}`;
  if (body.error === 'unknown_field' && Number.isInteger(body.entry)) {
    const item = fields[body.entry];
    return item ? `${item.field} is not a setting this page can change.` : null;
  }
  if (typeof body.error === 'string' && /\s/.test(body.error.trim())) return body.error;
  return null;
}

/** The preview's fields: the save's list item for item, each secret value replaced by `true`. */
function previewFields(fields) {
  return fields.map((item) => (item?.value && typeof item.value === 'object' && 'secret' in item.value
    ? { ...item, value: { secret: true } }
    : item));
}

/** A status line the host shows and the screen reader hears once focus is back on the page. */
function line(text, cls = 'settingsave-line') {
  announce(text);
  return el('p', { class: cls, tabindex: '-1' }, text);
}

/** The server's unified diff, one element per line, inserted as text. File headers stay unstyled. */
function diffFigure(diff) {
  const pre = el('pre', { class: 'diff' });
  for (const text of String(diff).split('\n')) {
    const header = text.startsWith('--- a/') || text.startsWith('+++ b/');
    const cls = header ? null : text.startsWith('@@') ? 'hunk' : text.startsWith('+') ? 'add' : text.startsWith('-') ? 'del' : null;
    pre.append(el('span', cls ? { class: cls } : {}, text), '\n');
  }
  return el('figure', { class: 'settingsave-diff' }, el('figcaption', {}, WORDS.caption), pre);
}

/** One patch step as a line an operator can apply by hand. */
function stepText(step) {
  const value = step.value === undefined ? '' : ` = ${JSON.stringify(step.value)}`;
  return `${step.op} ${step.path}${value}`;
}

/** The no-Save view: why it cannot be made in place, the patch to copy, and Back. */
function patchView(patch, back) {
  const steps = Array.isArray(patch) ? patch : [];
  const text = steps.map(stepText).join('\n');
  const copy = el('button', { class: 'btn', type: 'button' }, 'Copy');
  copy.addEventListener('click', () => { navigator.clipboard?.writeText(text).catch(() => {}); });
  return [
    line(WORDS.noInPlace, 'banner warning'),
    el('ul', { class: 'settingsave-reasons' },
      ...steps.map((s) => el('li', {}, `${s.path}: ${s.reason}${Number.isInteger(s.line) ? ` (line ${s.line})` : ''}`))),
    el('pre', { class: 'settingsave-patch' }, text),
    el('p', { class: 'settingsave-actions' }, copy, back),
  ];
}

/**
 * The confirm's words for a refused save: null (the shell's own words) or
 * both reason and next, never one alone. Every 409 gets words naming both of
 * the shell's buttons, because the shell shows Reload page on every 409.
 */
function failedWords(err, fields) {
  const body = err instanceof ApiError && err.body && typeof err.body === 'object' ? err.body : {};
  const status = err?.status;
  if (status === 409 && body.error === 'stale') {
    return {
      reason: 'gateway.yaml changed since you reviewed it.',
      next: typeof body.diff === 'string'
        ? 'Close to review the newer change here; Reload page discards this review.'
        : 'Close to see the patch to copy; Reload page discards this review.',
    };
  }
  if (status === 422 && body.error === 'not_in_place') {
    return { reason: 'This change cannot be made in place.', next: 'Close to see the patch to copy.' };
  }
  const said = sentenceOf(err, fields);
  if (!said) return null;
  return { reason: said, next: status === 409 ? WORDS.next409 : 'Close to keep this review.' };
}

/** The host's line for a refusal with no sentence: the shell's default reason. */
function defaultReason(err) {
  return `The gateway refused the request (HTTP ${err?.status ?? 0}).`;
}

/**
 * Review, confirm and save `fields` (the save route's list) for one settings
 * tab. Resolves once, when the flow ends, with { outcome: 'done', answer } |
 * 'back' | 'preview_failed' | 'unconfirmed' | 'declined' (plus error where one
 * exists). Check order at entry: an open flow on this host, then held.
 */
export function settingsSave({ host, fields, object, key, opener = null } = {}) {
  if (!(host instanceof Element)) throw new TypeError('settingsSave: host is required');
  if (!Array.isArray(fields)) throw new TypeError('settingsSave: fields must be a list');
  if (open.has(host)) return Promise.resolve({ outcome: 'declined' });
  if (held) {
    host.replaceChildren(line(WORDS.held));
    return Promise.resolve({ outcome: 'declined' });
  }
  open.add(host);
  if (!host.hasAttribute('tabindex')) host.setAttribute('tabindex', '-1');
  return new Promise((resolve) => {
    flow({ host, items: structuredClone(fields), object, key, opener, returnTo: document.activeElement, resolve });
  });
}

function flow(f) {
  const { host, items } = f;
  const end = (result) => { open.delete(host); f.resolve(result); };
  // Focus follows the flow while it is in the host (or lost to the body), never stolen from elsewhere.
  const show = (...nodes) => {
    const active = document.activeElement;
    const ours = !active || active === document.body || host.contains(active);
    host.replaceChildren(...nodes);
    if (ours) (host.querySelector('[tabindex="-1"]') ?? host).focus({ preventScroll: true });
  };
  const back = () => {
    const b = el('button', { class: 'btn quiet', type: 'button' }, 'Back');
    b.addEventListener('click', () => {
      host.replaceChildren();
      const to = f.returnTo?.isConnected && f.returnTo !== document.body ? f.returnTo : host;
      to.focus({ preventScroll: true });
      end({ outcome: 'back' });
    });
    return b;
  };

  host.replaceChildren(el('p', { class: 'settingsave-line' }, WORDS.preparing));
  api(DIFF_PATH, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ fields: previewFields(items) }) })
    .then((answer) => {
      if (answer && typeof answer.diff === 'string') review(answer.revision, answer.diff, null);
      else show(...patchView(answer?.patch, back()));
    }, (err) => {
      const said = sentenceOf(err, items);
      const cause = causeOf(err);
      show(line(said ?? `${WORDS.prepareFailed} ${cause.title}. ${cause.body}`));
      end({ outcome: 'preview_failed', error: err });
    });

  /** The review of `diff` at `revision`, with `note` (a refusal or the changed-since line) above it. */
  function review(revision, diff, note) {
    const save = el('button', { class: 'btn primary', type: 'button' }, 'Save');
    save.addEventListener('click', () => confirmSave(revision, diff, save));
    show(
      ...(note ? [line(note)] : []),
      el('h3', { tabindex: '-1' }, WORDS.reviewTitle),
      diffFigure(diff),
      el('p', {}, WORDS.rest),
      el('p', { class: 'settingsave-actions' }, save, back()),
    );
  }

  function confirmSave(revision, diff, save) {
    if (held) {
      show(line(WORDS.held));
      end({ outcome: 'declined' });
      return;
    }
    const names = items.map((i) => i.field).join(', ');
    confirmAction({
      opener: f.opener ?? save,
      key: f.key,
      verb: 'Save',
      object: f.object,
      tone: 'decision',
      progress: 'Saving…',
      consequences: [`Changes ${names} in gateway.yaml.`, 'Every other line and all comments stay.'],
      run: () => api(SAVE_PATH, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ base_revision: revision, fields: items }) }),
      failed: (err) => failedWords(err, items),
    }).then((result) => settle(result, revision, diff));
  }

  function settle(result, revision, diff) {
    const err = result.error;
    const body = err instanceof ApiError && err.body && typeof err.body === 'object' ? err.body : {};
    switch (result.outcome) {
      case 'done': {
        const answer = result.value;
        const lines = [line(answer?.changed === false ? WORDS.unchanged : WORDS.saved)];
        const restart = Array.isArray(answer?.restart_required) ? answer.restart_required : [];
        if (restart.length) lines.push(line(`Takes effect after a restart: ${restart.join(', ')}`));
        show(...lines);
        end({ outcome: 'done', answer });
        return;
      }
      case 'failed':
        if (err?.status === 409 && body.error === 'stale') {
          if (typeof body.diff === 'string') review(body.current, body.diff, WORDS.newer);
          else show(...patchView(body.patch, back()));
        } else if (err?.status === 422 && body.error === 'not_in_place') {
          show(...patchView(body.patch, back()));
        } else {
          review(revision, diff, sentenceOf(err, items) ?? defaultReason(err));
        }
        return;
      case 'unconfirmed': {
        held = true;
        const said = sentenceOf(err, items);
        show(line(WORDS.unconfirmed), ...(said ? [line(said)] : []));
        end({ outcome: 'unconfirmed', ...(err ? { error: err } : {}) });
        return;
      }
      case 'declined':
        show(line(WORDS.notStarted));
        end({ outcome: 'declined' });
        return;
      default: // kept: nothing was sent; the review stays as it is
    }
  }
}
