// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The screen gates, run over every entry of the screen table (screens.mjs):
//   G0  the table itself can be gated (no entry is missing a piece)
//   G2  axe at each width and colour scheme, per state
//   G2b the keyboard reaches every control, per state and width
//   G3  each journey, from the sidebar to its asserted outcome
//   G4  under reduced motion, only short opacity changes, per state and width
// Each gate also has a plant row: a fault put into a clean state that the gate
// must report. A plant row passes when the gate catches its fault.
import { test, expect, WIDTHS, blockingViolations } from './base.mjs';
import { SCREENS } from './screens.mjs';

const THEMES = ['dark', 'light'];

// One title per row, so one screen's result never stands in for another's.
const titles = {
  axe: (id, state, width, theme) => `${id} ${state} axe at ${width} px, ${theme}`,
  keys: (id, state, width) => `${id} ${state} keyboard at ${width} px`,
  journey: (id, name) => `${id} journey ${name}`,
  motion: (id, state, width) => `${id} ${state} reduced motion at ${width} px`,
};

function rowTitles(screens) {
  const all = [];
  for (const s of screens) {
    for (const st of s.states ?? []) {
      for (const w of WIDTHS) {
        for (const t of THEMES) all.push(titles.axe(s.id, st.name, w, t));
        all.push(titles.keys(s.id, st.name, w), titles.motion(s.id, st.name, w));
      }
    }
    for (const j of s.journeys ?? []) all.push(titles.journey(s.id, j.name));
  }
  return all;
}

/** Everything that stops the gates from covering `screens`; empty when nothing does. */
function tableProblems(screens) {
  const out = [];
  for (const s of screens) {
    for (const part of ['states', 'journeys', 'frames']) {
      if (!s[part]?.length) out.push(`${s.id}: no ${part}`);
    }
    const names = new Set((s.states ?? []).map((st) => st.name));
    for (const st of s.states ?? []) {
      if (typeof st.action !== 'string' || !st.action) out.push(`${s.id} ${st.name}: no main action`);
      if (typeof st.step !== 'function') out.push(`${s.id} ${st.name}: no step`);
    }
    for (const f of s.frames ?? []) {
      if (!f.regions?.length) out.push(`${s.id} ${f.file}: compares no region`);
      if (!names.has(f.state)) out.push(`${s.id} ${f.file}: drawn in state "${f.state}", which the entry lacks`);
    }
  }
  const seen = new Set();
  for (const t of rowTitles(screens)) {
    if (seen.has(t)) out.push(`two rows titled "${t}"`);
    seen.add(t);
  }
  return out;
}

async function axeFaults(page, state, { width, theme, plant }) {
  await page.setViewportSize({ width, height: 900 });
  await page.emulateMedia({ colorScheme: theme });
  await state.step(page);
  if (plant) await plant(page);
  const faults = await blockingViolations(page);
  // Where no frame exists (390 px, light), this row is the screen's layout check too.
  const wide = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (wide > 0) faults.push(`the page scrolls sideways by ${wide} px`);
  return faults;
}

const FOCUSABLE = 'a[href], button, input, select, textarea, summary, [tabindex]:not([tabindex="-1"])';

/**
 * Tab through the page a few presses past its control count; return what went wrong: the
 * controls never focused, or (for a state with a trap) the first press that left the trap.
 * In a trap only its own controls count, and the walk crosses both ends: Tab past the
 * last control, then Shift+Tab past the first.
 */
async function unreachedControls(page, state, { width, plant }) {
  await page.setViewportSize({ width, height: 900 });
  await state.step(page);
  if (plant) await plant(page);
  const trap = state.trap?.(page);
  if (trap) await expect(trap, 'the trap is on screen at this width').toBeVisible();
  const root = trap ? await trap.elementHandle() : null;
  const count = await page.evaluate(([sel, scope]) => [...(scope ?? document).querySelectorAll(sel)]
    .filter((el) => el.checkVisibility() && !el.disabled).length, [FOCUSABLE, root]);
  expect(count, 'the state has controls to reach').toBeGreaterThan(0);
  const keys = Array(count + 3).fill('Tab');
  if (trap) keys.push(...Array(count + 3).fill('Shift+Tab'));
  for (const [i, key] of keys.entries()) {
    await page.keyboard.press(key);
    // Past either end of a native modal, the browser's own controls take focus and the page
    // reports none (the body). That is not the page behind, which stays inert; a leak is
    // focus on a page element outside the trap.
    const inside = await page.evaluate((scope) => {
      const el = document.activeElement;
      el?.setAttribute('data-g2b-reached', '');
      return !scope || !el || el === document.body || scope.contains(el);
    }, root);
    if (!inside) return [`press ${i + 1} (${key}) moved focus out of the trap`];
  }
  if (trap) await expect(trap, 'the trap is still open after the walk').toBeVisible();
  return page.evaluate(([sel, scope]) => [...(scope ?? document).querySelectorAll(sel)]
    .filter((el) => el.checkVisibility() && !el.disabled && !el.hasAttribute('data-g2b-reached'))
    .map((el) => el.outerHTML.slice(0, 80)), [FOCUSABLE, root]);
}

// ---- G4: record every animation as it starts, then judge them all. ----

// Runs in every document of the row before its own scripts. Each animation is
// described when it starts (CSS animation, CSS transition, or element.animate),
// so one that has already finished by the check is still judged.
function installMotionRecorder() {
  const skip = new Set(['offset', 'easing', 'composite', 'computedOffset']);
  const kebab = (p) => p.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
  const describe = (anim, source) => {
    const props = new Set();
    for (const frame of anim.effect?.getKeyframes?.() ?? []) {
      for (const key of Object.keys(frame)) if (!skip.has(key)) props.add(kebab(key));
    }
    if (anim.transitionProperty) props.add(anim.transitionProperty);
    const timing = anim.effect?.getComputedTiming?.() ?? {};
    return {
      source,
      id: anim.id || anim.animationName || anim.transitionProperty || '',
      props: [...props],
      // Iteration length times iterations; start and end delays are not counted.
      active: timing.activeDuration ?? null,
      iterations: timing.iterations ?? null,
    };
  };
  const pending = [];
  const send = (rec) => pending.push(window.g4Record(rec));
  window.g4Describe = describe;
  window.g4Flush = () => Promise.all(pending);
  // A start event describes EVERY matching animation not yet logged (same element,
  // pseudo-element and name), so same-name twins are each judged by their own timing
  // whichever of them starts first. A later event whose matches are all logged adds
  // nothing; one with no match at all is logged as not found, which fails the rule.
  const logged = new WeakSet();
  const record = (ev, source, matches, fallback) => {
    const all = document.getAnimations().filter((a) => a.effect?.target === ev.target
      && (a.effect.pseudoElement ?? '') === (ev.pseudoElement ?? '') && matches(a));
    if (all.length === 0) return send(fallback);
    for (const anim of all.filter((a) => !logged.has(a))) {
      logged.add(anim);
      send(describe(anim, source));
    }
    return undefined;
  };
  document.addEventListener('animationstart', (ev) => record(ev, 'css animation',
    (a) => a.animationName === ev.animationName,
    { source: 'css animation', id: ev.animationName, props: ['(not found)'], active: null, iterations: null }), true);
  document.addEventListener('transitionrun', (ev) => record(ev, 'css transition',
    (a) => a.transitionProperty === ev.propertyName,
    { source: 'css transition', id: ev.propertyName, props: [ev.propertyName], active: null, iterations: null }), true);
  const animate = Element.prototype.animate;
  Element.prototype.animate = function recordedAnimate(...args) {
    const anim = animate.apply(this, args);
    send(describe(anim, 'element.animate'));
    return anim;
  };
}

const MOTION_LIMIT_MS = 120;

/** The rule broken by each recorded animation: opacity only, finite, at most 120 ms of change. */
function motionFaults(records) {
  return records.flatMap((r) => {
    const faults = [];
    const others = r.props.filter((p) => p !== 'opacity');
    if (r.props.length === 0) faults.push('names no property');
    if (others.length) faults.push(`animates ${others.join(', ')}`);
    if (typeof r.iterations !== 'number' || !Number.isFinite(r.iterations)) faults.push('repeats without end');
    if (typeof r.active !== 'number' || !(r.active <= MOTION_LIMIT_MS)) faults.push(`changes for ${r.active} ms`);
    return faults.map((f) => `${r.source} "${r.id}": ${f}`);
  });
}

async function motionCheck(page, state, { width, plant }) {
  const log = [];
  await page.exposeFunction('g4Record', (rec) => { log.push(rec); });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript(installMotionRecorder);
  await page.setViewportSize({ width, height: 900 });
  await state.step(page);
  if (state.act) await state.act(page);
  // The row's own probe: a recorder that records nothing fails here, not silently.
  await page.evaluate(() => document.body.animate({ opacity: [1, 0.98] }, { duration: 50, id: 'g4-probe' }));
  if (plant) await plant(page);
  await page.evaluate(() => new Promise((ok) => requestAnimationFrame(() => requestAnimationFrame(ok))));
  // Anything still pending or running now (a delayed start included) is judged by the same rule.
  const live = await page.evaluate(async () => {
    await window.g4Flush();
    return document.getAnimations()
      .filter((a) => a.pending || a.playState === 'running')
      .map((a) => window.g4Describe(a, 'still running'));
  });
  return { probed: log.some((r) => r.id === 'g4-probe'), faults: motionFaults([...log, ...live]) };
}

// ---- The rows. ----

test('G0 the screen table can be gated', () => {
  expect(tableProblems(SCREENS)).toEqual([]);
});

for (const screen of SCREENS) {
  for (const state of screen.states) {
    for (const width of WIDTHS) {
      for (const theme of THEMES) {
        test(titles.axe(screen.id, state.name, width, theme), async ({ page }) => {
          expect(await axeFaults(page, state, { width, theme })).toEqual([]);
        });
      }
      test(titles.keys(screen.id, state.name, width), async ({ page }) => {
        expect(await unreachedControls(page, state, { width })).toEqual([]);
      });
      test(titles.motion(screen.id, state.name, width), async ({ page }) => {
        const { probed, faults } = await motionCheck(page, state, { width });
        expect(probed, 'the recorder saw the row\'s own probe').toBe(true);
        expect(faults).toEqual([]);
      });
    }
  }
  for (const journey of screen.journeys) {
    test(titles.journey(screen.id, journey.name), async ({ page }) => {
      await journey.step(page);
    });
  }
}

// ---- Plants: each puts one fault into a clean state; the gate must name it. ----

const tools = SCREENS.find((s) => s.id === 'tools');
const plainState = tools.states.find((s) => s.name === 'most-called');

test('G0 plant: an entry with no frames is reported', () => {
  expect(tableProblems([{ ...tools, frames: [] }])).toEqual(['tools: no frames']);
});

// Why an entry has no frames yet: they arrive with a later screen cut.
const LATER = 'frames come with a later screen cut';

test('G0 plant: frames: [] passes only when a deferral reason comes with it', () => {
  expect(tableProblems([{ ...tools, frames: [], frames_deferred: LATER }])).toEqual([]);
  expect(tableProblems([{ ...tools, frames: [] }])).toEqual(['tools: no frames']);
});

test('G0 plant: a blank deferral reason does not count', () => {
  expect(tableProblems([{ ...tools, frames: [], frames_deferred: '' }])).toEqual(['tools: no frames']);
  expect(tableProblems([{ ...tools, frames: [], frames_deferred: ' \t ' }])).toEqual(['tools: no frames']);
});

test('G0 plant: real frames beside any deferral reason are refused', () => {
  for (const frames_deferred of [LATER, '', ' \t ']) {
    expect(tableProblems([{ ...tools, frames_deferred }]), JSON.stringify(frames_deferred))
      .toEqual(['tools: frames and frames_deferred both given']);
  }
});

test('G0 plant: a deferral reason without a frames array is refused', () => {
  expect(tableProblems([{ ...tools, frames: undefined, frames_deferred: LATER }])).toEqual(['tools: no frames']);
});

test('G0 plant: a non-string deferral reason does not count', () => {
  expect(tableProblems([{ ...tools, frames: [], frames_deferred: 42 }])).toEqual(['tools: no frames']);
});

test('G0 plant: a frame with an empty region list is refused', () => {
  const frames = [{ ...tools.frames[0], regions: [] }];
  expect(tableProblems([{ ...tools, frames }])).toEqual([`tools ${frames[0].file}: compares no region`]);
});

test('G0 plant: a frame drawn in a state the entry lacks is reported', () => {
  const frames = [{ ...tools.frames[0], state: 'nowhere' }];
  expect(tableProblems([{ ...tools, frames }])).toEqual([`tools ${frames[0].file}: drawn in state "nowhere", which the entry lacks`]);
});

test('G0 plant: a state with no main action is reported', () => {
  const states = tools.states.map((s) => (s === plainState ? { ...s, action: undefined } : s));
  expect(tableProblems([{ ...tools, states }])).toEqual(['tools most-called: no main action']);
});

test('G0 plant: two states with one name give rows one title, which is reported', () => {
  const problems = tableProblems([{ ...tools, states: [plainState, plainState] }]);
  expect(problems).toContain('two rows titled "tools most-called axe at 390 px, dark"');
});

test('G2 plant: a button with no name is reported', async ({ page }) => {
  const faults = await axeFaults(page, plainState, { width: 1440, theme: 'dark', plant: async (p) => {
    await p.evaluate(() => document.getElementById('content').append(document.createElement('button')));
  } });
  expect(faults.some((f) => f.startsWith('button-name'))).toBe(true);
});

test('G2 plant: a block wider than the 390 px screen is reported', async ({ page }) => {
  const faults = await axeFaults(page, plainState, { width: 390, theme: 'light', plant: async (p) => {
    await p.evaluate(() => {
      const strip = document.createElement('div');
      strip.style.setProperty('width', '900px');
      strip.style.setProperty('height', '4px');
      document.getElementById('content').append(strip);
    });
  } });
  expect(faults).toHaveLength(1);
  expect(faults[0]).toMatch(/^the page scrolls sideways by \d+ px$/);
});

test('G2b plant: a button taken out of the Tab order is reported', async ({ page }) => {
  const missed = await unreachedControls(page, plainState, { width: 1440, plant: async (p) => {
    await p.evaluate(() => {
      const b = document.createElement('button');
      b.textContent = 'Out of reach';
      b.tabIndex = -1;
      document.getElementById('content').append(b);
    });
  } });
  expect(missed).toEqual(['<button tabindex="-1">Out of reach</button>']);
});

test('G2b plant: a confirm that lets Tab out to the page behind is reported', async ({ page }) => {
  const confirmState = tools.states.find((s) => s.name === 'try-confirm');
  const missed = await unreachedControls(page, confirmState, { width: 1440, plant: async (p) => {
    // Tab past the confirm's last button hands focus to a control outside it (a second
    // dialog, opened on top, takes it). Every confirm control stays reachable first.
    await p.evaluate(() => {
      const buttons = document.querySelectorAll('dialog.confirm button');
      buttons[buttons.length - 1].addEventListener('keydown', (ev) => {
        if (ev.key !== 'Tab' || ev.shiftKey) return;
        ev.preventDefault();
        const other = document.createElement('dialog');
        other.append(Object.assign(document.createElement('button'), { textContent: 'Elsewhere' }));
        document.body.append(other);
        other.showModal();
      });
      buttons[0].focus();
    });
  } });
  expect(missed).toHaveLength(1);
  expect(missed[0]).toMatch(/^press \d+ \((Tab|Shift\+Tab)\) moved focus out of the trap$/);
});

test('G3 plant: a journey whose outcome text is wrong fails', async ({ page }) => {
  // The answer text changes once drawn, so the journey's literal no longer matches.
  await page.addInitScript(() => {
    new MutationObserver(() => {
      for (const pre of document.querySelectorAll('.tools-try-answer pre')) {
        if (pre.textContent === 'gate is open') pre.textContent = 'gate is shut';
      }
    }).observe(document, { childList: true, subtree: true });
  });
  const failure = await tools.journeys[0].step(page).then(() => null, (err) => err);
  // The matcher colours its message; read it plain.
  const plain = String(failure?.message).replace(/\u001b\[[0-9;]*m/g, '');
  expect(plain).toContain('Expected: "gate is open"');
  expect(plain).toContain('Received: "gate is shut"');
});

// The shell's CSP refuses style attributes and <style> elements, so a CSS plant goes in
// through the CSSOM, and its declarations are !important to beat the reduced-motion reset.
async function cssPlant(page, { keyframes = '', styles, change, wait = true }) {
  return page.evaluate(async ({ keyframes, styles, change, wait }) => {
    if (keyframes) {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(keyframes);
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
    }
    const box = Object.assign(document.createElement('div'), { textContent: 'plant' });
    for (const [prop, value] of styles) box.style.setProperty(prop, value, 'important');
    document.getElementById('content').append(box);
    box.getBoundingClientRect();
    if (change) box.style.setProperty(change[0], change[1], 'important');
    const anims = box.getAnimations();
    if (wait) await Promise.all(anims.map((a) => a.finished.catch(() => {})));
    return { started: anims.length, left: box.getAnimations().length };
  }, { keyframes, styles, change, wait });
}

const g4 = (plant) => async ({ page }) => motionCheck(page, plainState, { width: 1440, plant: (p) => plant(p) });

test('G4 plant: a 300 ms transform that has finished before the check is still reported', async ({ page }) => {
  let seen;
  const { faults } = await g4(async (p) => {
    seen = await cssPlant(p, {
      keyframes: '@keyframes g4-slide { from { transform: translateX(0) } to { transform: translateX(12px) } }',
      styles: [['animation', 'g4-slide 300ms linear 1']],
    });
  })({ page });
  // The premise: it ran and was over before the check, so only the recording can name it.
  expect(seen).toEqual({ started: 1, left: 0 });
  expect(faults).toEqual(['css animation "g4-slide": animates transform', 'css animation "g4-slide": changes for 300 ms']);
});

test('G4 plant: two animations sharing a name on one element are each judged by their own length', async ({ page }) => {
  const { faults } = await g4((p) => cssPlant(p, {
    keyframes: '@keyframes g4-twin { from { opacity: 1 } to { opacity: 0.6 } }',
    styles: [['animation', 'g4-twin 50ms linear 1, g4-twin 300ms linear 1']],
  }))({ page });
  expect(faults).toEqual(['css animation "g4-twin": changes for 300 ms']);
});

test('G4 plant: same-name twins with staggered starts: the one that ran and finished is still judged', async ({ page }) => {
  // The 50 ms twin waits a minute; the 300 ms twin starts now and finishes before the check.
  const { faults } = await g4((p) => p.evaluate(async () => {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync('@keyframes g4-stagger { from { opacity: 1 } to { opacity: 0.6 } }');
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
    const box = Object.assign(document.createElement('div'), { textContent: 'stagger' });
    box.style.setProperty('animation', 'g4-stagger 50ms linear 60s 1, g4-stagger 300ms linear 1', 'important');
    document.getElementById('content').append(box);
    const now = box.getAnimations().filter((a) => a.effect.getComputedTiming().delay === 0);
    await Promise.all(now.map((a) => a.finished));
  }))({ page });
  expect(faults).toEqual(['css animation "g4-stagger": changes for 300 ms']);
});

test('G4 plant: a transform on a pseudo-element is recorded', async ({ page }) => {
  const { faults } = await g4((p) => p.evaluate(async () => {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync('@keyframes g4-pseudo { to { transform: translateY(6px) } }'
      + ' .g4-host::after { content: "x"; animation: g4-pseudo 300ms linear 1 !important; }');
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
    const host = Object.assign(document.createElement('div'), { className: 'g4-host' });
    document.getElementById('content').append(host);
    const anims = document.getAnimations().filter((a) => a.effect?.pseudoElement === '::after');
    await Promise.all(anims.map((a) => a.finished.catch(() => {})));
  }))({ page });
  expect(faults).toEqual(['css animation "g4-pseudo": animates transform', 'css animation "g4-pseudo": changes for 300 ms']);
});

test('G4 plant: an animation recorded before a navigation is still judged after it', async ({ page }) => {
  const { faults } = await g4(async (p) => {
    await p.evaluate(() => document.getElementById('content').animate({ transform: ['none', 'scale(1.1)'] }, { duration: 40, id: 'g4-before-goto' }));
    // A full navigation replaces the document; the row's log lives outside it.
    await p.goto('/ui/tools/status');
    await expect(p.locator('#content [data-rendered]')).toBeVisible();
  })({ page });
  expect(faults).toEqual(['element.animate "g4-before-goto": animates transform']);
});

test('G4 plant: an opacity loop that never ends is reported', async ({ page }) => {
  const { faults } = await g4((p) => p.evaluate(() => {
    document.getElementById('content').animate({ opacity: [1, 0.5] }, { duration: 80, iterations: Infinity, id: 'g4-loop' });
  }))({ page });
  expect(faults).toContain('element.animate "g4-loop": repeats without end');
});

test('G4 plant: a finished 100 ms colour transition is reported for its property alone', async ({ page }) => {
  const { faults } = await g4((p) => cssPlant(p, {
    styles: [['color', 'rgb(200, 200, 200)'], ['transition', 'color 100ms linear']],
    change: ['color', 'rgb(90, 90, 90)'],
  }))({ page });
  expect(faults).toEqual(['css transition "color": animates color']);
});

test('G4 plant: a transform whose delay outlasts the row is reported by the final read', async ({ page }) => {
  // A CSS animation's start event waits out its delay, so only the final read can see this one.
  // The delay is a minute, far past the row, so no slow run can let the start event fire first.
  const { faults } = await g4((p) => cssPlant(p, {
    keyframes: '@keyframes g4-late { to { transform: scale(1.2) } }',
    styles: [['animation', 'g4-late 200ms linear 60s 1']],
    wait: false,
  }))({ page });
  // Only the final read names it: the start recorder never saw it.
  expect(faults).toEqual(['still running "g4-late": animates transform', 'still running "g4-late": changes for 200 ms']);
});

test('G4 plant: a 60 ms fade run three times is 180 ms of change and is reported', async ({ page }) => {
  const { faults } = await g4((p) => p.evaluate(() => {
    document.getElementById('content').animate({ opacity: [1, 0.6] }, { duration: 60, iterations: 3, id: 'g4-thrice' });
  }))({ page });
  expect(faults).toContain('element.animate "g4-thrice": changes for 180 ms');
});

test('G4 plant: the limit is 120 ms: a 120 ms fade passes and a 130 ms fade fails', async ({ page }) => {
  const { faults } = await g4((p) => p.evaluate(() => {
    const c = document.getElementById('content');
    c.animate({ opacity: [1, 0.7] }, { duration: 120, id: 'g4-at-limit' });
    c.animate({ opacity: [1, 0.7] }, { duration: 130, id: 'g4-over-limit' });
  }))({ page });
  expect(faults.filter((f) => f.includes('g4-at-limit'))).toEqual([]);
  expect(faults).toContain('element.animate "g4-over-limit": changes for 130 ms');
});

test('G4 plant: a 120 ms fade after a 200 ms delay passes, since a delay is not motion', async ({ page }) => {
  const { probed, faults } = await g4((p) => p.evaluate(() => {
    document.getElementById('content').animate({ opacity: [1, 0.7] }, { duration: 120, delay: 200, id: 'g4-delayed' });
  }))({ page });
  expect(probed).toBe(true);
  expect(faults).toEqual([]);
});
