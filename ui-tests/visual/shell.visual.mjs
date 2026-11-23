// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The shell's regions against the design frames (row F17 of the shell test
// plan). The frames live in the design workspace, not in this repository, so
// this is its own project, run locally with FRAMES_DIR set; CI does not run
// it. A missing FRAMES_DIR or frame fails the run, never skips it. Page
// bodies are not compared: their content belongs to the screen tickets.
// Both images are decoded in the browser's own canvas, so no image library
// is needed. The ratio per region is printed for the PR.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { test, expect } from '../tests/base.mjs';
import { withFixturePages, tooltipModuleUrl } from '../tests/shell.mjs';
import { SCREENS } from '../tests/screens.mjs';

const FRAMES = process.env.FRAMES_DIR;

// The ticket's limit is 2% of a region. A region above it carries its own
// ceiling, the measured share plus a little, and the named cause, which the
// pull request lists as an intended difference.
const LIMIT = 0.02;
// [frame file, width, height, colour scheme, regions as [name, x, y, w, h, ceiling?, cause?]]
const CASES = [
  ['40-overview-1440.png', 1440, 1100, 'dark', [
    ['sidebar', 0, 0, 232, 400, 0.03, 'no logo mark; the frame shows a sample decisions count'],
    ['title', 232, 52, 500, 70]]],
  ['37-overview-light.png', 1440, 1100, 'light', [
    ['sidebar', 0, 0, 232, 400, 0.03, 'no logo mark; the frame shows a sample decisions count'],
    ['title', 232, 52, 500, 70]]],
  ['40-overview-390.png', 390, 844, 'dark', [
    // 0.075, not 0.07: the shell draws the MCP-GATEWAY wordmark where the frame has a logo, which
    // pushes the environment chip right of the frame chip. The logo swap is out of scope here.
    ['top bar', 0, 0, 390, 56, 0.075, 'no logo or Live indicator yet; the frame draws the search glyph differently; the wordmark pushes the environment chip right'],
    ['title', 0, 56, 390, 60]]],
  // Frame 46 exists only at 1440 px, dark. Its entries are the github page's
  // own data, so only the palette's input row is compared; the frame draws
  // the dialog 80 px further right, given as the frame box's x.
  ['46-command-palette.png', 1440, 1000, 'dark', [
    ['palette input', 400, 120, 640, 50, 0.02, '', 480, 120]], 'palette:github'],
  // Frame 32 exists at 1440 and 390 px, dark only. The shell's card adds two
  // lines (the handoff route and the in-memory key note the shell ADR asks
  // for), so it centres 21 px higher; the key form is compared, frame box
  // shifted down by that much. The frame's logo mark is not drawn yet.
  ['32-sign-in.png', 1440, 1000, 'dark', [
    ['key form', 546, 446, 348, 135, 0.02, '', 546, 467]], 'signin'],
  ['32-sign-in-390.png', 390, 800, 'dark', [
    ['key form', 42, 346, 306, 135, 0.02, '', 42, 367]], 'signin'],
  // Frame 48q moved to the screen table (tests/screens.mjs), drawn through its catalogue state.
  // Frame 36 draws its tooltips as a sheet. The tooltip module's own tip()
  // draws the "Calls today" one with the frame's copy, its box placed on the frame's.
  ['36-tooltip-sheet.png', 1440, 1000, 'dark', [
    ['tooltip', 388, 142, 300, 200]], 'tooltip'],
];

const FRAME_COPY = {
  _pending: {},
  'fixture.status.calls': { title: 'Calls today', rows: [
    ['What', 'Tool calls github answered or refused.'],
    ['Window', "Since 00:00 in the gateway's time zone, per call."],
    ['Source', "The gateway's call log."],
    ['Compared', '↘ 48% against yesterday by the same time.']] },
};

test.describe('frames', () => {
  test('FRAMES_DIR points at the r6 frames', () => {
    expect(FRAMES, 'set FRAMES_DIR to the r6 PNG directory').toBeTruthy();
    const files = [...CASES.map(([file]) => file), ...SCREENS.flatMap((s) => s.frames.map((f) => f.file))];
    for (const file of files) expect(existsSync(join(FRAMES, file)), file).toBe(true);
  });

  for (const [file, width, height, scheme, regions, act] of CASES) {
    test(`F17 ${file}`, async ({ page }) => {
      expect(FRAMES).toBeTruthy();
      await page.setViewportSize({ width, height });
      await page.emulateMedia({ colorScheme: scheme });
      if (act === 'signin') {
        await page.route('**/ui/api/status', (r) => r.fulfill({ json: { auth: { enabled: true, signed_in: false, admin: false } } }));
      }
      if (act === 'tooltip') await page.route('**/ui/assets/tips.*.json', (r) => r.fulfill({ json: FRAME_COPY }));
      // The fixture pages give Overview its subtitle, as a real screen will.
      await withFixturePages(page);
      await page.goto('/ui/overview/status');
      await page.waitForSelector(act === 'signin' ? '#signin:not([hidden])' : '#content [data-rendered]');
      if (act === 'tooltip') {
        await page.evaluate(async (url) => {
          const tips = await import(url);
          await tips.tipsSettled();
          const t = tips.tip('fixture.status.calls');
          // The box opens 6 px under its 14 px trigger; the frame's box sits at y = 142.5.
          Object.assign(t.style, { position: 'fixed', left: '388px', top: '122.5px' });
          document.body.append(t);
        }, tooltipModuleUrl());
        await page.locator('.has-tip button').focus();
        await expect(page.locator('.tip.open')).toHaveCount(1);
        await page.evaluate(() => Promise.all(document.getAnimations().map((a) => a.finished)));
      }
      if (act?.startsWith('palette:')) {
        await page.keyboard.press('Control+KeyK');
        await page.keyboard.type(act.slice('palette:'.length));
      }
      // Focus is state, not look: the frames draw the controls unfocused.
      if (act === 'signin') await page.evaluate(() => document.activeElement?.blur());
      await compareWithFrame(page, file, regions);
    });
  }

  // The screen table's frames, each drawn through the same state step the CI gates use.
  for (const screen of SCREENS) {
    for (const f of screen.frames) {
      test(`${screen.id} frame ${f.file}`, async ({ page }) => {
        expect(FRAMES).toBeTruthy();
        await page.setViewportSize({ width: f.width, height: f.height });
        await page.emulateMedia({ colorScheme: f.scheme });
        await screen.states.find((s) => s.name === f.state).step(page, f.data);
        // The frames draw no focus ring; let a fading ring (any finite animation) finish first.
        await page.evaluate(async () => {
          document.activeElement?.blur();
          const ending = document.getAnimations().filter((a) => a.effect?.getComputedTiming().endTime !== Infinity);
          await Promise.all(ending.map((a) => a.finished.catch(() => {})));
        });
        await compareWithFrame(page, f.file, f.regions, f.masks);
      });
    }
  }
});

/**
 * Screenshot the page and compare each region with the same box of the frame (or the
 * frame box given at index 7-8). A pixel differs when its three channels differ by more
 * than 96 in sum. Mask boxes are filled one colour on both images and their pixels are
 * not counted, so live numbers neither pass nor fail a region. Both crops of every region
 * go to the test output for the PR; each region is then held to its ceiling.
 */
async function compareWithFrame(page, file, regions, masks = []) {
  await page.evaluate(() => document.fonts.ready);
  const shot = (await page.screenshot()).toString('base64');
  const frame = readFileSync(join(FRAMES, file)).toString('base64');
  const found = await page.evaluate(async ({ shot, frame, regions, masks }) => {
    const paint = async (b64) => {
      const img = new Image();
      img.src = `data:image/png;base64,${b64}`;
      await img.decode();
      const c = new OffscreenCanvas(img.width, img.height);
      const g = c.getContext('2d', { willReadFrequently: true });
      g.drawImage(img, 0, 0);
      g.fillStyle = '#ff00ff';
      for (const [x, y, w, h] of masks) g.fillRect(x, y, w, h);
      return g;
    };
    const [mine, theirs] = await Promise.all([paint(shot), paint(frame)]);
    const hidden = (px, py) => masks.some(([x, y, w, h]) => px >= x && px < x + w && py >= y && py < y + h);
    const asPng = async (g, x, y, w, h) => {
      const out = new OffscreenCanvas(w, h);
      out.getContext('2d').drawImage(g.canvas, x, y, w, h, 0, 0, w, h);
      const blob = await out.convertToBlob({ type: 'image/png' });
      return new Promise((ok) => {
        const r = new FileReader();
        r.onload = () => ok(String(r.result).split(',')[1]);
        r.readAsDataURL(blob);
      });
    };
    return Promise.all(regions.map(async ([name, x, y, w, h, , , fx = x, fy = y]) => {
      const p = mine.getImageData(x, y, w, h).data;
      const q = theirs.getImageData(fx, fy, w, h).data;
      let counted = 0;
      let differ = 0;
      for (let i = 0; i < w * h; i += 1) {
        if (hidden(x + (i % w), y + Math.floor(i / w))) continue;
        counted += 1;
        const k = i * 4;
        if (Math.abs(p[k] - q[k]) + Math.abs(p[k + 1] - q[k + 1]) + Math.abs(p[k + 2] - q[k + 2]) > 96) differ += 1;
      }
      return { name, ratio: counted ? differ / counted : 1, ours: await asPng(mine, x, y, w, h), frame: await asPng(theirs, fx, fy, w, h) };
    }));
  }, { shot, frame, regions, masks });
  const pct = (r) => `${(r * 100).toFixed(2)}%`;
  for (const r of found) {
    const slug = `${file.replace('.png', '')}-${r.name.replace(' ', '-')}`;
    writeFileSync(test.info().outputPath(`${slug}-shell.png`), Buffer.from(r.ours, 'base64'));
    writeFileSync(test.info().outputPath(`${slug}-frame.png`), Buffer.from(r.frame, 'base64'));
    console.log(`visual: ${file} ${r.name} ${pct(r.ratio)} differs`);
    test.info().annotations.push({ type: 'diff', description: `${file} ${r.name} ${pct(r.ratio)}` });
  }
  for (const [i, r] of found.entries()) {
    const [, , , , , ceiling = LIMIT, cause = ''] = regions[i];
    expect(r.ratio, `${file} ${r.name}${cause ? ` (${cause})` : ''}`).toBeLessThanOrEqual(ceiling);
  }
}
