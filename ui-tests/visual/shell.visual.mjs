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
import { withFixturePages, shellModuleUrl } from '../tests/shell.mjs';

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
    ['top bar', 0, 0, 390, 56, 0.07, 'no logo or Live indicator yet; the frame draws the search glyph differently'],
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
  // Frame 36 draws its tooltips as a sheet. The shell's own tip() draws the
  // "Calls today" one with the frame's copy, its box placed on the frame's.
  ['36-tooltip-sheet.png', 1440, 1000, 'dark', [
    ['tooltip', 388, 142, 300, 182]], 'tooltip'],
];

const FRAME_COPY = {
  _pending: {},
  'fixture.status.calls': { title: 'Calls today', rows: [
    ['What', 'Tool calls github answered or refused.'],
    ['Window', 'Since 00:00 CEST, per call.'],
    ['Source', "The gateway's call log."],
    ['Compared', '↘ 48% against yesterday by the same time.']] },
};

test.describe('frames', () => {
  test('FRAMES_DIR points at the r6 frames', () => {
    expect(FRAMES, 'set FRAMES_DIR to the r6 PNG directory').toBeTruthy();
    for (const [file] of CASES) expect(existsSync(join(FRAMES, file)), file).toBe(true);
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
      if (act?.startsWith('palette:')) {
        await page.keyboard.press('Control+KeyK');
        await page.keyboard.type(act.slice('palette:'.length));
      }
      if (act === 'tooltip') {
        const url = await shellModuleUrl(page);
        await page.evaluate(async (url) => {
          const shell = await import(url);
          await shell.tipsReady();
          const t = shell.tip('fixture.status.calls');
          // The box opens 6 px under its 14 px trigger: wrapper top = 142 - 20,
          // plus the half pixel the frame's own flow layout puts its box at.
          Object.assign(t.style, { position: 'fixed', left: '388px', top: '122.5px' });
          document.body.append(t);
        }, url);
        await page.locator('.has-tip button').focus();
        await page.evaluate(() => Promise.all(document.getAnimations().map((a) => a.finished)));
      }
      // Focus is state, not look: the frames draw the controls unfocused.
      if (act === 'signin') await page.evaluate(() => document.activeElement?.blur());
      await page.evaluate(() => document.fonts.ready);
      const shot = (await page.screenshot()).toString('base64');
      const frame = readFileSync(join(FRAMES, file)).toString('base64');
      const ratios = await page.evaluate(async ({ shot, frame, regions }) => {
        const load = async (b64) => {
          const img = new Image();
          img.src = `data:image/png;base64,${b64}`;
          await img.decode();
          return img;
        };
        const [a, b] = await Promise.all([load(shot), load(frame)]);
        const pixels = (img, [x, y, w, h]) => {
          const c = new OffscreenCanvas(w, h);
          const g = c.getContext('2d');
          g.drawImage(img, x, y, w, h, 0, 0, w, h);
          return g.getImageData(0, 0, w, h).data;
        };
        const crop = (img, [x, y, w, h]) => {
          const c = document.createElement('canvas');
          c.width = w;
          c.height = h;
          c.getContext('2d').drawImage(img, x, y, w, h, 0, 0, w, h);
          return c.toDataURL('image/png').split(',')[1];
        };
        return regions.map(([name, x, y, w, h, , , fx = x, fy = y]) => {
          const box = [x, y, w, h];
          const frameBox = [fx, fy, w, h];
          const p = pixels(a, box);
          const q = pixels(b, frameBox);
          let diff = 0;
          for (let i = 0; i < p.length; i += 4) {
            if (Math.abs(p[i] - q[i]) + Math.abs(p[i + 1] - q[i + 1]) + Math.abs(p[i + 2] - q[i + 2]) > 96) diff++;
          }
          return [name, diff / (p.length / 4), crop(a, box), crop(b, frameBox)];
        });
      }, { shot, frame, regions });
      // The two crops of each region, side by side in the test output, for the PR.
      for (const [name, , shotCrop, frameCrop] of ratios) {
        const slug = `${file.replace('.png', '')}-${name.replace(' ', '-')}`;
        writeFileSync(test.info().outputPath(`${slug}-shell.png`), Buffer.from(shotCrop, 'base64'));
        writeFileSync(test.info().outputPath(`${slug}-frame.png`), Buffer.from(frameCrop, 'base64'));
      }
      for (const [i, [name, ratio]] of ratios.entries()) {
        const [, , , , , ceiling = LIMIT, cause = ''] = regions[i];
        expect(ratio, `${file} ${name}${cause ? ` (${cause})` : ''}`).toBeLessThanOrEqual(ceiling);
      }
      for (const [name, ratio] of ratios) console.log(`visual: ${file} ${name} ${(ratio * 100).toFixed(2)}% differs`);
      test.info().annotations.push(...ratios.map(([name, ratio]) => ({ type: 'diff', description: `${file} ${name} ${(ratio * 100).toFixed(2)}%` })));
    });
  }
});
