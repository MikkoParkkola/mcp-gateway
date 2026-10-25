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

const FRAMES = process.env.FRAMES_DIR;

// [frame file, width, height, colour scheme, regions as [name, x, y, w, h]]
const CASES = [
  ['40-overview-1440.png', 1440, 1100, 'dark', [['sidebar', 0, 0, 232, 400], ['title', 232, 52, 500, 70]]],
  ['37-overview-light.png', 1440, 1100, 'light', [['sidebar', 0, 0, 232, 400], ['title', 232, 52, 500, 70]]],
  ['40-overview-390.png', 390, 844, 'dark', [['top bar', 0, 0, 390, 56], ['title', 0, 56, 390, 60]]],
];

test.describe('frames', () => {
  test('FRAMES_DIR points at the r6 frames', () => {
    expect(FRAMES, 'set FRAMES_DIR to the r6 PNG directory').toBeTruthy();
    for (const [file] of CASES) expect(existsSync(join(FRAMES, file)), file).toBe(true);
  });

  for (const [file, width, height, scheme, regions] of CASES) {
    test(`F17 ${file}`, async ({ page }) => {
      expect(FRAMES).toBeTruthy();
      await page.setViewportSize({ width, height });
      await page.emulateMedia({ colorScheme: scheme });
      await page.goto('/ui/overview/status');
      await page.waitForSelector('#content [data-rendered]');
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
        return regions.map(([name, ...box]) => {
          const p = pixels(a, box);
          const q = pixels(b, box);
          let diff = 0;
          for (let i = 0; i < p.length; i += 4) {
            if (Math.abs(p[i] - q[i]) + Math.abs(p[i + 1] - q[i + 1]) + Math.abs(p[i + 2] - q[i + 2]) > 96) diff++;
          }
          return [name, diff / (p.length / 4), crop(a, box), crop(b, box)];
        });
      }, { shot, frame, regions });
      // The two crops of each region, side by side in the test output, for the PR.
      for (const [name, , shotCrop, frameCrop] of ratios) {
        const slug = `${file.replace('.png', '')}-${name.replace(' ', '-')}`;
        writeFileSync(test.info().outputPath(`${slug}-shell.png`), Buffer.from(shotCrop, 'base64'));
        writeFileSync(test.info().outputPath(`${slug}-frame.png`), Buffer.from(frameCrop, 'base64'));
      }
      for (const [name, ratio] of ratios) console.log(`visual: ${file} ${name} ${(ratio * 100).toFixed(2)}% differs`);
      test.info().annotations.push(...ratios.map(([name, ratio]) => ({ type: 'diff', description: `${file} ${name} ${(ratio * 100).toFixed(2)}%` })));
    });
  }
});
