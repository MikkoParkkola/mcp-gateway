// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The screen table the screen gates loop over (screen-gates.spec.mjs) and the
// visual project draws from (visual/shell.visual.mjs). A screen ticket adds its
// entry here; it writes no gate code of its own.
//
// An entry:
//   id        the sidebar page id
//   states    [{ name, action, act?, step(page, tools?) }]: step mocks the API and
//             drives the page until the state is settled; `action` names the
//             state's main motion (G4) and `act`, when present, performs it after
//             the step. A step takes its tool list as an argument, so a frame can
//             pass the list its picture was drawn with.
//   journeys  [{ name, step(page) }]: starts at the sidebar, ends on an asserted outcome
//   frames    [{ file, width, height, scheme, state, tools?, regions, masks }]:
//             regions as [name, x, y, w, h, ceiling?, cause?]; masks as
//             [x, y, w, h], painted one colour on both images and left out of the ratio
import { expect } from './base.mjs';

const ADMIN = { auth: { signed_in: true, admin: true, enabled: true } };

/** Answer the shell's status read as a signed-in admin, and the tool list with `tools`. */
async function serveTools(page, tools) {
  await page.route('**/ui/api/status', async (route) => route.fulfill({ json: ADMIN }));
  await page.route('**/ui/api/tools**', async (route) => route.fulfill({ json: { tools, total: tools.length } }));
}

/** Wait until the content is drawn, its fonts are in and nothing is still moving. */
export async function settled(page) {
  await page.waitForSelector('#content [data-rendered]');
  await page.evaluate(async () => {
    await document.fonts.ready;
    await Promise.all(document.getAnimations().map((a) => a.finished.catch(() => {})));
  });
}

const called = (name, server, hour, before, description = '') => ({
  name, server, description, class: 'read', class_source: 'declared', schema: {}, calls_1h: hour, calls_prev_1h: before,
});

// Twelve tools: ten called this hour, two not, so the panel is full and still trims.
const TOOLS_SMALL = [
  called('kettle.boil', 'kitchen', 410, 380, 'Heat the water'),
  called('lamp.dim', 'house', 377, 377, 'Lower the light'),
  called('gate.open', 'yard', 351, 300, 'Open the front gate'),
  called('pump.start', 'yard', 296, 310, 'Start the well pump'),
  called('oven.preheat', 'kitchen', 248, 0, 'Warm the oven'),
  called('blind.lower', 'house', 205, 190, 'Close the blinds'),
  called('hose.run', 'yard', 163, 170, 'Water the beds'),
  called('fan.spin', 'house', 121, 95, 'Move the air'),
  called('clock.chime', 'house', 88, 91, 'Ring the hour'),
  called('sink.drain', 'kitchen', 47, 40, 'Empty the sink'),
  called('shed.lock', 'yard', 0, 3, 'Lock the shed'),
  called('attic.vent', 'house', 0, 0, 'Air the attic'),
];

/** Frame 48s: its six ranked rows (server = the frame's group), padded to 1,284 tools on 28 servers. */
function frame48sTools() {
  const drawn = [
    called('web.search', 'Search and web', 612, 561),
    called('fs.read_file', 'Developer tools', 540, 529),
    called('tavily.search', 'Search and web', 388, 359),
    called('context7.get_docs', 'Developer tools', 301, 301),
    called('memory.search', 'Productivity', 264, 269),
    called('http.get', 'Search and web', 214, 189),
  ];
  const rest = Array.from({ length: 1284 - drawn.length }, (_, i) => called(`zz_quiet_${i}`, `zz_group_${i % 25}`, 0, 0));
  return [...drawn, ...rest];
}

const mostCalledRows = (page) => page.getByRole('region', { name: 'Most called tools', exact: true }).locator('tbody tr');

export const SCREENS = [
  {
    id: 'tools',
    states: [
      {
        name: 'most-called',
        action: 'the ranked rows painting',
        async step(page, tools = TOOLS_SMALL) {
          await serveTools(page, tools);
          await page.goto('/ui/tools/status');
          await expect(mostCalledRows(page).first()).toBeVisible();
          await settled(page);
        },
      },
    ],
    journeys: [
      {
        // One path: the sidebar, a ranked row, its page, Try with that tool, the answer, then Back.
        name: 'J-most-called',
        async step(page) {
          await serveTools(page, TOOLS_SMALL);
          await page.route('**/ui/api/tools/call', async (route) => route.fulfill({ json: {
            disposition: 'ran', latency_ms: 37, result: { content: [{ type: 'text', text: 'gate is open' }] },
          } }));
          await page.goto('/ui/overview/status');
          await settled(page);
          await page.locator('nav.route-nav').getByRole('link', { name: 'Tools', exact: true }).click();
          await expect(page).toHaveURL('/ui/tools/status');
          await mostCalledRows(page).getByRole('link', { name: 'gate.open', exact: true }).click();
          await expect(page).toHaveURL('/ui/tools/yard%3Agate.open/status');
          await expect(page.getByRole('heading', { level: 2, name: 'gate.open', exact: true })).toBeVisible();
          // The tool page has no Try link: Try lives on the Actions tab, with its own picker.
          await page.getByRole('link', { name: 'Actions', exact: true }).click();
          await page.getByLabel('Tool', { exact: true }).selectOption({ label: 'gate.open yard · reads only' });
          await page.getByRole('button', { name: 'Run gate.open', exact: true }).click();
          const answer = page.locator('.tools-try-answer');
          await expect(answer.locator('p').first()).toHaveText('Answered in 37 ms');
          await expect(answer.locator('pre')).toHaveText('gate is open');
          await page.goBack();
          await expect(page).toHaveURL('/ui/tools/yard%3Agate.open/status');
          await page.goBack();
          await expect(page).toHaveURL('/ui/tools/status');
          await expect(mostCalledRows(page)).toHaveCount(10);
        },
      },
    ],
    frames: [
      {
        file: '48s-tools-status.png', width: 1440, height: 1000, scheme: 'dark', state: 'most-called', tools: frame48sTools(),
        regions: [
          ['toolbar', 256, 200, 1160, 50, 0.105, 'the search box is drawn 640 px wide where the frame has 320'],
          // Measured 4.96% masked and 5.79% with the mask removed, so the ceiling catches a lost mask.
          ['list', 256, 258, 1160, 330, 0.052, 'the column is Server, further left, where the frame has Group; '
            + 'table.t draws uppercase headings; a See all link sits beside the heading'],
        ],
        // The live band of every row: call counts, the frame's sparklines, the change words.
        masks: [[1030, 337, 386, 248]],
      },
    ],
  },
];
