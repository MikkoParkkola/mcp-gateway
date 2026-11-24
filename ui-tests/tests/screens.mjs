// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The screen table the screen gates loop over (screen-gates.spec.mjs) and the
// visual project draws from (visual/shell.visual.mjs). A screen ticket adds its
// entry here; it writes no gate code of its own.
//
// An entry:
//   id        the sidebar page id
//   states    [{ name, action, act?, trap?, step(page, data?) }]: step mocks the API and
//             drives the page until the state is settled; `action` names the
//             state's main motion (G4) and `act`, when present, performs it after
//             the step. `trap(page)`, for a state that opens a modal surface, is
//             that surface's locator: the keyboard walk must stay inside it. A step
//             takes its fixture (`data`) as an argument with a small default, so a
//             frame can pass the data its picture was drawn with.
//   journeys  [{ name, step(page) }]: starts at the sidebar, ends on an asserted outcome
//   frames    [{ file, width, height, scheme, state, data?, regions, masks }]:
//             regions as [name, x, y, w, h, ceiling?, cause?]; masks as
//             [x, y, w, h], painted one colour on both images and left out of the ratio
//   frames_deferred  a non-blank string saying why `frames` is still [], given only then
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
    // Only animations that end are waited for: an endless one is G4's to name, not a hang here.
    const ending = document.getAnimations().filter((a) => a.effect?.getComputedTiming().endTime !== Infinity);
    await Promise.all(ending.map((a) => a.finished.catch(() => {})));
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

// The catalogue step opens the row a fixture marks `open`; by default one with a real schema.
const TOOLS_CATALOGUE = TOOLS_SMALL.map((t) => (t.name !== 'kettle.boil' ? t : {
  ...t, open: true, schema: { type: 'object', properties: { celsius: { type: 'integer', default: 95 } } },
}));

/** The tools frame 48q draws, then filler to its totals. */
function frameTools() {
  const drawn = [
    ['aws.describe_instances', 'aws', 'List EC2 instances with state and tags'],
    ['aws.get_object', 'aws', 'Read an object from an S3 bucket'],
    ['context7.get_docs', 'context7', 'Fetch current documentation for a library'],
    ['docker.list_containers', 'docker', 'List containers and their state'],
    ['filesystem.list_dir', 'filesystem', 'List a folder inside the allowed paths'],
    ['filesystem.read_file', 'filesystem', 'Read a text file inside the allowed paths'],
  ].map(([name, server, description]) => ({ name, server, description, class: 'read', class_source: 'declared',
    schema: name === 'filesystem.list_dir'
      ? { type: 'object', properties: { path: { type: 'string', description: 'Folder to list' }, depth: { type: 'integer', default: 1 } }, required: ['path'] }
      : { type: 'object' } }));
  const filler = Array.from({ length: 1284 - drawn.length }, (_, i) => ({
    name: `zz_filler_${i}`, server: `zz_server_${i % 24}`, description: 'Filler', class: 'read', class_source: 'declared', schema: {},
  }));
  return [...drawn, ...filler];
}

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

// ---- Try a tool (Tools › Actions) ----

const tryTool = (name, cls, schema = {}) => ({
  name, server: 'maps', description: `The ${name} tool`, class: cls, class_source: 'declared', schema,
});

// Listed in this order: Try keeps the API's order and starts on the first.
const TRY_TOOLS = [
  tryTool('atlas.lookup', 'read', { type: 'object', properties: {
    place: { type: 'string', description: 'Where to look' }, limit: { type: 'integer', default: 3 },
  } }),
  tryTool('atlas.nearby', 'read'),
  tryTool('atlas.pin', 'write'),
];

const ranText = (ms, text) => ({ json: { disposition: 'ran', latency_ms: ms, result: { content: [{ type: 'text', text }] } } });
const refusal = (status, error, message, disposition) => ({
  status, json: disposition ? { error, message, disposition } : { error, message },
});

// The ten answer kinds Try draws, a closed list (design section 4): name -> the call's
// reply, the first line the panel must show, and the detail it must show under it (the
// answer text or the gateway's message; none when the gateway never answered).
const ANSWER_KINDS = {
  ran: [ranText(64, 'Two places found'), 'Answered in 64 ms', 'Two places found'],
  'is-error': [{ json: { ...ranText(64, 'lookup service down').json, is_error: true } }, 'The tool answered with an error', 'lookup service down'],
  blocked: [refusal(403, 'refused', 'a rule stopped this call', 'not_run'), 'Blocked', 'a rule stopped this call'],
  'bad-request': [refusal(400, 'bad_request', 'limit is not a number'), 'Not run', 'limit is not a number'],
  missing: [refusal(404, 'not_found', 'that tool is gone'), 'Not run', 'that tool is gone'],
  failed: [refusal(500, 'failed', 'the call broke after it left', 'may_have_run'), 'The tool may have run', 'the call broke after it left'],
  deadline: [refusal(504, 'deadline', 'no answer in time', 'may_have_run'), 'Timed out; the tool may still be running', 'no answer in time'],
  'audit-not-run': [refusal(503, 'audit_unavailable', 'the audit log is unavailable', 'not_run'), 'Not run', 'the audit log is unavailable'],
  'audit-may': [refusal(503, 'audit_unavailable', 'the audit log is unavailable', 'may_have_run'), 'The tool may have run', 'the audit log is unavailable'],
  'no-answer': [{ abort: true }, 'No answer from the gateway; the tool may have run', null],
};

const tryPanel = (page) => page.locator('section.tools-try');
const tryAnswer = (page) => page.locator('.tools-try-answer');
const runButton = (page, name) => page.getByRole('button', { name: `Run ${name}`, exact: true });

/**
 * Open Tools › Actions with `data` = { tools, pick?, fill?, reply?, receipt? }:
 * pick names the tool to choose, fill maps field labels to values, reply answers the
 * call ({ status?, json } or { abort: true }), and receipt = { account, results? }
 * makes the call findable in Activity as row "row-7". `via` is 'address' (go straight
 * to the tab) or 'sidebar' (start on Overview, then Tools in the sidebar, then Actions).
 */
async function openTry(page, data, via = 'address') {
  await serveTools(page, data.tools);
  const calls = [];
  await page.route('**/ui/api/tools/call', async (route) => {
    calls.push(route.request().postDataJSON());
    const reply = data.reply ?? ANSWER_KINDS.ran[0];
    if (reply.abort) return route.abort('failed');
    const json = data.receipt ? { ...reply.json, receipt: 'trace-7' } : reply.json;
    return route.fulfill({ status: reply.status ?? 200, json });
  });
  if (data.receipt) {
    await page.route('**/ui/api/activity**', async (route) => {
      const url = new URL(route.request().url());
      if (url.searchParams.get('q') === 'trace-7') {
        return route.fulfill({ json: { rows: [{ id: 'row-7', trace_id: 'trace-7', who: { account: data.receipt.account } }] } });
      }
      return route.fulfill({ json: { answer: { records: [{ findings_listed: 0 }] } } });
    });
  }
  if (via === 'sidebar') {
    await page.goto('/ui/overview/status');
    await settled(page);
    await page.locator('nav.route-nav').getByRole('link', { name: 'Tools', exact: true }).click();
    await expect(page).toHaveURL('/ui/tools/status');
    await page.getByRole('link', { name: 'Actions', exact: true }).click();
    await expect(page).toHaveURL('/ui/tools/actions');
  } else {
    await page.goto('/ui/tools/actions');
  }
  const name = data.pick ?? data.tools[0].name;
  if (data.pick) await page.getByLabel('Tool', { exact: true }).selectOption({ label: optionLabel(data.tools, name) });
  for (const [label, value] of Object.entries(data.fill ?? {})) await page.getByLabel(label, { exact: true }).fill(value);
  await expect(runButton(page, name)).toBeVisible();
  return { name, calls };
}

/** The picker's label for a tool, as Try writes it: name, server, and what it may do. */
function optionLabel(tools, name) {
  const t = tools.find((x) => x.name === name);
  return `${t.name} ${t.server} · ${t.class === 'read' ? 'reads only' : 'writes'}`;
}

/**
 * Run the picked tool and wait for the answer's first line (and `detail` under it, when
 * given). The one call sent must name the picked tool and carry every filled value.
 */
async function runAndAnswer(page, data, headline, detail = null) {
  const { name, calls } = await openTry(page, data);
  await runButton(page, name).click();
  await expect(tryAnswer(page).locator('p').first()).toHaveText(headline);
  if (detail) await expect(tryAnswer(page)).toContainText(detail);
  if (data.receipt) await expect(tryAnswer(page)).toContainText(`Recorded in Activity as a call by ${data.receipt.account}`);
  const tool = data.tools.find((t) => t.name === name);
  expect(calls).toHaveLength(1);
  expect(calls[0]).toMatchObject({ server: tool.server, tool: name, confirm_write: false, arguments: data.fill ?? {} });
  await settled(page);
}

const answeredStates = Object.entries(ANSWER_KINDS).map(([kind, [reply, headline, detail]]) => ({
  name: `try-answered-${kind}`,
  action: 'Run',
  async step(page, data = { tools: TRY_TOOLS, reply }) {
    // A frame passes its own reply and headline; the kind's detail then belongs to the default reply only.
    if (data.headline) await runAndAnswer(page, data, data.headline);
    else await runAndAnswer(page, data, headline, detail);
  },
}));

/** Frame 48: web.search first, the frame's query and answer, recorded by mikko; 1,284 tools on 28 servers. */
function frame48Data() {
  const search = tryTool('web.search', 'read', { type: 'object', properties: {
    query: { type: 'string' }, max_results: { type: 'integer', default: 5 },
  } });
  const rest = Array.from({ length: 1283 }, (_, i) => ({ ...tryTool(`zz_try_${i}`, 'read'), server: `zz_group_${i % 27}` }));
  return {
    tools: [{ ...search, server: 'Search and web' }, ...rest],
    fill: { query: 'mcp gateway prompt injection' },
    reply: ranText(212, '[{"title": "Prompt injection in tool answers", "url": "https://…"},\n'
      + ' {"title": "Securing MCP servers behind a gateway", "url": "https://…"}, …]'),
    receipt: { account: 'mikko' },
    headline: 'Answered in 212 ms',
  };
}

/** Frame 48f: filesystem.list_dir first, path ~/Documents, recorded by "you"; 39 tools on 3 servers. */
function frame48fData() {
  const list = tryTool('filesystem.list_dir', 'read', { type: 'object', properties: {
    path: { type: 'string' }, depth: { type: 'integer', default: 1 },
  } });
  const rest = Array.from({ length: 38 }, (_, i) => ({ ...tryTool(`zz_first_${i}`, 'read'), server: ['Developer tools', 'Productivity', 'Search and web'][i % 3] }));
  return {
    tools: [{ ...list, server: 'Developer tools' }, ...rest],
    fill: { path: '~/Documents' },
    reply: ranText(18, '["Invoices/", "Notes/", "plan.md", …]'),
    receipt: { account: 'you' },
    headline: 'Answered in 18 ms',
  };
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
      {
        name: 'catalogue-open-row',
        action: 'opening the row',
        async step(page, tools = TOOLS_CATALOGUE) {
          await serveTools(page, tools);
          await page.goto('/ui/tools/status?view=all');
          const toggle = page.getByRole('button', { name: tools.find((t) => t.open).name, exact: true });
          await toggle.click();
          await expect(toggle).toHaveAttribute('aria-expanded', 'true');
          await settled(page);
        },
      },
      {
        name: 'try-form',
        action: 'picking another tool',
        async step(page, data = { tools: TRY_TOOLS }) {
          await openTry(page, data);
          await settled(page);
        },
        async act(page) {
          await page.getByLabel('Tool', { exact: true }).selectOption({ label: optionLabel(TRY_TOOLS, 'atlas.nearby') });
          await expect(runButton(page, 'atlas.nearby')).toBeVisible();
        },
      },
      ...answeredStates,
      {
        name: 'try-confirm',
        action: 'opening the confirm',
        trap: (page) => page.locator('dialog.confirm'),
        async step(page, data = { tools: TRY_TOOLS, pick: 'atlas.pin' }) {
          const { name } = await openTry(page, data);
          await runButton(page, name).click();
          await expect(page.locator('dialog.confirm')).toBeVisible();
          await settled(page);
        },
      },
      {
        // No key exists yet: the call is recorded as made by "you" (the one-time sign-in link).
        name: 'try-first-run',
        action: 'Run',
        async step(page, data = { tools: TRY_TOOLS, fill: { place: 'harbour' }, receipt: { account: 'you' } }) {
          await runAndAnswer(page, data, data.headline ?? 'Answered in 64 ms');
        },
      },
    ],
    journeys: [
      {
        // One path: the sidebar, a ranked row, its page, Try with that tool, the answer, then Back.
        name: 'J-most-called',
        async step(page) {
          await serveTools(page, TOOLS_SMALL);
          const calls = [];
          await page.route('**/ui/api/tools/call', async (route) => {
            calls.push(route.request().postDataJSON());
            return route.fulfill({ json: {
              disposition: 'ran', latency_ms: 37, result: { content: [{ type: 'text', text: 'gate is open' }] },
            } });
          });
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
          expect(calls).toEqual([{ server: 'yard', tool: 'gate.open', arguments: {}, confirm_write: false }]);
          await page.goBack();
          await expect(page).toHaveURL('/ui/tools/yard%3Agate.open/status');
          await page.goBack();
          await expect(page).toHaveURL('/ui/tools/status');
          await expect(mostCalledRows(page)).toHaveCount(10);
        },
      },
      {
        // The sidebar, Actions, a read tool run, its answer, and where Activity will show it.
        name: 'J-try',
        async step(page) {
          const { calls } = await openTry(page, {
            tools: TRY_TOOLS, pick: 'atlas.nearby', reply: ranText(41, 'one cafe nearby'), receipt: { account: 'mikko' },
          }, 'sidebar');
          await runButton(page, 'atlas.nearby').click();
          await expect(tryAnswer(page).locator('p').first()).toHaveText('Answered in 41 ms');
          await expect(tryAnswer(page).locator('pre')).toHaveText('one cafe nearby');
          await expect(tryAnswer(page).getByRole('link', { name: 'Open', exact: true })).toHaveAttribute('href', '/ui/activity/row-7/status');
          expect(calls).toEqual([{ server: 'maps', tool: 'atlas.nearby', arguments: {}, confirm_write: false }]);
        },
      },
      {
        // A write tool asks first; Cancel sends nothing and gives focus back to Run.
        name: 'J-try-write',
        async step(page) {
          const { calls } = await openTry(page, { tools: TRY_TOOLS, pick: 'atlas.pin' }, 'sidebar');
          await runButton(page, 'atlas.pin').click();
          const confirm = page.locator('dialog.confirm');
          await expect(confirm).toBeVisible();
          await confirm.getByRole('button', { name: 'Cancel atlas.pin', exact: true }).click();
          await expect(confirm).toHaveCount(0);
          await expect(runButton(page, 'atlas.pin')).toBeFocused();
          // A call sent after the dialog closed would still be a write: give the page a round
          // trip and two frames to send one, then require that none came.
          await page.evaluate(() => new Promise((ok) => requestAnimationFrame(() => requestAnimationFrame(ok))));
          await page.evaluate(() => null);
          expect(calls).toEqual([]);
        },
      },
    ],
    frames: [
      {
        file: '48s-tools-status.png', width: 1440, height: 1000, scheme: 'dark', state: 'most-called', data: frame48sTools(),
        regions: [
          ['toolbar', 256, 200, 1160, 50, 0.105, 'the search box is drawn 640 px wide where the frame has 320'],
          // Measured 4.96% masked and 5.79% with the mask removed, so the ceiling catches a lost mask.
          ['list', 256, 258, 1160, 330, 0.052, 'the column is Server, further left, where the frame has Group; '
            + 'table.t draws uppercase headings; a See all link sits beside the heading'],
        ],
        // The live band of every row: call counts, the frame's sparklines, the change words.
        masks: [[1030, 337, 386, 248]],
      },
      {
        file: '48q-tools-status-search-results.png', width: 1440, height: 900, scheme: 'dark', state: 'catalogue-open-row',
        // The catalogue step opens the row marked `open`; the frame draws filesystem.list_dir open.
        data: frameTools().map((t) => (t.name === 'filesystem.list_dir' ? { ...t, open: true } : t)),
        regions: [
          ['toolbar', 256, 200, 760, 52, 0.15, 'the server filter is a native select where the frame draws a button; '
            + 'the page search shows no ⌘K hint, since ⌘K belongs to the palette'],
          ['list', 256, 258, 1160, 448, 0.06, 'table.t puts uppercase headings inside the card padding; the open row adds '
            + 'an Open link and the class after "Input schema"; a count line stands where the frame has a scroll footer'],
        ],
        // The fixture reproduces every number the frame shows, so nothing is masked.
        masks: [],
      },
      {
        file: '48-tools-actions-try.png', width: 1440, height: 1000, scheme: 'dark', state: 'try-answered-ran', data: frame48Data(),
        regions: [['try panel', 256, 205, 880, 470, 0.065, 'labels sit above their fields where the frame sets a '
          + 'two-column grid; no Run as row (cut 2026-11-15); the tool choice is a native select; the answer heading is a '
          + 'plain line, not a capitals header with a check mark; the counts line says "1 results" under the receipt']],
        // The fixture shows the frame's own numbers (212 ms, mikko), so nothing needs masking.
        masks: [],
      },
      {
        file: '48f-tools-actions-try-first-run.png', width: 1440, height: 1000, scheme: 'dark', state: 'try-first-run', data: frame48fData(),
        regions: [['try panel', 256, 205, 880, 490, 0.057, 'labels sit above their fields where the frame sets a '
          + 'two-column grid; no Run as row, so no one-time-link line (cut 2026-11-15); the answer heading is a plain line; '
          + 'the counts line says "1 results" where the frame says "14 entries"; Connect a client is a link, not a Step 3 button']],
        // The fixture shows the frame's own numbers (18 ms, "you"), so nothing needs masking.
        masks: [],
      },
    ],
  },
];
