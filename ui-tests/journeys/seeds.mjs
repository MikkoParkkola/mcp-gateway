// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Seed classes (HARNESS.4). Every seed starts from `mcp-gateway init`'s starter config, which the harness
// has already written (design ITEM P1), and appends what its class needs. Each returns the stub servers it started
// and, where the state needs the gateway running, a `ready(gw, deadline)` that proves the state exists.
import { appendFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const STUB = join(dirname(fileURLToPath(import.meta.url)), 'stub-mcp.mjs');

/** One stdio stub server per name; each logs every request to <home>/stub-<name>.log. */
function backends(home, names) {
  const lines = names.map((n) => `  ${n}:\n    command: "${process.execPath} ${STUB} ${join(home, `stub-${n}.log`)}"\n`);
  return `\nbackends:\n${lines.join('')}`;
}

const SEEDS = {
  // A fresh install: init's starter config and nothing else.
  fresh: async ({ configPath, marker }) => {
    await appendFile(configPath, `\nenvironment: ${marker}\n`);
    return { stubs: [] };
  },
  // A populated gateway: two stub MCP servers this test starts.
  populated: async ({ home, configPath, marker }) => {
    const stubs = ['tide', 'harbour'];
    await appendFile(configPath, `\nenvironment: ${marker}\n${backends(home, stubs)}`);
    return { stubs };
  },
  // For the harness's own row H11 only: a config the gateway refuses, so it never becomes healthy.
  'refused-config': async ({ configPath }) => {
    await writeFile(configPath, 'server: [unterminated\n', { mode: 0o600 });
    return { stubs: [] };
  },
};

export async function applySeed(name, ctx) {
  const seed = SEEDS[name];
  if (!seed) throw new Error(`unknown seed class ${name}: one of ${Object.keys(SEEDS).join(', ')}`);
  return seed(ctx);
}
