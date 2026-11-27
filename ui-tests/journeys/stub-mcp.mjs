// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A minimal stdio MCP server for the journey harness. Usage: node stub-mcp.mjs <log file>.
// Tools: <server>_table (answers "<server>-answered") and <server>_secret, named from the log file stub-<server>.log
// (tide when there is none). Every request line is appended to the log, which
// is the stub's own record of what reached it: a journey reads it outside the browser.
// Silent mode (part C, C-H4): while the flag file beside the log (<home>/stub-<name>.silent) exists, the stub still
// reads and logs every line but answers nothing, and it never exits for it (an exit is a crashed backend).
import { appendFileSync, existsSync } from 'node:fs';
import { basename } from 'node:path';
import { createInterface } from 'node:readline';

const log = process.argv[2];
const silentFlag = log ? log.replace(/\.log$/, '.silent') : null;
// Each stub's tools carry its server's name (stub-<name>.log), so two stubs never serve the same tool.
const server = (log && basename(log).match(/^stub-(.+)\.log$/)?.[1]) || 'tide';
const TOOLS = [
  { name: `${server}_table`, description: `Today's ${server} table`, inputSchema: { type: 'object', properties: {} } },
  { name: `${server}_secret`, description: 'A tool a rule may block', inputSchema: { type: 'object', properties: {} } },
];

function reply(id, result) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, result })}\n`);
}

createInterface({ input: process.stdin }).on('line', (line) => {
  if (log) appendFileSync(log, `${line}\n`);
  if (silentFlag && existsSync(silentFlag)) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.id === undefined) return; // a notification
  if (msg.method === 'initialize') {
    reply(msg.id, { protocolVersion: msg.params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} },
      serverInfo: { name: 'journey-stub', version: '1.0.0' } });
  } else if (msg.method === 'tools/list') {
    reply(msg.id, { tools: TOOLS });
  } else if (msg.method === 'tools/call') {
    const name = msg.params?.name;
    reply(msg.id, { content: [{ type: 'text', text: name === `${server}_table` ? `${server}-answered` : `${name}-answered` }] });
  } else {
    process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'method not found' } })}\n`);
  }
});
