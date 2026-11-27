// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The stub's silent mode as a unit (part C, C-H4; Q1 proves it through the gateway): with the flag file beside its
// log the stub still logs each line but answers nothing, and it keeps running; without the flag it answers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { STUB } from './seeds.mjs';

/** The next stdout line from the stub, or null when none comes within `ms`. */
function nextLine(child, ms) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => { child.stdout.off('data', on); resolve(null); }, ms);
    function on(chunk) { clearTimeout(timer); child.stdout.off('data', on); resolve(String(chunk).trim()); }
    child.stdout.on('data', on);
  });
}

test('Q1 unit: silenced, the stub logs the call, answers nothing and keeps running; unsilenced it answers', async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'jh-stub-'));
  const log = path.join(home, 'stub-tide.log');
  const flag = path.join(home, 'stub-tide.silent');
  const child = spawn(process.execPath, [STUB, log], { stdio: ['pipe', 'pipe', 'inherit'] });
  const send = (id) => child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'tide_table' } })}\n`);
  try {
    send(1);
    assert.match(await nextLine(child, 2000) ?? '', /tide-answered/, 'the unsilenced stub did not answer');
    await writeFile(flag, '');
    send(2);
    assert.equal(await nextLine(child, 700), null, 'the silenced stub answered');
    assert.equal(child.exitCode, null, 'the silenced stub exited');
    assert.match(await readFile(log, 'utf8'), /"id":2/, 'the silenced stub did not log the call');
    await rm(flag);
    send(3);
    assert.match(await nextLine(child, 2000) ?? '', /"id":3/, 'the stub did not answer again once unsilenced');
  } finally {
    child.kill();
    await rm(home, { recursive: true, force: true });
  }
});
