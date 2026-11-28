// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// R6 and the C-H1 command check as units (part C design, "The harness contract"): the start command the gateway
// shows is `'<exe>' serve --config '<config>'`, each path one POSIX single-quoted word whose apostrophes the gateway
// writes as '\''. parseStartCommand splits it with no shell; checkStartArgv accepts only the gateway's four words
// naming this test's own binary and config. Both throw, naming the offending token, and nothing runs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, realpath, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { checkStartArgv, parseStartCommand } from './gateway.mjs';

test('R6 the gateway\'s own form splits into its four words', () => {
  assert.deepEqual(parseStartCommand("'/opt/gw/mcp-gateway' serve --config '/tmp/h/gateway.yaml'"),
    ['/opt/gw/mcp-gateway', 'serve', '--config', '/tmp/h/gateway.yaml']);
  assert.deepEqual(parseStartCommand("  '/a b/gw' serve --config '/c d/g.yaml'  "), ['/a b/gw', 'serve', '--config', '/c d/g.yaml']);
});

test('R6 the apostrophe form between quoted runs is one word with an apostrophe', () => {
  assert.deepEqual(parseStartCommand("'/tmp/it'\\''s/gw' serve --config '/c'"), ["/tmp/it's/gw", 'serve', '--config', '/c']);
  assert.deepEqual(parseStartCommand("'/a$b' serve --config '/c'")[0], '/a$b', 'a $ inside quotes is a literal');
});

test('R6 an unbalanced quote, any other backslash, a $ outside quotes or anything after the words is refused', () => {
  const refused = {
    "'/opt/gw serve --config '/c'": /unbalanced/,
    "'/opt/gw' serve --config '/c": /unbalanced/,
    '/opt/gw\\ x serve --config /c': /backslash/,
    "'/a'\\x serve": /backslash/,
    "\\''/a' serve": /backslash/,
    "'/a'\\'' serve": /unbalanced/,
    "$HOME/gw serve --config '/c'": /\$/,
    "'/opt/gw' serve --config '/c'; rm x": /;/,
    "'/opt/gw' serve --config '/c' && x": /&/,
    "'/opt/gw' serve --config '/c' | x": /\|/,
    "'/opt/gw' serve --config `x`": /`/,
    "\"/opt/gw\" serve": /"/,
    "'/opt/gw' serve\n--config '/c'": /character/,
    '   ': /no command/,
  };
  for (const [text, why] of Object.entries(refused)) {
    assert.throws(() => parseStartCommand(text), why, `not refused: ${JSON.stringify(text)}`);
  }
});

async function fixture() {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'jh-startcmd-')));
  const bin = join(dir, 'mcp-gateway');
  await writeFile(bin, '#!/bin/sh\n');
  await chmod(bin, 0o755);
  const config = join(dir, 'gateway.yaml');
  await writeFile(config, 'server: {}\n');
  const other = join(dir, 'other.yaml');
  await writeFile(other, 'server: {}\n');
  const alias = join(dir, 'alias-gateway');
  await symlink(bin, alias);
  return { dir, bin, config, other, alias };
}

test('C-H1 the check accepts the gateway\'s four words and returns the binary\'s real path', async () => {
  const f = await fixture();
  assert.equal(checkStartArgv([f.bin, 'serve', '--config', f.config], { bin: f.bin, configPath: f.config }), f.bin);
});

test('R3b a symlink alias of the real binary is accepted and resolved to the real path', async () => {
  const f = await fixture();
  assert.equal(checkStartArgv([f.alias, 'serve', '--config', f.config], { bin: f.bin, configPath: f.config }), f.bin);
});

test('R1 R1b R2 another binary, a relative path, other words or another file are refused', async () => {
  const f = await fixture();
  const ctx = { bin: f.bin, configPath: f.config };
  const refused = [
    [[process.execPath, 'serve', '--config', f.config], /not this test's gateway binary/],
    [[relative(process.cwd(), f.bin), 'serve', '--config', f.config], /not an absolute path/],
    [[join(f.dir, 'missing'), 'serve', '--config', f.config], /not this test's gateway binary/],
    [[f.bin, 'serve', '--config', f.config, '--extra'], /5 words/],
    [[f.bin, 'serve', '--config'], /3 words/],
    [[f.bin, 'serve', '-c', f.config], /"-c"/],
    [[f.bin, 'run', '--config', f.config], /"run"/],
    [[f.bin, 'serve', '--config', f.other], /not this test's config/],
    [[f.bin, 'serve', '--config', join(f.dir, 'nope.yaml')], /not this test's config/],
  ];
  for (const [argv, why] of refused) {
    assert.throws(() => checkStartArgv(argv, ctx), why, `not refused: ${JSON.stringify(argv)}`);
  }
});
