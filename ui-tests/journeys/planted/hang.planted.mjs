// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Planted for row H10: a test that TIMES OUT after its gateway started. It records the
// gateway's pid and port to JH_PLANT_RECORD, so meta can check the fixture's teardown still stopped it.
import { appendFileSync } from 'node:fs';
import { test } from '../gateway.mjs';

test('planted: hangs with a running gateway', async ({ gw }) => {
  appendFileSync(process.env.JH_PLANT_RECORD, `${JSON.stringify({ pid: gw.pid, port: gw.port })}\n`);
  await new Promise(() => {}); // the planted config's 60 s test limit times it out, after the gateway is up
});
