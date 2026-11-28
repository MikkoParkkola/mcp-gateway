// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Planted for row H10: a test that FAILS after its gateway started. It records the gateway's pid and port to the
// file meta names in JH_PLANT_RECORD, so meta can check the gateway is gone after the run.
import { appendFileSync } from 'node:fs';
import { test, expect } from '../gateway.mjs';

test('planted: fails with a running gateway', async ({ gw }) => {
  appendFileSync(process.env.JH_PLANT_RECORD, `${JSON.stringify({ pid: gw.pid, port: gw.port })}\n`);
  expect('planted failure').toBe('a passing test');
});
