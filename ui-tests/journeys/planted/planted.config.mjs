// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Used ONLY by journeys/meta.test.mjs (row H10): two planted tests that fail and time out on purpose, so meta can
// prove the harness stops their gateways. The journeys project never matches these files (*.planted.mjs).
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: '*.planted.mjs',
  timeout: 60_000,
  retries: 0,
  reporter: 'list',
});
