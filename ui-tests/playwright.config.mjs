// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Chromium only, against the fixture server (server.mjs). Every test also
// refuses requests to any host but the fixture server (tests/base.mjs).
import { defineConfig, devices } from '@playwright/test';

const PORT = Number(process.env.UI_TESTS_PORT ?? 4173);

export default defineConfig({
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
  },
  // `chromium` is the CI gate. `visual` compares against the design frames,
  // which are not in this repository: run it locally with FRAMES_DIR set
  // (`npx playwright test --project=visual`). `perf` measures LCP and CLS
  // (`npx playwright test --project=perf`) with tracing off, because a retained
  // trace would run inside every sample. CI runs `chromium` and also `perf`;
  // in `perf` an LCP miss fails the job and a CLS miss is reported only.
  projects: [
    { name: 'chromium', testDir: 'tests', use: { ...devices['Desktop Chrome'] } },
    { name: 'visual', testDir: 'visual', testMatch: '*.visual.mjs', use: { ...devices['Desktop Chrome'] } },
    { name: 'perf', testDir: 'perf', testMatch: '*.perf.mjs', use: { ...devices['Desktop Chrome'], trace: 'off' } },
    // The real gateway binary per test: JOURNEYS_GATEWAY_BIN names a debug build; unset fails the run.
    // A test's own start (two inits, the start, the home proofs) can take seconds, so it gets more than the default.
    { name: 'journeys', testDir: 'journeys', testMatch: '*.journey.mjs', timeout: 90_000, use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'node server.mjs',
    url: `http://127.0.0.1:${PORT}/ui/classic`,
    env: { PORT: String(PORT) },
    // Never attach to a server this run did not start: one left on the port by
    // another worktree would serve that worktree's shell. A busy port fails the
    // run; lanes running side by side set their own UI_TESTS_PORT.
    reuseExistingServer: false,
  },
});
