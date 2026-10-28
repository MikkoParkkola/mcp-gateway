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
  // (`npx playwright test --project=visual`). CI runs only `chromium`.
  projects: [
    { name: 'chromium', testDir: 'tests', use: { ...devices['Desktop Chrome'] } },
    { name: 'visual', testDir: 'visual', testMatch: '*.visual.mjs', use: { ...devices['Desktop Chrome'] } },
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
