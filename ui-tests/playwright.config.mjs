// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Chromium only, against the fixture server (server.mjs). Every test also
// refuses requests to any host but the fixture server (tests/base.mjs).
import { defineConfig, devices } from '@playwright/test';

const PORT = 4173;

export default defineConfig({
  testDir: 'tests',
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'node server.mjs',
    url: `http://127.0.0.1:${PORT}/ui/classic`,
    env: { PORT: String(PORT) },
    reuseExistingServer: !process.env.CI,
  },
});
