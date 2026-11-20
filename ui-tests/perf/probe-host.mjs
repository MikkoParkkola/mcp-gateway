// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Throwaway host probe, never merged: on one hosted runner, what can the
// first-paint gate's busy check read, which CPU is this, and how far apart are
// the benchmark indices of 20 unthrottled runs of the real page. Uses the
// gate's own server, Lighthouse run, sampler and unthrottled settings.
import { readFileSync } from 'node:fs';
import { cpus } from 'node:os';
import { startServer, lighthouseRun, startSampler } from './first-paint.mjs';
import { passSettings, stats } from './first-paint-lib.mjs';

const RUN_COUNT = 20;

function fileOrReason(path) {
  try {
    return readFileSync(path, 'utf8').trim().replace(/\n/g, ' | ');
  } catch (e) {
    return `unreadable (${e.code ?? e.message})`;
  }
}

const cores = cpus();
console.log(`probe cpu: ${cores[0]?.model ?? 'unknown'}, ${cores.length} logical cores`);
console.log(`probe pressure file: ${fileOrReason('/proc/pressure/cpu')}`);
console.log(`probe loadavg file: ${fileOrReason('/proc/loadavg')}`);

const { screenEmulationMetrics } = await import('lighthouse/core/config/constants.js');
const settings = passSettings('unthrottled', { screens: { mobile: screenEmulationMetrics.mobile } });
const server = await startServer([]);
const sampler = startSampler();
const indices = [];
const firstPaints = [];
try {
  for (let run = 1; run <= RUN_COUNT; run += 1) {
    const report = await lighthouseRun(server.url, settings);
    const index = report?.environment?.benchmarkIndex;
    const fcp = report?.audits?.['first-contentful-paint']?.numericValue;
    const problem = report?.runtimeError?.code ?? '';
    console.log(`probe run ${run}: benchmarkIndex ${index} fcp ${fcp} ${problem}`.trim());
    if (Number.isFinite(index)) indices.push(index);
    if (Number.isFinite(fcp)) firstPaints.push(fcp);
  }
} finally {
  sampler.stop();
  server.stop();
}

const summary = (values) => {
  if (values.length === 0) return 'none';
  const { median, min, max, range } = stats(values);
  return `n ${values.length}, median ${median}, min ${min}, max ${max}, range ${range}, range/median ${(range / median).toFixed(3)}`;
};
const seen = (key) => sampler.samples.map((s) => s[key]).filter((v) => v != null);
const peak = (key) => (seen(key).length ? Math.max(...seen(key)) : 'unreadable');
console.log(`probe index: ${summary(indices)}`);
console.log(`probe fcp unthrottled: ${summary(firstPaints)}`);
console.log(`probe samples: ${sampler.samples.length}, pressure peak ${peak('pressure')}, load1 peak ${peak('load1')}`);
