// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Throwaway host probe, never merged: can one hosted runner carry the first-paint gate?
// On this VM it measures the real page's first paint at the gate's mobile settings
// (devtools throttling, Lighthouse's mobile network values, 4x CPU, the mobile screen),
// 20 samples from the plain server and 20 from the planted one (a 300 ms wall-clock spin
// first in the head), taken one and one. Every sample is a fresh Chrome.
import { cpus } from 'node:os';
import { startServer, lighthouseRun } from './first-paint.mjs';
import { stats } from './first-paint-lib.mjs';

const SAMPLES = 20;
const { screenEmulationMetrics, throttling } = await import('lighthouse/core/config/constants.js');
const settings = {
  throttlingMethod: 'devtools',
  throttling: { ...throttling.mobileSlow4G, cpuSlowdownMultiplier: 4 },
  formFactor: 'mobile',
  screenEmulation: screenEmulationMetrics.mobile,
};

const cpu = cpus()[0]?.model ?? 'unknown';
const t = settings.throttling;
const s = settings.screenEmulation;
console.log(`probe cpu: ${cpu}, ${cpus().length} logical cores`);
console.log(
  `probe settings: latency ${t.requestLatencyMs} ms, down ${t.downloadThroughputKbps} kbps, up ${t.uploadThroughputKbps} kbps, ` +
    `cpu x${t.cpuSlowdownMultiplier}, screen ${s.width}x${s.height} dpr ${s.deviceScaleFactor}`,
);

const firstPaints = { gate: [], planted: [] };
const indices = [];
let faults = 0;
const plain = await startServer([]);
const planted = await startServer(['--plant-first-paint-delay-ms=300']);
try {
  for (let round = 1; round <= SAMPLES; round += 1) {
    for (const [kind, server] of [['gate', plain], ['planted', planted]]) {
      const report = await lighthouseRun(server.url, settings);
      const fcp = report?.audits?.['first-contentful-paint']?.numericValue;
      const index = report?.environment?.benchmarkIndex;
      const problem = report?.runtimeError?.code ?? '';
      console.log(`probe sample ${kind} ${round}: fcp ${fcp} benchmarkIndex ${index} ${problem}`.trim());
      if (problem || !Number.isFinite(fcp) || !Number.isFinite(index)) {
        faults += 1;
        continue;
      }
      firstPaints[kind].push(fcp);
      indices.push(index);
    }
  }
} finally {
  plain.stop();
  planted.stop();
}

const median = (values) => (values.length ? stats(values).median : NaN);
const gate = firstPaints.gate.length ? stats(firstPaints.gate) : null;
const gateMedian = median(firstPaints.gate);
const plantedMedian = median(firstPaints.planted);
const round1 = (v) => Math.round(v * 10) / 10;
console.log(
  `probe result: cpu "${cpu}" | benchmarkIndex median ${round1(median(indices))} | ` +
    `gate n ${firstPaints.gate.length} median ${round1(gateMedian)} min ${gate ? round1(gate.min) : 'none'} max ${gate ? round1(gate.max) : 'none'} | ` +
    `planted n ${firstPaints.planted.length} median ${round1(plantedMedian)} | planted minus gate ${round1(plantedMedian - gateMedian)} | faults ${faults}`,
);
