// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The first-paint gate's rules (its design's section 9), on fixture
// reports: no Lighthouse runs here. The live runs happen only on Spark.
// Every expected value is written out in the row.
import { test, expect } from '@playwright/test';
import {
  stats, judge, checkRun, passComplete, drift, busy, controlCheck, exitCode, recalibrationFlag,
} from '../perf/first-paint-lib.mjs';

const URL = 'http://127.0.0.1:4390/ui/overview/status';
const SHELL = 'shell.0123456789ab.js';
const SETTINGS = {
  throttlingMethod: 'devtools',
  throttling: { requestLatencyMs: 562.5, downloadThroughputKbps: 1474.56, uploadThroughputKbps: 675, cpuSlowdownMultiplier: 5.4 },
  formFactor: 'mobile',
  screenEmulation: { mobile: true, width: 412, height: 823, deviceScaleFactor: 1.75, disabled: false },
};
const EXPECTED = { url: URL, shellFile: SHELL, settings: SETTINGS, lighthouseVersion: '13.5.0', chromeVersion: '140.0.7339.16' };

/** One Lighthouse report as the gate reads it; `over` replaces parts to break one thing at a time. */
function report(over = {}) {
  const base = {
    lighthouseVersion: '13.5.0',
    finalDisplayedUrl: URL,
    environment: { benchmarkIndex: 2500, hostUserAgent: 'Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/140.0.7339.16 Safari/537.36' },
    configSettings: structuredClone(SETTINGS),
    audits: {
      'first-contentful-paint': { numericValue: 742.5 },
      'network-requests': { details: { items: [
        { url: URL, statusCode: 200, resourceType: 'Document' },
        { url: `http://127.0.0.1:4390/ui/shell/${SHELL}`, statusCode: 200, resourceType: 'Script' },
      ] } },
    },
  };
  return { ...base, ...over };
}

const TWENTY = [812, 790, 805, 760, 798, 801, 777, 790, 815, 793, 788, 820, 799, 786, 803, 795, 781, 809, 797, 802];

test('R1 budget: a median of 999.9 passes and 1000.0 fails', () => {
  expect(judge({ median: 999.9, baseline: 900 }).verdict).toBe('pass');
  expect(judge({ median: 1000.0, baseline: 900 }).verdict).toBe('fail');
  expect(judge({ median: 1000.0, baseline: 900 }).reasons).toEqual(['budget']);
});

test('R2 warn: 900.0 warns and 899.9 does not', () => {
  expect(judge({ median: 900.0, baseline: 800 }).warn).toBe(true);
  expect(judge({ median: 899.9, baseline: 800 }).warn).toBe(false);
});

test('R3 regression: with baseline 600, a median of 849.9 passes and 850.0 fails', () => {
  expect(judge({ median: 849.9, baseline: 600 }).verdict).toBe('pass');
  expect(judge({ median: 850.0, baseline: 600 })).toEqual({ verdict: 'fail', warn: false, reasons: ['regression'] });
});

test('R4 median and spread from a literal set of 20', () => {
  expect(stats(TWENTY)).toEqual({ median: 797.5, p25: 788, p75: 803, iqr: 15, min: 760, max: 820, range: 60, values: TWENTY });
});

test('R5 faults: each broken report is refused with its own problem', () => {
  expect(checkRun(report(), EXPECTED)).toEqual({ ok: true, fcp: 742.5, index: 2500 });
  const cases = [
    ['no fcp', report({ audits: { ...report().audits, 'first-contentful-paint': {} } }), 'no first-contentful-paint value'],
    ['runtime error', report({ runtimeError: { code: 'NO_FCP' } }), 'runtime error NO_FCP'],
    ['wrong url', report({ finalDisplayedUrl: 'http://127.0.0.1:4390/ui/error' }), 'final URL is not the page'],
    ['404 document', report({ audits: { ...report().audits, 'network-requests': { details: { items: [
      { url: URL, statusCode: 404, resourceType: 'Document' },
      { url: `http://127.0.0.1:4390/ui/shell/${SHELL}`, statusCode: 200, resourceType: 'Script' }] } } } }), 'document answered 404'],
    ['stale shell', report({ audits: { ...report().audits, 'network-requests': { details: { items: [
      { url: URL, statusCode: 200, resourceType: 'Document' },
      { url: 'http://127.0.0.1:4390/ui/shell/shell.ffffffffffff.js', statusCode: 200, resourceType: 'Script' }] } } } }), 'shell module shell.0123456789ab.js not loaded'],
    ['settings', report({ configSettings: { ...structuredClone(SETTINGS), throttlingMethod: 'simulate' } }), 'setting throttlingMethod is simulate, expected devtools'],
    ['lighthouse version', report({ lighthouseVersion: '13.6.0' }), 'Lighthouse 13.6.0, expected 13.5.0'],
    ['chrome version', report({ environment: { ...report().environment, hostUserAgent: 'Mozilla/5.0 HeadlessChrome/141.0.7390.1 Safari/537.36' } }), 'Chrome 141.0.7390.1, expected 140.0.7339.16'],
    ['zero index', report({ environment: { ...report().environment, benchmarkIndex: 0 } }), 'no benchmark index'],
    ['missing index', report({ environment: { hostUserAgent: report().environment.hostUserAgent } }), 'no benchmark index'],
    ['infinite index', report({ environment: { ...report().environment, benchmarkIndex: Infinity } }), 'no benchmark index'],
  ];
  for (const [name, r, problem] of cases) expect(checkRun(r, EXPECTED), name).toEqual({ ok: false, problem });
  expect(passComplete(Array.from({ length: 19 }, () => report()), EXPECTED)).toEqual({ ok: false, problem: '19 valid reports, expected 20' });
  expect(passComplete(Array.from({ length: 20 }, () => report()), EXPECTED).ok).toBe(true);
});

test('R6 control: the plant must show, and must fail when the baseline is the current page', () => {
  expect(controlCheck({ mode: 'nightly', controlMedian: 1049.9, gateMedian: 800, baseline: 900 })).toEqual({ ok: false, problem: 'control 249.9 ms over the gate, expected 250 or more' });
  expect(controlCheck({ mode: 'nightly', controlMedian: 1050, gateMedian: 800, baseline: 900 })).toEqual({ ok: true });
  expect(controlCheck({ mode: 'nightly', controlMedian: 850, gateMedian: 600, baseline: 900 })).toEqual({ ok: true });
  expect(controlCheck({ mode: 'ready', controlMedian: 850, gateMedian: 600, baseline: 900 })).toEqual({ ok: false, problem: 'control did not fail the gate' });
  expect(controlCheck({ mode: 'ready', controlMedian: 1050, gateMedian: 800, baseline: 800 })).toEqual({ ok: true });
});

test('R7 drift: 20.1% over and under refuse, exactly 20.0% judges', () => {
  expect(drift([1201], 1000)).toEqual({ ratio: 0.201, refuse: true });
  expect(drift([799], 1000)).toEqual({ ratio: 0.201, refuse: true });
  expect(drift([1200], 1000)).toEqual({ ratio: 0.2, refuse: false });
  expect(drift([1100, 900, 1000, 1300, 700], 1000)).toEqual({ ratio: 0, refuse: false });
});

test('R8 busy: pressure or load over a threshold refuses; exactly a threshold judges; unreadable is a fault', () => {
  const t = { pressure: 6.0, load1: 3.0 };
  expect(busy([{ pressure: 6.0, load1: 3.0 }, { pressure: 0.5, load1: 1.0 }], t)).toEqual({ refuse: false, fault: false });
  expect(busy([{ pressure: 0.5, load1: 1.0 }, { pressure: 6.01, load1: 1.0 }], t)).toEqual({ refuse: true, fault: false, problem: 'sample 2: pressure 6.01 over 6' });
  expect(busy([{ pressure: 0.5, load1: 3.01 }], t)).toEqual({ refuse: true, fault: false, problem: 'sample 1: load1 3.01 over 3' });
  expect(busy([{ pressure: null, load1: 1.0 }], t)).toEqual({ refuse: false, fault: true, problem: 'sample 1: pressure unreadable' });
  expect(busy([], t)).toEqual({ refuse: false, fault: true, problem: 'no samples' });
});

test('R9 exit precedence: fault 2 > busy 3 > drift 4 > failed 1 > passed 0', () => {
  expect(exitCode({ fault: true, busy: true, drift: true, failed: true })).toBe(2);
  expect(exitCode({ busy: true, drift: true, failed: true })).toBe(3);
  expect(exitCode({ drift: true, failed: true })).toBe(4);
  expect(exitCode({ failed: true })).toBe(1);
  expect(exitCode({})).toBe(0);
});

test('R11 recalibration: a baseline rising 100.0 ms needs sign-off, 99.9 ms does not', () => {
  expect(recalibrationFlag(700, 800)).toEqual({ rise: 100, needsSignoff: true });
  expect(recalibrationFlag(700, 799.9)).toEqual({ rise: 99.9, needsSignoff: false });
  expect(recalibrationFlag(800, 700)).toEqual({ rise: -100, needsSignoff: false });
});
