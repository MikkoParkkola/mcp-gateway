// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The first-paint gate's judgement, as pure functions over Lighthouse reports
// and host samples, so every rule is a unit row (tests/first-paint-gate.spec.mjs).
// The Spark runner (first-paint.mjs) only gathers the inputs and calls these.
// Comparisons use unrounded milliseconds; nothing here rounds before judging.

export const BUDGET_MS = 1000;
export const WARN_MS = 900;
export const REGRESSION_MS = 250;
export const DRIFT_LIMIT = 0.2;
export const RUNS = 20;
export const SIGNOFF_RISE_MS = 100;

/** Median (mean of the two middle values for an even count), nearest-rank p25 and p75, and the spread. */
export function stats(values) {
  const s = [...values].sort((a, b) => a - b);
  const n = s.length;
  const median = n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
  const rank = (q) => s[Math.ceil(q * n) - 1];
  const p25 = rank(0.25);
  const p75 = rank(0.75);
  return { median, p25, p75, iqr: p75 - p25, min: s[0], max: s[n - 1], range: s[n - 1] - s[0], values };
}

/** The gate's two failure rules, and the warning. `baseline` null means the pass has no regression rule (desktop). */
export function judge({ median, baseline }) {
  const reasons = [];
  if (median >= BUDGET_MS) reasons.push('budget');
  if (baseline != null && median >= baseline + REGRESSION_MS) reasons.push('regression');
  return { verdict: reasons.length ? 'fail' : 'pass', warn: median >= WARN_MS, reasons };
}

const chromeOf = (ua) => (/Chrome\/([\d.]+)/.exec(ua ?? '') ?? [])[1];
const positive = (x) => typeof x === 'number' && Number.isFinite(x) && x > 0;

/** Compare the setting `name` in the report with the expected one; null when equal. */
function settingProblem(name, got, want) {
  if (want !== null && typeof want === 'object') {
    for (const [k, v] of Object.entries(want)) {
      const p = settingProblem(`${name}.${k}`, got?.[k], v);
      if (p) return p;
    }
    return null;
  }
  return got === want ? null : `setting ${name} is ${got}, expected ${want}`;
}

/** One run's report: identity, settings and the two numbers the gate reads. Any miss is a fault. */
export function checkRun(report, expected) {
  const bad = (problem) => ({ ok: false, problem });
  if (report.runtimeError) return bad(`runtime error ${report.runtimeError.code}`);
  if (report.finalDisplayedUrl !== expected.url) return bad('final URL is not the page');
  const items = report.audits?.['network-requests']?.details?.items ?? [];
  const doc = items.find((i) => i.resourceType === 'Document' && i.url === expected.url);
  if (!doc || doc.statusCode !== 200) return bad(`document answered ${doc?.statusCode ?? 'nothing'}`);
  const shell = items.find((i) => i.url.endsWith(`/${expected.shellFile}`) && i.statusCode === 200);
  if (!shell) return bad(`shell module ${expected.shellFile} not loaded`);
  for (const key of Object.keys(expected.settings)) {
    const p = settingProblem(key, report.configSettings?.[key], expected.settings[key]);
    if (p) return bad(p);
  }
  if (report.lighthouseVersion !== expected.lighthouseVersion) {
    return bad(`Lighthouse ${report.lighthouseVersion}, expected ${expected.lighthouseVersion}`);
  }
  const chrome = chromeOf(report.environment?.hostUserAgent);
  if (chrome !== expected.chromeVersion) return bad(`Chrome ${chrome}, expected ${expected.chromeVersion}`);
  const fcp = report.audits?.['first-contentful-paint']?.numericValue;
  if (!positive(fcp)) return bad('no first-contentful-paint value');
  const index = report.environment?.benchmarkIndex;
  if (!positive(index)) return bad('no benchmark index');
  return { ok: true, fcp, index };
}

/** A pass needs exactly RUNS valid reports. */
export function passComplete(reports, expected) {
  const checked = reports.map((r) => checkRun(r, expected));
  const firstBad = checked.find((c) => !c.ok);
  if (firstBad) return { ok: false, problem: firstBad.problem };
  if (checked.length !== RUNS) return { ok: false, problem: `${checked.length} valid reports, expected ${RUNS}` };
  return { ok: true, fcps: checked.map((c) => c.fcp), indices: checked.map((c) => c.index) };
}

/** Drift of the median benchmark index from the calibration, both directions; exactly the limit still judges. */
export function drift(indices, calibrationIndex) {
  const { median } = stats(indices);
  const ratio = Math.abs(median - calibrationIndex) / calibrationIndex;
  return { ratio, refuse: ratio > DRIFT_LIMIT };
}

/** Busy host: any sample over a threshold refuses; an unreadable sample is a fault; exactly a threshold judges. */
export function busy(samples, thresholds) {
  if (!samples.length) return { refuse: false, fault: true, problem: 'no samples' };
  for (const [i, s] of samples.entries()) {
    for (const key of ['pressure', 'load1']) {
      if (typeof s[key] !== 'number' || !Number.isFinite(s[key])) {
        return { refuse: false, fault: true, problem: `sample ${i + 1}: ${key} unreadable` };
      }
    }
  }
  for (const [i, s] of samples.entries()) {
    for (const key of ['pressure', 'load1']) {
      if (s[key] > thresholds[key]) {
        return { refuse: true, fault: false, problem: `sample ${i + 1}: ${key} ${s[key]} over ${thresholds[key]}` };
      }
    }
  }
  return { refuse: false, fault: false };
}

/**
 * The planted slowdown must show (the control at least REGRESSION_MS over the same round's gate), and,
 * when the baseline is the current page (calibration and READY), must fail the gate's rules.
 */
export function controlCheck({ mode, controlMedian, gateMedian, baseline }) {
  const over = controlMedian - gateMedian;
  if (over < REGRESSION_MS) {
    return { ok: false, problem: `control ${Math.round(over * 10) / 10} ms over the gate, expected ${REGRESSION_MS} or more` };
  }
  if (mode !== 'nightly' && judge({ median: controlMedian, baseline }).verdict !== 'fail') {
    return { ok: false, problem: 'control did not fail the gate' };
  }
  return { ok: true };
}

/** Exit codes, highest first when several apply: fault 2, busy 3, drift 4, failed 1, passed 0. */
export function exitCode({ fault, busy: isBusy, drift: drifted, failed }) {
  if (fault) return 2;
  if (isBusy) return 3;
  if (drifted) return 4;
  if (failed) return 1;
  return 0;
}

/** A recalibration whose baseline rises SIGNOFF_RISE_MS or more needs the lead's sign-off. */
export function recalibrationFlag(oldBaseline, newBaseline) {
  const rise = Math.round((newBaseline - oldBaseline) * 10) / 10;
  return { rise, needsSignoff: rise >= SIGNOFF_RISE_MS };
}
