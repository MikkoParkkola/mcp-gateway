// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The first-paint gate's judgement, as pure functions over Lighthouse reports
// and host samples, so every rule is a unit row (tests/first-paint-gate.spec.mjs).
// The Spark runner (first-paint.mjs) only gathers the inputs and calls these.
// Comparisons use unrounded milliseconds; nothing here rounds before judging.

export const BUDGET_MS = 1000;
export const WARN_MS = 900;
export const MARGIN_MS = 250;
export const MARGIN_CEILING_MS = 290;
export const DRIFT_LIMIT = 0.2;
export const RUNS = 20;
export const SIDE_RUNS = 5;
export const NIGHTLY_MAX_AGE_MS = 26 * 3600 * 1000;

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
export function judge({ median, baseline, margin }) {
  const reasons = [];
  if (median >= BUDGET_MS) reasons.push('budget');
  if (baseline != null && median >= baseline + margin) reasons.push('regression');
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

/** A pass needs exactly its table count of valid reports (RUNS for the gates and the control, SIDE_RUNS for the rest). */
export function passComplete(reports, expected, count) {
  const checked = reports.map((r) => checkRun(r, expected));
  const firstBad = checked.find((c) => !c.ok);
  if (firstBad) return { ok: false, problem: firstBad.problem };
  if (checked.length !== count) return { ok: false, problem: `${checked.length} valid reports, expected ${count}` };
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
 * The planted slowdown must show (the control at least the margin over the same round's gate), and,
 * in proof mode (calibration and this ticket's READY, when the baseline is the current page), must fail the gate's rules.
 * Every later run is in gate mode, so an improved page never turns the control into a permanent fault.
 */
export function controlCheck({ mode, controlMedian, gateMedian, baseline, margin }) {
  const over = controlMedian - gateMedian;
  if (over < margin) {
    return { ok: false, problem: `control ${Math.round(over * 10) / 10} ms over the gate, expected ${margin} or more` };
  }
  if (mode === 'proof' && judge({ median: controlMedian, baseline, margin }).verdict !== 'fail') {
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

/** Any rise of the baseline in a recalibration needs the lead's sign-off, so small rises cannot ratchet it up. */
export function recalibrationFlag(oldBaseline, newBaseline) {
  const rise = Math.round((newBaseline - oldBaseline) * 10) / 10;
  return { rise, needsSignoff: newBaseline > oldBaseline };
}

/**
 * The regression margin from the calibration's five gate-mobile medians: MARGIN_MS while it is at least 3x their
 * spread (max - min), else 3x the spread rounded up to 10 ms; over MARGIN_CEILING_MS refuses, because the 300 ms
 * control could no longer be told from noise.
 */
export function marginFromSpread(medians) {
  const spread = Math.max(...medians) - Math.min(...medians);
  const widened = 3 * spread > MARGIN_MS;
  const margin = widened ? Math.ceil((3 * spread) / 10) * 10 : MARGIN_MS;
  return { spread, margin, widened, refuse: margin > MARGIN_CEILING_MS };
}

/**
 * At READY: no nightly record, or a newest one older than NIGHTLY_MAX_AGE_MS, blocks ("nightly missed").
 * A newest nightly that did not exit 0 does not block (that would also stop the PR fixing it); it returns a banner.
 */
export function nightlyCheck(record, nowMs) {
  if (!record) return { ok: false, problem: 'nightly missed: no record' };
  if (nowMs - Date.parse(record.timestamp) > NIGHTLY_MAX_AGE_MS) {
    return { ok: false, problem: `nightly missed: last run ${record.timestamp}` };
  }
  const banner = record.exit === 0 ? null : `NIGHTLY FAILED: exit ${record.exit} at ${record.timestamp} on ${record.sha}`;
  return { ok: true, banner };
}

/** The verdict binds to the commit it names: HEAD must be the expected SHA and `git status --porcelain` empty. */
export function treeCheck({ head, expected, porcelain }) {
  if (head !== expected) return `HEAD ${head} is not the expected ${expected}`;
  const first = porcelain.split('\n').find((l) => l !== '');
  return first === undefined ? null : `tree not clean: ${first}`;
}
