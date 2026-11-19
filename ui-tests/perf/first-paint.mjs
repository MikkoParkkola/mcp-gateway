// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The first-paint gate's runner on Spark. It only gathers:
// server children, Lighthouse runs, host samples. Every judgement is in
// first-paint-lib.mjs, where each rule has a row. Started on Spark by
// first-paint-launch.sh (Mac side: tree check, sync, lock, slot).
//
//   node perf/first-paint.mjs --mode=<nightly|ready|proof|verdicts|calibrate> --sha=<40 hex>

import { spawn, execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { homedir, hostname } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import lighthouse from 'lighthouse';
import { chromium } from '@playwright/test';
import {
  RUNS, SIDE_RUNS, GATE_SCHEDULE, VERDICT_SCHEDULE, busy, judgeJob, passSettings, nightlyCheck, stats, drift,
  marginFromSpread, recalibrationFlag, controlCheck, passComplete, DRIFT_LIMIT,
} from './first-paint-lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const UI_TESTS = join(HERE, '..');
const SHELL_DIR = join(UI_TESTS, '..', 'src', 'gateway', 'ui', 'shell');
export const CONFIG_PATH = join(HERE, 'first-paint.config.json');
const HOME = process.env.FIRST_PAINT_HOME ?? join(homedir(), 'first-paint');
export const NIGHTLY_RECORD = join(HOME, 'nightly.json');
const PAGE = '/ui/overview/status';
const READY_TIMEOUT_MS = 30_000;
const AUDITS = ['first-contentful-paint', 'network-requests'];

/** A fault: the harness, identity or settings went wrong; the gate exits 2 and judges nothing. */
export class Fault extends Error {}

export function parseArgs(argv) {
  const get = (k) => argv.find((a) => a.startsWith(`--${k}=`))?.slice(k.length + 3);
  const mode = get('mode');
  const sha = get('sha');
  if (!['nightly', 'ready', 'proof', 'verdicts', 'calibrate'].includes(mode)) throw new Fault(`--mode is required: nightly, ready, proof, verdicts or calibrate (got ${mode})`);
  if (!/^[0-9a-f]{40}$/.test(sha ?? '')) throw new Fault(`--sha must be a full 40-character commit (got ${sha})`);
  return { mode, sha };
}

/** The shell module the page loads, read from the synced tree's index.html; the file must exist beside it. */
export function shellFile() {
  const doc = readFileSync(join(SHELL_DIR, 'index.html'), 'utf8');
  const m = [...doc.matchAll(/<script type="module" src="\/ui\/assets\/(shell\.[0-9a-f]+\.js)"><\/script>/g)];
  if (m.length !== 1) throw new Fault(`index.html names ${m.length} shell modules, expected 1`);
  if (!existsSync(join(SHELL_DIR, m[0][1]))) throw new Fault(`${m[0][1]} is named by index.html but not in the tree`);
  return m[0][1];
}

/** The config the calibration wrote; every number the gate judges with must be finite and positive. */
export function loadConfig() {
  if (!existsSync(CONFIG_PATH)) throw new Fault(`no config at ${CONFIG_PATH}: run the calibration first`);
  const c = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
  for (const k of ['calibrationIndex', 'multiplier', 'baseline', 'margin']) {
    if (typeof c[k] !== 'number' || !Number.isFinite(c[k]) || c[k] <= 0) throw new Fault(`config ${k} is ${c[k]}, not a finite positive number`);
  }
  for (const k of ['pressure', 'load1']) {
    if (typeof c.thresholds?.[k] !== 'number' || !Number.isFinite(c.thresholds[k])) throw new Fault(`config thresholds.${k} is ${c.thresholds?.[k]}`);
  }
  return c;
}

/** One server.mjs child on a free port; resolves with its URL once it printed its ready line and answered the page 200. */
export async function startServer(extraArgs) {
  const child = spawn(process.execPath, [join(UI_TESTS, 'server.mjs'), '--perf-gate', ...extraArgs], {
    env: { ...process.env, PORT: '0' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (d) => { stderr += d; });
  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Fault(`server gave no ready line in ${READY_TIMEOUT_MS / 1000} s`)), READY_TIMEOUT_MS);
    child.stdout.on('data', (d) => {
      const m = /fixture server on http:\/\/127\.0\.0\.1:(\d+)/.exec(String(d));
      if (m) { clearTimeout(timer); resolve(Number(m[1])); }
    });
    child.on('exit', (code) => { clearTimeout(timer); reject(new Fault(`server exited ${code} before ready: ${stderr.trim()}`)); });
  });
  const url = `http://127.0.0.1:${port}${PAGE}`;
  const res = await fetch(url);
  if (res.status !== 200) { child.kill(); throw new Fault(`server answered the page ${res.status}`); }
  return { url, stop: () => child.kill() };
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
    s.on('error', reject);
  });
}

/** One cold Lighthouse run in a fresh Chrome. A run that throws becomes a report with a runtime error, which checkRun faults. */
export async function lighthouseRun(url, settings) {
  const port = await freePort();
  const browser = await chromium.launch({ args: [`--remote-debugging-port=${port}`] });
  try {
    const result = await lighthouse(url, { port, output: 'json', logLevel: 'error' }, { extends: 'lighthouse:default', settings: { ...settings, onlyAudits: AUDITS } });
    return result?.lhr ?? { runtimeError: { code: 'NO_RESULT' } };
  } catch (e) {
    return { runtimeError: { code: 'LIGHTHOUSE_THREW', message: String(e?.message ?? e) } };
  } finally {
    await browser.close();
  }
}

/** One host sample: CPU pressure (some avg10) and load1; an unreadable value is null, which busy() faults. */
function readSample() {
  const num = (path, re) => {
    try {
      const v = Number(re.exec(readFileSync(path, 'utf8'))?.[1]);
      return Number.isFinite(v) ? v : null;
    } catch {
      return null;
    }
  };
  return { at: new Date().toISOString(), pressure: num('/proc/pressure/cpu', /some avg10=([\d.]+)/), load1: num('/proc/loadavg', /^([\d.]+)/) };
}

/** Samples the host every 10 s, from before the first run to after the last. */
export function startSampler() {
  const samples = [readSample()];
  const id = setInterval(() => samples.push(readSample()), 10_000);
  return { samples, stop: () => { clearInterval(id); samples.push(readSample()); } };
}

// Every round runs each RUNS-count pass once; SIDE_RUNS-count passes run in these rounds only, so the
// drift sample spans the whole job (design section 3).
const ORDER = ['gateMobile', 'gateDesktop', 'control', 'unthrottled', 'simulate'];
const SIDE_ROUNDS = new Set([1, 5, 9, 13, 17]);

/**
 * Runs a schedule interleaved round by round. Before each run the samples so far are judged against `limits`
 * (pressure, load1); any sample over a limit stops the job at once (no further runs start).
 */
export async function gather({ schedule, settings, urls, sampler, limits, log }) {
  for (const n of Object.values(schedule)) if (n !== RUNS && n !== SIDE_RUNS) throw new Fault(`schedule count ${n} is neither ${RUNS} nor ${SIDE_RUNS}`);
  const reports = Object.fromEntries(Object.keys(schedule).map((p) => [p, []]));
  for (let round = 1; round <= RUNS; round += 1) {
    for (const p of ORDER) {
      if (!(p in schedule) || (schedule[p] === SIDE_RUNS && !SIDE_ROUNDS.has(round))) continue;
      if (busy(sampler.samples, limits).refuse) return { reports, stopped: true };
      const lhr = await lighthouseRun(urls[p], settings[p]);
      reports[p].push(lhr);
      log(`round ${round} ${p}: fcp ${lhr.audits?.['first-contentful-paint']?.numericValue ?? '-'} index ${lhr.environment?.benchmarkIndex ?? '-'}${lhr.runtimeError ? ` error ${lhr.runtimeError.code}` : ''}`);
    }
  }
  return { reports, stopped: false };
}

/** What every report of each pass must show (identity, settings, versions). */
export function expectations(schedule, config, urls, shell) {
  const settings = {};
  const expected = {};
  for (const p of Object.keys(schedule)) {
    settings[p] = passSettings(p, config);
    expected[p] = { url: urls[p], shellFile: shell, settings: settings[p], lighthouseVersion: config.lighthouseVersion, chromeVersion: config.chromeVersion };
  }
  return { settings, expected };
}

/** One job: gather under the host sampler, then judge. `controlMode` is 'proof' or 'gate'. */
export async function oneJob({ controlMode, config, schedule, urls, shell, log }) {
  const { settings, expected } = expectations(schedule, config, urls, shell);
  const sampler = startSampler();
  let gathered;
  try {
    gathered = await gather({ schedule, settings, urls, sampler, limits: config.thresholds, log });
  } finally {
    sampler.stop();
  }
  const judged = judgeJob({ mode: controlMode, config, schedule, expected, reports: gathered.reports, samples: sampler.samples, thresholds: config.thresholds });
  return { ...judged, reports: gathered.reports, samples: sampler.samples, stopped: gathered.stopped };
}

export const UI12_9_PASSES = 20;
export const UI12_9_MAX_VERDICTS = 30;

/** UI12.9: verdicts on the unchanged head until 20 pass in a row; any non-pass resets the count. */
export async function consecutiveVerdicts({ config, urls, shell, log }) {
  const verdicts = [];
  let streak = 0;
  while (streak < UI12_9_PASSES && verdicts.length < UI12_9_MAX_VERDICTS) {
    const v = await oneJob({ controlMode: 'gate', config, schedule: VERDICT_SCHEDULE, urls, shell, log });
    streak = v.exit === 0 ? streak + 1 : 0;
    verdicts.push(v);
    log(`verdict ${verdicts.length}: exit ${v.exit}, median ${v.stats.gateMobile?.median ?? '-'}, streak ${streak}${v.problems.length ? `, ${v.problems.join('; ')}` : ''}`);
  }
  const exit = streak >= UI12_9_PASSES ? 0 : [...verdicts].reverse().find((v) => v.exit !== 0)?.exit ?? 1;
  return { exit, streak, verdicts };
}

const MEANING = { 0: 'judged and passed', 1: 'budget or regression failed', 2: 'fault', 3: 'busy host, not judged', 4: 'index drift, recalibrate' };
const ms = (x) => (x == null ? '-' : `${Math.round(x * 10) / 10} ms`);

/** The summary's lines for one job (also printed). */
export function jobLines(job) {
  const out = [];
  for (const [p, s] of Object.entries(job.stats)) {
    const v = job.verdicts[p];
    const tag = v ? ` ${v.verdict}${v.warn ? ' WARN' : ''}${v.reasons.length ? ` (${v.reasons.join(', ')})` : ''}` : ' (recorded only)';
    out.push(`${p}: median ${ms(s.median)}, p25 ${ms(s.p25)}, p75 ${ms(s.p75)}, IQR ${ms(s.iqr)}, min ${ms(s.min)}, max ${ms(s.max)}${tag}`);
  }
  if (job.stats.control && job.stats.gateMobile) out.push(`control over gateMobile: ${ms(job.stats.control.median - job.stats.gateMobile.median)}`);
  if (job.drift) out.push(`index drift ${Math.round(job.drift.ratio * 1000) / 10}% (limit ${DRIFT_LIMIT * 100}%)`);
  const ok = job.samples.filter((s) => s.pressure != null && s.load1 != null);
  if (ok.length) out.push(`host: ${job.samples.length} samples, max pressure ${Math.max(...ok.map((s) => s.pressure))}, max load1 ${Math.max(...ok.map((s) => s.load1))}`);
  for (const p of job.problems) out.push(`problem: ${p}`);
  out.push(`exit ${job.exit}: ${MEANING[job.exit]}`);
  return out;
}

// Calibration (design sections 4-6). The multiplier rule is this design's approximation: Lighthouse's mid-tier
// bracket midpoint as the target index, not a phone's measured speed.
const TARGET_INDEX = 462.5;
const CAL_START = { pressure: 1.0, load1: 2.0 };
const CAL_LIMITS = { pressure: 2 * CAL_START.pressure, load1: 2 * CAL_START.load1 };
const THRESHOLD_ADD = { pressure: 5.0, load1: 1.0 };
const THRESHOLD_CAP = { pressure: 15.0, load1: 4.0 };
const REPEATS = 5;

const snapshot = () => execFileSync('ps', ['-eo', 'pid,comm,%cpu', '--sort=-%cpu'], { encoding: 'utf8' }).split('\n').slice(0, 11).join('\n');

/** The pinned tools' versions and Lighthouse's own constants, copied into the config. */
async function pinnedBase() {
  const c = await import('lighthouse/core/config/constants.js');
  const { requestLatencyMs, downloadThroughputKbps, uploadThroughputKbps } = c.throttling.mobileSlow4G;
  const d = c.throttling.desktopDense4G;
  const browser = await chromium.launch();
  const chromeVersion = browser.version();
  await browser.close();
  return {
    lighthouseVersion: JSON.parse(readFileSync(join(UI_TESTS, 'node_modules', 'lighthouse', 'package.json'), 'utf8')).version,
    chromeVersion,
    mobileNetwork: { requestLatencyMs, downloadThroughputKbps, uploadThroughputKbps },
    desktopNetwork: { requestLatencyMs: d.requestLatencyMs, downloadThroughputKbps: d.downloadThroughputKbps, uploadThroughputKbps: d.uploadThroughputKbps },
    screens: { mobile: c.screenEmulationMetrics.mobile, desktop: c.screenEmulationMetrics.desktop },
    simulateThrottling: c.throttling.mobileSlow4G,
  };
}

/** Gathers one schedule and requires every pass complete and valid; a busy stop is exit 3. */
async function gatherAll({ schedule, config, urls, shell, sampler, log }) {
  const { settings, expected } = expectations(schedule, config, urls, shell);
  const g = await gather({ schedule, settings, urls, sampler, limits: CAL_LIMITS, log });
  const host = busy(sampler.samples, CAL_LIMITS);
  if (host.fault) return { exit: 2, problem: host.problem };
  if (g.stopped) return { exit: 3, problem: `host rose past ${JSON.stringify(CAL_LIMITS)} during calibration: ${host.problem}` };
  const out = {};
  for (const [p, n] of Object.entries(schedule)) {
    const c = passComplete(g.reports[p], expected[p], n);
    if (!c.ok) return { exit: 2, problem: `${p}: ${c.problem}` };
    out[p] = c;
  }
  return { exit: 0, passes: out };
}

/** Calibration: step 1 fixes the index and multiplier; step 2 runs five gate schedules with it. Writes the config. */
export async function calibrate({ sha, urls, shell, log }) {
  const start = readSample();
  if (!(start.pressure <= CAL_START.pressure && start.load1 < CAL_START.load1)) {
    return { exit: 3, lines: [`not quiet enough to calibrate: pressure ${start.pressure}, load1 ${start.load1} (need <= ${CAL_START.pressure} and < ${CAL_START.load1})`] };
  }
  const base = await pinnedBase();
  const snapshots = { start: snapshot() };
  const sampler = startSampler();
  try {
    const step1 = await gatherAll({ schedule: { unthrottled: RUNS }, config: { ...base, multiplier: 1 }, urls, shell, sampler, log });
    if (step1.exit) return { exit: step1.exit, lines: [`step 1: ${step1.problem}`] };
    const index = stats(step1.passes.unthrottled.indices).median;
    const multiplier = Math.round((index / TARGET_INDEX) * 10) / 10;
    log(`step 1: calibration index ${index}, multiplier ${multiplier}`);
    const repeats = [];
    for (let r = 1; r <= REPEATS; r += 1) {
      const g = await gatherAll({ schedule: GATE_SCHEDULE, config: { ...base, multiplier }, urls, shell, sampler, log });
      if (g.exit) return { exit: g.exit, lines: [`step 2 repeat ${r}: ${g.problem}`] };
      const d = drift(g.passes.unthrottled.indices, index);
      if (d.refuse) return { exit: 4, lines: [`step 2 repeat ${r}: index drift ${d.ratio} over ${DRIFT_LIMIT}`] };
      repeats.push({ gate: stats(g.passes.gateMobile.fcps).median, control: stats(g.passes.control.fcps).median, desktop: stats(g.passes.gateDesktop.fcps).median, drift: d.ratio });
      log(`step 2 repeat ${r}: gateMobile ${repeats.at(-1).gate}, control ${repeats.at(-1).control}, desktop ${repeats.at(-1).desktop}, drift ${d.ratio}`);
      if (r === 3) snapshots.middle = snapshot();
    }
    snapshots.end = snapshot();
    const medians = repeats.map((x) => x.gate);
    const baseline = stats(medians).median;
    const m = marginFromSpread(medians);
    const lines = [`five gateMobile medians ${medians.join(', ')}: spread ${m.spread}, margin ${m.margin}${m.widened ? ` (widened: 3x the spread is over 250)` : ''}`];
    if (m.refuse) return { exit: 2, lines: [...lines, `margin ${m.margin} is over 290 ms: the 300 ms control cannot be told from noise; goes to the lead`] };
    for (const [i, x] of repeats.entries()) {
      const c = controlCheck({ mode: 'proof', controlMedian: x.control, gateMedian: x.gate, baseline, margin: m.margin });
      if (!c.ok) return { exit: 2, lines: [...lines, `repeat ${i + 1}: ${c.problem}`] };
    }
    const ok = sampler.samples.filter((s) => s.pressure != null && s.load1 != null);
    const peak = { pressure: Math.max(...ok.map((s) => s.pressure)), load1: Math.max(...ok.map((s) => s.load1)) };
    const thresholds = {
      pressure: Math.min(peak.pressure + THRESHOLD_ADD.pressure, THRESHOLD_CAP.pressure),
      load1: Math.min(peak.load1 + THRESHOLD_ADD.load1, THRESHOLD_CAP.load1),
    };
    const previous = existsSync(CONFIG_PATH) ? JSON.parse(readFileSync(CONFIG_PATH, 'utf8')) : null;
    const config = {
      ...base, calibrationIndex: index, multiplier, baseline, margin: m.margin, medians, spread: m.spread, thresholds,
      peak, worstRepeatDrift: Math.max(...repeats.map((x) => x.drift)), repeats, host: hostname(), date: new Date().toISOString(), sha, snapshots,
    };
    writeFileSync(CONFIG_PATH, `${JSON.stringify(config, null, 2)}\n`);
    lines.push(`calibration index ${index}, multiplier ${multiplier}, baseline ${baseline}, thresholds pressure ${thresholds.pressure} load1 ${thresholds.load1}`);
    if (previous) {
      const f = recalibrationFlag(previous.baseline, baseline);
      lines.push(`baseline ${previous.baseline} -> ${baseline} (${f.rise >= 0 ? '+' : ''}${f.rise} ms)${f.needsSignoff ? ": needs the lead's sign-off" : ''}`);
    }
    return { exit: 0, lines, config };
  } finally {
    sampler.stop();
  }
}

function readRecord() {
  return existsSync(NIGHTLY_RECORD) ? JSON.parse(readFileSync(NIGHTLY_RECORD, 'utf8')) : null;
}

/** Writes first-paint-<sha>-<UTC>.json and .md under ~/first-paint/out; never overwrites. */
function writeOutputs({ mode, sha, lines, data }) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = join(HOME, 'out');
  mkdirSync(dir, { recursive: true });
  const name = join(dir, `first-paint-${sha.slice(0, 12)}-${mode}-${stamp}`);
  writeFileSync(`${name}.json`, `${JSON.stringify({ mode, sha, ...data }, null, 2)}\n`, { flag: 'wx' });
  writeFileSync(`${name}.md`, `${lines.join('\n')}\n`, { flag: 'wx' });
  return name;
}

/** Per-run values kept for the record (the full Lighthouse reports are not). */
const runValues = (reports) => Object.fromEntries(Object.entries(reports).map(([p, rs]) => [p, rs.map((r) => ({
  fcp: r.audits?.['first-contentful-paint']?.numericValue ?? null, index: r.environment?.benchmarkIndex ?? null, error: r.runtimeError?.code ?? null,
}))]));

async function main(argv) {
  const { mode, sha } = parseArgs(argv);
  const log = (s) => console.log(s);
  const shell = shellFile();
  let banner = null;
  let config = null;
  if (mode !== 'calibrate') {
    config = loadConfig();
    if (mode !== 'nightly') {
      const n = nightlyCheck(readRecord(), Date.now());
      if (!n.ok) throw new Fault(`${n.problem}; start the nightly by hand: launchctl kickstart -k gui/$(id -u)/com.claude.mcp-gateway.first-paint-nightly`);
      banner = n.banner;
    }
  }
  if (banner) console.log(banner);
  const plain = await startServer([]);
  const planted = mode === 'verdicts' ? null : await startServer(['--plant-first-paint-delay-ms=300']);
  const urls = { gateMobile: plain.url, gateDesktop: plain.url, unthrottled: plain.url, simulate: plain.url, control: planted?.url };
  let result;
  try {
    if (mode === 'calibrate') result = await calibrate({ sha, urls, shell, log });
    else if (mode === 'verdicts') result = await consecutiveVerdicts({ config, urls, shell, log });
    else result = await oneJob({ controlMode: mode === 'proof' ? 'proof' : 'gate', config, schedule: GATE_SCHEDULE, urls, shell, log });
  } finally {
    plain.stop();
    planted?.stop();
  }
  const head = [`first paint, ${mode}, ${sha}, ${new Date().toISOString()}`, ...(banner ? [banner] : [])];
  let lines;
  let data;
  if (mode === 'calibrate') {
    lines = [...head, ...result.lines, `exit ${result.exit}`];
    data = { exit: result.exit, config: result.config ?? null };
  } else if (mode === 'verdicts') {
    lines = [...head, `UI12.9: ${result.streak} consecutive passing verdicts of ${UI12_9_PASSES} needed, ${result.verdicts.length} run`,
      ...result.verdicts.map((v, i) => `verdict ${i + 1}: exit ${v.exit}, median ${ms(v.stats.gateMobile?.median)}${v.drift ? `, drift ${Math.round(v.drift.ratio * 1000) / 10}%` : ''}`),
      `exit ${result.exit}`];
    data = { exit: result.exit, streak: result.streak, verdicts: result.verdicts.map((v) => ({ exit: v.exit, problems: v.problems, stats: v.stats, drift: v.drift, samples: v.samples, runs: runValues(v.reports) })) };
  } else {
    lines = [...head, ...jobLines(result)];
    data = { exit: result.exit, problems: result.problems, verdicts: result.verdicts, stats: result.stats, drift: result.drift, samples: result.samples, runs: runValues(result.reports), config };
  }
  const name = writeOutputs({ mode, sha, lines, data });
  for (const l of lines.slice(1)) console.log(l);
  console.log(`outputs: ${name}.json, ${name}.md`);
  if (banner) console.log(banner);
  return result.exit;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let mode = null;
  let sha = null;
  try {
    ({ mode, sha } = parseArgs(process.argv.slice(2)));
  } catch { /* main reports it */ }
  const record = (exit) => {
    if (mode !== 'nightly' || !sha) return;
    mkdirSync(HOME, { recursive: true });
    writeFileSync(NIGHTLY_RECORD, `${JSON.stringify({ timestamp: new Date().toISOString(), sha, exit })}\n`);
  };
  main(process.argv.slice(2)).then((exit) => {
    record(exit);
    process.exit(exit);
  }, (e) => {
    console.error(e instanceof Fault ? `fault: ${e.message}` : e?.stack ?? String(e));
    console.log('exit 2: fault');
    record(2);
    process.exit(2);
  });
}
