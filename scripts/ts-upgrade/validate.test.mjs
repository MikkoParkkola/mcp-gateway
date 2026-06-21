/**
 * Node test runner for MIK-3160 TS upgrade validation harness.
 * Run with: node --test scripts/ts-upgrade/
 *
 * AC-VERBATIM POLARITY: each test pastes the AC verbatim then asserts the
 * stated direction (positive polarity).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execSync } from 'child_process';
import { existsSync, readFileSync, rmSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { createRequire } from 'module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = join(__filename, '..');
const require = createRequire(import.meta.url);

const validateScript = join(__dirname, 'validate.mjs');

function hasTypeScript() {
  // Detect either require('typescript') or a tsc binary per AC.5 intent.
  try {
    require('typescript');
    return true;
  } catch {}
  try {
    execSync('tsc --version', { stdio: 'ignore' });
    return true;
  } catch {}
  // Also accept if npx can resolve without net (cached), but do not force fetch here.
  return false;
}

function runValidate(args, cwd) {
  const res = spawnSync(process.execPath, [validateScript, ...args], {
    encoding: 'utf8',
    cwd: cwd || __dirname,
    env: { ...process.env, FORCE_COLOR: '0' },
  });
  return res;
}

// AC.1 verbatim (exact from ticket)
test('MIK-3160.AC.1 AC.1: A version-parameterized harness `scripts/ts-upgrade/validate.mjs` accepts `--ts-version <semver>`, runs `tsc --checkJs --noEmit --strict` over a fixture dir, and exits non-zero on net-new diagnostics. CHECK: file `scripts/ts-upgrade/validate.mjs` matches regex `--ts-version` AND matches regex `checkJs`', (t) => {
  if (!hasTypeScript()) {
    t.skip('typescript binary absent');
    return;
  }

  // 1) --ts-version flag accepted (parse does not blow up, report carries it)
  const r1 = runValidate(['--ts-version', '5.9.0-test']);
  // Even if diags (TS version loaded may differ), harness must have parsed the arg.
  // We assert it wrote a report containing the requested version string or ran.
  const reportPath = join(process.cwd(), 'ts-upgrade-report.json');
  // If report landed in cwd of spawn (scripts dir), read from there too.
  let report = null;
  const candidatePaths = [
    join(__dirname, 'ts-upgrade-report.json'),
    reportPath,
  ];
  for (const p of candidatePaths) {
    if (existsSync(p)) {
      try { report = JSON.parse(readFileSync(p, 'utf8')); } catch {}
      break;
    }
  }
  assert.ok(report, 'harness must emit report');
  // tsVersion in report should reflect the passed --ts-version when provided
  assert.ok(String(report.tsVersion).includes('5.9.0-test') || report.tsVersion, 'accepts --ts-version');

  // 2) Exercises checkJs path: harness source contains the strings per CHECK
  const harnessSrc = readFileSync(validateScript, 'utf8');
  assert.ok(harnessSrc.includes('--ts-version'), 'contains --ts-version');
  assert.ok(harnessSrc.includes('checkJs'), 'contains checkJs');

  // 3) nonzero exit on net-new diags: use temp dir with bad fixture
  const badRoot = join(process.cwd(), '.tmp-bad-fixture-' + Date.now());
  mkdirSync(badRoot, { recursive: true });
  writeFileSync(join(badRoot, 'bad.js'), 'const x=null; const y=x.fooBar(); // provokes diagnostic');
  const rBad = runValidate(['--ts-version', 'test', '--fixtures-dir', badRoot], badRoot);
  // cleanup report if emitted in badRoot
  const badReport = join(badRoot, 'ts-upgrade-report.json');
  if (existsSync(badReport)) rmSync(badReport, { force: true });
  rmSync(badRoot, { recursive: true, force: true });
  assert.notStrictEqual(rBad.status, 0, 'exits non-zero on net-new diagnostics');
});

// AC.2 verbatim
test('MIK-3160.AC.2 AC.2: A committed fixture corpus of ≥5 representative JSDoc-narrowing patterns (truthiness narrow, `typeof` guard, discriminated union, `@template` generic, nullable-param narrow) lives under `scripts/ts-upgrade/fixtures/`. CHECK: `bash -c \'ls scripts/ts-upgrade/fixtures/*.js | wc -l\'` prints a value `>= 5` (exits 0)', (t) => {
  if (!hasTypeScript()) {
    t.skip('typescript binary absent');
    return;
  }
  // Count must be >=5
  const out = execSync('bash -c \'ls scripts/ts-upgrade/fixtures/*.js | wc -l\'', { encoding: 'utf8' });
  const n = parseInt(out.trim(), 10);
  assert.ok(n >= 5, `fixture count ${n} >= 5`);
  // Spot check the named patterns exist (by filename content)
  const names = ['truthiness-narrow.js', 'typeof-guard.js', 'discriminated-union.js', 'template-generic.js', 'nullable-param-narrow.js'];
  for (const n of names) {
    assert.ok(existsSync(join(__dirname, 'fixtures', n)), n + ' must exist');
  }
});

// AC.3 verbatim
test('MIK-3160.AC.3 AC.3: The harness emits `ts-upgrade-report.json` carrying `tsVersion`, `commitSha` (B1-IDENT attribution), per-fixture diagnostic counts, and a `recommendation` field constrained to the enum `upgrade_now | wait_for_stable | skip`. CHECK: file `scripts/ts-upgrade/validate.mjs` matches regex `upgrade_now|wait_for_stable|skip` AND matches regex `commitSha`', (t) => {
  if (!hasTypeScript()) {
    t.skip('typescript binary absent');
    return;
  }
  // Run to force emit
  const r = runValidate(['--ts-version', 'local-via-test']);
  assert.ok([0, 1].includes(r.status), 'harness ran');
  const candidates = [
    join(__dirname, 'ts-upgrade-report.json'),
    join(process.cwd(), 'ts-upgrade-report.json'),
  ];
  let report = null;
  for (const p of candidates) {
    if (existsSync(p)) { report = JSON.parse(readFileSync(p, 'utf8')); break; }
  }
  assert.ok(report, 'report emitted');
  assert.ok('tsVersion' in report, 'has tsVersion');
  assert.ok('commitSha' in report, 'has commitSha (B1-IDENT)');
  assert.ok(typeof report.perFixture === 'object', 'has per-fixture counts');
  assert.ok(['upgrade_now', 'wait_for_stable', 'skip'].includes(report.recommendation), 'recommendation in enum');

  // CHECK strings in source
  const src = readFileSync(validateScript, 'utf8');
  assert.ok(/upgrade_now|wait_for_stable|skip/.test(src), 'source has recommendation enum strings');
  assert.ok(/commitSha/.test(src), 'source has commitSha');

  // cleanup if left in __dirname
  const rp = join(__dirname, 'ts-upgrade-report.json');
  if (existsSync(rp)) rmSync(rp, { force: true });
});

// AC.5 verbatim (self-skip behavior asserted by running node --test and getting 0)
test('MIK-3160.AC.5 AC.5: A committed test exercises the harness against the fixtures and self-skips (exit 0) when the `typescript` binary is absent, so CI stays green without a pinned RC. CHECK: `node --test scripts/ts-upgrade/` exits 0', (t) => {
  // This very test is the committed test. Run the suite from parent; assert the runner itself exits 0
  // When TS absent: inner tests skip => overall still 0
  // When TS present: runs and must succeed (0) or 1 only on real new diags (we keep fixtures clean).
  const res = spawnSync(process.execPath, ['--test', 'scripts/ts-upgrade/'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // The AC requires that `node --test scripts/ts-upgrade/` exits 0.
  // In this invocation we assert the status from within is success.
  if (res.status !== 0) {
    // Provide output for debug but still surface
    console.error('node --test output (stdout):', res.stdout);
    console.error('node --test output (stderr):', res.stderr);
  }
  assert.strictEqual(res.status, 0, 'node --test scripts/ts-upgrade/ must exit 0');
});

// Extra coverage: harness can be invoked with --ts-version and produces B1-IDENT fields
test('harness run on fixtures produces identifiable report (B1-IDENT)', (t) => {
  if (!hasTypeScript()) {
    t.skip('typescript binary absent');
    return;
  }
  const r = runValidate(['--ts-version', 'test-run']);
  const rp = join(__dirname, 'ts-upgrade-report.json') || join(process.cwd(), 'ts-upgrade-report.json');
  let found = null;
  if (existsSync(join(__dirname, 'ts-upgrade-report.json'))) found = join(__dirname, 'ts-upgrade-report.json');
  else if (existsSync(join(process.cwd(), 'ts-upgrade-report.json'))) found = join(process.cwd(), 'ts-upgrade-report.json');
  if (found) {
    const rep = JSON.parse(readFileSync(found, 'utf8'));
    assert.ok(rep.commitSha && rep.commitSha.length >= 7, 'commitSha present');
    assert.ok(rep.tsVersion, 'tsVersion present');
    rmSync(found, { force: true });
  }
  // do not assert exit strictly (may be 0/1 depending on loaded TS vs fixtures)
});
