#!/usr/bin/env node
/**
 * MIK-3160 TS 7.0 JSDoc-narrowing validation harness.
 *
 * Usage:
 *   node scripts/ts-upgrade/validate.mjs --ts-version 7.0.0-dev
 *   node scripts/ts-upgrade/validate.mjs --ts-version <semver> --fixtures-dir path/to/dir
 *
 * - Accepts --ts-version <semver>
 * - Runs TypeScript check using --checkJs --noEmit --strict (via compiler API or tsc)
 * - Emits ts-upgrade-report.json (cwd) with tsVersion, commitSha, counts, recommendation
 * - Exits non-zero when net-new diagnostics are present.
 */

import { createRequire } from 'module';
import { readdirSync, writeFileSync } from 'fs';
import { join, basename } from 'path';
import { execSync } from 'child_process';
import process from 'process';

const require = createRequire(import.meta.url);

const __filename = new URL(import.meta.url).pathname;
const __dirname = join(__filename, '..');

function parseArgs(argv) {
  const out = { tsVersion: null, fixturesDir: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--ts-version' && i + 1 < argv.length) {
      out.tsVersion = argv[++i];
    } else if (argv[i] === '--fixtures-dir' && i + 1 < argv.length) {
      out.fixturesDir = argv[++i];
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      console.log('validate.mjs --ts-version <semver> [--fixtures-dir <dir>]');
      process.exit(0);
    }
  }
  return out;
}

function getCommitSha() {
  try {
    return execSync('git rev-parse HEAD', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return 'unknown';
  }
}

function loadTypeScript() {
  // Prefer direct require (works when typescript is resolvable)
  try {
    return require('typescript');
  } catch {}
  // Try common global npm path (non-fatal)
  const candidates = [
    '/home/mikko/.npm-global/lib/node_modules/typescript',
    '/usr/local/lib/node_modules/typescript',
  ];
  for (const c of candidates) {
    try {
      return require(c);
    } catch {}
  }
  return null;
}

function getTsVersion(ts, argVer) {
  if (argVer) return argVer;
  if (ts && ts.version) return ts.version;
  try {
    const out = execSync('tsc --version', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const m = out.match(/Version\s+([^\s]+)/i);
    if (m) return m[1];
  } catch {}
  return 'unknown';
}

function collectFixtures(dir) {
  try {
    const all = readdirSync(dir);
    return all
      .filter((f) => f.endsWith('.js'))
      .map((f) => join(dir, f))
      .sort();
  } catch {
    return [];
  }
}

function runCheckWithApi(ts, files) {
  if (!ts || files.length === 0) return { diagnostics: [], program: null };
  const options = {
    noEmit: true,
    checkJs: true,
    strict: true,
    allowJs: true,
    skipLibCheck: true,
    target: ts.ScriptTarget?.ES2022 ?? 99,
    module: ts.ModuleKind?.ESNext ?? 99,
    moduleResolution: ts.ModuleResolutionKind?.Bundler ?? 100,
  };
  const program = ts.createProgram(files, options);
  const diags = ts.getPreEmitDiagnostics(program);
  return { diagnostics: diags, program };
}

function runCheckWithTsc(files) {
  // Fallback when no TS module: shell to tsc if present
  if (files.length === 0) return { stdout: '', stderr: '', status: 0 };
  const cmd = ['tsc', '--noEmit', '--checkJs', '--strict', '--skipLibCheck', '--allowJs', ...files];
  try {
    const out = execSync(cmd.join(' '), { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { stdout: out, stderr: '', status: 0 };
  } catch (e) {
    return { stdout: e.stdout || '', stderr: e.stderr || e.message || '', status: e.status || 1 };
  }
}

function parseDiagCountByFile(diags, ts, fallbackStderr) {
  const counts = {};
  const details = [];
  if (ts && Array.isArray(diags)) {
    for (const d of diags) {
      let fileName = 'unknown.js';
      if (d.file && d.file.fileName) {
        fileName = basename(d.file.fileName);
      }
      counts[fileName] = (counts[fileName] || 0) + 1;
      const msg = ts.flattenDiagnosticMessageText ? ts.flattenDiagnosticMessageText(d.messageText, '\n') : String(d.messageText);
      details.push({ file: fileName, code: d.code, message: msg });
    }
  } else if (fallbackStderr) {
    // naive parse of tsc stderr like: foo.js(3,5): error TS2322: ...
    const lines = fallbackStderr.split(/\r?\n/);
    for (const line of lines) {
      const m = line.match(/^\s*([A-Za-z0-9_.-]+\.js)(?:\(|\s|:)/);
      if (m) {
        const f = m[1];
        counts[f] = (counts[f] || 0) + 1;
      }
    }
  }
  return { counts, details };
}

function decideRecommendation(total) {
  if (total === 0) return 'upgrade_now';
  if (total <= 2) return 'wait_for_stable';
  return 'skip';
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const fixturesDir = args.fixturesDir || join(__dirname, 'fixtures');
  const commitSha = getCommitSha();
  const ts = loadTypeScript();
  const tsVersion = getTsVersion(ts, args.tsVersion);

  const files = collectFixtures(fixturesDir);

  let diags = [];
  let tscStderr = '';
  let exitFromTsc = 0;
  if (ts) {
    const res = runCheckWithApi(ts, files);
    diags = res.diagnostics || [];
  } else {
    const res = runCheckWithTsc(files);
    tscStderr = res.stderr || res.stdout || '';
    exitFromTsc = res.status || 0;
  }

  const { counts, details } = parseDiagCountByFile(diags, ts, tscStderr);
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || (diags.length || (exitFromTsc !== 0 ? 1 : 0));

  const recommendation = decideRecommendation(total);

  const report = {
    tsVersion,
    commitSha,
    fixtureDir: fixturesDir,
    perFixture: counts,
    totalDiagnostics: total,
    recommendation,
    details: details.length ? details.slice(0, 50) : undefined,
  };

  const reportPath = join(process.cwd(), 'ts-upgrade-report.json');
  writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n');
  console.log(`ts-upgrade-report.json written (tsVersion=${tsVersion}, commitSha=${commitSha.slice(0, 12)}, totalDiagnostics=${total}, recommendation=${recommendation})`);

  if (total > 0) {
    console.error(`Net-new diagnostics detected: ${total}`);
    process.exit(1);
  }
  process.exit(0);
}

main();
