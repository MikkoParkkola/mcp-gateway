// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The first-paint gate's judgement, as pure functions over Lighthouse reports
// and host samples, so every rule is a unit row (tests/first-paint-gate.spec.mjs).
// The Spark runner (first-paint.mjs) only gathers the inputs and calls these.
// STUB: red first; every function returns nothing until the rows pin it.

export const BUDGET_MS = 1000;
export const WARN_MS = 900;
export const REGRESSION_MS = 250;
export const DRIFT_LIMIT = 0.2;
export const RUNS = 20;
export const SIGNOFF_RISE_MS = 100;

export function stats(_values) { return {}; }
export function judge(_input) { return {}; }
export function checkRun(_report, _expected) { return {}; }
export function passComplete(_reports, _expected) { return {}; }
export function drift(_indices, _calibrationIndex) { return {}; }
export function busy(_samples, _thresholds) { return {}; }
export function controlCheck(_input) { return {}; }
export function exitCode(_conditions) { return {}; }
export function recalibrationFlag(_oldBaseline, _newBaseline) { return {}; }
