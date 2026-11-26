// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The one chart module every screen draws with: chart() for a time chart and
// spark() for a tile's sparkline. No state, no fetch, no listeners: each call
// builds its nodes and returns them. A unit is required by both, so no chart
// can be drawn without saying what it counts. Another drawing (a strip of up
// and down time, say) is one more exported function here, under the same rule.
// Its stylesheet, chart.css, is imported by each charting screen's own stylesheet,
// which the shell loads before the screen draws: a sheet the module linked itself
// would land after the first paint and move the chart under the reader.
import { el as h } from '/ui/assets/shell.eb4a79cf1d0c.js';

/** The unit's words, or a TypeError: a chart that cannot say what it counts is not drawn. */
function unitWords(unit, who) {
  if (typeof unit?.words !== 'string' || !unit.words.trim()) throw new TypeError(`${who}: unit.words is required (a unit says what the chart counts)`);
  return unit.words;
}

// The SVG namespace, read off an element the HTML parser makes, so no asset carries a URL.
const SVG = document.createRange().createContextualFragment('<svg></svg>').firstChild.namespaceURI;

/** A decorative sparkline; null values are gaps, so each run of numbers is its own line. The svg stays decorative; the
 * unit reaches a reader as hidden text in a wrapper span, whose title carries it for a pointer. */
export function spark(values, { unit, label } = {}) {
  const words = `${label}, ${unitWords(unit, 'spark')}`;
  const nums = values.filter((v) => v !== null);
  const max = Math.max(...nums, 0);
  const step = values.length > 1 ? 72 / (values.length - 1) : 0;
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('class', 'ov-spark');
  svg.setAttribute('viewBox', '0 0 72 18');
  svg.setAttribute('preserveAspectRatio', 'none');
  svg.setAttribute('aria-hidden', 'true');
  let run = [];
  const flush = () => {
    if (run.length) {
      const line = document.createElementNS(SVG, 'polyline');
      line.setAttribute('points', run.join(' '));
      svg.append(line);
    }
    run = [];
  };
  values.forEach((v, i) => {
    if (v === null) return flush();
    run.push(`${(i * step).toFixed(1)},${(17 - (max ? (v / max) * 16 : 0)).toFixed(1)}`);
  });
  flush();
  return h('span', { class: 'chart-spark', title: words, 'data-unit': unit.words }, svg, h('span', { class: 'sr-only' }, words));
}

const NOTHING = 'Nothing counted in this period yet';
const NOT_COUNTED = 'not counted';
/** Ids for the summary each plot is named by; unique within the page. */
let made = 0;
/** A coordinate as short text. */
const num = (v) => String(Math.round(v * 1000) / 1000);
const isValue = (v) => typeof v === 'number' && Number.isFinite(v);

/** The top of the y scale: the largest value rounded up to 1, 2 or 5 times a power of ten; 1 for a quiet chart. */
function scaleTop(v) {
  if (!(v > 0)) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  return [1, 2, 5, 10].map((m) => m * p).find((c) => c >= v * (1 - 1e-9));
}

/** A legend swatch: a short line in its series' stroke pattern. */
function swatch(role) {
  const box = svgEl('svg', { class: 'chart-swatch', viewBox: '0 0 24 4', 'aria-hidden': 'true' });
  box.append(svgEl('line', { class: `chart-line chart-${role}`, x1: 0, y1: 2, x2: 24, y2: 2 }));
  return box;
}

/** An SVG element with its attributes. */
function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  return node;
}

/**
 * A time chart as one figure.chart: caption, summary and legend as text; y ticks, plot and x
 * ticks in a grid; the markers as a list; the values as a table in a closed details element.
 *
 * unit:    { words, symbol? }   required; words name the measure ("calls per 30 min"), the symbol
 *                               ("$") goes before every y value
 * series:  [{ name, points: [{t, v}], role: 'main' | 'previous' | 'second' }]; a null v is a gap
 * markers: [{ t, glyph, words }], worded by the caller
 * limit:   { value, words } | null, a horizontal line
 * x, y:    (t) => words for a time, (v) => words for a number
 *
 * Every point and marker is placed by its time against the main series: x = (t - t0) / step + 0.5,
 * with t0 its first time and step the gap between its first two; a marker stands in the middle of
 * the bucket that holds its time. Nothing is placed by index, so a
 * previous period reaches the plot only when the caller has moved its times into the main one's.
 */
export function chart({ caption, unit, series, markers = [], limit = null, x, y, summary }) {
  const words = unitWords(unit, 'chart');
  const symbol = typeof unit.symbol === 'string' ? unit.symbol : '';
  const yWords = (v) => `${symbol}${y(v)}`;
  const lines = series.map((s) => ({ ...s, points: [...s.points].sort((a, b) => a.t - b.t) }));
  const main = lines.find((s) => s.role === 'main') ?? lines[0];
  const id = `chart-summary-${++made}`;
  const fig = h('figure', { class: 'chart', 'data-unit': words });
  const caption2 = limit ? [h('span', { class: 'chart-limit' }, `${limit.words}: ${yWords(limit.value)}`)] : [];
  const cap = h('figcaption', {}, h('span', { class: 'chart-caption' }, caption), ...caption2,
    h('p', { class: 'chart-summary', id }, summary));
  fig.append(cap);
  const values = lines.flatMap((s) => s.points.map((p) => p.v)).filter(isValue);
  if (!main?.points.length || !values.length) {
    fig.append(h('p', { class: 'chart-empty' }, NOTHING));
    return fig;
  }
  // A legend only for lines that are drawn.
  cap.append(h('ul', { class: 'chart-legend', role: 'list' }, ...lines.map((s) => h('li', { 'data-role': s.role }, swatch(s.role), s.name))));
  const t0 = main.points[0].t;
  const step = main.points.length > 1 ? main.points[1].t - t0 : 1;
  // The plot spans the main series' time, not its count, so a time it leaves out keeps its place.
  const buckets = main.points.length > 1 ? Math.round((main.points.at(-1).t - t0) / step) + 1 : 1;
  const xAt = (t) => (t - t0) / step + 0.5;
  const shown = (xv) => xv >= 0 && xv <= buckets;
  const top = scaleTop(Math.max(...values, limit && isValue(limit.value) ? limit.value : 0));
  const yAt = (v) => 100 - (v / top) * 100;

  const plot = svgEl('svg', { class: 'chart-plot', viewBox: `0 0 ${buckets} 100`, preserveAspectRatio: 'none', role: 'img', 'aria-labelledby': id });
  for (const s of lines) {
    let run = [];
    const end = () => {
      // A lone value is a short level stroke, so it can be seen.
      if (run.length === 1) run = [[run[0][0] - 0.25, run[0][1]], [run[0][0] + 0.25, run[0][1]]];
      if (run.length) {
        plot.append(svgEl('polyline', { class: `chart-line chart-${s.role}`, 'data-role': s.role, points: run.map(([a, b]) => `${num(a)},${num(b)}`).join(' ') }));
      }
      run = [];
    };
    // A missing time is a gap as well as a null: points more than a bucket and a half apart
    // start a new run (a day of 23 or 25 hours in a daily chart stays one run).
    let last = null;
    for (const p of s.points) {
      const xv = xAt(p.t);
      if (!isValue(p.v)) end();
      else if (shown(xv)) {
        if (last !== null && xv - last > 1.5) end();
        run.push([xv, yAt(p.v)]);
        last = xv;
      }
    }
    end();
  }
  if (limit && isValue(limit.value)) {
    plot.append(svgEl('line', { class: 'chart-limit', x1: 0, x2: buckets, y1: num(yAt(limit.value)), y2: num(yAt(limit.value)) }));
  }
  const marks = [...markers].sort((a, b) => a.t - b.t);
  // The bucket holding a time (-1 or past the end when outside); with one bucket, every time from t0 on.
  const bucketOf = (t) => (buckets === 1 ? (t >= t0 ? 0 : -1) : Math.floor((t - t0) / step));
  // Each main point's own bucket (rounded, so a day of 23 or 25 hours keeps its place), for the labels.
  const starts = new Map(main.points.map((p) => [Math.round((p.t - t0) / step), p.t]));
  // The main row whose span holds a time: from its start to the next row's, at most one step; with
  // one row, every time from t0 on. -1 outside every span.
  const n = main.points.length;
  const rowOf = (t) => {
    let i = -1;
    for (let k = 0; k < n && main.points[k].t <= t; k += 1) i = k;
    if (i < 0) return -1;
    const span = n === 1 ? Infinity : Math.min(step, i + 1 < n ? main.points[i + 1].t - main.points[i].t : step);
    return t < main.points[i].t + span ? i : -1;
  };
  for (const m of marks) {
    // A marker stands in the middle of the bucket that holds its time, so the newest one shows too.
    const at = bucketOf(m.t);
    if (at >= 0 && at < buckets) plot.append(svgEl('line', { class: 'chart-mark', x1: at + 0.5, x2: at + 0.5, y1: 0, y2: 100 }));
  }

  // x labels: the first, middle and last bucket (kept on a phone), and every sixth from twelve
  // buckets, unless it would crowd a kept one.
  const keep = [0, Math.floor((buckets - 1) / 2), buckets - 1];
  const extra = buckets >= 12 ? Array.from({ length: buckets }, (_, i) => i).filter((i) => i % 6 === 0 && keep.every((k) => Math.abs(k - i) > 2)) : [];
  const xTicks = h('div', { class: 'chart-x', 'aria-hidden': 'true' });
  for (const i of [...new Set([...keep, ...extra])].sort((a, b) => a - b)) {
    const label = h('span', { class: keep.includes(i) ? 'chart-x-keep' : null }, x(starts.get(i) ?? t0 + i * step));
    label.style.left = `${((i + 0.5) / buckets) * 100}%`;
    xTicks.append(label);
  }
  const yTicks = h('div', { class: 'chart-y', 'aria-hidden': 'true' }, ...[top, top / 2, 0].map((v) => h('span', {}, yWords(v))));
  fig.append(h('div', { class: 'chart-grid' }, yTicks, plot, xTicks));

  if (marks.length) {
    fig.append(h('ol', { class: 'chart-markers', role: 'list' }, ...marks.map((m) => h('li', {},
      h('span', { class: 'chart-glyph' }, m.glyph), ' ', h('span', { class: 'chart-when num' }, x(m.t)), ' ', m.words))));
  }

  // The numbers: one row per main point, one column per series, each value in the row whose span
  // holds its time (rowOf), so a main row always shows its own value.
  const byBucket = lines.map((s) => {
    const held = new Map();
    for (const p of s.points) if (rowOf(p.t) >= 0 && !held.has(rowOf(p.t))) held.set(rowOf(p.t), p.v);
    return held;
  });
  const cell = (v) => h('td', { class: 'num' }, isValue(v) ? yWords(v) : NOT_COUNTED);
  fig.append(h('details', { class: 'chart-numbers' }, h('summary', {}, 'The numbers'),
    h('table', {},
      h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Time'), ...lines.map((s) => h('th', { scope: 'col' }, `${s.name} (${words})`)))),
      h('tbody', {}, ...main.points.map((p, i) => h('tr', {}, h('th', { scope: 'row' }, x(p.t)), ...byBucket.map((m) => cell(m.get(i)))))))));
  return fig;
}
