import { Tiktoken } from 'https://esm.sh/js-tiktoken/lite';

const { createApp } = window.Vue;

const MODEL_TO_ENCODING = {
  'gpt-4.1': 'o200k_base',
  'gpt-4o': 'o200k_base',
  'gpt-4o-mini': 'o200k_base',
  o1: 'o200k_base',
  o3: 'o200k_base',
  'o3-mini': 'o200k_base',
  'gpt-4-turbo': 'cl100k_base',
  'gpt-4': 'cl100k_base',
  'gpt-3.5-turbo': 'cl100k_base'
};

const encodingCache = new Map();

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch (error) {
    return null;
  }
}

function shortText(value, limit = 220) {
  const clean = String(value || '').replace(/\s+/g, ' ').trim();
  if (!clean) {
    return '';
  }
  return clean.length > limit ? clean.slice(0, limit - 3) + '...' : clean;
}

function shortMultiline(value, limit = 440) {
  const clean = String(value || '').trim();
  if (!clean) {
    return '';
  }
  return clean.length > limit ? clean.slice(0, limit - 3) + '...' : clean;
}

function numberFormat(value) {
  if (value === null || value === undefined || value === '') {
    return 'n/a';
  }
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return String(value);
  }
  return new Intl.NumberFormat().format(number);
}

function formatTimestamp(value) {
  if (!value) {
    return 'n/a';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleString();
}

function parseArguments(raw) {
  if (!raw) {
    return {};
  }
  if (typeof raw === 'object') {
    return raw;
  }
  const parsed = safeJsonParse(raw);
  return parsed && typeof parsed === 'object' ? parsed : {};
}

function primaryCommand(raw) {
  const input = String(raw || '').trim();
  if (!input) {
    return 'none';
  }
  const pieces = input.split(/&&|\|\|/).map((piece) => piece.trim()).filter(Boolean);
  const target = pieces.find((piece) => !/^cd\s+/.test(piece)) || pieces[0] || input;
  if (target.startsWith('python - <<')) {
    return 'python-heredoc';
  }
  if (target.startsWith('printf ')) {
    return 'printf';
  }
  const match = target.match(/^([A-Za-z0-9._/-]+)/);
  return match ? match[1] : shortText(target, 40);
}

function parseExitCode(text) {
  const match = String(text || '').match(/(?:Return code:|Process exited with code|<exited with exit code)\s*(-?\d+)/i);
  return match ? Number(match[1]) : null;
}

function parseSessionId(text) {
  const match = String(text || '').match(/session(?:\s+ID)?\s+(\d+)/i);
  return match ? match[1] : '';
}

function countBy(items, selector) {
  const counts = new Map();
  for (const item of items) {
    const key = selector(item);
    if (!key) {
      continue;
    }
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([label, value]) => ({ label, value }));
}

function toBarRows(rows, limit = 6) {
  const subset = rows.slice(0, limit);
  const max = subset.reduce((value, row) => Math.max(value, row.value), 0) || 1;
  return subset.map((row) => ({
    label: row.label,
    value: row.value,
    width: Math.max(8, Math.round((row.value / max) * 100))
  }));
}

function tokenRowsFromTotals(tokens) {
  if (!tokens) {
    return [{ label: 'availability', value: 'n/a' }];
  }
  return [
    { label: 'input', value: numberFormat(tokens.input_tokens) },
    { label: 'output', value: numberFormat(tokens.output_tokens) },
    { label: 'reasoning', value: numberFormat(tokens.reasoning_output_tokens) },
    { label: 'cached', value: numberFormat(tokens.cached_input_tokens) },
    { label: 'total', value: numberFormat(tokens.total_tokens) }
  ];
}

function extractTrajectoryUsage(text, fileName) {
  const parsed = safeJsonParse(String(text || '').trim());
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.messages)) {
    throw new Error('Attachment must be a valid trajectory.json file.');
  }
  let latestUsage = null;
  parsed.messages.forEach((message) => {
    const usage = message && message.extra && message.extra.usage;
    const cumulative = usage && usage.cumulative_response;
    if (cumulative && typeof cumulative.total_tokens === 'number') {
      latestUsage = cumulative;
    }
  });
  if (!latestUsage) {
    throw new Error('trajectory.json does not contain messages[].extra.usage.cumulative_response.');
  }
  return {
    fileName,
    exactTokens: latestUsage,
    tokenRows: tokenRowsFromTotals(latestUsage),
    tokenSourceLabel: 'Exact tokens from attached trajectory.json.'
  };
}

function applyTrajectoryCompanion(trace, companion) {
  return Object.assign({}, trace, {
    exactTokens: companion.exactTokens,
    tokenRows: companion.tokenRows,
    tokenSourceLabel: companion.tokenSourceLabel,
    tokenModeLabel: 'exact',
    companionFileName: companion.fileName
  });
}

function stripTrajectoryCompanion(trace) {
  const exactTokens = trace.baseExactTokens || null;
  return Object.assign({}, trace, {
    exactTokens,
    tokenRows: exactTokens ? tokenRowsFromTotals(exactTokens) : [{ label: 'availability', value: 'estimate pending' }],
    tokenSourceLabel: trace.baseTokenSourceLabel,
    tokenModeLabel: exactTokens ? 'exact' : 'estimate',
    companionFileName: ''
  });
}

function statusFromExit(exitCode, sessionId, output, done) {
  if (exitCode === 0) {
    return { label: 'ok', css: 'good' };
  }
  if (exitCode !== null && exitCode !== 0) {
    return { label: 'error', css: 'bad' };
  }
  if (done === true) {
    return { label: 'done', css: 'good' };
  }
  if (sessionId || /process running/i.test(String(output || ''))) {
    return { label: 'streaming', css: 'warn' };
  }
  return { label: 'unknown', css: '' };
}

function splitConcatenatedJsonObjects(text) {
  const source = String(text || '');
  const segments = [];
  let start = -1;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (start === -1) {
      if (char === '{') {
        start = index;
        depth = 1;
        inString = false;
        escaped = false;
      }
      continue;
    }
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (char === '\\') {
        escaped = true;
      } else if (char === '"') {
        inString = false;
      }
      continue;
    }
    if (char === '"') {
      inString = true;
      continue;
    }
    if (char === '{') {
      depth += 1;
      continue;
    }
    if (char === '}') {
      depth -= 1;
      if (depth === 0) {
        segments.push(source.slice(start, index + 1));
        start = -1;
      }
    }
  }
  return segments.map((segment) => safeJsonParse(segment)).filter(Boolean);
}

function getTokenizerSelection(value) {
  const [mode, name] = String(value || 'model:o3').split(':');
  const encoding = mode === 'model' ? MODEL_TO_ENCODING[name] || 'o200k_base' : name || 'o200k_base';
  return { mode, name: name || 'o3', encoding };
}

async function loadEncoder(encoding) {
  if (encodingCache.has(encoding)) {
    return encodingCache.get(encoding);
  }
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), 8000);
  let response;
  try {
    response = await fetch(`https://tiktoken.pages.dev/js/${encoding}.json`, {
      signal: controller.signal
    });
  } finally {
    window.clearTimeout(timeoutId);
  }
  if (!response.ok) {
    throw new Error(`Failed to load ${encoding} ranks from CDN`);
  }
  const ranks = await response.json();
  const encoder = new Tiktoken(ranks);
  encodingCache.set(encoding, encoder);
  return encoder;
}

function quickTokenEstimate(text) {
  const source = String(text || '');
  if (!source.trim()) {
    return 0;
  }
  return Math.max(1, Math.ceil(source.length / 4));
}

function mergeEstimateParts(parts) {
  const grouped = new Map();
  for (const part of parts || []) {
    if (!part || !String(part.text || '').trim()) {
      continue;
    }
    const key = part.label || 'other';
    if (!grouped.has(key)) {
      grouped.set(key, []);
    }
    grouped.get(key).push(String(part.text));
  }
  return Array.from(grouped.entries()).map(([label, texts]) => ({
    label,
    text: texts.join('\n\n')
  }));
}

function contentToText(content) {
  if (typeof content === 'string') {
    return content;
  }
  if (Array.isArray(content)) {
    return content.map((part) => {
      if (typeof part === 'string') {
        return part;
      }
      if (part && typeof part === 'object') {
        if (typeof part.text === 'string') {
          return part.text;
        }
        if (typeof part.content === 'string') {
          return part.content;
        }
      }
      return part ? JSON.stringify(part) : '';
    }).filter(Boolean).join('\n\n');
  }
  return content ? JSON.stringify(content) : '';
}

function normalizeObservation(message) {
  const extra = message && message.extra ? message.extra : {};
  if (extra.observation && typeof extra.observation === 'object') {
    return {
      output: String(extra.observation.command_output || ''),
      exitCode: typeof extra.observation.returncode === 'number' ? extra.observation.returncode : parseExitCode(extra.observation.command_output || ''),
      command: String(extra.observation.command || ''),
      success: extra.observation.success
    };
  }
  const text = contentToText(message.content);
  if (!/^Observation:/i.test(text)) {
    return null;
  }
  const outputMatch = text.match(/Command output:\n([\s\S]*)$/i);
  const commandMatch = text.match(/Command:\s*([^\n]+)/i);
  return {
    output: outputMatch ? outputMatch[1].trim() : text,
    exitCode: parseExitCode(text),
    command: commandMatch ? commandMatch[1].trim() : '',
    success: /Status:\s*ok/i.test(text)
  };
}

function stripSessionMarkup(text) {
  return String(text || '')
    .replace(/<details>/gi, '')
    .replace(/<\/details>/gi, '')
    .replace(/<summary>.*?<\/summary>/gis, '')
    .replace(/<sub>.*?<\/sub>/gis, '')
    .replace(/^---$/gm, '')
    .trim();
}

function extractCodeFences(text) {
  const fences = [];
  const regex = /(^|\n)(`{3,})([^\n]*)\n([\s\S]*?)\n\2(?=\n|$)/g;
  let match = regex.exec(text);
  while (match) {
    fences.push({
      fence: match[2],
      language: (match[3] || '').trim(),
      content: match[4]
    });
    match = regex.exec(text);
  }
  return fences;
}

function normalizeCodeLanguage(language) {
  const value = String(language || '').trim().toLowerCase();
  if (!value) {
    return '';
  }
  if (value === 'sh' || value === 'shell' || value === 'zsh') {
    return 'bash';
  }
  if (value === 'py') {
    return 'python';
  }
  if (value === 'patch') {
    return 'diff';
  }
  return value;
}

function looksLikeShell(text) {
  return /(^|\n)\s*(\$ |(?:cd|ls|pwd|cat|rg|sed|find|git|npm|pnpm|yarn|uv|python|python3|bash|sh|chmod|cp|mv|rm)\b)/m.test(String(text || ''));
}

function inferCodeLanguage(text, fallback = '') {
  const normalizedFallback = normalizeCodeLanguage(fallback);
  const source = String(text || '').trim();
  if (!source) {
    return normalizedFallback || 'plaintext';
  }
  if (normalizedFallback) {
    return normalizedFallback;
  }
  if (/^\*\*\* Begin Patch/m.test(source) || /^\*\*\* (Add|Update|Delete) File:/m.test(source)) {
    return 'diff';
  }
  if (looksLikePython(source)) {
    return 'python';
  }
  if (safeJsonParse(source) !== null) {
    return 'json';
  }
  if (looksLikeShell(source)) {
    return 'bash';
  }
  return 'plaintext';
}

function makeTextSection(text, label = '') {
  return { type: 'text', label, text: String(text || '').trim() };
}

function makeCodeSection(text, language = '', label = '') {
  return {
    type: 'code',
    label,
    language: inferCodeLanguage(text, language),
    text: String(text || '').trim()
  };
}

function buildRichTextSections(text, options = {}) {
  const source = String(text || '').trim();
  if (!source) {
    return [];
  }
  if (options.forceCode) {
    return [makeCodeSection(source, options.language || '', options.codeLabel || 'Code')];
  }
  const sections = [];
  const regex = /(^|\n)(`{3,})([^\n]*)\n([\s\S]*?)\n\2(?=\n|$)/g;
  let cursor = 0;
  let match = regex.exec(source);
  while (match) {
    const start = match.index + match[1].length;
    const before = source.slice(cursor, start).trim();
    if (before) {
      sections.push(makeTextSection(before, sections.length ? '' : (options.textLabel || '')));
    }
    const language = normalizeCodeLanguage(match[3]);
    const content = String(match[4] || '').trim();
    if (content) {
      sections.push(makeCodeSection(content, language || options.language || '', options.codeLabel || 'Code'));
    }
    cursor = regex.lastIndex;
    match = regex.exec(source);
  }
  const tail = source.slice(cursor).trim();
  if (tail) {
    sections.push(makeTextSection(tail, sections.length ? '' : (options.textLabel || '')));
  }
  if (!sections.length) {
    if (options.detectCode && (options.language || looksLikePython(source) || looksLikeShell(source) || safeJsonParse(source) !== null)) {
      return [makeCodeSection(source, options.language || '', options.codeLabel || 'Code')];
    }
    return [makeTextSection(source, options.textLabel || '')];
  }
  return sections;
}

function buildCommandSections(command, channel, outputText = '', outputLabel = 'Output') {
  const sections = [];
  const commandText = String(command || '').trim();
  const resultText = String(outputText || '').trim();
  if (commandText) {
    sections.push(makeCodeSection(commandText, inferCodeLanguage(commandText, channel), 'Command'));
  }
  if (resultText) {
    sections.push(makeCodeSection(resultText, inferCodeLanguage(resultText), outputLabel));
  }
  return sections;
}

function createDetailEntry({
  id,
  kind,
  kindLabel,
  summary = '',
  timeLabel = 'n/a',
  chips = [],
  sections = []
}) {
  return {
    id,
    kind,
    kindLabel: kindLabel || kind.replace(/_/g, ' '),
    summary,
    timeLabel,
    chips: uniqueStrings(chips),
    sections: sections.filter((section) => section && String(section.text || '').trim())
  };
}

function extractBoldSummary(text) {
  const match = String(text || '').match(/\*\*([^*\n][\s\S]*?)\*\*/);
  return match ? shortText(match[1].trim(), 140) : '';
}

function extractPatchTargets(patchText) {
  const targets = [];
  const regex = /^\*\*\*\s+(Add|Update|Delete) File:\s+(.+)$/gm;
  let match = regex.exec(String(patchText || ''));
  while (match) {
    targets.push({ action: match[1], path: match[2].trim() });
    match = regex.exec(String(patchText || ''));
  }
  return targets;
}

function summarizePatchTargets(targets) {
  if (!targets.length) {
    return 'apply_patch';
  }
  const first = targets[0];
  const suffix = targets.length > 1 ? ' +' + (targets.length - 1) + ' more' : '';
  return 'apply_patch ' + first.action + ' ' + first.path + suffix;
}

function extractLargeOutputPath(text) {
  const match = String(text || '').match(/Saved to:\s*(\/\S+)/);
  return match ? match[1] : '';
}

function extractSessionMetadata(text) {
  const source = String(text || '');
  const readValue = (label) => {
    const match = source.match(new RegExp('^> - \\*\\*' + label + ':\\*\\*\\s+(.+?)\\s*$', 'm'));
    return match ? match[1].replace(/`/g, '').trim() : '';
  };
  return {
    sessionId: readValue('Session ID'),
    started: readValue('Started'),
    duration: readValue('Duration'),
    exported: readValue('Exported')
  };
}

function looksLikePython(text) {
  return /(from\s+[A-Za-z0-9_\.]+\s+import\s+|import\s+[A-Za-z0-9_\.]+|async\s+def\s+|def\s+[A-Za-z_][A-Za-z0-9_]*\s*\(|class\s+[A-Za-z_][A-Za-z0-9_]*\s*[(:]|asyncio\.run\(|await\s+[A-Za-z_][A-Za-z0-9_\.]*\(|if\s+__name__\s*==\s*['"]__main__['"])/m.test(String(text || ''));
}

function extractPythonHeredocs(text) {
  const blocks = [];
  const regex = /(?:^|\n)[^\n]*\bpython(?:3(?:\.\d+)?)?\s+-\s*<<['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\n([\s\S]*?)\n\1(?=\n|$)/g;
  let match = regex.exec(String(text || ''));
  while (match) {
    const body = String(match[2] || '').trim();
    if (body && looksLikePython(body)) {
      blocks.push({ title: 'python heredoc', text: body, sourceLabel: 'python heredoc' });
    }
    match = regex.exec(String(text || ''));
  }
  return blocks;
}

function extractPythonFromPatch(text) {
  const lines = String(text || '').split(/\r?\n/);
  const blocks = [];
  let active = null;
  const flush = () => {
    if (!active) {
      return;
    }
    const body = active.lines.join('\n').replace(/^\n+|\n+$/g, '');
    if (body && looksLikePython(body)) {
      blocks.push({
        title: active.path,
        text: body,
        sourceLabel: active.action.toLowerCase() + ' patch'
      });
    }
    active = null;
  };
  lines.forEach((line) => {
    const fileMatch = line.match(/^\*\*\*\s+(Add|Update|Delete) File:\s+(.+)$/);
    if (fileMatch) {
      flush();
      const action = fileMatch[1];
      const path = fileMatch[2].trim();
      active = path.endsWith('.py') && action !== 'Delete' ? { action, path, lines: [] } : null;
      return;
    }
    if (!active) {
      return;
    }
    if (/^\*\*\* End Patch$/.test(line)) {
      flush();
      return;
    }
    if (line.startsWith('@@') || line.startsWith('-')) {
      return;
    }
    if (line.startsWith('+')) {
      active.lines.push(line.slice(1));
      return;
    }
    active.lines.push(line);
  });
  flush();
  return blocks;
}

function extractPythonBlocks(text) {
  const blocks = [];
  const rawText = String(text || '').trim();
  extractCodeFences(text).forEach((fence) => {
    const language = String(fence.language || '').toLowerCase();
    const content = String(fence.content || '').trim();
    if (!content) {
      return;
    }
    if (language === 'python' || language === 'py' || (!language && looksLikePython(content))) {
      blocks.push({ title: 'python fence', text: content, sourceLabel: language || 'python fence' });
    }
  });
  blocks.push(...extractPythonHeredocs(text));
  blocks.push(...extractPythonFromPatch(text));
  if (rawText && looksLikePython(rawText)) {
    blocks.push({ title: 'python snippet', text: rawText, sourceLabel: 'python snippet' });
  }
  const seen = new Set();
  return blocks.filter((block) => {
    const key = String(block.text || '').trim();
    if (!key || seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function uniqueStrings(values) {
  return Array.from(new Set((values || []).filter(Boolean)));
}

function appendPythonScripts(target, seen, text, options = {}) {
  extractPythonBlocks(text).forEach((block) => {
    const scriptText = String(block.text || '').trim();
    if (!scriptText || seen.has(scriptText)) {
      return;
    }
    seen.add(scriptText);
    const order = target.length + 1;
    target.push({
      id: (options.idPrefix || 'python-script') + '-' + order,
      order,
      title: block.title || options.title || 'Python script ' + order,
      text: scriptText,
      sections: [makeCodeSection(scriptText, 'python', 'Python')],
      timeLabel: options.timeLabel || 'n/a',
      sourceLabel: options.sourceLabel || block.sourceLabel || '',
      chips: uniqueStrings([options.sourceLabel || block.sourceLabel || 'python'].concat(options.chips || []))
    });
  });
}

function extractActionPayload(record, action = null) {
  const source = record && typeof record === 'object' ? record : {};
  const actionSource = action && typeof action === 'object' ? action : {};
  const bashCommand = String(source.bash_command || actionSource.bash_command || '').trim();
  if (bashCommand) {
    return {
      text: bashCommand,
      field: 'bash_command',
      channel: 'bash_command',
      estimateLabel: 'bash_command fields'
    };
  }
  const pythonCode = String(source.python_code || actionSource.python_code || '').trim();
  if (pythonCode) {
    return {
      text: pythonCode,
      field: 'python_code',
      channel: 'python_code',
      estimateLabel: 'python_code fields'
    };
  }
  const genericCommand = String(source.command || actionSource.command || '').trim();
  if (genericCommand) {
    const looksPython = looksLikePython(genericCommand);
    return {
      text: genericCommand,
      field: 'command',
      channel: looksPython ? 'python_code' : 'command',
      estimateLabel: looksPython ? 'python_code fields' : 'command fields'
    };
  }
  return {
    text: '',
    field: '',
    channel: '',
    estimateLabel: ''
  };
}

function extractModelToolPayload(args, fallbackCommand) {
  if (typeof args === 'string' && args.trim()) {
    return args.trim();
  }
  if (!args || typeof args !== 'object') {
    return String(fallbackCommand || '').trim();
  }
  for (const key of ['input', 'cmd', 'command', 'bash_command']) {
    if (typeof args[key] === 'string' && args[key].trim()) {
      return args[key].trim();
    }
  }
  const picked = {};
  ['query', 'path', 'pattern', 'skill', 'filePath', 'old_path', 'new_path'].forEach((key) => {
    if (typeof args[key] === 'string' && args[key].trim()) {
      picked[key] = args[key].trim();
    }
  });
  if (Array.isArray(args.urls) && args.urls.length) {
    picked.urls = args.urls;
  }
  return Object.keys(picked).length ? JSON.stringify(picked, null, 2) : String(fallbackCommand || '').trim();
}

function extractFirstPath(text) {
  const match = String(text || '').match(/\/(?:[^\s`*]|\\ )+/);
  return match ? match[0].replace(/\\ /g, ' ') : '';
}

function parseMarkdownSections(text) {
  const lines = String(text || '').split(/\r?\n/);
  const sections = [];
  let pendingTime = '';
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    const timeMatch = line.match(/^<sub>.*?⏱️\s*([^<]+)<\/sub>$/);
    if (timeMatch) {
      pendingTime = timeMatch[1].trim();
      index += 1;
      continue;
    }
    const headingMatch = line.match(/^###\s+(ℹ️ Info|👤 User|💬 Copilot|✅\s+`([^`]+)`)\s*$/);
    if (!headingMatch) {
      index += 1;
      continue;
    }
    const tool = headingMatch[2] || '';
    let type = 'info';
    if (tool) {
      type = 'tool';
    } else if (/User/.test(headingMatch[1])) {
      type = 'user';
    } else if (/Copilot/.test(headingMatch[1])) {
      type = 'copilot';
    }
    let cursor = index + 1;
    const bodyLines = [];
    while (cursor < lines.length) {
      if (lines[cursor].match(/^<sub>.*?⏱️/)) {
        break;
      }
      if (lines[cursor].match(/^###\s+(ℹ️ Info|👤 User|💬 Copilot|✅\s+`[^`]+`)\s*$/)) {
        break;
      }
      bodyLines.push(lines[cursor]);
      cursor += 1;
    }
    sections.push({ type, tool, timeLabel: pendingTime || 'n/a', body: bodyLines.join('\n').trim() });
    pendingTime = '';
    index = cursor;
  }
  return sections;
}

function parseSessionToolSection(section, side, commandOrder, eventOrder) {
  const body = section.body || '';
  const fences = extractCodeFences(body);
  const plainBody = stripSessionMarkup(body);
  const title = extractBoldSummary(plainBody);
  const argsFence = fences.find((fence) => fence.language === 'json');
  const parsedArgs = argsFence ? safeJsonParse(argsFence.content.trim()) : null;
  let command = '';
  let output = '';
  let exitCode = null;
  let extraChips = [];
  let payloadText = '';
  if (section.tool === 'bash') {
    const commandFence = fences.find((fence) => /^\$\s/m.test(fence.content));
    const outputFenceIndex = commandFence ? fences.indexOf(commandFence) + 1 : -1;
    command = commandFence ? commandFence.content.replace(/^\$\s?/, '').trim() : '';
    output = outputFenceIndex > 0 && fences[outputFenceIndex] ? fences[outputFenceIndex].content.trim() : plainBody;
    exitCode = parseExitCode(output);
    const savedPath = extractLargeOutputPath(output);
    if (title) {
      extraChips.push(title);
    }
    if (savedPath) {
      extraChips.push('saved output');
    }
    payloadText = command;
  } else if (section.tool === 'apply_patch') {
    const patchValue = typeof parsedArgs === 'string' ? parsedArgs : parsedArgs && typeof parsedArgs.input === 'string' ? parsedArgs.input : '';
    const patchTargets = extractPatchTargets(patchValue);
    command = patchValue ? ('apply_patch\n' + patchValue.trim()) : 'apply_patch';
    output = fences.length > 1 ? fences[fences.length - 1].content.trim() : plainBody;
    extraChips = [summarizePatchTargets(patchTargets)].concat(patchTargets.slice(0, 3).map((target) => target.action.toLowerCase()));
    payloadText = patchValue;
  } else if (section.tool === 'view') {
    const path = extractFirstPath(plainBody);
    command = path ? 'view ' + path : 'view';
    output = fences.length ? fences[fences.length - 1].content.trim() : plainBody;
    if (title) {
      extraChips.push(title);
    }
    payloadText = extractModelToolPayload(parsedArgs, command);
  } else if (section.tool === 'glob') {
    const pattern = fences.length ? fences[0].content.trim() : shortText(plainBody, 120);
    command = pattern ? 'glob ' + pattern : 'glob';
    output = fences.length > 1 ? fences[1].content.trim() : plainBody;
    if (title) {
      extraChips.push(title);
    }
    payloadText = extractModelToolPayload(parsedArgs, command);
  } else if (section.tool === 'skill') {
    const argsText = parsedArgs ? JSON.stringify(parsedArgs) : shortText(plainBody, 160);
    command = 'skill ' + shortText(argsText, 80);
    output = fences.length ? fences[fences.length - 1].content.trim() : plainBody;
    if (title) {
      extraChips.push(title);
    }
    payloadText = extractModelToolPayload(parsedArgs, command);
  } else {
    const path = extractFirstPath(plainBody);
    command = section.tool + (path ? ' ' + path : '');
    output = fences.length ? fences[fences.length - 1].content.trim() : plainBody;
    if (title) {
      extraChips.push(title);
    }
    payloadText = extractModelToolPayload(parsedArgs, command);
  }
  if (!payloadText) {
    payloadText = extractModelToolPayload(parsedArgs, command);
  }
  if (title && section.tool === 'apply_patch') {
    output = (title + '\n' + output).trim();
  }
  const state = statusFromExit(exitCode, '', output, false);
  const pythonScripts = [];
  appendPythonScripts(pythonScripts, new Set(), payloadText, {
    idPrefix: side + '-session-python-' + commandOrder,
    timeLabel: section.timeLabel,
    sourceLabel: section.tool,
    chips: [section.tool]
  });
  return {
    run: {
      id: side + '-session-command-' + commandOrder,
      order: commandOrder,
      command,
      primaryCommand: primaryCommand(command || section.tool),
      channel: section.tool,
      timeLabel: section.timeLabel,
      exitCode,
      outputPreview: shortMultiline(output, 520),
      outputText: output,
      status: state.label,
      statusClass: state.css,
      sections: buildCommandSections(command, section.tool, output)
    },
    events: [
      {
        id: side + '-session-event-' + eventOrder,
        kind: 'tool_call',
        summary: section.tool === 'apply_patch' ? (command || plainBody) : shortMultiline(command || plainBody, 460),
        timeLabel: section.timeLabel,
        chips: [section.tool, primaryCommand(command || section.tool)].concat(extraChips)
      },
      {
        id: side + '-session-event-' + (eventOrder + 1),
        kind: 'tool_result',
        summary: shortMultiline(output || plainBody, 460),
        timeLabel: section.timeLabel,
        chips: [section.tool].concat(exitCode !== null ? ['exit ' + exitCode] : []).concat(extractLargeOutputPath(output) ? ['saved output'] : [])
      }
    ],
    detailEntries: [
      createDetailEntry({
        id: side + '-session-detail-tool-' + commandOrder,
        kind: 'tool',
        kindLabel: 'Tool',
        summary: section.tool === 'apply_patch'
          ? (command || plainBody)
          : shortMultiline(command || output || plainBody, 460),
        timeLabel: section.timeLabel,
        chips: [section.tool, primaryCommand(command || section.tool)]
          .concat(extraChips)
          .concat(exitCode !== null ? ['exit ' + exitCode] : [])
          .concat(extractLargeOutputPath(output) ? ['saved output'] : []),
        sections: buildCommandSections(command || payloadText, section.tool, output || plainBody)
      })
    ],
    estimateParts: [
      title ? { label: 'tool titles', text: title } : null,
      parsedArgs ? { label: 'tool arguments', text: typeof parsedArgs === 'string' ? parsedArgs : JSON.stringify(parsedArgs, null, 2) } : null,
      command ? { label: 'tool commands', text: command } : null,
      output ? { label: 'tool outputs', text: output } : null
    ].filter(Boolean),
    pythonScripts
  };
}

function detectFormat(text) {
  const source = String(text || '').trim();
  if (!source) {
    return null;
  }
  if (/^#\s+🤖\s+Copilot CLI Session/m.test(source) || /^###\s+💬\s+Copilot/m.test(source)) {
    return 'copilot_session_md';
  }
  if (source[0] === '{' || source[0] === '[') {
    const parsed = safeJsonParse(source);
    if (parsed && typeof parsed === 'object' && Array.isArray(parsed.messages) && parsed.info) {
      return 'trajectory_json';
    }
  }
  const lines = source.split(/\r?\n/).filter(Boolean);
  if (!lines.length) {
    return null;
  }
  const first = safeJsonParse(lines[0]);
  if (!first || typeof first !== 'object') {
    return null;
  }
  if (first.timestamp && first.type) {
    return 'codex_jsonl';
  }
  if (first.event === 'raw_text' && typeof first.raw_text === 'string') {
    return 'raw_response_jsonl';
  }
  return null;
}

function finalizeTrace(base) {
  const commandFamilies = toBarRows(countBy(base.commandRuns, (run) => run.primaryCommand));
  const defaultChannelFamilies = toBarRows(countBy(base.events, (event) => event.kind));
  const exactTokens = base.exactTokens || null;
  const tokenSourceLabel = base.tokenSourceLabel || 'Estimated from extracted trace text.';
  return {
    side: base.side,
    kind: base.kind,
    formatLabel: base.formatLabel,
    description: base.description,
    fileName: base.fileName,
    filePath: base.filePath,
    taskPrompt: base.taskPrompt,
    events: base.events,
    thoughtEntries: base.thoughtEntries,
    commandRuns: base.commandRuns,
    finalResponses: base.finalResponses,
    pythonScripts: base.pythonScripts || [],
    detailEntries: base.detailEntries || [],
    metrics: base.metrics,
    commandFamilies,
    channelFamilies: base.channelFamilies || defaultChannelFamilies,
    exactTokens,
    baseExactTokens: exactTokens,
    tokenRows: exactTokens ? tokenRowsFromTotals(exactTokens) : [{ label: 'availability', value: 'estimate pending' }],
    tokenSourceLabel,
    baseTokenSourceLabel: tokenSourceLabel,
    tokenModeLabel: exactTokens ? 'exact' : 'estimate',
    tokenEstimateParts: mergeEstimateParts(base.tokenEstimateParts || []),
    countedFieldLabels: base.countedFieldLabels || [],
    tokenBasisRows: [],
    tokenEstimateTotal: null,
    tokenEstimateError: '',
    tokenSelectionLabel: '',
    companionFileName: '',
    summary: {
      thoughts: base.thoughtEntries.length,
      commands: base.commandRuns.length,
      commandRuns: base.commandRuns.length,
      pythonScripts: (base.pythonScripts || []).length,
      finalResponses: base.finalResponses.length,
      events: base.events.length
    }
  };
}

function normalizeCodex(text, fileName, filePath, side) {
  const lines = text.split(/\r?\n/).filter(Boolean);
  const entries = [];
  const callById = new Map();
  const runByCallId = new Map();
  const runBySession = new Map();
  const commandRuns = [];
  const thoughtEntries = [];
  const finalResponses = [];
  const pythonScripts = [];
  const pythonSeen = new Set();
  const events = [];
  const detailEntries = [];
  const estimateParts = [];
  let latestTokens = null;
  let thoughtOrder = 0;
  let commandOrder = 0;
  let userPrompt = '';
  lines.forEach((line) => {
    const item = safeJsonParse(line);
    if (!item || typeof item !== 'object') {
      return;
    }
    entries.push(item);
    if (item.type === 'event_msg' && item.payload && item.payload.type === 'token_count') {
      latestTokens = item.payload.info ? item.payload.info.total_token_usage : null;
    }
  });
  entries.forEach((item, index) => {
    const id = side + '-codex-' + index;
    const timeLabel = formatTimestamp(item.timestamp || '');
    if (item.type === 'event_msg' && item.payload && item.payload.type === 'user_message') {
      const summary = shortMultiline(item.payload.message, 360);
      if (!userPrompt) {
        userPrompt = summary;
      }
      estimateParts.push({ label: 'user messages', text: String(item.payload.message || '') });
      events.push({ id, kind: 'user_message', summary, timeLabel, chips: ['user'] });
      detailEntries.push(createDetailEntry({
        id: id + '-detail',
        kind: 'user_message',
        kindLabel: 'User',
        summary,
        timeLabel,
        chips: ['user'],
        sections: buildRichTextSections(item.payload.message, { textLabel: 'Prompt' })
      }));
      return;
    }
    if (item.type === 'event_msg' && item.payload && item.payload.type === 'agent_message') {
      thoughtOrder += 1;
      const textBody = shortMultiline(item.payload.message, 520);
      thoughtEntries.push({
        id,
        order: thoughtOrder,
        text: textBody,
        timeLabel,
        chips: [item.payload.phase || 'commentary'],
        sections: buildRichTextSections(item.payload.message, { textLabel: 'Reasoning', detectCode: true })
      });
      estimateParts.push({ label: 'agent messages', text: String(item.payload.message || '') });
      appendPythonScripts(pythonScripts, pythonSeen, item.payload.message, {
        idPrefix: side + '-codex-python',
        timeLabel,
        sourceLabel: 'agent message',
        chips: [item.payload.phase || 'commentary']
      });
      events.push({ id, kind: 'thought', summary: textBody, timeLabel, chips: [item.payload.phase || 'commentary'] });
      detailEntries.push(createDetailEntry({
        id: id + '-detail',
        kind: 'thought',
        kindLabel: 'Thought',
        summary: textBody,
        timeLabel,
        chips: [item.payload.phase || 'commentary'],
        sections: buildRichTextSections(item.payload.message, { textLabel: 'Reasoning', detectCode: true })
      }));
      if (/final|answer|result/i.test(item.payload.phase || '') && textBody) {
        finalResponses.push({ id: id + '-final', order: finalResponses.length + 1, text: textBody, timeLabel });
      }
      return;
    }
    if (item.type === 'event_msg' && item.payload && item.payload.type === 'token_count') {
      const total = item.payload.info && item.payload.info.total_token_usage ? item.payload.info.total_token_usage : {};
      events.push({
        id,
        kind: 'token_snapshot',
        summary: 'total=' + numberFormat(total.total_tokens) + ', input=' + numberFormat(total.input_tokens) + ', output=' + numberFormat(total.output_tokens),
        timeLabel,
        chips: ['tokens']
      });
      return;
    }
    if (item.type === 'response_item' && item.payload && item.payload.type === 'function_call') {
      const args = parseArguments(item.payload.arguments);
      const tool = item.payload.name || 'unknown';
      const command = args.cmd || args.command || args.bash_command || '';
      const payloadText = extractModelToolPayload(args, command);
      callById.set(item.payload.call_id, { tool, args, command });
      if (command) {
        commandOrder += 1;
        const run = {
          id: item.payload.call_id,
          order: commandOrder,
          command,
          primaryCommand: primaryCommand(command),
          channel: tool,
          timeLabel,
          exitCode: null,
          outputPreview: '',
          sessionId: '',
          status: 'started',
          statusClass: '',
          outputText: '',
          sections: buildCommandSections(command, tool)
        };
        commandRuns.push(run);
        runByCallId.set(item.payload.call_id, run);
      }
      if (payloadText) {
        estimateParts.push({ label: 'model-emitted tool payloads', text: payloadText });
        appendPythonScripts(pythonScripts, pythonSeen, payloadText, {
          idPrefix: side + '-codex-python',
          timeLabel,
          sourceLabel: tool,
          chips: [tool]
        });
      }
      events.push({
        id,
        kind: 'tool_call',
        summary: command ? shortMultiline(command, 420) : shortText(JSON.stringify(args), 240),
        timeLabel,
        chips: command ? [tool, primaryCommand(command)] : [tool]
      });
      detailEntries.push(createDetailEntry({
        id: id + '-detail',
        kind: 'tool_call',
        kindLabel: 'Tool Call',
        summary: command ? shortMultiline(command, 420) : shortText(JSON.stringify(args), 240),
        timeLabel,
        chips: command ? [tool, primaryCommand(command)] : [tool],
        sections: command
          ? buildCommandSections(command, tool)
          : [makeCodeSection(JSON.stringify(args, null, 2), 'json', 'Arguments')]
      }));
      return;
    }
    if (item.type === 'response_item' && item.payload && item.payload.type === 'function_call_output') {
      const call = callById.get(item.payload.call_id) || {};
      const outputText = Array.isArray(item.payload.output) ? JSON.stringify(item.payload.output) : String(item.payload.output || '');
      const exitCode = parseExitCode(outputText);
      const sessionId = parseSessionId(outputText);
      let run = runByCallId.get(item.payload.call_id) || null;
      if (!run && call.tool === 'write_stdin' && call.args && call.args.session_id) {
        run = runBySession.get(String(call.args.session_id)) || null;
      }
      if (run) {
        if (sessionId && !run.sessionId) {
          run.sessionId = sessionId;
          runBySession.set(sessionId, run);
        }
        if (exitCode !== null) {
          run.exitCode = exitCode;
        }
        if (outputText) {
          run.outputPreview = shortMultiline(outputText, 520);
          run.outputText = outputText;
          run.sections = buildCommandSections(run.command, run.channel, outputText);
        }
        const state = statusFromExit(run.exitCode, sessionId, outputText, false);
        run.status = state.label;
        run.statusClass = state.css;
      }
      if (outputText) {
        estimateParts.push({ label: 'tool outputs', text: outputText });
      }
      events.push({
        id,
        kind: 'tool_result',
        summary: shortMultiline(outputText, 460),
        timeLabel,
        chips: [call.tool || 'tool_result'].concat(exitCode !== null ? ['exit ' + exitCode] : sessionId ? ['session ' + sessionId] : [])
      });
      detailEntries.push(createDetailEntry({
        id: id + '-detail',
        kind: 'tool_result',
        kindLabel: 'Tool Result',
        summary: shortMultiline(outputText, 460),
        timeLabel,
        chips: [call.tool || 'tool_result'].concat(exitCode !== null ? ['exit ' + exitCode] : sessionId ? ['session ' + sessionId] : []),
        sections: [makeCodeSection(outputText, inferCodeLanguage(outputText), 'Output')]
      }));
    }
  });
  commandRuns.forEach((run) => {
    if (run.status === 'started') {
      const state = statusFromExit(run.exitCode, '', run.outputPreview, false);
      run.status = state.label;
      run.statusClass = state.css;
    }
  });
  const channelFamilies = toBarRows([
    { label: 'thought entries', value: thoughtEntries.length },
    { label: 'command runs', value: commandRuns.length },
    { label: 'tool results', value: events.filter((event) => event.kind === 'tool_result').length },
    { label: 'token snapshots', value: events.filter((event) => event.kind === 'token_snapshot').length },
    { label: 'final responses', value: finalResponses.length }
  ]);
  return finalizeTrace({
    side,
    kind: 'codex_jsonl',
    formatLabel: 'Codex JSONL',
    description: 'Codex CLI session JSONL with user, agent, tool, and token events.',
    fileName,
    filePath,
    taskPrompt: userPrompt,
    events,
    thoughtEntries,
    commandRuns,
    finalResponses,
    pythonScripts,
    detailEntries,
    exactTokens: latestTokens,
    tokenSourceLabel: latestTokens
      ? 'Exact tokens from token_count snapshot.'
      : 'Estimated from extracted trace text.',
    tokenEstimateParts: estimateParts,
    countedFieldLabels: [
      'event_msg.user_message.message',
      'event_msg.agent_message.message',
      'response_item.function_call.arguments.(cmd|command|bash_command)',
      'response_item.function_call_output.output'
    ],
    metrics: [
      { label: 'Events', value: numberFormat(events.length), sub: 'normalized event records' },
      { label: 'Thoughts', value: numberFormat(thoughtEntries.length), sub: 'agent commentary entries' },
      { label: 'Commands', value: numberFormat(commandRuns.length), sub: 'shell commands reconstructed from tool calls' },
      { label: 'Token source', value: latestTokens ? 'exact' : 'estimate', sub: latestTokens ? 'token_count snapshot present' : 'fallback to tokenizer estimate' }
    ],
    channelFamilies
  });
}

function normalizeRawResponses(text, fileName, filePath, side) {
  const lines = text.split(/\r?\n/).filter(Boolean);
  const events = [];
  const thoughtEntries = [];
  const commandRuns = [];
  const finalResponses = [];
  const pythonScripts = [];
  const pythonSeen = new Set();
  const detailEntries = [];
  const estimateParts = [];
  let thoughtOrder = 0;
  let commandOrder = 0;
  let finalOrder = 0;
  let extractedFrames = 0;
  let emptyFrames = 0;
  let taskPrompt = '';
  lines.forEach((line, lineIndex) => {
    const outer = safeJsonParse(line);
    if (!outer || typeof outer !== 'object') {
      return;
    }
    const timeLabel = formatTimestamp(outer.timestamp || '');
    if (outer.event !== 'raw_text') {
      return;
    }
    const frames = splitConcatenatedJsonObjects(outer.raw_text);
    frames.forEach((frame, frameIndex) => {
      const idBase = side + '-raw-' + lineIndex + '-' + frameIndex;
      const actionPayload = extractActionPayload(frame);
      const hasThought = !!String(frame.thought || '').trim();
      const hasCommand = !!actionPayload.text;
      const hasFinal = !!String(frame.final_response || '').trim();
      const frameSections = [];
      const frameChips = ['attempt ' + (outer.attempt || 'n/a')];
      if (!hasThought && !hasCommand && !hasFinal) {
        emptyFrames += 1;
        return;
      }
      extractedFrames += 1;
      if (hasThought) {
        thoughtOrder += 1;
        const textBody = shortMultiline(frame.thought, 520);
        thoughtEntries.push({
          id: idBase + '-thought',
          order: thoughtOrder,
          text: textBody,
          timeLabel,
          chips: ['attempt ' + (outer.attempt || 'n/a')],
          sections: buildRichTextSections(frame.thought, { textLabel: 'Reasoning', detectCode: true })
        });
        estimateParts.push({ label: 'thought fields', text: String(frame.thought || '') });
        appendPythonScripts(pythonScripts, pythonSeen, frame.thought, {
          idPrefix: side + '-raw-python',
          timeLabel,
          sourceLabel: 'thought field',
          chips: ['attempt ' + (outer.attempt || 'n/a')]
        });
        events.push({ id: idBase + '-thought-event', kind: 'thought', summary: textBody, timeLabel, chips: ['attempt ' + (outer.attempt || 'n/a')] });
        if (!taskPrompt && /task|search|goal/i.test(textBody)) {
          taskPrompt = textBody;
        }
        frameSections.push(...buildRichTextSections(frame.thought, { textLabel: 'Reasoning', detectCode: true }));
      }
      if (hasCommand) {
        commandOrder += 1;
        const command = actionPayload.text;
        const state = statusFromExit(null, '', '', frame.done === true);
        commandRuns.push({
          id: idBase + '-command',
          order: commandOrder,
          command,
          primaryCommand: primaryCommand(command),
          channel: actionPayload.channel,
          timeLabel,
          exitCode: null,
          outputPreview: hasFinal ? shortMultiline(frame.final_response, 320) : '',
          outputText: hasFinal ? String(frame.final_response || '').trim() : '',
          status: state.label,
          statusClass: state.css,
          sections: buildCommandSections(command, actionPayload.channel, hasFinal ? String(frame.final_response || '') : '', hasFinal ? 'Result' : 'Output')
        });
        estimateParts.push({ label: actionPayload.estimateLabel, text: command });
        appendPythonScripts(pythonScripts, pythonSeen, command, {
          idPrefix: side + '-raw-python',
          timeLabel,
          sourceLabel: actionPayload.field || actionPayload.channel || 'command',
          chips: ['attempt ' + (outer.attempt || 'n/a')]
        });
        events.push({ id: idBase + '-command-event', kind: 'command', summary: shortMultiline(command, 460), timeLabel, chips: ['attempt ' + (outer.attempt || 'n/a'), primaryCommand(command)] });
        frameSections.push(makeCodeSection(command, actionPayload.channel, 'Command'));
        frameChips.push(primaryCommand(command));
      }
      if (hasFinal) {
        finalOrder += 1;
        const responseText = shortMultiline(frame.final_response, 520);
        finalResponses.push({ id: idBase + '-final', order: finalOrder, text: responseText, timeLabel });
        estimateParts.push({ label: 'final_response fields', text: String(frame.final_response || '') });
        appendPythonScripts(pythonScripts, pythonSeen, frame.final_response, {
          idPrefix: side + '-raw-python',
          timeLabel,
          sourceLabel: 'final_response',
          chips: ['done=' + Boolean(frame.done)]
        });
        events.push({ id: idBase + '-final-event', kind: 'final_response', summary: responseText, timeLabel, chips: ['done=' + Boolean(frame.done)] });
        frameSections.push(...buildRichTextSections(frame.final_response, { textLabel: 'Response', detectCode: true }));
        frameChips.push('done=' + Boolean(frame.done));
      }
      detailEntries.push(createDetailEntry({
        id: idBase + '-frame-detail',
        kind: 'frame',
        kindLabel: 'Step',
        summary: shortMultiline(
          actionPayload.text || String(frame.final_response || '') || String(frame.thought || ''),
          460
        ),
        timeLabel,
        chips: frameChips,
        sections: frameSections
      }));
    });
  });
  const channelFamilies = toBarRows([
    { label: 'thought entries', value: thoughtEntries.length },
    { label: 'command frames', value: commandRuns.length },
    { label: 'final responses', value: finalResponses.length },
    { label: 'outer lines', value: lines.length },
    { label: 'empty frames dropped', value: emptyFrames }
  ]);
  return finalizeTrace({
    side,
    kind: 'raw_response_jsonl',
    formatLabel: 'Webwright Responses JSONL',
    description: 'Webwright raw_responses.jsonl with embedded thought, bash, and final-response frames.',
    fileName,
    filePath,
    taskPrompt,
    events,
    thoughtEntries,
    commandRuns,
    finalResponses,
    pythonScripts,
    detailEntries,
    tokenSourceLabel: 'Estimated from extracted trace text.',
    tokenEstimateParts: estimateParts,
    countedFieldLabels: ['raw_text frame.thought', 'raw_text frame.bash_command', 'raw_text frame.python_code', 'raw_text frame.final_response'],
    metrics: [
      { label: 'Outer lines', value: numberFormat(lines.length), sub: 'top-level raw_text records' },
      { label: 'Frames', value: numberFormat(extractedFrames), sub: 'embedded JSON frames extracted from raw_text' },
      { label: 'Thoughts', value: numberFormat(thoughtEntries.length), sub: 'inner thought strings' },
      { label: 'Commands', value: numberFormat(commandRuns.length), sub: 'inner action strings' }
    ],
    channelFamilies
  });
}

function normalizeTrajectory(text, fileName, filePath, side) {
  const parsed = safeJsonParse(text);
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.messages)) {
    throw new Error('Invalid trajectory.json structure');
  }
  const events = [];
  const thoughtEntries = [];
  const commandRuns = [];
  const finalResponses = [];
  const pythonScripts = [];
  const pythonSeen = new Set();
  const detailEntries = [];
  const estimateParts = [];
  let latestTokens = null;
  let taskPrompt = '';
  let thoughtOrder = 0;
  let commandOrder = 0;
  let finalOrder = 0;
  let pendingRun = null;
  parsed.messages.forEach((message, index) => {
    const id = side + '-trajectory-' + index;
    const timeLabel = 'step ' + (index + 1);
    const role = message.role || 'unknown';
    const contentText = contentToText(message.content);
    if (role === 'user') {
      const observation = normalizeObservation(message);
      if (observation && pendingRun) {
        if (observation.command && !pendingRun.command) {
          pendingRun.command = observation.command;
          pendingRun.primaryCommand = primaryCommand(observation.command);
        }
        pendingRun.exitCode = observation.exitCode;
        pendingRun.outputPreview = shortMultiline(observation.output, 520);
        pendingRun.outputText = observation.output;
        const state = statusFromExit(observation.exitCode, '', observation.output, false);
        pendingRun.status = state.label;
        pendingRun.statusClass = state.css;
        pendingRun.sections = buildCommandSections(pendingRun.command, pendingRun.channel, observation.output);
        estimateParts.push({ label: 'observation outputs', text: observation.output });
        events.push({ id, kind: 'observation', summary: shortMultiline(observation.output, 460), timeLabel, chips: observation.exitCode !== null ? ['exit ' + observation.exitCode] : ['observation'] });
        detailEntries.push(createDetailEntry({
          id: id + '-observation-detail',
          kind: 'observation',
          kindLabel: 'Observation',
          summary: shortMultiline(observation.output, 460),
          timeLabel,
          chips: observation.exitCode !== null ? ['exit ' + observation.exitCode] : ['observation'],
          sections: [makeCodeSection(observation.output, inferCodeLanguage(observation.output), 'Output')]
        }));
      } else if (contentText) {
        if (!taskPrompt) {
          taskPrompt = shortMultiline(contentText, 360);
        }
        estimateParts.push({ label: 'user messages', text: contentText });
        events.push({ id, kind: 'user_message', summary: shortMultiline(contentText, 420), timeLabel, chips: ['user'] });
        detailEntries.push(createDetailEntry({
          id: id + '-detail',
          kind: 'user_message',
          kindLabel: 'User',
          summary: shortMultiline(contentText, 420),
          timeLabel,
          chips: ['user'],
          sections: buildRichTextSections(contentText, { textLabel: 'Prompt' })
        }));
      }
      return;
    }
    if (role !== 'assistant') {
      return;
    }
    const extra = message.extra || {};
    const raw = extra.raw_response && typeof extra.raw_response === 'object' ? extra.raw_response : {};
    const usage = extra.usage && typeof extra.usage === 'object' ? (extra.usage.cumulative_response || extra.usage.last_response || extra.usage) : null;
    if (usage && typeof usage.total_tokens === 'number') {
      latestTokens = usage;
    }
    const thoughtText = String(raw.thought || contentText || '').trim();
    const action = Array.isArray(extra.actions) && extra.actions.length ? extra.actions[0] : null;
    const actionPayload = extractActionPayload(raw, action);
    const commandText = actionPayload.text;
    const finalText = String(raw.final_response || '').trim();
    const done = raw.done === true || extra.done === true;
    if (thoughtText) {
      thoughtOrder += 1;
      estimateParts.push({ label: 'assistant thoughts', text: thoughtText });
      appendPythonScripts(pythonScripts, pythonSeen, thoughtText, {
        idPrefix: side + '-trajectory-python',
        timeLabel,
        sourceLabel: 'assistant thought',
        chips: [done ? 'done' : 'assistant']
      });
      thoughtEntries.push({
        id: id + '-thought',
        order: thoughtOrder,
        text: shortMultiline(thoughtText, 520),
        timeLabel,
        chips: [done ? 'done' : 'assistant'],
        sections: buildRichTextSections(thoughtText, { textLabel: 'Reasoning', detectCode: true })
      });
      events.push({ id: id + '-thought-event', kind: 'thought', summary: shortMultiline(thoughtText, 460), timeLabel, chips: [done ? 'done' : 'assistant'] });
      detailEntries.push(createDetailEntry({
        id: id + '-thought-detail',
        kind: 'thought',
        kindLabel: 'Thought',
        summary: shortMultiline(thoughtText, 460),
        timeLabel,
        chips: [done ? 'done' : 'assistant'],
        sections: buildRichTextSections(thoughtText, { textLabel: 'Reasoning', detectCode: true })
      }));
    }
    if (commandText) {
      commandOrder += 1;
      const run = {
        id: id + '-command',
        order: commandOrder,
        command: commandText,
        primaryCommand: primaryCommand(commandText),
        channel: actionPayload.channel,
        timeLabel,
        exitCode: null,
        outputPreview: '',
        outputText: '',
        status: 'started',
        statusClass: '',
        sections: buildCommandSections(commandText, actionPayload.channel)
      };
      pendingRun = run;
      commandRuns.push(run);
      estimateParts.push({ label: actionPayload.estimateLabel || 'assistant commands', text: commandText });
      appendPythonScripts(pythonScripts, pythonSeen, commandText, {
        idPrefix: side + '-trajectory-python',
        timeLabel,
        sourceLabel: actionPayload.field || actionPayload.channel || 'assistant command',
        chips: ['assistant', primaryCommand(commandText)]
      });
      events.push({ id: id + '-command-event', kind: 'command', summary: shortMultiline(commandText, 460), timeLabel, chips: ['assistant', primaryCommand(commandText)] });
      detailEntries.push(createDetailEntry({
        id: id + '-command-detail',
        kind: 'command',
        kindLabel: 'Command',
        summary: shortMultiline(commandText, 460),
        timeLabel,
        chips: ['assistant', primaryCommand(commandText)],
        sections: buildCommandSections(commandText, actionPayload.channel)
      }));
    }
    if (finalText) {
      finalOrder += 1;
      estimateParts.push({ label: 'assistant final responses', text: finalText });
      appendPythonScripts(pythonScripts, pythonSeen, finalText, {
        idPrefix: side + '-trajectory-python',
        timeLabel,
        sourceLabel: 'assistant final response',
        chips: ['done=' + done]
      });
      finalResponses.push({ id: id + '-final', order: finalOrder, text: shortMultiline(finalText, 520), timeLabel });
      events.push({ id: id + '-final-event', kind: 'final_response', summary: shortMultiline(finalText, 460), timeLabel, chips: ['done=' + done] });
      detailEntries.push(createDetailEntry({
        id: id + '-final-detail',
        kind: 'final_response',
        kindLabel: 'Final Response',
        summary: shortMultiline(finalText, 460),
        timeLabel,
        chips: ['done=' + done],
        sections: buildRichTextSections(finalText, { textLabel: 'Response', detectCode: true })
      }));
    }
  });
  commandRuns.forEach((run) => {
    if (run.status === 'started') {
      const state = statusFromExit(run.exitCode, '', run.outputPreview, false);
      run.status = state.label;
      run.statusClass = state.css;
    }
  });
  return finalizeTrace({
    side,
    kind: 'trajectory_json',
    formatLabel: 'Trajectory JSON',
    description: 'Webwright trajectory.json transcript with assistant actions, observations, and usage snapshots.',
    fileName,
    filePath,
    taskPrompt,
    events,
    thoughtEntries,
    commandRuns,
    finalResponses,
    pythonScripts,
    detailEntries,
    exactTokens: latestTokens,
    tokenSourceLabel: latestTokens
      ? 'Exact tokens from usage snapshot.'
      : 'Estimated from extracted trace text.',
    tokenEstimateParts: estimateParts,
    countedFieldLabels: [
      'messages[].content',
      'messages[].extra.raw_response.thought',
      'messages[].extra.raw_response.bash_command',
      'messages[].extra.raw_response.python_code',
      'messages[].extra.raw_response.final_response',
      'messages[].extra.observation.command_output'
    ],
    metrics: [
      { label: 'Messages', value: numberFormat(parsed.messages.length), sub: 'top-level transcript turns' },
      { label: 'Thoughts', value: numberFormat(thoughtEntries.length), sub: 'assistant reasoning entries' },
      { label: 'Commands', value: numberFormat(commandRuns.length), sub: 'assistant action commands' },
      { label: 'API calls', value: numberFormat(parsed.info && parsed.info.api_calls), sub: 'info.api_calls from trajectory metadata' }
    ]
  });
}

function normalizeCopilotSessionMarkdown(text, fileName, filePath, side) {
  const sections = parseMarkdownSections(text);
  const metadata = extractSessionMetadata(text);
  const events = [];
  const thoughtEntries = [];
  const commandRuns = [];
  const finalResponses = [];
  const pythonScripts = [];
  const pythonSeen = new Set();
  const detailEntries = [];
  const estimateParts = [];
  let taskPrompt = '';
  let thoughtOrder = 0;
  let commandOrder = 0;
  let eventOrder = 0;
  if (metadata.sessionId || metadata.duration || metadata.started || metadata.exported) {
    const summary = [
      metadata.sessionId ? 'session ' + metadata.sessionId : '',
      metadata.started ? 'started ' + metadata.started : '',
      metadata.duration ? 'duration ' + metadata.duration : '',
      metadata.exported ? 'exported ' + metadata.exported : ''
    ].filter(Boolean).join(' | ');
    events.push({
      id: side + '-session-meta',
      kind: 'info',
      summary,
      timeLabel: 'session',
      chips: ['session metadata']
    });
    eventOrder += 1;
  }
  sections.forEach((section) => {
    if (section.type === 'user') {
      const clean = stripSessionMarkup(section.body);
      const textBody = shortMultiline(clean, 520);
      if (!taskPrompt && textBody) {
        taskPrompt = textBody;
      }
      if (clean) {
        estimateParts.push({ label: 'user sections', text: clean });
        events.push({ id: side + '-session-user-' + eventOrder, kind: 'user_message', summary: textBody, timeLabel: section.timeLabel, chips: ['user'] });
        detailEntries.push(createDetailEntry({
          id: side + '-session-user-detail-' + eventOrder,
          kind: 'user_message',
          kindLabel: 'User',
          summary: textBody,
          timeLabel: section.timeLabel,
          chips: ['user'],
          sections: buildRichTextSections(clean, { textLabel: 'Prompt', detectCode: true })
        }));
        eventOrder += 1;
      }
      return;
    }
    if (section.type === 'copilot') {
      const clean = stripSessionMarkup(section.body);
      if (!clean) {
        return;
      }
      thoughtOrder += 1;
      estimateParts.push({ label: 'copilot sections', text: clean });
      appendPythonScripts(pythonScripts, pythonSeen, clean, {
        idPrefix: side + '-session-python',
        timeLabel: section.timeLabel,
        sourceLabel: 'copilot section',
        chips: ['copilot']
      });
      thoughtEntries.push({
        id: side + '-session-thought-' + thoughtOrder,
        order: thoughtOrder,
        text: shortMultiline(clean, 520),
        timeLabel: section.timeLabel,
        chips: ['copilot'],
        sections: buildRichTextSections(clean, { textLabel: 'Narrative', detectCode: true })
      });
      events.push({ id: side + '-session-copilot-' + eventOrder, kind: 'thought', summary: shortMultiline(clean, 460), timeLabel: section.timeLabel, chips: ['copilot'] });
      detailEntries.push(createDetailEntry({
        id: side + '-session-copilot-detail-' + eventOrder,
        kind: 'thought',
        kindLabel: 'Copilot',
        summary: shortMultiline(clean, 460),
        timeLabel: section.timeLabel,
        chips: ['copilot'],
        sections: buildRichTextSections(clean, { textLabel: 'Narrative', detectCode: true })
      }));
      eventOrder += 1;
      if (/final|done|complete|result/i.test(clean)) {
        finalResponses.push({ id: side + '-session-final-' + finalResponses.length, order: finalResponses.length + 1, text: shortMultiline(clean, 520), timeLabel: section.timeLabel });
      }
      return;
    }
    if (section.type === 'tool') {
      commandOrder += 1;
      const parsed = parseSessionToolSection(section, side, commandOrder, eventOrder);
      commandRuns.push(parsed.run);
      parsed.events.forEach((event) => events.push(event));
      parsed.detailEntries.forEach((entry) => detailEntries.push(entry));
      estimateParts.push(...parsed.estimateParts);
      parsed.pythonScripts.forEach((script) => {
        if (pythonSeen.has(script.text)) {
          return;
        }
        pythonSeen.add(script.text);
        pythonScripts.push(Object.assign({}, script, {
          id: side + '-session-python-' + (pythonScripts.length + 1),
          order: pythonScripts.length + 1
        }));
      });
      eventOrder += parsed.events.length;
      return;
    }
    const infoText = stripSessionMarkup(section.body);
    if (infoText) {
      events.push({ id: side + '-session-info-' + eventOrder, kind: 'info', summary: shortMultiline(infoText, 420), timeLabel: section.timeLabel, chips: ['info'] });
      eventOrder += 1;
    }
  });
  const channelFamilies = toBarRows([
    { label: 'user sections', value: events.filter((event) => event.kind === 'user_message').length },
    { label: 'copilot sections', value: thoughtEntries.length },
    { label: 'tool sections', value: commandRuns.length },
    { label: 'info sections', value: events.filter((event) => event.kind === 'info').length }
  ]);
  return finalizeTrace({
    side,
    kind: 'copilot_session_md',
    formatLabel: 'Copilot Session MD',
    description: 'GitHub Copilot CLI markdown session export with user, copilot, and tool sections.',
    fileName,
    filePath,
    taskPrompt,
    events,
    thoughtEntries,
    commandRuns,
    finalResponses,
    pythonScripts,
    detailEntries,
    tokenSourceLabel: 'Estimated from extracted trace text.',
    tokenEstimateParts: estimateParts,
    countedFieldLabels: ['session header metadata', '### User body text', '### Copilot body text', 'tool titles', '### ✅ tool Arguments blocks', '### ✅ tool commands / outputs'],
    metrics: [
      { label: 'Sections', value: numberFormat(sections.length), sub: 'top-level markdown sections' },
      { label: 'Thoughts', value: numberFormat(thoughtEntries.length), sub: 'copilot narrative blocks' },
      { label: 'Commands', value: numberFormat(commandRuns.length), sub: 'tool sections mapped to comparable command rows' },
      { label: 'Finals', value: numberFormat(finalResponses.length), sub: 'copilot blocks that look like terminal summaries' },
      { label: 'Session duration', value: metadata.duration || 'n/a', sub: metadata.started ? 'started ' + metadata.started : 'header metadata if present' }
    ],
    channelFamilies
  });
}

function normalizeTrace(text, fileName, filePath, side) {
  const format = detectFormat(text);
  if (!format) {
    throw new Error('Supported inputs: Codex JSONL, Webwright Responses JSONL (raw_responses.jsonl), trajectory.json, and Copilot session markdown.');
  }
  if (format === 'codex_jsonl') {
    return normalizeCodex(text, fileName, filePath, side);
  }
  if (format === 'raw_response_jsonl') {
    return normalizeRawResponses(text, fileName, filePath, side);
  }
  if (format === 'trajectory_json') {
    return normalizeTrajectory(text, fileName, filePath, side);
  }
  return normalizeCopilotSessionMarkdown(text, fileName, filePath, side);
}

const app = createApp({
  data() {
    return {
      activeView: 'summary',
      traceTab: 'python',
      dragTarget: null,
      left: null,
      right: null,
      errors: { left: '', right: '' },
      attachmentErrors: { left: '', right: '' },
      tokenTarget: 'model:o3',
      tokenizerStatus: 'Ready.'
    };
  },
  computed: {
    slots() {
      return [
        { key: 'left', title: 'Trace A', subtitle: 'Load Codex JSONL, Webwright Responses JSONL (raw_responses.jsonl), trajectory.json, or Copilot session markdown on this side.' },
        { key: 'right', title: 'Trace B', subtitle: 'Load a second trace and compare thoughts, commands, token source, and extracted outputs.' }
      ];
    },
    tokenizerOptions() {
      return [
        { value: 'model:o3', label: 'o3' },
        { value: 'model:o3-mini', label: 'o3-mini' },
        { value: 'model:gpt-4o', label: 'gpt-4o' },
        { value: 'encoding:o200k_base', label: 'o200k_base' },
        { value: 'encoding:cl100k_base', label: 'cl100k_base' }
      ];
    },
    bothLoaded() {
      return !!(this.left && this.right);
    },
    hasAnyTrace() {
      return !!(this.left || this.right);
    },
    loadedTraces() {
      return [this.left, this.right].filter(Boolean);
    },
    leftTrace() {
      return this.left;
    },
    rightTrace() {
      return this.right;
    },
    detailTabs() {
      return [
        { label: 'Python Scripts', value: 'python' },
        { label: 'Thoughts', value: 'thoughts' },
        { label: 'Commands', value: 'commands' },
        { label: 'All', value: 'all' }
      ];
    },
    comparisonRows() {
      if (!this.bothLoaded) {
        return [];
      }
      return [
        { label: 'Format', left: this.left.formatLabel, right: this.right.formatLabel },
        { label: 'Thought entries', left: numberFormat(this.left.thoughtEntries.length), right: numberFormat(this.right.thoughtEntries.length) },
        { label: 'Command runs', left: numberFormat(this.left.commandRuns.length), right: numberFormat(this.right.commandRuns.length) },
        { label: 'Final responses', left: numberFormat(this.left.finalResponses.length), right: numberFormat(this.right.finalResponses.length) },
        { label: 'Python scripts', left: numberFormat(this.left.pythonScripts.length), right: numberFormat(this.right.pythonScripts.length) },
        { label: 'Token total', left: this.tokenTotalDisplay(this.left), right: this.tokenTotalDisplay(this.right) },
        { label: 'Token source', left: this.left.tokenModeLabel, right: this.right.tokenModeLabel },
        { label: 'Counted fields', left: this.left.countedFieldLabels.join(', '), right: this.right.countedFieldLabels.join(', ') },
        {
          label: 'Top command families',
          left: this.left.commandFamilies.map((row) => row.label + ' ' + row.value).join(', '),
          right: this.right.commandFamilies.map((row) => row.label + ' ' + row.value).join(', ')
        },
        { label: 'Task hint', left: this.left.taskPrompt || 'n/a', right: this.right.taskPrompt || 'n/a' }
      ];
    },
    tokenizerSelectionLabel() {
      const selection = getTokenizerSelection(this.tokenTarget);
      return selection.mode === 'model' ? selection.name + ' -> ' + selection.encoding : selection.encoding;
    }
  },
  watch: {
    tokenTarget() {
      this.refreshAllTokens();
    }
  },
  mounted() {
    this.highlightRenderedCode();
  },
  updated() {
    this.highlightRenderedCode();
  },
  methods: {
    codeClass(language) {
      return 'language-' + (normalizeCodeLanguage(language) || 'plaintext');
    },
    shouldShowEntrySummary(entry) {
      if (!entry || !String(entry.summary || '').trim()) {
        return false;
      }
      if (entry.kind === 'frame' && Array.isArray(entry.sections) && entry.sections.length) {
        return false;
      }
      const sections = Array.isArray(entry.sections) ? entry.sections : [];
      if (sections.length !== 1) {
        return true;
      }
      const onlySection = sections[0];
      if (!onlySection || onlySection.type !== 'text') {
        return true;
      }
      return shortMultiline(onlySection.text, 460) !== shortMultiline(entry.summary, 460);
    },
    traceBySide(side) {
      return this[side];
    },
    errorBySide(side) {
      return this.errors[side];
    },
    attachmentErrorBySide(side) {
      return this.attachmentErrors[side];
    },
    clearTrace(side) {
      this[side] = null;
      this.errors[side] = '';
      this.attachmentErrors[side] = '';
    },
    clearCompanion(side) {
      const trace = this[side];
      if (!trace || trace.kind !== 'raw_response_jsonl') {
        return;
      }
      this.attachmentErrors[side] = '';
      this[side] = stripTrajectoryCompanion(trace);
    },
    tokenTotalDisplay(trace) {
      if (!trace) {
        return 'n/a';
      }
      if (trace.exactTokens && typeof trace.exactTokens.total_tokens === 'number') {
        return 'Exact tokens: ' + numberFormat(trace.exactTokens.total_tokens);
      }
      if (typeof trace.tokenEstimateTotal === 'number') {
        return 'Est. output tokens: ~' + numberFormat(trace.tokenEstimateTotal);
      }
      if (trace.tokenEstimateError) {
        return 'Est. output tokens failed';
      }
      return 'Estimating output tokens...';
    },
    tokenNote(trace) {
      if (!trace) {
        return '';
      }
      return trace.tokenSourceLabel;
    },
    async handleFileInput(side, event) {
      const file = event.target.files && event.target.files[0];
      if (!file) {
        return;
      }
      await this.loadFile(side, file);
      event.target.value = '';
    },
    async handleDrop(side, event) {
      this.dragTarget = null;
      const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
      if (!file) {
        return;
      }
      await this.loadFile(side, file);
    },
    async handleCompanionInput(side, event) {
      const file = event.target.files && event.target.files[0];
      if (!file) {
        return;
      }
      this.attachmentErrors[side] = '';
      try {
        const trace = this[side];
        if (!trace || trace.kind !== 'raw_response_jsonl') {
          throw new Error('Attach trajectory.json only to a Webwright Responses JSONL trace (raw_responses.jsonl).');
        }
        const text = await file.text();
        const companion = extractTrajectoryUsage(text, file.name);
        const updatedTrace = applyTrajectoryCompanion(trace, companion);
        this[side] = updatedTrace;
        this.enrichTraceTokens(updatedTrace);
      } catch (error) {
        this.attachmentErrors[side] = error && error.message ? error.message : 'Failed to attach trajectory.json';
      } finally {
        event.target.value = '';
      }
    },
    async enrichTraceTokens(trace) {
      const selection = getTokenizerSelection(this.tokenTarget);
      trace.tokenSelectionLabel = selection.mode === 'model' ? selection.name + ' / ' + selection.encoding : selection.encoding;
      trace.tokenEstimateError = '';
      if (!trace.tokenEstimateParts.length) {
        trace.tokenBasisRows = [];
        if (!trace.exactTokens) {
          trace.tokenRows = [{ label: 'availability', value: 'no text fields to estimate' }];
        }
        return trace;
      }
      const quickBasisRows = trace.tokenEstimateParts
        .map((part) => ({ label: part.label, value: quickTokenEstimate(part.text) }))
        .filter((row) => row.value > 0);
      trace.tokenEstimateTotal = quickBasisRows.reduce((sum, row) => sum + row.value, 0);
      if (!trace.exactTokens) {
        trace.tokenRows = [
          { label: 'basis', value: 'estimated' },
          { label: 'encoding', value: selection.encoding + ' pending' },
          { label: 'est. output tokens', value: '~' + numberFormat(trace.tokenEstimateTotal) }
        ];
      }
      try {
        this.tokenizerStatus = 'Counting tokens with ' + selection.encoding + '...';
        const encoder = await loadEncoder(selection.encoding);
        const basisRows = trace.tokenEstimateParts.map((part) => ({ label: part.label, value: encoder.encode(part.text).length })).filter((row) => row.value > 0);
        trace.tokenBasisRows = toBarRows(basisRows, 8);
        trace.tokenEstimateTotal = basisRows.reduce((sum, row) => sum + row.value, 0);
        trace.tokenModeLabel = trace.exactTokens ? 'exact' : 'estimate';
        trace.tokenRows = trace.exactTokens
          ? tokenRowsFromTotals(trace.exactTokens)
          : [
              { label: 'basis', value: 'estimated' },
              { label: 'encoding', value: selection.encoding },
              { label: 'est. output tokens', value: '~' + numberFormat(trace.tokenEstimateTotal) }
            ];
        this.tokenizerStatus = 'Ready.';
      } catch (error) {
        trace.tokenEstimateError = error && error.message ? error.message : 'Failed to estimate tokens';
        trace.tokenBasisRows = toBarRows(quickBasisRows, 8);
        if (!trace.exactTokens) {
          trace.tokenRows = [
            { label: 'basis', value: 'estimated' },
            { label: 'encoding', value: 'quick fallback' },
            { label: 'est. output tokens', value: '~' + numberFormat(trace.tokenEstimateTotal) }
          ];
        }
        this.tokenizerStatus = trace.tokenEstimateError + '. Showing quick estimate.';
      }
      return trace;
    },
    async refreshAllTokens() {
      const traces = [this.left, this.right].filter(Boolean);
      for (const trace of traces) {
        await this.enrichTraceTokens(trace);
      }
    },
    async loadFile(side, file) {
      this.errors[side] = '';
      this.attachmentErrors[side] = '';
      try {
        const text = await file.text();
        const trace = normalizeTrace(text, file.name, file.path || '', side);
        this[side] = trace;
        this.enrichTraceTokens(trace);
      } catch (error) {
        this[side] = null;
        this.errors[side] = error && error.message ? error.message : 'Failed to parse file';
      }
    },
    filteredEvents(trace) {
      if (!trace) {
        return [];
      }
      return trace.events.filter((event) => event.kind !== 'token_snapshot');
    },
    highlightRenderedCode() {
      if (!window.hljs) {
        return;
      }
      this.$nextTick(() => {
        document.querySelectorAll('#app pre code').forEach((node) => {
          if (node.dataset.highlighted === 'yes') {
            delete node.dataset.highlighted;
          }
          window.hljs.highlightElement(node);
        });
      });
    }
  }
});

window.__traceJsonlCompareVm = app.mount('#app');
