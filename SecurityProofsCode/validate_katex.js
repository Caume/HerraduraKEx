#!/usr/bin/env node
// Validate all math spans in a Markdown file against KaTeX, simulating
// GitHub's pipeline: CommonMark backslash-escape resolution for inline math,
// verbatim pass-through for display math.
//
// Exit 0 if all spans pass; exit 1 if any FAIL.

'use strict';
const fs   = require('fs');
const path = require('path');

function loadKatex() {
  const candidates = [
    path.join(__dirname, '../node_modules/katex'),
    '/tmp/katex-validate/node_modules/katex',
  ];
  for (const p of candidates) {
    try { return require(p); } catch (_) {}
  }
  throw new Error('katex not found; run: cd /tmp/katex-validate && npm install katex');
}
const katex = loadKatex();

// CommonMark §6.7: backslash escapes all ASCII punctuation
const ASCII_PUNCT = new Set('!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'.split(''));

function cmEscape(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\' && i + 1 < s.length && ASCII_PUNCT.has(s[i + 1])) {
      out += s[i + 1];
      i++;
    } else {
      out += s[i];
    }
  }
  return out;
}

// Pipe-fail: these spacing commands become bare punctuation in inline spans
const PIPE_FAIL_RE = /\\[;!,:](?![a-zA-Z])/;

function tryRender(expr, display) {
  try {
    katex.renderToString(expr, { displayMode: display, throwOnError: true });
    return null; // success
  } catch (e) {
    return e.message.split('\n')[0];
  }
}

// ── parser ───────────────────────────────────────────────────────────────────

function extractSpans(src) {
  const spans = [];

  // Build line-number index (1-based)
  const lineStarts = [0];
  for (let i = 0; i < src.length; i++) {
    if (src[i] === '\n') lineStarts.push(i + 1);
  }
  function lineOf(pos) {
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= pos) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  }

  // Mask buffer: replace masked chars with spaces so indices stay stable
  const buf = src.split('');
  function mask(start, end) {
    for (let i = start; i < end; i++) buf[i] = ' ';
  }

  // 1. Code fences (``` or ~~~)
  const fenceRe = /^(`{3,}|~{3,})[^\n]*\n[\s\S]*?\n\1[ \t]*(?:\n|$)/gm;
  for (const m of src.matchAll(fenceRe)) mask(m.index, m.index + m[0].length);

  // 2. Inline code spans (backtick runs)
  const codeRe = /(`+)([\s\S]*?)\1/g;
  for (const m of src.matchAll(codeRe)) mask(m.index, m.index + m[0].length);

  const masked = buf.join('');

  // 3. Display math $$...$$  (greedy shortest match)
  const displayRe = /\$\$([\s\S]*?)\$\$/g;
  const displayMatches = [];
  for (const m of masked.matchAll(displayRe)) {
    displayMatches.push({ index: m.index, len: m[0].length, content: m[1] });
  }
  for (const d of displayMatches) {
    // GitHub applies CommonMark escape resolution to display blocks too
    spans.push({ line: lineOf(d.index), type: 'display', raw: d.content, content: cmEscape(d.content) });
    mask(d.index, d.index + d.len);
  }

  const masked2 = buf.join('');

  // 4. Inline math $...$ (single-line only, no leading/trailing space in content)
  let i = 0;
  while (i < masked2.length) {
    if (masked2[i] === '$') {
      let j = i + 1;
      // Content must not start with space/newline
      if (j < masked2.length && (masked2[j] === ' ' || masked2[j] === '\n')) { i++; continue; }
      while (j < masked2.length && masked2[j] !== '\n') {
        if (masked2[j] === '$') break;
        j++;
      }
      if (j < masked2.length && masked2[j] === '$' && masked2[j - 1] !== ' ') {
        const raw = src.slice(i + 1, j);
        if (raw.trim().length > 0) {
          spans.push({ line: lineOf(i), type: 'inline', raw, content: cmEscape(raw) });
        }
        i = j + 1;
        continue;
      }
    }
    i++;
  }

  spans.sort((a, b) => a.line - b.line);
  return spans;
}

// ── main ─────────────────────────────────────────────────────────────────────

const file = process.argv[2];
if (!file) {
  console.error('Usage: node validate_katex.js <file.md>');
  process.exit(2);
}

const src = fs.readFileSync(file, 'utf8');
const spans = extractSpans(src);

let ok = 0, fail = 0, pipeFail = 0;

for (const s of spans) {
  const isPipe = PIPE_FAIL_RE.test(s.raw); // check both inline and display
  const err = tryRender(s.content, s.type === 'display');

  if (err) {
    fail++;
    const preview = s.raw.replace(/\s+/g, ' ').slice(0, 70);
    console.log(`FAIL  line ${s.line} [${s.type}]: ${preview}`);
    console.log(`      → ${err}`);
  } else if (isPipe) {
    pipeFail++;
    const preview = s.raw.replace(/\s+/g, ' ').slice(0, 70);
    console.log(`PIPE  line ${s.line} [${s.type}]: ${preview}`);
  } else {
    ok++;
  }
}

console.log(`\n${ok} OK, ${fail} FAIL, ${pipeFail} PIPE-FAIL`);
process.exit(fail > 0 ? 1 : 0);
