// highlight.js — Tree-sitter syntax highlighting with brotli-compressed grammars
// Loads tree-sitter runtime uncompressed, decompresses grammar WASMs on demand via ink-brotli.

import { brotliDecompress } from './wasm.js?v=10';

const SYNTAX_BASE = './syntax/';

let Parser = null;
let initPromise = null;
const parsers = new Map(); // lang → Parser instance with language set

// Language detection heuristics
const LANG_PATTERNS = [
  ['javascript', /\b(const|let|var|function|=>|require\(|import\s+.*\s+from)\b/],
  ['typescript', /\b(interface|type\s+\w+\s*=|:\s*(string|number|boolean|any)\b)/],
  ['tsx', /<[A-Z]\w*[\s/>].*\b(interface|type\s+\w+)/s],
  ['python', /\b(def\s+\w+|import\s+\w+|from\s+\w+\s+import|if\s+__name__)\b/],
  ['rust', /\b(fn\s+\w+|let\s+mut|impl\s+|pub\s+(fn|struct|enum)|use\s+\w+::)\b/],
  ['go', /\b(func\s+\w+|package\s+\w+|import\s+\(|:=)\b/],
  ['java', /\b(public\s+(class|static|void)|System\.out|import\s+java\.)\b/],
  ['c', /\b(#include\s*<|int\s+main\s*\(|printf\s*\(|void\s+\w+\s*\()\b/],
  ['cpp', /\b(#include\s*<iostream>|std::|cout|cin|class\s+\w+\s*\{|template\s*<)\b/],
  ['ruby', /\b(def\s+\w+|end\b|require\s+['"]|class\s+\w+\s*<|puts\s+)/],
  ['bash', /^#!\/bin\/(bash|sh|zsh)|^\s*(if\s+\[|for\s+\w+\s+in|echo\s+)/m],
  ['json', /^\s*[\[{]\s*"[^"]*"\s*:/m],
  ['html', /<!DOCTYPE\s+html|<html|<head|<body|<div|<script/i],
  ['css', /\b(body|div|span|\.[\w-]+|#[\w-]+)\s*\{[^}]*[;:]/],
  ['sql', /\b(SELECT|INSERT|UPDATE|DELETE|CREATE\s+TABLE|FROM|WHERE)\b/i],
  ['toml', /^\s*\[[\w.-]+\]\s*$/m],
  ['yaml', /^\s*[\w-]+\s*:\s+/m],
  ['lua', /\b(local\s+\w+|function\s+\w+|then|end\b|require\s*\()/],
  ['swift', /\b(func\s+\w+|var\s+\w+\s*:|let\s+\w+\s*:|import\s+Foundation|guard\s+let)\b/],
  ['kotlin', /\b(fun\s+\w+|val\s+\w+|var\s+\w+|class\s+\w+|import\s+kotlin\.)\b/],
  ['zig', /\b(const\s+\w+\s*=|fn\s+\w+|@import\(|pub\s+fn)\b/],
  ['elixir', /\b(defmodule|def\s+\w+|do\b|\|>|Enum\.|IO\.puts)/],
  ['scala', /\b(def\s+\w+|val\s+\w+|var\s+\w+|object\s+\w+|import\s+scala\.)\b/],
  ['make', /^[\w.-]+\s*:.*\n\t/m],
  ['php', /<\?php|\$\w+\s*=/],
  ['c_sharp', /\b(using\s+System|namespace\s+\w+|class\s+\w+\s*:\s*\w+|Console\.Write)/],
];

// Highlight class mapping — tree-sitter node types to CSS classes
const NODE_CLASSES = {
  'string': 'hl-string',
  'string_literal': 'hl-string',
  'template_string': 'hl-string',
  'number': 'hl-number',
  'integer': 'hl-number',
  'float': 'hl-number',
  'comment': 'hl-comment',
  'line_comment': 'hl-comment',
  'block_comment': 'hl-comment',
  'keyword': 'hl-keyword',
  'type': 'hl-type',
  'type_identifier': 'hl-type',
  'primitive_type': 'hl-type',
  'function': 'hl-function',
  'function_item': 'hl-function',
  'method_definition': 'hl-function',
  'call_expression': 'hl-function',
  'identifier': 'hl-ident',
  'property_identifier': 'hl-prop',
  'field_identifier': 'hl-prop',
  'operator': 'hl-op',
  'boolean': 'hl-const',
  'true': 'hl-const',
  'false': 'hl-const',
  'null': 'hl-const',
  'none': 'hl-const',
  'nil': 'hl-const',
};

async function initTreeSitter() {
  if (Parser) return;
  if (initPromise) return initPromise;
  initPromise = (async () => {
    const mod = await import('./syntax/tree-sitter.js');
    const TS = mod.default || mod;
    await TS.init({
      locateFile: () => SYNTAX_BASE + 'tree-sitter.wasm',
    });
    Parser = TS;
  })();
  return initPromise;
}

async function loadGrammar(lang) {
  if (parsers.has(lang)) return parsers.get(lang);
  await initTreeSitter();

  // Fetch compressed grammar
  const resp = await fetch(SYNTAX_BASE + lang + '.wasm.br');
  if (!resp.ok) return null;
  const compressed = new Uint8Array(await resp.arrayBuffer());
  const wasmBytes = await brotliDecompress(compressed);

  const language = await Parser.Language.load(wasmBytes.buffer);
  const parser = new Parser();
  parser.setLanguage(language);
  parsers.set(lang, { parser, language });
  return { parser, language };
}

/**
 * Detect language from text content.
 * @returns {string|null} Language name or null
 */
export function detectLanguage(text) {
  const sample = text.slice(0, 2000); // only check first 2KB
  for (const [lang, pattern] of LANG_PATTERNS) {
    if (pattern.test(sample)) return lang;
  }
  return null;
}

/**
 * Highlight text with tree-sitter.
 * @param {string} text - Source code
 * @param {string} [lang] - Language (auto-detected if omitted)
 * @returns {Promise<string|null>} HTML with <span class="hl-*"> or null if unsupported
 */
export async function highlight(text, lang) {
  lang = lang || detectLanguage(text);
  if (!lang) return null;

  let grammar;
  try { grammar = await loadGrammar(lang); }
  catch { return null; }
  if (!grammar) return null;

  const tree = grammar.parser.parse(text);
  const root = tree.rootNode;

  // Build highlighted HTML by walking the tree
  const chars = [...text];
  const tags = new Array(chars.length).fill(null); // start index → class

  function walk(node) {
    const cls = NODE_CLASSES[node.type];
    if (cls && node.childCount === 0) {
      // Leaf node with a known class — mark its range
      for (let i = node.startIndex; i < node.endIndex && i < tags.length; i++) {
        if (!tags[i]) tags[i] = cls; // first match wins
      }
    }
    for (let i = 0; i < node.childCount; i++) {
      walk(node.child(i));
    }
  }
  walk(root);

  // Build HTML
  let html = '';
  let currentClass = null;
  for (let i = 0; i < chars.length; i++) {
    const cls = tags[i];
    if (cls !== currentClass) {
      if (currentClass) html += '</span>';
      if (cls) html += `<span class="${cls}">`;
      currentClass = cls;
    }
    const ch = chars[i];
    if (ch === '&') html += '&amp;';
    else if (ch === '<') html += '&lt;';
    else if (ch === '>') html += '&gt;';
    else html += ch;
  }
  if (currentClass) html += '</span>';

  tree.delete();
  return html;
}

/**
 * List available languages.
 */
export function availableLanguages() {
  return LANG_PATTERNS.map(([lang]) => lang);
}
