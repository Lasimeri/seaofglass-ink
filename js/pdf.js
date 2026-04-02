// pdf.js — Minimal PDF 1.4 generator for text content
// No dependencies. Generates valid PDF with monospace text, page breaks, and metadata.
// Designed for CSP-restricted environments (no eval, no external scripts).

const FONT_SIZE = 10;
const LINE_HEIGHT = 14;
const MARGIN_TOP = 72;
const MARGIN_BOTTOM = 72;
const MARGIN_LEFT = 72;
const MARGIN_RIGHT = 72;
const PAGE_WIDTH = 612;  // US Letter
const PAGE_HEIGHT = 792;

const USABLE_WIDTH = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT;
const USABLE_HEIGHT = PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM;
const LINES_PER_PAGE = Math.floor(USABLE_HEIGHT / LINE_HEIGHT);

// Approximate character width for Courier at given font size
const CHAR_WIDTH = FONT_SIZE * 0.6;
const CHARS_PER_LINE = Math.floor(USABLE_WIDTH / CHAR_WIDTH);

/** Escape special PDF string characters */
function pdfEscape(str) {
  return str.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

/** Encode string to Latin-1 bytes, replacing non-Latin-1 chars with ? */
function toLatin1(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    bytes.push(code > 255 ? 63 : code); // 63 = '?'
  }
  return new Uint8Array(bytes);
}

/** Wrap a long line into multiple lines at character boundary */
function wrapLine(line, maxChars) {
  if (line.length <= maxChars) return [line];
  const wrapped = [];
  let pos = 0;
  while (pos < line.length) {
    wrapped.push(line.slice(pos, pos + maxChars));
    pos += maxChars;
  }
  return wrapped;
}

/** Split text into pages of wrapped lines */
function paginate(text) {
  const rawLines = text.split('\n');
  const allLines = [];
  for (const line of rawLines) {
    if (line.length === 0) {
      allLines.push('');
    } else {
      allLines.push(...wrapLine(line, CHARS_PER_LINE));
    }
  }
  const pages = [];
  for (let i = 0; i < allLines.length; i += LINES_PER_PAGE) {
    pages.push(allLines.slice(i, i + LINES_PER_PAGE));
  }
  if (pages.length === 0) pages.push(['']);
  return pages;
}

/** Build a PDF page content stream */
function buildPageStream(lines) {
  const cmds = [];
  cmds.push('BT');
  cmds.push(`/F1 ${FONT_SIZE} Tf`);
  cmds.push(`${MARGIN_LEFT} ${PAGE_HEIGHT - MARGIN_TOP} Td`);
  cmds.push(`${LINE_HEIGHT} TL`);
  for (const line of lines) {
    cmds.push(`(${pdfEscape(line)}) Tj T*`);
  }
  cmds.push('ET');
  return cmds.join('\n');
}

/**
 * Generate a PDF from plain text.
 * @param {string} text - The text content
 * @param {object} [opts] - Options
 * @param {string} [opts.title] - Document title metadata
 * @param {string} [opts.created] - Creation date string
 * @returns {Blob} PDF file as a Blob
 */
export function generatePDF(text, opts = {}) {
  const pages = paginate(text);
  const objects = [];
  let nextId = 1;

  function addObj(content) {
    const id = nextId++;
    objects.push({ id, content });
    return id;
  }

  // Object 1: Catalog
  const catalogId = addObj(null); // placeholder
  // Object 2: Pages
  const pagesId = addObj(null); // placeholder
  // Object 3: Font (Courier — built-in, no embedding needed)
  const fontId = addObj('<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>');
  // Object 4: Info
  const infoContent = ['<< /Producer (seaofglass.ink pdf.js)'];
  if (opts.title) infoContent.push(`/Title (${pdfEscape(opts.title)})`);
  infoContent.push(`/CreationDate (D:${new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)})`);
  infoContent.push('>>');
  const infoId = addObj(infoContent.join(' '));

  // Page objects
  const pageIds = [];
  const streamIds = [];
  for (const pageLines of pages) {
    const stream = buildPageStream(pageLines);
    const streamBytes = toLatin1(stream);
    const streamId = addObj(
      `<< /Length ${streamBytes.length} >>\nstream\n${stream}\nendstream`
    );
    streamIds.push(streamId);
    const pageId = addObj(
      `<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] ` +
      `/Contents ${streamId} 0 R /Resources << /Font << /F1 ${fontId} 0 R >> >> >>`
    );
    pageIds.push(pageId);
  }

  // Fill in catalog
  objects[catalogId - 1].content = `<< /Type /Catalog /Pages ${pagesId} 0 R >>`;
  // Fill in pages
  objects[pagesId - 1].content =
    `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pageIds.length} >>`;

  // Build the PDF byte stream
  const parts = [];
  const offsets = [];

  parts.push('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n');

  for (const obj of objects) {
    offsets.push(parts.reduce((a, p) => a + toLatin1(p).length, 0));
    parts.push(`${obj.id} 0 obj\n${obj.content}\nendobj\n`);
  }

  const xrefOffset = parts.reduce((a, p) => a + toLatin1(p).length, 0);

  // Cross-reference table
  const xref = [`xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`];
  for (const off of offsets) {
    xref.push(`${String(off).padStart(10, '0')} 00000 n \n`);
  }

  parts.push(xref.join(''));
  parts.push(
    `trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R /Info ${infoId} 0 R >>\n` +
    `startxref\n${xrefOffset}\n%%EOF\n`
  );

  // Convert to bytes
  const totalLength = parts.reduce((a, p) => a + toLatin1(p).length, 0);
  const pdf = new Uint8Array(totalLength);
  let pos = 0;
  for (const part of parts) {
    const bytes = toLatin1(part);
    pdf.set(bytes, pos);
    pos += bytes.length;
  }

  return new Blob([pdf], { type: 'application/pdf' });
}

/**
 * Trigger a PDF download.
 * @param {string} text - Text content
 * @param {string} [filename] - Download filename
 * @param {object} [opts] - Options passed to generatePDF
 */
export function downloadPDF(text, filename, opts) {
  const blob = generatePDF(text, opts);
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename || 'paste.pdf';
  a.click();
  URL.revokeObjectURL(a.href);
}
