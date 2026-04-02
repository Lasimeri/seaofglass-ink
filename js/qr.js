// Minimal QR Code generator — byte mode, EC level L, versions 1–6
// Self-contained, no external dependencies. Renders to <canvas>.

// Version table: [totalCodewords, ecCodewordsPerBlock, numBlocks, dataCodewords]
const VER = [
  ,// skip 0
  [26,  7, 1, 19],   // v1: 19 data bytes
  [44, 10, 1, 34],   // v2: 34
  [70, 15, 1, 55],   // v3: 55
  [100,20, 1, 80],   // v4: 80
  [134,26, 1,108],   // v5: 108
  [172,18, 2,136],   // v6: 136 (2 blocks, 18 ec each)
];

// Size = 17 + 4*version
function qrSize(v) { return 17 + 4 * v; }

// ---- GF(256) arithmetic for Reed-Solomon ----

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x = (x << 1) ^ (x & 128 ? 0x11d : 0);
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
}

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

// Generate Reed-Solomon generator polynomial of degree n
function rsGenPoly(n) {
  let g = [1];
  for (let i = 0; i < n; i++) {
    const ng = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) {
      ng[j] ^= g[j];
      ng[j + 1] ^= gfMul(g[j], GF_EXP[i]);
    }
    g = ng;
  }
  return g;
}

// Compute RS error correction codewords
function rsEncode(data, ecLen) {
  const gen = rsGenPoly(ecLen);
  const buf = new Uint8Array(data.length + ecLen);
  buf.set(data);
  for (let i = 0; i < data.length; i++) {
    const coef = buf[i];
    if (coef === 0) continue;
    for (let j = 0; j < gen.length; j++) {
      buf[i + j] ^= gfMul(gen[j], coef);
    }
  }
  return buf.slice(data.length);
}

// ---- Data encoding (byte mode only, EC level L) ----

function pickVersion(len) {
  for (let v = 1; v <= 6; v++) {
    // Byte mode overhead: 4 (mode) + charCountBits + data
    // charCountBits = 8 for v1-9
    const overhead = 4 + 8; // bits
    const dataBits = VER[v][3] * 8;
    if (overhead + len * 8 <= dataBits) return v;
  }
  return 0; // too long
}

function encodeData(text, version) {
  const info = VER[version];
  const dataBytes = info[3];
  const bytes = new TextEncoder().encode(text);
  const bits = [];

  function pushBits(val, len) {
    for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
  }

  // Mode indicator: 0100 = byte mode
  pushBits(0b0100, 4);
  // Character count (8 bits for v1-9)
  pushBits(bytes.length, 8);
  // Data
  for (const b of bytes) pushBits(b, 8);
  // Terminator (up to 4 zero bits)
  const termLen = Math.min(4, dataBytes * 8 - bits.length);
  pushBits(0, termLen);
  // Pad to byte boundary
  while (bits.length % 8 !== 0) bits.push(0);
  // Pad bytes to fill capacity
  const padBytes = [0xEC, 0x11];
  let padIdx = 0;
  while (bits.length < dataBytes * 8) {
    pushBits(padBytes[padIdx], 8);
    padIdx ^= 1;
  }

  // Convert bits to bytes
  const data = new Uint8Array(dataBytes);
  for (let i = 0; i < dataBytes; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
    data[i] = byte;
  }
  return data;
}

// ---- Interleave blocks + EC ----

function buildCodewords(data, version) {
  const info = VER[version];
  const [totalCW, ecPerBlock, numBlocks, dataCW] = info;
  const blockDataLen = Math.floor(dataCW / numBlocks);
  const remainder = dataCW % numBlocks;

  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;

  for (let b = 0; b < numBlocks; b++) {
    const len = blockDataLen + (b < remainder ? 1 : 0);
    const block = data.slice(offset, offset + len);
    offset += len;
    dataBlocks.push(block);
    ecBlocks.push(rsEncode(block, ecPerBlock));
  }

  // Interleave data blocks
  const result = [];
  const maxDataLen = blockDataLen + (remainder > 0 ? 1 : 0);
  for (let i = 0; i < maxDataLen; i++) {
    for (let b = 0; b < numBlocks; b++) {
      if (i < dataBlocks[b].length) result.push(dataBlocks[b][i]);
    }
  }
  // Interleave EC blocks
  for (let i = 0; i < ecPerBlock; i++) {
    for (let b = 0; b < numBlocks; b++) {
      result.push(ecBlocks[b][i]);
    }
  }

  return new Uint8Array(result);
}

// ---- Matrix construction ----

function createMatrix(version) {
  const size = qrSize(version);
  // 0 = white, 1 = black, -1 = unset
  const matrix = Array.from({ length: size }, () => new Int8Array(size).fill(-1));
  return matrix;
}

function setModule(matrix, row, col, val) {
  if (row >= 0 && row < matrix.length && col >= 0 && col < matrix.length) {
    matrix[row][col] = val ? 1 : 0;
  }
}

// Finder pattern (7x7) at top-left corner (row, col)
function drawFinder(matrix, row, col) {
  for (let r = -1; r <= 7; r++) {
    for (let c = -1; c <= 7; c++) {
      const inOuter = r >= 0 && r <= 6 && c >= 0 && c <= 6;
      const inInner = r >= 2 && r <= 4 && c >= 2 && c <= 4;
      const onBorder = r === 0 || r === 6 || c === 0 || c === 6;
      const val = inInner || (inOuter && onBorder) ? 1 : 0;
      setModule(matrix, row + r, col + c, val);
    }
  }
}

// Alignment pattern center at (row, col) — only for v2+
const ALIGN_POS = [, , [6, 18], [6, 22], [6, 26], [6, 30], [6, 34]];

function drawAlignment(matrix, version) {
  if (version < 2) return;
  const positions = ALIGN_POS[version];
  for (const r of positions) {
    for (const c of positions) {
      // Skip if overlapping finder patterns
      if (r <= 8 && c <= 8) continue; // top-left finder
      if (r <= 8 && c >= matrix.length - 8) continue; // top-right finder
      if (r >= matrix.length - 8 && c <= 8) continue; // bottom-left finder
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const val = Math.abs(dr) === 2 || Math.abs(dc) === 2 ||
                      (dr === 0 && dc === 0) ? 1 : 0;
          setModule(matrix, r + dr, c + dc, val);
        }
      }
    }
  }
}

function drawTimingPatterns(matrix) {
  const size = matrix.length;
  for (let i = 8; i < size - 8; i++) {
    const val = i % 2 === 0 ? 1 : 0;
    if (matrix[6][i] === -1) matrix[6][i] = val; // horizontal
    if (matrix[i][6] === -1) matrix[i][6] = val; // vertical
  }
}

function drawFormatInfo(matrix, maskPattern) {
  // EC level L = 01, mask pattern 3 bits
  const formatBits = encodeFormat(0b01, maskPattern);
  const size = matrix.length;

  for (let i = 0; i < 15; i++) {
    const bit = (formatBits >> (14 - i)) & 1;

    // Around top-left finder
    if (i < 6) matrix[i][8] = bit;
    else if (i === 6) matrix[i + 1][8] = bit;
    else if (i === 7) matrix[8][8] = bit;
    else if (i === 8) matrix[8][7] = bit;
    else matrix[8][14 - i] = bit;

    // Around top-right and bottom-left finders
    if (i < 8) {
      matrix[8][size - 1 - i] = bit;
    } else {
      matrix[size - 15 + i][8] = bit;
    }
  }
  // Dark module
  matrix[size - 8][8] = 1;
}

function encodeFormat(ecLevel, mask) {
  const data = (ecLevel << 3) | mask;
  let bits = data << 10;
  // Generator polynomial for format info: x^10 + x^8 + x^5 + x^4 + x^2 + x + 1 = 0x537
  let gen = 0x537;
  for (let i = 4; i >= 0; i--) {
    if (bits & (1 << (i + 10))) bits ^= gen << i;
  }
  bits = (data << 10) | bits;
  // XOR mask
  return bits ^ 0x5412;
}

function reserveFunctionPatterns(matrix, version) {
  const size = matrix.length;

  // Finder patterns + separators
  drawFinder(matrix, 0, 0);
  drawFinder(matrix, 0, size - 7);
  drawFinder(matrix, size - 7, 0);

  // Timing patterns
  drawTimingPatterns(matrix);

  // Alignment patterns
  drawAlignment(matrix, version);

  // Reserve format info areas (will be written later)
  for (let i = 0; i < 8; i++) {
    if (matrix[i][8] === -1) matrix[i][8] = 0;
    if (matrix[8][i] === -1) matrix[8][i] = 0;
    if (matrix[8][size - 1 - i] === -1) matrix[8][size - 1 - i] = 0;
    if (matrix[size - 1 - i][8] === -1) matrix[size - 1 - i][8] = 0;
  }
  if (matrix[8][8] === -1) matrix[8][8] = 0;
  // Dark module
  matrix[size - 8][8] = 1;
}

// ---- Data placement ----

function placeData(matrix, codewords) {
  const size = matrix.length;
  let bitIdx = 0;
  const totalBits = codewords.length * 8;

  // Traverse in 2-column strips from right to left
  let col = size - 1;
  while (col >= 0) {
    if (col === 6) col--; // skip timing column
    for (let row = 0; row < size; row++) {
      for (let c = 0; c < 2; c++) {
        const actualCol = col - c;
        // Determine direction: upward for even strips (counting from right), downward for odd
        const stripIndex = col >= 7 ? Math.floor((size - 1 - col) / 2) : Math.floor((size - 2 - col) / 2);
        const actualRow = stripIndex % 2 === 0 ? size - 1 - row : row;

        if (actualCol < 0 || actualCol >= size) continue;
        if (matrix[actualRow][actualCol] !== -1) continue;
        if (bitIdx < totalBits) {
          const byteIdx = bitIdx >> 3;
          const bitPos = 7 - (bitIdx & 7);
          matrix[actualRow][actualCol] = (codewords[byteIdx] >> bitPos) & 1;
          bitIdx++;
        } else {
          matrix[actualRow][actualCol] = 0;
        }
      }
    }
    col -= 2;
  }
}

// ---- Masking ----

const MASK_FNS = [
  (r, c) => (r + c) % 2 === 0,
  (r, c) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => (r * c) % 2 + (r * c) % 3 === 0,
  (r, c) => ((r * c) % 2 + (r * c) % 3) % 2 === 0,
  (r, c) => ((r + c) % 2 + (r * c) % 3) % 2 === 0,
];

function isFunction(matrix, funcMatrix, row, col) {
  return funcMatrix[row][col] !== -1;
}

function applyMask(matrix, funcMatrix, maskIdx) {
  const size = matrix.length;
  const fn = MASK_FNS[maskIdx];
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!isFunction(matrix, funcMatrix, r, c) && fn(r, c)) {
        matrix[r][c] ^= 1;
      }
    }
  }
}

// Penalty scoring for mask selection
function penaltyScore(matrix) {
  const size = matrix.length;
  let penalty = 0;

  // Rule 1: consecutive same-colored modules in row/col (>=5)
  for (let r = 0; r < size; r++) {
    let count = 1;
    for (let c = 1; c < size; c++) {
      if (matrix[r][c] === matrix[r][c - 1]) {
        count++;
      } else {
        if (count >= 5) penalty += count - 2;
        count = 1;
      }
    }
    if (count >= 5) penalty += count - 2;
  }
  for (let c = 0; c < size; c++) {
    let count = 1;
    for (let r = 1; r < size; r++) {
      if (matrix[r][c] === matrix[r - 1][c]) {
        count++;
      } else {
        if (count >= 5) penalty += count - 2;
        count = 1;
      }
    }
    if (count >= 5) penalty += count - 2;
  }

  // Rule 2: 2x2 blocks of same color
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = matrix[r][c];
      if (v === matrix[r][c + 1] && v === matrix[r + 1][c] && v === matrix[r + 1][c + 1]) {
        penalty += 3;
      }
    }
  }

  // Rule 3: finder-like patterns (1011101 preceded/followed by 4 whites)
  const pat1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const pat2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
  for (let r = 0; r < size; r++) {
    for (let c = 0; c <= size - 11; c++) {
      let match1 = true, match2 = true;
      for (let i = 0; i < 11; i++) {
        if (matrix[r][c + i] !== pat1[i]) match1 = false;
        if (matrix[r][c + i] !== pat2[i]) match2 = false;
      }
      if (match1 || match2) penalty += 40;
    }
  }
  for (let c = 0; c < size; c++) {
    for (let r = 0; r <= size - 11; r++) {
      let match1 = true, match2 = true;
      for (let i = 0; i < 11; i++) {
        if (matrix[r + i][c] !== pat1[i]) match1 = false;
        if (matrix[r + i][c] !== pat2[i]) match2 = false;
      }
      if (match1 || match2) penalty += 40;
    }
  }

  // Rule 4: proportion of dark modules
  let dark = 0;
  for (let r = 0; r < size; r++)
    for (let c = 0; c < size; c++)
      if (matrix[r][c] === 1) dark++;
  const pct = (dark * 100) / (size * size);
  const prev5 = Math.floor(pct / 5) * 5;
  const next5 = prev5 + 5;
  penalty += Math.min(Math.abs(prev5 - 50) / 5, Math.abs(next5 - 50) / 5) * 10;

  return penalty;
}

function deepCopy(matrix) {
  return matrix.map(row => new Int8Array(row));
}

// ---- Main generation ----

function generateQR(text) {
  const bytes = new TextEncoder().encode(text);
  const version = pickVersion(bytes.length);
  if (!version) return null;

  const data = encodeData(text, version);
  const codewords = buildCodewords(data, version);

  // Build function pattern reference
  const funcMatrix = createMatrix(version);
  reserveFunctionPatterns(funcMatrix, version);

  // Build actual matrix with data
  const matrix = createMatrix(version);
  reserveFunctionPatterns(matrix, version);
  placeData(matrix, codewords);

  // Try all 8 masks, pick lowest penalty
  let bestMask = 0;
  let bestPenalty = Infinity;
  let bestMatrix = null;

  for (let m = 0; m < 8; m++) {
    const trial = deepCopy(matrix);
    applyMask(trial, funcMatrix, m);
    drawFormatInfo(trial, m);
    const p = penaltyScore(trial);
    if (p < bestPenalty) {
      bestPenalty = p;
      bestMask = m;
      bestMatrix = trial;
    }
  }

  return bestMatrix;
}

// ---- Canvas rendering ----

export function renderQR(canvas, text, moduleSize = 4) {
  const matrix = generateQR(text);
  if (!matrix) {
    canvas.width = 0;
    canvas.height = 0;
    throw new Error('Text too long for QR');
  }

  const size = matrix.length;
  const quiet = 4; // quiet zone modules
  const total = size + quiet * 2;
  canvas.width = total * moduleSize;
  canvas.height = total * moduleSize;

  const ctx = canvas.getContext('2d');
  // Background
  ctx.fillStyle = '#0a0a0f';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  // Modules
  ctx.fillStyle = '#c4945a';
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c] === 1) {
        ctx.fillRect((c + quiet) * moduleSize, (r + quiet) * moduleSize, moduleSize, moduleSize);
      }
    }
  }
}
