'use strict';

/**
 * Generates Gray Hat Person emblem PNG icons (16, 32, 48, 128) for safe (green),
 * warning (amber), and danger (red) states using only Node.js built-ins.
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const OUT_DIR = path.join(__dirname, '..', 'extension', 'icons');
if (!fs.existsSync(OUT_DIR)) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
}

// CRC32 table for PNG chunks
const crcTable = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  crcTable[n] = c >>> 0;
}

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function makeChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

function encodePNG(width, height, rgba) {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter type None
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  const compressed = zlib.deflateSync(raw, { level: 9 });

  return Buffer.concat([
    sig,
    makeChunk('IHDR', ihdr),
    makeChunk('IDAT', compressed),
    makeChunk('IEND', Buffer.alloc(0))
  ]);
}

function sampleGrayHatPixel(nx, ny, palette) {
  const distSq = nx * nx + ny * ny;
  if (distSq > 0.94 * 0.94) return null;

  // Clean borderless matte circular backdrop (no outer outline/ring)
  let col = palette.bg;

  // Scale character slightly up to fill the borderless emblem cleanly
  const sx = nx * 0.88;
  const sy = ny * 0.88;
  const ax = Math.abs(sx);

  // 1. Shoulders & trench coat silhouette (bottom)
  if (sy >= 0.32 && sy <= 0.86) {
    const t = (sy - 0.32) / 0.54;
    const maxW = 0.28 + Math.sin(t * Math.PI * 0.55) * 0.38;
    if (ax <= maxW) {
      // Inner V lapel collar
      const lapelW = Math.max(0, 0.22 - (sy - 0.32) * 0.65);
      col = ax <= lapelW ? [30, 41, 59] : [100, 116, 139];
    }
  }

  // 2. Shadowed head/jaw silhouette under the hat brim
  if (sy >= -0.02 && sy <= 0.32) {
    const faceR = ((sx / 0.28) ** 2) + (((sy - 0.02) / 0.30) ** 2);
    if (faceR <= 1.0) {
      col = [30, 41, 59];
      // Subtle visor/glasses glint
      if (sy >= 0.03 && sy <= 0.13 && ax >= 0.04 && ax <= 0.22) {
        col = [148, 163, 184];
      }
    }
  }

  // 3. Gray Fedora Crown (pinched top)
  if (sy >= -0.62 && sy <= -0.14) {
    const crownT = (sy + 0.62) / 0.48; // 0 at top, 1 at base
    const halfW = 0.24 + crownT * 0.15;
    // Slight dip at top center for classic fedora pinch
    const topY = -0.62 + Math.exp(-((sx / 0.14) ** 2)) * 0.07;
    if (sy >= topY && ax <= halfW) {
      if (sy >= -0.25 && sy <= -0.14) {
        // Dark charcoal hatband (or subtle status accent on warning/danger)
        col = palette.band;
      } else {
        // Metallic gray hat crown with subtle left-to-right sheen
        col = sx < 0 ? [203, 213, 225] : [148, 163, 184];
      }
    }
  }

  // 4. Wide Curved Gray Fedora Brim
  const brimCenterY = -0.11 + (sx * sx) * 0.09;
  const brimHalfThickness = Math.max(0, 0.095 * (1 - (ax / 0.72) ** 2));
  if (ax <= 0.70 && Math.abs(sy - brimCenterY) <= brimHalfThickness) {
    col = sy < brimCenterY ? [226, 232, 240] : [148, 163, 184];
  }

  return col;
}

const PALETTES = {
  safe: { bg: [19, 21, 20], band: [51, 65, 85] },       // Clean matte charcoal
  warning: { bg: [36, 28, 16], band: [231, 169, 66] },  // Subtle amber tint + amber hatband
  danger: { bg: [40, 18, 18], band: [235, 98, 98] }     // Subtle crimson tint + crimson hatband
};

const SIZES = [16, 32, 48, 128];

for (const [state, palette] of Object.entries(PALETTES)) {
  for (const size of SIZES) {
    const rgba = Buffer.alloc(size * size * 4);
    const offsets = [-0.375, -0.125, 0.125, 0.375]; // 4x4 supersampling for crisp edges
    const totalSubpixels = offsets.length * offsets.length;

    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        let r = 0, g = 0, b = 0, hits = 0;
        for (const oy of offsets) {
          for (const ox of offsets) {
            const nx = ((x + 0.5 + ox) / size) * 2 - 1;
            const ny = ((y + 0.5 + oy) / size) * 2 - 1;
            const col = sampleGrayHatPixel(nx, ny, palette);
            if (col) {
              r += col[0];
              g += col[1];
              b += col[2];
              hits++;
            }
          }
        }
        const idx = (y * size + x) * 4;
        if (hits > 0) {
          rgba[idx] = Math.round(r / hits);
          rgba[idx + 1] = Math.round(g / hits);
          rgba[idx + 2] = Math.round(b / hits);
          rgba[idx + 3] = Math.round((hits / totalSubpixels) * 255);
        }
      }
    }

    const png = encodePNG(size, size, rgba);
    const outPath = path.join(OUT_DIR, `icon-${state}-${size}.png`);
    fs.writeFileSync(outPath, png);
  }
}

console.log('Generated Gray Hat Person icons in', OUT_DIR);
