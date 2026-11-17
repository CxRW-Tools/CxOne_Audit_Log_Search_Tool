import * as fs from 'fs';
import * as path from 'path';
import { parseAuditLog } from '../src/parser.js';

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error('Usage: npm run ingest -- <path-to-audit.log> [--out public/data/audit.json]');
  process.exit(1);
}

const inputPath = args[0];
let outputPath = 'public/data/audit.json';

const outIdx = args.indexOf('--out');
if (outIdx !== -1 && args[outIdx + 1]) {
  outputPath = args[outIdx + 1];
}

console.log(`Reading: ${inputPath}`);

// Read as UTF-16LE (the CxOne export format)
const buf = fs.readFileSync(inputPath);

let text: string;
// Check for UTF-16LE BOM: 0xFF 0xFE
if (buf[0] === 0xff && buf[1] === 0xfe) {
  text = buf.toString('utf16le');
} else {
  text = buf.toString('utf8');
}

console.log(`Parsing...`);
const dataset = parseAuditLog(text);

const outDir = path.dirname(outputPath);
if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}

fs.writeFileSync(outputPath, JSON.stringify(dataset));
console.log(`Written: ${outputPath}`);
console.log(`  Total events  : ${dataset.meta.total}`);
console.log(`  Event types   : ${dataset.meta.eventTypes}`);
console.log(`  Named actors  : ${dataset.meta.namedActors}`);
console.log(`  Categories    : ${dataset.cats.length}`);
console.log(`  Date range    : ${dataset.meta.dateMin} → ${dataset.meta.dateMax}`);
console.log(`  Distinct days : ${dataset.meta.days}`);
