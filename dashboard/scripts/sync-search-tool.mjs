// Copy the built dashboard into the Search Tool's web/ folder, which `python main.py --serve` serves.
// Usage: npm run sync:search-tool [-- <path to CxOne_Audit_Log_Search_Tool>]
// Default target: a sibling checkout at ../CxOne_Audit_Log_Search_Tool
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'dist', 'CxOne_Audit_Log_Dashboard.html');
const toolDir = resolve(process.argv[2] ?? join(root, '..', 'CxOne_Audit_Log_Search_Tool'));

if (!existsSync(src)) {
  console.error(`Build output not found: ${src}\nRun "npm run build" first.`);
  process.exit(1);
}
if (!existsSync(join(toolDir, 'main.py'))) {
  console.error(`Search Tool not found at ${toolDir}\nPass its path: npm run sync:search-tool -- <path>`);
  process.exit(1);
}

const dest = join(toolDir, 'web', 'CxOne_Audit_Log_Dashboard.html');
mkdirSync(dirname(dest), { recursive: true });
copyFileSync(src, dest);
console.log(`Copied dashboard to ${dest}`);
