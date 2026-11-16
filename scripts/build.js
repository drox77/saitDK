// Сборка статики для Vercel: копирует public в dist, подставляя адрес сайта и версию файлов.
import fs from 'node:fs';
import path from 'node:path';

import { loadConfig } from '../src/config.js';
import { renderSite } from '../src/static.js';

const config = loadConfig(process.env);
const outDir = path.join(import.meta.dirname, '..', 'dist');
const { files, version } = renderSite(config);

fs.rmSync(outDir, { recursive: true, force: true });
for (const file of files) {
  const target = path.join(outDir, file.urlPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, file.body);
}

console.log(`dist: ${files.length} файлов, версия ${version}, адрес сайта ${config.siteUrl}`);
