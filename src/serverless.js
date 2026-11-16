import { createApi } from './api.js';
import { loadConfig } from './config.js';
import { log } from './log.js';

// Общая точка входа для функций Vercel в каталоге api/.
const config = loadConfig(process.env);
for (const warning of config.warnings) log('warn', 'config_warning', { warning });

export const api = createApi(config);
