import crypto from 'node:crypto';
import path from 'node:path';

const TOKEN_PATTERN = /^\d{6,}:[A-Za-z0-9_-]{30,}$/;
const CHAT_ID_PATTERN = /^-?\d{5,}$/;

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export function loadConfig(env) {
  const warnings = [];
  const port = positiveInt(env.PORT, 3000);
  const onVercel = Boolean(env.VERCEL);
  const isProduction = env.NODE_ENV === 'production' || onVercel;

  const token = (env.TELEGRAM_BOT_TOKEN || '').trim();
  const chatIds = (env.TELEGRAM_CHAT_IDS || '').split(',').map((id) => id.trim()).filter(Boolean);
  const tokenValid = TOKEN_PATTERN.test(token);
  const chatIdsValid = chatIds.length > 0 && chatIds.every((id) => CHAT_ID_PATTERN.test(id));
  if (!tokenValid) warnings.push('TELEGRAM_BOT_TOKEN не задан или имеет неверный формат: форма будет отвечать 503');
  if (!chatIdsValid) warnings.push('TELEGRAM_CHAT_IDS не задан или содержит нечисловые значения: форма будет отвечать 503');

  let siteUrl = (env.SITE_URL || '').trim().replace(/\/+$/, '');
  if (!siteUrl && env.VERCEL_PROJECT_PRODUCTION_URL) siteUrl = `https://${env.VERCEL_PROJECT_PRODUCTION_URL}`;
  if (!siteUrl) {
    siteUrl = `http://localhost:${port}`;
    if (isProduction) warnings.push('SITE_URL не задан: canonical, sitemap.xml и Open Graph указывают на localhost');
  }

  let csrfSecret = (env.CSRF_SECRET || '').trim();
  if (csrfSecret.length < 32 && tokenValid) {
    // Секрет, одинаковый для всех экземпляров сервера: без него токен, выданный одной функцией, не примет другая.
    csrfSecret = crypto.createHash('sha256').update(`csrf:${token}`).digest('hex');
  } else if (csrfSecret.length < 32) {
    csrfSecret = crypto.randomBytes(32).toString('hex');
  }

  return {
    port,
    host: env.HOST || '0.0.0.0',
    isProduction,
    siteUrl,
    siteOrigin: new URL(siteUrl).origin,
    publicDir: path.join(import.meta.dirname, '..', 'public'),
    csrfSecret,
    trustProxy: Math.max(0, Number.parseInt(env.TRUST_PROXY ?? (onVercel ? '1' : '0'), 10) || 0),
    rateLimit: {
      max: positiveInt(env.RATE_LIMIT_MAX, 5),
      windowMs: positiveInt(env.RATE_LIMIT_WINDOW_MIN, 10) * 60_000,
    },
    telegram: {
      apiBase: 'https://api.telegram.org',
      token,
      chatIds,
      ready: tokenValid && chatIdsValid,
    },
    warnings,
  };
}
