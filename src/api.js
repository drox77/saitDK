import crypto from 'node:crypto';

import { validateLead } from '../public/js/lead-rules.js';
import { issueToken, verifyToken, TOKEN_TTL_MS } from './csrf.js';
import { createLedger } from './ledger.js';
import { log } from './log.js';
import { createRateLimiter } from './rate-limit.js';
import { deliverLead, formatLead } from './telegram.js';

const MAX_BODY_BYTES = 8 * 1024;
const CSRF_COOKIE = 'dk_csrf';

export class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

// Те же заголовки для статики на Vercel записаны в vercel.json; их совпадение проверяет тест.
export function securityHeaders(isProduction) {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ];
  const headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
  };
  if (isProduction) {
    csp.push('upgrade-insecure-requests');
    headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  }
  headers['Content-Security-Policy'] = csp.join('; ');
  return headers;
}

export function sendJson(res, status, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

function requireMethod(req, ...allowed) {
  if (allowed.includes(req.method)) return;
  throw new HttpError(405, 'method_not_allowed', 'Метод не поддерживается.', { headers: { Allow: allowed.join(', ') } });
}

function readJsonBody(req) {
  if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) {
    throw new HttpError(415, 'unsupported_media_type', 'Ожидается JSON.');
  }
  const tooLarge = () => new HttpError(413, 'too_large', 'Слишком большой запрос.', { headers: { Connection: 'close' } });
  const badJson = () => new HttpError(400, 'bad_json', 'Некорректный запрос.');
  if (Number(req.headers['content-length']) > MAX_BODY_BYTES) throw tooLarge();

  // Vercel сам читает тело и отдаёт его через req.body; на некорректном JSON это свойство бросает ошибку.
  if ('body' in req) {
    let parsed;
    try {
      parsed = req.body;
    } catch {
      throw badJson();
    }
    if (Buffer.isBuffer(parsed)) throw badJson();
    return parsed;
  }

  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) reject(tooLarge());
      else chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(badJson());
      }
    });
    req.on('error', reject);
  });
}

function fingerprint(lead) {
  const source = [lead.firstName, lead.patronymic, lead.email, lead.phone].join('\n').toLowerCase();
  return crypto.createHash('sha256').update(source).digest('hex');
}

// Обработчики /api/csrf и /api/lead. Их вызывают и встроенный сервер (src/app.js), и функции Vercel (api/*.js).
export function createApi(config) {
  const headers = securityHeaders(config.isProduction);
  const leadLimiter = createRateLimiter(config.rateLimit);
  const csrfLimiter = createRateLimiter({ max: 60, windowMs: config.rateLimit.windowMs });
  const ledger = createLedger();

  function clientIp(req) {
    if (config.trustProxy > 0) {
      const chain = String(req.headers['x-forwarded-for'] || '').split(',').map((part) => part.trim()).filter(Boolean);
      const forwarded = chain[chain.length - config.trustProxy];
      if (forwarded) return forwarded;
    }
    return req.socket?.remoteAddress || 'unknown';
  }

  function isSameOrigin(req) {
    const { origin } = req.headers;
    if (!origin) return false;
    const fetchSite = req.headers['sec-fetch-site'];
    if (fetchSite && fetchSite !== 'same-origin') return false;
    if (origin === config.siteOrigin) return true;

    const host = (config.trustProxy > 0 && req.headers['x-forwarded-host']) || req.headers.host;
    return URL.canParse(origin) && new URL(origin).host === host;
  }

  function limit(limiter, req) {
    limiter.sweep();
    const { allowed, retryAfterSec } = limiter.take(clientIp(req));
    if (allowed) return;
    throw new HttpError(429, 'rate_limited', 'Слишком много попыток. Повторите через несколько минут.', {
      headers: { 'Retry-After': String(retryAfterSec) },
    });
  }

  function csrf(req, res) {
    requireMethod(req, 'GET', 'HEAD');
    limit(csrfLimiter, req);
    const { nonce, token, expiresAt } = issueToken(config.csrfSecret);
    const cookie = [
      `${CSRF_COOKIE}=${nonce}`,
      'Path=/api',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${TOKEN_TTL_MS / 1000}`,
      ...(config.isProduction ? ['Secure'] : []),
    ].join('; ');
    sendJson(res, 200, { token, expiresAt }, { 'Set-Cookie': cookie });
  }

  async function lead(req, res, requestId) {
    requireMethod(req, 'POST');
    limit(leadLimiter, req);

    if (!isSameOrigin(req)) {
      log('warn', 'lead_rejected', { requestId, reason: 'origin' });
      throw new HttpError(403, 'origin', 'Запрос отклонён.');
    }
    const nonce = new RegExp(`(?:^|;\\s*)${CSRF_COOKIE}=([^;]+)`).exec(req.headers.cookie || '')?.[1];
    if (!verifyToken(config.csrfSecret, req.headers['x-csrf-token'], nonce)) {
      throw new HttpError(403, 'csrf', 'Сессия формы устарела. Отправьте заявку ещё раз.');
    }

    const body = await readJsonBody(req);
    if (body === null || typeof body !== 'object') throw new HttpError(400, 'bad_json', 'Некорректный запрос.');

    // Поле-ловушка скрыто от людей. Боту отвечаем как при успехе, но ничего не отправляем.
    if (typeof body.website === 'string' && body.website.trim()) {
      log('warn', 'lead_rejected', { requestId, reason: 'honeypot' });
      sendJson(res, 200, { ok: true });
      return;
    }

    const { values, errors, valid } = validateLead(body);
    if (!valid) throw new HttpError(422, 'validation', 'Проверьте поля формы.', { errors });

    if (!config.telegram.ready) {
      log('error', 'lead_rejected', { requestId, reason: 'telegram_not_configured' });
      throw new HttpError(503, 'unavailable', 'Приём заявок временно недоступен. Попробуйте позже.');
    }

    const key = fingerprint(values);
    const started = ledger.begin(key);
    if (started.status === 'duplicate') {
      log('info', 'lead_duplicate', { requestId });
      sendJson(res, 200, { ok: true, duplicate: true });
      return;
    }
    if (started.status === 'busy') {
      throw new HttpError(409, 'busy', 'Заявка уже отправляется. Подождите несколько секунд.');
    }

    let delivered = [];
    try {
      delivered = await deliverLead(config.telegram, formatLead(values), started.deliveredTo);
    } finally {
      const total = started.deliveredTo.size + delivered.length;
      ledger.settle(key, delivered, total === config.telegram.chatIds.length);
    }

    const deliveredTotal = started.deliveredTo.size + delivered.length;
    if (deliveredTotal < config.telegram.chatIds.length) {
      log('error', 'lead_delivery_incomplete', { requestId, delivered: deliveredTotal, recipients: config.telegram.chatIds.length });
      throw new HttpError(502, 'delivery_failed', 'Не удалось отправить заявку. Попробуйте ещё раз через минуту.');
    }

    log('info', 'lead_delivered', { requestId, recipients: deliveredTotal });
    sendJson(res, 200, { ok: true });
  }

  // Общая обвязка запроса: заголовки безопасности и перевод ошибок в ответы без внутренних деталей.
  async function run(req, res, handler) {
    const requestId = crypto.randomUUID();
    for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);

    try {
      await handler(req, res, requestId);
    } catch (error) {
      if (error instanceof HttpError) {
        const { headers: extraHeaders, ...fields } = error.extra;
        sendJson(res, error.status, { ok: false, code: error.code, message: error.message, ...fields }, extraHeaders);
        return;
      }
      log('error', 'request_failed', { requestId, name: error.name, message: error.message });
      if (res.headersSent) res.destroy();
      else sendJson(res, 500, { ok: false, code: 'internal', message: 'Внутренняя ошибка. Попробуйте позже.' });
    }
  }

  return { run, csrf, lead };
}
