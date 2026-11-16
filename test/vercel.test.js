import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { after, before, test } from 'node:test';

import { createApi, securityHeaders } from '../src/api.js';
import { CHAT_IDS, startSite, startTelegramMock, testConfig, VALID_LEAD } from './helpers.js';

process.env.LOG_LEVEL = 'silent';

const root = path.join(import.meta.dirname, '..');
let telegram;
let site;

// Повторяет поведение Vercel: тело запроса уже прочитано и доступно через req.body, поток пуст.
async function vercelLikeHandler(api, req, res) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  Object.defineProperty(req, 'body', { get: () => JSON.parse(raw) });
  const { pathname } = new URL(req.url, 'http://localhost');
  await api.run(req, res, pathname === '/api/csrf' ? api.csrf : api.lead);
}

before(async () => {
  telegram = await startTelegramMock();
  const api = createApi(testConfig({ VERCEL: '1' }, telegram.url));
  site = await startSite({}, telegram.url, (req, res) => vercelLikeHandler(api, req, res));
});

after(() => {
  site.close();
  telegram.close();
});

test('заголовки безопасности в vercel.json совпадают с серверными', () => {
  const config = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
  const fromFile = Object.fromEntries(config.headers[0].headers.map(({ key, value }) => [key, value]));
  assert.equal(config.headers[0].source, '/(.*)');
  assert.deepEqual(fromFile, securityHeaders(true));
});

test('сборка кладёт в dist готовый сайт без незаполненных шаблонов', () => {
  const output = execFileSync('node', ['scripts/build.js'], {
    cwd: root,
    env: { PATH: process.env.PATH, VERCEL: '1', VERCEL_PROJECT_PRODUCTION_URL: 'dk-test.vercel.app' },
    encoding: 'utf8',
  });
  assert.match(output, /https:\/\/dk-test\.vercel\.app/);

  const dist = path.join(root, 'dist');
  const html = fs.readFileSync(path.join(dist, 'index.html'), 'utf8');
  assert.ok(html.includes('<link rel="canonical" href="https://dk-test.vercel.app/">'));
  assert.ok(!html.includes('{{'));
  assert.match(fs.readFileSync(path.join(dist, 'robots.txt'), 'utf8'), /Sitemap: https:\/\/dk-test\.vercel\.app\/sitemap\.xml/);
  for (const file of ['404.html', 'privacy.html', 'sitemap.xml', 'css/styles.css', 'js/lead-rules.js', 'img/og.png']) {
    assert.ok(fs.existsSync(path.join(dist, file)), file);
  }
  fs.rmSync(dist, { recursive: true });
});

test('функция заявки работает с телом, которое уже разобрал Vercel', async () => {
  const { status, body, headers } = await site.postLead({ ...VALID_LEAD, email: 'vercel@example.ru' });
  assert.equal(status, 200);
  assert.deepEqual(body, { ok: true });
  assert.match(headers.get('content-security-policy'), /default-src 'self'/);
  assert.deepEqual(telegram.requests.map((request) => String(request.body.chat_id)).sort(), CHAT_IDS);
});

test('функция заявки отклоняет битый JSON, неверные поля и чужой метод', async () => {
  assert.equal((await site.postLead('{broken')).status, 400);
  assert.equal((await site.postLead('null')).status, 400);
  assert.equal((await site.postLead({ ...VALID_LEAD, phone: '1' })).status, 422);
  assert.equal((await fetch(`${site.url}/api/lead`)).status, 405);
  assert.equal((await fetch(`${site.url}/api/csrf`, { method: 'POST' })).status, 405);
});

test('на Vercel cookie формы помечается Secure, а секрет одинаков для всех экземпляров', async () => {
  const response = await fetch(`${site.url}/api/csrf`);
  assert.match(response.headers.get('set-cookie'), /; Secure/);

  const env = { VERCEL: '1', TELEGRAM_BOT_TOKEN: '123456789:TEST_ONLY_token_abcdefghijklmnopqrstuvwxyz', TELEGRAM_CHAT_IDS: '111111' };
  const first = testConfig({ ...env, CSRF_SECRET: '' });
  const second = testConfig({ ...env, CSRF_SECRET: '' });
  assert.equal(first.csrfSecret, second.csrfSecret);
  assert.ok(!first.csrfSecret.includes('TEST_ONLY'));
  assert.equal(first.trustProxy, 1);
});

test('файлы функций в api/ загружаются и отвечают', async () => {
  const { default: csrf } = await import('../api/csrf.js');
  const { default: lead } = await import('../api/lead.js');
  const direct = await startSite({}, undefined, (req, res) => (req.url === '/api/csrf' ? csrf(req, res) : lead(req, res)));
  try {
    assert.equal((await fetch(`${direct.url}/api/csrf`)).status, 200);
    assert.equal((await direct.postLead({ ...VALID_LEAD, email: 'direct@example.ru' })).status, 503);
  } finally {
    direct.close();
  }
});
