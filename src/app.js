import { createApi, HttpError, sendJson } from './api.js';
import { loadAssets, sendAsset } from './static.js';

// Встроенный сервер: раздаёт public и обслуживает /api. Нужен для локального запуска и хостингов с постоянным процессом.
export function createApp(config) {
  const { assets, version } = loadAssets(config);
  const api = createApi(config);

  async function route(req, res, requestId) {
    if (config.isProduction && config.trustProxy > 0 && req.headers['x-forwarded-proto'] === 'http') {
      res.writeHead(308, { Location: `https://${req.headers.host}${req.url}` });
      res.end();
      return;
    }
    if (!URL.canParse(req.url, 'http://localhost')) throw new HttpError(400, 'bad_request', 'Некорректный запрос.');
    const { pathname, searchParams } = new URL(req.url, 'http://localhost');

    if (pathname === '/api/lead') {
      await api.lead(req, res, requestId);
      return;
    }
    if (pathname === '/api/csrf') {
      api.csrf(req, res);
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      throw new HttpError(405, 'method_not_allowed', 'Метод не поддерживается.', { headers: { Allow: 'GET, HEAD' } });
    }
    if (pathname === '/healthz') {
      sendJson(res, 200, { ok: true });
      return;
    }

    const asset = assets.get(pathname);
    if (asset) sendAsset(req, res, asset, { immutable: searchParams.get('v') === version });
    else sendAsset(req, res, assets.get('/404.html'), { status: 404 });
  }

  return { handle: (req, res) => api.run(req, res, route) };
}
