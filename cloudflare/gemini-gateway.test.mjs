/**
 * Проверка cloudflare/gemini-gateway.js без деплоя: поднимает локальный
 * апстрим, подменяет fetch и гоняет запросы через обработчик Worker.
 *
 *   node cloudflare/gemini-gateway.test.mjs
 */

import http from 'node:http';
import worker from './gemini-gateway.js';

const realFetch = globalThis.fetch;
const seen = [];

const upstream = http.createServer(async (req, res) => {
  let body = '';
  for await (const chunk of req) body += chunk;
  seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, key: req.headers['x-goog-api-key'], body });

  if (req.url.startsWith('/v1beta/openai/chat/completions')) {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'transfer-encoding': 'chunked' });
    for (const part of ['data: {"a":1}', 'data: [DONE]']) {
      res.write(part + '\n\n');
      await new Promise((done) => setTimeout(done, 30));
    }
    res.end();
    return;
  }

  if (req.url.startsWith('/country')) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ip: '203.0.113.7', country: 'SE' }));
    return;
  }

  if (req.url.startsWith('/v1beta/models')) {
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: { code: 403, message: 'Permission denied on the service.' } }));
    return;
  }

  res.writeHead(404);
  res.end();
});

const results = [];
const check = (name, ok, extra = '') => results.push(`${ok ? '✅' : '❌'} ${name}${extra ? ' — ' + extra : ''}`);

await new Promise((done) => upstream.listen(0, '127.0.0.1', done));
const base = `http://127.0.0.1:${upstream.address().port}`;

// Node требует duplex для потокового тела, в Workers это не нужно.
globalThis.fetch = (input, init = {}) => {
  const next = { ...init };
  if (next.body && typeof next.body !== 'string' && !next.duplex) next.duplex = 'half';
  return realFetch(input, next);
};

const env = { UPSTREAM: base, API_KEY: 'secret-key' };
const call = (path, init = {}) => worker.fetch(new Request('https://gemini-gw.test' + path, init), env);
const auth = { authorization: 'Bearer secret-key' };

let res = await call('/health');
check('health отвечает', res.status === 200, (await res.text()).trim());

res = await call('/v1beta/models', { headers: { authorization: 'Bearer wrong' } });
check('чужой ключ → 401', res.status === 401);

res = await call('/v1beta/models', { headers: auth });
const body = await res.text();
check('ответ апстрима проходит как есть', res.status === 403 && body.includes('Permission denied'));
check('CORS в ответе', res.headers.get('access-control-allow-origin') === '*');
check('путь и query переданы', seen.at(-1).url === '/v1beta/models', seen.at(-1).url);

res = await call('/v1beta/openai/chat/completions', {
  method: 'POST',
  headers: { ...auth, 'content-type': 'application/json' },
  body: JSON.stringify({ model: 'gemini-2.5-flash', messages: [{ role: 'user', content: 'hi' }] }),
});
const reader = res.body.getReader();
const decoder = new TextDecoder();
const arrivals = [];

while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  arrivals.push(decoder.decode(value));
}

check('SSE стримится частями', arrivals.length > 1, `${arrivals.length} чтений`);
check('SSE склеивается в [DONE]', arrivals.join('').includes('[DONE]'));
check('content-length снят из потока', !res.headers.get('content-length'));
check('тело POST дошло', seen.at(-1).body.includes('gemini-2.5-flash'));
check('authorization сохранён', seen.at(-1).auth === 'Bearer secret-key');

res = await call('/v1beta/models', { headers: { 'x-goog-api-key': 'secret-key' } });
check('x-goog-api-key считается ключом', res.status === 403, seen.at(-1).key);

res = await call('/v1beta/models?key=abc', { headers: auth });
check('query не теряется', seen.at(-1).url === '/v1beta/models?key=abc', seen.at(-1).url);

res = await call('/openai/v1/chat/completions', { headers: auth });
check('посторонний путь → 404', res.status === 404);

res = await call('/v1beta/models', { method: 'OPTIONS' });
check('preflight → 204', res.status === 204 && res.headers.get('access-control-allow-origin') === '*');

res = await worker.fetch(new Request('https://gemini-gw.test/v1beta/models'), { UPSTREAM: 'http://127.0.0.1:1' });
check('недоступный апстрим → 502', res.status === 502);

res = await worker.fetch(new Request('https://gemini-gw.test/v1beta/models'), { UPSTREAM: base });
check('без API_KEY запрос проходит', res.status === 403);

res = await worker.fetch(
  new Request('https://gemini-gw.test/egress'),
  { UPSTREAM: base, EGRESS_URL: base + '/country' },
);
const egressInfo = JSON.parse(await res.text());
check('egress показывает страну выхода', res.status === 200 && egressInfo.country === 'SE', JSON.stringify(egressInfo));

res = await worker.fetch(
  new Request('https://gemini-gw.test/egress'),
  { EGRESS_URL: 'http://127.0.0.1:1/' },
);
check('egress без сети → 502', res.status === 502);

console.log(results.join('\n'));
upstream.close();
process.exit(results.some((line) => line.startsWith('❌')) ? 1 : 0);
