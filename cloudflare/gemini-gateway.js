/**
 * Cloudflare Worker: выход к Gemini API из страны, которой Google отказывает.
 *
 * Google проверяет страну IP клиента и отвечает «User location is not supported»
 * (без ключа — 403 ACCESS_DENIED). Подмена SNI здесь не помогает: запрос должен
 * физически выйти из поддерживаемой страны. Этот Worker исполняется в дата-центре
 * Cloudflare (для России — за пределами РФ) и ходит в Google уже оттуда, поэтому
 * ключ работает. Бесплатный план, карта не нужна.
 *
 * Разворачивание:
 *   1. https://dash.cloudflare.com → Workers & Pages → Create → Worker.
 *   2. Вставить этот файл целиком, Deploy.
 *   3. (по желанию) Settings → Variables → добавить секрет API_KEY со значением
 *      вашего Gemini API key: тогда Worker обслужит только запросы с этим ключом.
 *   4. Адрес будет вида https://gemini-gw.<аккаунт>.workers.dev.
 *
 * Клиенты:
 *   Gemini CLI:      GOOGLE_GEMINI_BASE_URL=https://gemini-gw.<аккаунт>.workers.dev
 *   VS Code:         Manage Models → Custom Endpoint → URL
 *                    https://gemini-gw.<аккаунт>.workers.dev/v1beta/openai/chat/completions
 *   Свой код:        base_url = "https://gemini-gw.<аккаунт>.workers.dev"
 *
 * Диагностика:
 *   /health — жив ли воркер и в каком дата-центре Cloudflare он исполняется;
 *   /egress — каким адресом и из какой страны воркер выходит в интернет
 *             (именно эту страну видит Google).
 *
 * Проксируется только Gemini API: пути /v1, /v1beta, /v1alpha. Всё остальное —
 * 404, чтобы Worker нельзя было использовать как открытый прокси.
 */

const DEFAULT_UPSTREAM = 'https://generativelanguage.googleapis.com';
const ALLOWED_PATH = /^\/(v1|v1beta|v1alpha)(\/|$)/;
// Сервисы, которые отвечают «чей это IP». Первый ответивший и покажет страну,
// из которой воркер ходит в Google.
const EGRESS_PROBES = ['https://api.country.is/', 'https://ipinfo.io/json'];

// Заголовки, которые нельзя передавать дальше: они описывают конкретное
// соединение или выдают клиента Cloudflare апстриму.
const REQUEST_SKIP = new Set([
  'host', 'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
  'proxy-authorization', 'proxy-connection', 'content-length',
  'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor',
  'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip',
]);

// Тело ответа Cloudflare отдаёт уже распакованным, поэтому content-encoding и
// content-length от апстрима были бы враньём: ответ уходит потоком (chunked),
// и SSE стримится как есть.
const RESPONSE_SKIP = new Set([
  'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
  'content-encoding', 'content-length',
]);

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type, x-goog-api-key, x-goog-api-client, x-gateway-token',
  'access-control-max-age': '86400',
};

function json(status, error) {
  return new Response(JSON.stringify({ error }, null, 2) + '\n', {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...CORS },
  });
}

function presentedKey(request) {
  const auth = (request.headers.get('authorization') || '').trim();
  const match = /^Bearer\s+(.+)$/i.exec(auth);

  if (match) {
    return match[1].trim();
  }

  return (request.headers.get('x-goog-api-key') || '').trim();
}

async function egress(colo, env) {
  const probes = env.EGRESS_URL ? [env.EGRESS_URL] : EGRESS_PROBES;

  for (const probe of probes) {
    try {
      const response = await fetch(probe, { headers: { accept: 'application/json' } });

      if (!response.ok) {
        continue;
      }

      const info = await response.json();

      return new Response(JSON.stringify({ ok: true, colo, probe, ...info }) + '\n', {
        status: 200,
        headers: { 'content-type': 'application/json; charset=utf-8', ...CORS },
      });
    } catch {
      // пробуем следующий сервис
    }
  }

  return json(502, { code: 502, message: 'Не удалось узнать свой внешний адрес', status: 'UNAVAILABLE' });
}

export default {
  async fetch(request, env = {}) {
    const url = new URL(request.url);
    const colo = (request.cf && request.cf.colo) || null;

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (url.pathname === '/' || url.pathname === '/health') {
      return new Response(
        JSON.stringify({
          ok: true,
          colo,
          upstream: env.UPSTREAM || DEFAULT_UPSTREAM,
          keyCheck: Boolean(env.API_KEY),
        }) + '\n',
        { status: 200, headers: { 'content-type': 'application/json; charset=utf-8', ...CORS } },
      );
    }

    if (url.pathname === '/egress') {
      return egress(colo, env);
    }

    if (env.API_KEY && presentedKey(request) !== env.API_KEY) {
      return json(401, {
        code: 401,
        message: 'Worker принимает только запросы с ключом из переменной API_KEY',
        status: 'UNAUTHENTICATED',
      });
    }

    if (!ALLOWED_PATH.test(url.pathname)) {
      return json(404, {
        code: 404,
        message: 'Проксируются только пути /v1, /v1beta и /v1alpha',
        status: 'NOT_FOUND',
      });
    }

    const base = (env.UPSTREAM || DEFAULT_UPSTREAM).replace(/\/+$/, '');
    const target = new URL(base + url.pathname);
    target.search = url.search;

    const headers = new Headers();

    for (const [name, value] of request.headers) {
      if (!REQUEST_SKIP.has(name.toLowerCase())) {
        headers.set(name, value);
      }
    }

    const hasBody = !['GET', 'HEAD'].includes(request.method);

    let upstream;

    try {
      upstream = await fetch(target.toString(), {
        method: request.method,
        headers,
        body: hasBody ? request.body : undefined,
        redirect: 'manual',
      });
    } catch (exc) {
      return json(502, {
        code: 502,
        message: `Апстрим недоступен: ${exc && exc.message}`,
        status: 'UNAVAILABLE',
      });
    }

    const out = new Headers();

    for (const [name, value] of upstream.headers) {
      if (!RESPONSE_SKIP.has(name.toLowerCase())) {
        out.set(name, value);
      }
    }

    for (const [name, value] of Object.entries(CORS)) {
      out.set(name, value);
    }

    return new Response(upstream.body, { status: upstream.status, headers: out });
  },
};
