'use strict';

/**
 * Тесты расширения без запуска VS Code: подменяем модуль `vscode` заглушкой и
 * проверяем преобразование сообщений/инструментов и разбор SSE-потока.
 *
 *   node vscode-extension/test/extension.test.js
 */

const assert = require('assert');
const Module = require('module');
const path = require('path');

class LanguageModelTextPart {
  constructor(value) {
    this.value = value;
  }
}

class LanguageModelToolCallPart {
  constructor(callId, name, input) {
    this.callId = callId;
    this.name = name;
    this.input = input;
  }
}

class LanguageModelToolResultPart {
  constructor(callId, content) {
    this.callId = callId;
    this.content = content;
  }
}

class LanguageModelDataPart {
  constructor(data, mimeType) {
    this.data = data;
    this.mimeType = mimeType;
  }
}

const vscodeStub = {
  LanguageModelTextPart,
  LanguageModelToolCallPart,
  LanguageModelToolResultPart,
  LanguageModelDataPart,
  LanguageModelChatMessageRole: { User: 1, Assistant: 2 },
  EventEmitter: class {
    constructor() {
      this.listeners = [];
      this.event = (listener) => {
        this.listeners.push(listener);
        return { dispose: () => {} };
      };
    }
    fire(value) {
      this.listeners.forEach((listener) => listener(value));
    }
    dispose() {}
  },
  ThemeIcon: class {},
  window: { showInformationMessage: async () => undefined, showInputBox: async () => undefined },
  workspace: {
    getConfiguration: () => ({ get: (key) => settings[key] }),
    onDidChangeConfiguration: () => ({ dispose() {} }),
  },
  commands: { registerCommand: () => ({ dispose() {} }) },
  extensions: { getExtension: () => undefined },
  lm: {
    registerLanguageModelChatProvider: (vendor, provider) => {
      registered.push({ vendor, provider });
      return { dispose() {} };
    },
  },
};

const settings = { baseUrl: 'https://w.test', fallbackModels: ['gemini-2.5-flash'] };
const registered = [];
const secrets = {
  value: 'test-key',
  get: async () => secrets.value,
  delete: async () => { secrets.value = undefined; },
  store: async (_key, value) => { secrets.value = value; },
  onDidChange: () => ({ dispose() {} }),
};

const originalLoad = Module._load;
Module._load = function load(request, parent, isMain) {
  if (request === 'vscode') {
    return vscodeStub;
  }
  return originalLoad.call(this, request, parent, isMain);
};

const extension = require(path.join(__dirname, '..', 'gemini-worker-chat', 'extension.js'));
const { convertMessages, convertTools, streamCompletion, summarize } = extension._internals;

const results = [];
const check = (name, fn) => {
  try {
    fn();
    results.push(`✅ ${name}`);
  } catch (error) {
    results.push(`❌ ${name} — ${error.message}`);
  }
};

check('текст и система → messages', () => {
  const messages = convertMessages([
    { role: 3, content: [new LanguageModelTextPart('ты ассистент')] },
    { role: 1, content: [new LanguageModelTextPart('привет')] },
  ]);

  assert.deepStrictEqual(messages, [
    { role: 'system', content: 'ты ассистент' },
    { role: 'user', content: 'привет' },
  ]);
});

check('tool call и tool result разъезжаются по ролям', () => {
  const messages = convertMessages([
    { role: 1, content: [new LanguageModelTextPart('погода?')] },
    {
      role: 2,
      content: [new LanguageModelToolCallPart('call-1', 'get_weather', { city: 'СПб' })],
    },
    {
      role: 1,
      content: [new LanguageModelToolResultPart('call-1', [new LanguageModelTextPart('+5')])],
    },
  ]);

  assert.strictEqual(messages[1].role, 'assistant');
  assert.strictEqual(messages[1].tool_calls[0].function.name, 'get_weather');
  assert.strictEqual(messages[1].tool_calls[0].function.arguments, '{"city":"СПб"}');
  assert.deepStrictEqual(messages[2], { role: 'tool', tool_call_id: 'call-1', content: '+5' });
});

check('картинка уходит как image_url в user-сообщении', () => {
  const messages = convertMessages([
    {
      role: 1,
      content: [
        new LanguageModelTextPart('что на фото?'),
        new LanguageModelDataPart(Buffer.from([1, 2, 3]), 'image/png'),
      ],
    },
  ]);

  assert.strictEqual(messages[0].content[0].type, 'text');
  assert.strictEqual(messages[0].content[1].type, 'image_url');
  assert.match(messages[0].content[1].image_url.url, /^data:image\/png;base64,/);
});

check('инструменты → OpenAI-схема, без параметров тоже', () => {
  const tools = convertTools([
    { name: 'read', description: 'чтение', inputSchema: { type: 'object', properties: { p: { type: 'string' } } } },
    { name: 'ping' },
  ]);

  assert.strictEqual(tools.length, 2);
  assert.deepStrictEqual(tools[1].function.parameters, { type: 'object', properties: {} });
});

check('summarize вытаскивает текст ошибки Google', () => {
  const text = summarize('{"error":{"code":400,"message":"User location is not supported for the API use."}}');

  assert.strictEqual(text, 'User location is not supported for the API use.');
});

const encoder = new TextEncoder();

function sseResponse(chunks) {
  return {
    body: (async function* generate() {
      for (const chunk of chunks) {
        yield encoder.encode(chunk);
      }
    })(),
  };
}

async function streamTests() {
  const reports = [];
  const progress = { report: (part) => reports.push(part) };
  const token = { isCancellationRequested: false };

  await streamCompletion(
    sseResponse([
      'data: {"choices":[{"delta":{"content":"При"}}]}\n\n',
      'data: {"choices":[{"delta":{"content":"вет"}}]}\n\n',
      'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-9","function":{"name":"get_weather","arguments":"{\\"city\\":"}}]}}]}\n\n',
      'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\\"СПб\\"}"}}]}}]}\n\n',
      'data: [DONE]\n\n',
    ]),
    progress,
    token,
  );

  results.push(
    reports
      .filter((part) => part instanceof LanguageModelTextPart)
      .map((part) => part.value)
      .join('') === 'Привет'
      ? '✅ SSE: текст собирается по дельтам'
      : '❌ SSE: текст собирается по дельтам',
  );

  const toolCall = reports.find((part) => part instanceof LanguageModelToolCallPart);

  results.push(
    toolCall && toolCall.callId === 'call-9' && toolCall.name === 'get_weather' && toolCall.input.city === 'СПб'
      ? '✅ SSE: tool call склеивается из фрагментов'
      : `❌ SSE: tool call склеивается из фрагментов — ${JSON.stringify(toolCall)}`,
  );

  const cancelled = [];
  await streamCompletion(
    sseResponse(['data: {"choices":[{"delta":{"content":"x"}}]}\n\n']),
    { report: (part) => cancelled.push(part) },
    { isCancellationRequested: true },
  );

  results.push(cancelled.length === 0 ? '✅ отмена прекращает разбор потока' : '❌ отмена прекращает разбор потока');
}

const http = require('http');

/** Интеграция: активируем расширение, гоняем провайдера по настоящему HTTP. */
async function integrationTests() {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    requests.push({ url: req.url, headers: req.headers, body });

    if (req.url.startsWith('/v1beta/models')) {
      if (req.headers['x-goog-api-key'] !== 'test-key') {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'Permission denied on the service.' } }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        models: [
          { name: 'models/gemini-2.5-flash', displayName: 'Gemini 2.5 Flash', inputTokenLimit: 1048576, outputTokenLimit: 65536, supportedGenerationMethods: ['generateContent'] },
          { name: 'models/text-embedding-004', supportedGenerationMethods: ['embedContent'] },
        ],
      }));
      return;
    }

    if (req.url === '/v1beta/openai/chat/completions') {
      if (req.headers.authorization !== 'Bearer bad-key') {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.write('data: {"choices":[{"delta":{"content":"готово"}}]}\n\n');
        res.write('data: [DONE]\n\n');
        res.end();
        return;
      }
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'User location is not supported for the API use.' } }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  settings.baseUrl = `http://127.0.0.1:${server.address().port}`;

  const context = {
    subscriptions: [],
    secrets,
    globalStorageUri: { fsPath: '/tmp' },
  };

  try {
    extension.activate(context);
    const provider = registered.at(-1)?.provider;
    results.push(registered.at(-1)?.vendor === 'gemini-worker' ? '✅ провайдер зарегистрирован под своим vendor' : '❌ провайдер зарегистрирован под своим vendor');

    const models = await provider.provideLanguageModelChatInformation({}, { isCancellationRequested: false });
    results.push(
      models.length === 1 && models[0].id === 'gemini-2.5-flash' && models[0].isUserSelectable && models[0].isBYOK
        ? '✅ список моделей: только generateContent-модели, выбираемые'
        : `❌ список моделей — ${JSON.stringify(models)}`,
    );

    const parts = [];
    await provider.provideLanguageModelChatResponse(
      models[0],
      [{ role: 1, content: [new LanguageModelTextPart('привет')] }],
      { tools: [{ name: 'read_file', description: 'чтение', inputSchema: { type: 'object', properties: {} } }], modelOptions: {} },
      { report: (part) => parts.push(part) },
      { isCancellationRequested: false, onCancellationRequested: () => ({ dispose() {} }) },
    );

    const sent = JSON.parse(requests.find((item) => item.url === '/v1beta/openai/chat/completions').body);
    results.push(
      sent.model === 'gemini-2.5-flash' && sent.stream === true && sent.tools?.[0]?.function?.name === 'read_file'
        ? '✅ запрос ушёл с моделью, stream и инструментами'
        : `❌ тело запроса — ${JSON.stringify(sent).slice(0, 200)}`,
    );
    results.push(
      parts.map((part) => part.value || '').join('') === 'готово' ? '✅ ответ доехал до чата' : '❌ ответ доехал до чата',
    );

    secrets.value = 'bad-key';
    let failure = '';
    try {
      await provider.provideLanguageModelChatResponse(
        models[0],
        [{ role: 1, content: [new LanguageModelTextPart('привет')] }],
        { modelOptions: {} },
        { report: () => {} },
        { isCancellationRequested: false, onCancellationRequested: () => ({ dispose() {} }) },
      );
    } catch (error) {
      failure = error.message;
    }
    results.push(
      failure.includes('User location is not supported')
        ? '✅ ошибка Google доходит до чата текстом'
        : `❌ текст ошибки — ${failure}`,
    );
  } finally {
    server.close();
  }
}

async function main() {
  await streamTests();
  await integrationTests();
  console.log(results.join('\n'));
  process.exit(results.some((line) => line.startsWith('❌')) ? 1 : 0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
