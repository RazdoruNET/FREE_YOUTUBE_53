'use strict';

/**
 * Модели Gemini в чате VS Code (Copilot Chat) через Cloudflare Worker.
 *
 * Зачем: Google отказывает по стране IP («User location is not supported»),
 * а воркер исполняется в дата-центре Cloudflare вне РФ и ходит в Gemini оттуда.
 * Провайдер говорит с ним по OpenAI-совместимому слою Gemini
 * (`/v1beta/openai/chat/completions`), поэтому подмены формата не требуется.
 *
 * Регистрация — стабильный API `vscode.lm.registerLanguageModelChatProvider`,
 * тот же, которым пользуются сторонние BYOK-расширения.
 */

const vscode = require('vscode');
const crypto = require('crypto');

const VENDOR = 'gemini-worker';
const SECRET_KEY = 'geminiWorker.apiKey';
// LanguageModelChatMessageRole.System не экспортирован в публичном API.
const SYSTEM_ROLE = 3;
const CONFIG_SECTION = 'geminiWorker';
const MODELS_TTL_MS = 5 * 60 * 1000;
const MODELS_TIMEOUT_MS = 15000;

function config() {
  return vscode.workspace.getConfiguration(CONFIG_SECTION);
}

function baseUrl() {
  return String(config().get('baseUrl') || '').trim().replace(/\/+$/, '');
}

function fallbackModelIds() {
  const ids = config().get('fallbackModels');
  return Array.isArray(ids) && ids.length ? ids.map(String) : ['gemini-2.5-flash'];
}

function safeJson(value) {
  try {
    return JSON.stringify(value ?? {});
  } catch {
    return '{}';
  }
}

function isImagePart(part) {
  return Boolean(
    part &&
      typeof part.mimeType === 'string' &&
      part.mimeType.startsWith('image/') &&
      part.data &&
      typeof part.data.length === 'number',
  );
}

function textOfToolResult(part) {
  const chunks = [];

  for (const item of part.content || []) {
    if (typeof item === 'string') {
      chunks.push(item);
    } else if (item && typeof item.value === 'string') {
      chunks.push(item.value);
    } else if (item) {
      chunks.push(safeJson(item));
    }
  }

  return chunks.join('');
}

/** Сообщения VS Code → Chat Completions (текст, картинки, tool calls, tool results). */
function convertMessages(messages) {
  const out = [];

  for (const message of messages) {
    const role = message.role === 2 ? 'assistant' : message.role === SYSTEM_ROLE ? 'system' : 'user';
    let text = '';
    const images = [];
    const toolCalls = [];
    const toolResults = [];

    for (const part of message.content || []) {
      if (part instanceof vscode.LanguageModelTextPart) {
        text += part.value;
      } else if (part instanceof vscode.LanguageModelToolCallPart) {
        toolCalls.push({
          id: part.callId,
          type: 'function',
          function: { name: part.name, arguments: safeJson(part.input) },
        });
      } else if (part instanceof vscode.LanguageModelToolResultPart) {
        toolResults.push({ callId: part.callId, content: textOfToolResult(part) });
      } else if (isImagePart(part)) {
        images.push({
          type: 'image_url',
          image_url: { url: `data:${part.mimeType};base64,${Buffer.from(part.data).toString('base64')}` },
        });
      }
    }

    if (role === 'assistant') {
      if (text || toolCalls.length) {
        const entry = { role: 'assistant', content: text };

        if (toolCalls.length) {
          entry.tool_calls = toolCalls;
        }

        out.push(entry);
      }
    } else if (role === 'system') {
      if (text) {
        out.push({ role: 'system', content: text });
      }
    } else if (images.length) {
      out.push({ role: 'user', content: [...(text ? [{ type: 'text', text }] : []), ...images] });
    } else if (text) {
      out.push({ role: 'user', content: text });
    }

    for (const result of toolResults) {
      out.push({ role: 'tool', tool_call_id: result.callId, content: result.content });
    }
  }

  return out;
}

function convertTools(tools) {
  if (!tools || !tools.length) {
    return undefined;
  }

  return tools.map((tool) => ({
    type: 'function',
    function: {
      name: tool.name,
      description: tool.description,
      // Совместимые шлюзы иногда требуют явную схему и для инструментов без параметров.
      parameters: tool.inputSchema || { type: 'object', properties: {} },
    },
  }));
}

class GeminiWorkerProvider {
  constructor(context) {
    this.context = context;
    this.changeEmitter = new vscode.EventEmitter();
    this.onDidChangeLanguageModelChatInformation = this.changeEmitter.event;
    this.models = null;
    this.modelsStamp = 0;
    this.modelsError = null;

    context.subscriptions.push(
      this.changeEmitter,
      vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration(CONFIG_SECTION)) {
          this.invalidate();
        }
      }),
      context.secrets.onDidChange((event) => {
        if (event.key === SECRET_KEY) {
          this.invalidate();
        }
      }),
    );
  }

  invalidate() {
    this.models = null;
    this.modelsStamp = 0;
    this.changeEmitter.fire();
  }

  async apiKey() {
    const stored = await this.context.secrets.get(SECRET_KEY);

    if (stored) {
      return stored;
    }

    return (process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || '').trim();
  }

  /** Список моделей из `/v1beta/models`; при сбое — запасной список. */
  async listModels() {
    const fresh = this.models && Date.now() - this.modelsStamp < MODELS_TTL_MS;

    if (fresh) {
      return this.models;
    }

    const fallback = fallbackModelIds().map((id) => ({
      id,
      name: id,
      maxInputTokens: 1048576,
      maxOutputTokens: 65536,
      fromApi: false,
    }));
    const key = await this.apiKey();

    if (!key) {
      this.modelsError = 'Не задан API-ключ';
      this.models = fallback;
      this.modelsStamp = Date.now();
      return this.models;
    }

    try {
      const response = await fetch(`${baseUrl()}/v1beta/models`, {
        headers: { 'x-goog-api-key': key },
        signal: AbortSignal.timeout(MODELS_TIMEOUT_MS),
      });
      const payload = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      }

      const models = (payload.models || [])
        .filter((model) => (model.supportedGenerationMethods || []).includes('generateContent'))
        .map((model) => ({
          id: String(model.name || '').replace(/^models\//, ''),
          name: model.displayName || String(model.name || '').replace(/^models\//, ''),
          maxInputTokens: model.inputTokenLimit || 1048576,
          maxOutputTokens: model.outputTokenLimit || 65536,
          fromApi: true,
        }))
        .filter((model) => model.id);

      if (!models.length) {
        throw new Error('API вернул пустой список моделей');
      }

      this.models = models;
      this.modelsError = null;
    } catch (error) {
      this.modelsError = `${error && error.message ? error.message : error}`;
      this.models = fallback;
    }

    this.modelsStamp = Date.now();

    return this.models;
  }

  async provideLanguageModelChatInformation(_options, _token) {
    const models = await this.listModels();

    return models.map((model) => ({
      id: model.id,
      name: model.name,
      family: 'gemini',
      version: '1.0',
      detail: model.fromApi ? 'Gemini через Cloudflare Worker' : 'Gemini (список моделей не получен)',
      tooltip: `${baseUrl()}/v1beta/openai${this.modelsError ? ` — ${this.modelsError}` : ''}`,
      maxInputTokens: model.maxInputTokens,
      maxOutputTokens: model.maxOutputTokens,
      isBYOK: true,
      isUserSelectable: true,
      capabilities: {
        toolCalling: true,
        imageInput: true,
      },
    }));
  }

  async provideLanguageModelChatResponse(modelInfo, messages, options, progress, token) {
    const key = await this.apiKey();

    if (!key) {
      throw new Error('Gemini (Worker): не задан API-ключ — выполните команду «Gemini (Worker): задать API-ключ».');
    }

    const body = {
      model: modelInfo.id,
      messages: convertMessages(messages),
      stream: true,
      max_tokens: options.modelOptions?.maxTokens || modelInfo.maxOutputTokens,
    };
    const tools = convertTools(options.tools);

    if (tools) {
      body.tools = tools;
      body.tool_choice = 'auto';
    }

    if (typeof options.modelOptions?.temperature === 'number') {
      body.temperature = options.modelOptions.temperature;
    }

    const controller = new AbortController();
    const cancelSubscription = token.onCancellationRequested(() => controller.abort());

    try {
      const response = await fetch(`${baseUrl()}/v1beta/openai/chat/completions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${key}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text().catch(() => '');
        throw new Error(`Gemini: HTTP ${response.status} ${summarize(text)}`);
      }

      await streamCompletion(response, progress, token);
    } finally {
      cancelSubscription.dispose();
    }
  }

  async provideTokenCount(_modelInfo, text) {
    const chars = typeof text === 'string' ? text.length : countMessageChars(text);

    return Math.max(1, Math.ceil(chars / 4));
  }
}

function summarize(text) {
  const raw = String(text || '').trim();

  try {
    const parsed = JSON.parse(raw);
    const message = parsed?.error?.message || parsed?.message;

    if (message) {
      return String(message);
    }
  } catch {
    // Не JSON — отдаём как есть.
  }

  return raw.slice(0, 300);
}

function countMessageChars(message) {
  let total = 0;

  for (const part of message?.content || []) {
    if (part && typeof part.value === 'string') {
      total += part.value.length;
    }
  }

  return total;
}

/** Читает SSE от Chat Completions и отдаёт части в чат. */
async function streamCompletion(response, progress, token) {
  const decoder = new TextDecoder();
  const pending = new Map();
  let buffer = '';

  for await (const chunk of response.body) {
    if (token.isCancellationRequested) {
      return;
    }

    buffer += decoder.decode(chunk, { stream: true });

    let index;

    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);

      if (!line.startsWith('data:')) {
        continue;
      }

      const data = line.slice(5).trim();

      if (!data || data === '[DONE]') {
        continue;
      }

      let parsed;

      try {
        parsed = JSON.parse(data);
      } catch {
        continue;
      }

      if (parsed.error) {
        throw new Error(`Gemini: ${parsed.error.message || 'ошибка потока'}`);
      }

      const delta = parsed.choices?.[0]?.delta;

      if (!delta) {
        continue;
      }

      if (typeof delta.content === 'string' && delta.content) {
        progress.report(new vscode.LanguageModelTextPart(delta.content));
      }

      for (const call of delta.tool_calls || []) {
        const slot = pending.get(call.index ?? 0) || { id: '', name: '', args: '' };

        if (call.id) {
          slot.id = call.id;
        }

        if (call.function?.name) {
          slot.name += call.function.name;
        }

        if (call.function?.arguments) {
          slot.args += call.function.arguments;
        }

        pending.set(call.index ?? 0, slot);
      }
    }
  }

  for (const slot of pending.values()) {
    if (!slot.name) {
      continue;
    }

    let input = {};

    try {
      input = slot.args ? JSON.parse(slot.args) : {};
    } catch {
      input = {};
    }

    progress.report(
      new vscode.LanguageModelToolCallPart(slot.id || crypto.randomUUID(), slot.name, input),
    );
  }
}

async function setApiKey(provider) {
  const value = await vscode.window.showInputBox({
    title: 'Gemini (Worker): API-ключ',
    prompt: 'Ключ из Google AI Studio (хранится в SecretStorage VS Code)',
    password: true,
    ignoreFocusOut: true,
    validateInput: (text) => (text && text.trim() ? undefined : 'Ключ не может быть пустым'),
  });

  if (!value) {
    return;
  }

  await provider.context.secrets.store(SECRET_KEY, value.trim());
  provider.invalidate();
  vscode.window.showInformationMessage('Gemini (Worker): ключ сохранён.');
}

async function clearApiKey(provider) {
  await provider.context.secrets.delete(SECRET_KEY);
  provider.invalidate();
  vscode.window.showInformationMessage('Gemini (Worker): ключ удалён.');
}

async function showStatus(provider) {
  const models = await provider.listModels();
  const key = await provider.apiKey();

  await vscode.window.showInformationMessage(
    `Gemini (Worker): ${baseUrl()} — ключ ${key ? 'есть' : 'не задан'}, моделей ${models.length}` +
      (provider.modelsError ? `, ошибка: ${provider.modelsError}` : ''),
    { modal: false },
  );
}

function activate(context) {
  const provider = new GeminiWorkerProvider(context);

  context.subscriptions.push(
    vscode.commands.registerCommand('geminiWorker.setApiKey', () => setApiKey(provider)),
    vscode.commands.registerCommand('geminiWorker.clearApiKey', () => clearApiKey(provider)),
    vscode.commands.registerCommand('geminiWorker.showStatus', () => showStatus(provider)),
    vscode.lm.registerLanguageModelChatProvider(VENDOR, provider),
  );

  // Copilot Chat опрашивает провайдеров при своей активации: подталкиваем его,
  // иначе модели могут не появиться в списке до первого открытия чата.
  provider.changeEmitter.fire();
  Promise.resolve(vscode.extensions.getExtension('github.copilot-chat')?.activate())
    .then(() => provider.changeEmitter.fire())
    .catch(() => undefined);

  return { dispose: () => provider.changeEmitter.dispose() };
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
  // Экспортируется для тестов (vscode-extension/test/extension.test.js).
  _internals: { convertMessages, convertTools, streamCompletion, summarize },
};
