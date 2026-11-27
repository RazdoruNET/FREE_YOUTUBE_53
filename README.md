Вот видео подтверждение работоспособности... наслаждайтесь. https://www.youtube.com/watch?v=FQREHZC-gNk

# Знаешь почему это так просто?

80% бюджета осело еще до того как дошло до исполнителей на их руках осело еще 15-18% по итогу нужно было что то делать.
DPI? Ебанулся какой нахуй DPI это килотонны бабала на железо... знаешь скока щас стоит нужно для такой системы железо?
А бабаки выделяли и делать что-то надо... 

забанить айпи нельзя гугл ляжет. 
Забанить днс тоже смысла нет.

А давай пакастить отслеживать SNI и если они идут к youtube ломать рукопожатие... дешево и сердито...

Хуй там изи обойти... где бабки зина?

------------------------------

Завтра дополню обработчиком маршрутов что бы он не ломал трафик на других сайтах.
А пока вот вам рабочий болд наслаждайся:

## SNI-Swap Forward Proxy (YouTube + Telegram + Instagram/TikTok + Gemini API)
Высокопроизводительный асинхронный Forward-прокси на Python для обхода глубокого анализа пакетов (DPI) и ограничений доступа к YouTube и Telegram методом SNI-Swap (подмены заголовка Server Name Indication на google.com). Instagram и TikTok прокси тоже обслуживает, но без подмены SNI — для них включены DNS по HTTPS, перебор адресов и необязательный релей (см. раздел ниже). Gemini API — отдельная история: Google отказывает по стране IP, поэтому там нужен релей в поддерживаемой стране (раздел «Gemini API и Gemini CLI»).

------------------------------

## 🛠 Принцип работы (Архитектура)
Прокси-сервер выступает в роли посредника (MitmProxy) между вашим браузером и удалёнными серверами (Google Edge для YouTube, Telegram Edge для telegram.org). Весь процесс обхода ограничений разделен на 4 ключевых этапа:

[Браузер] --- (1) HTTP CONNECT ---> [Прокси (8443)] ---> (2) OK 200 Established
[Браузер] <===(3) TLS Handshake ===> [Внутренний TLS (8444)]
[Браузер] --- (4) Расшифрованный HTTP Запрос (Host: youtube.com) ---> [Внутренний TLS (8444)]
                                                                                      | (5) SNI-SWAP
                                                                                      v
                                                                             [Google Edge Server]
                                                                             (SNI: google.com)
                                                                             (Host: youtube.com)


   1. Перехват соединения (HTTP CONNECT): Браузер, настроенный на работу с прокси, отправляет на порт 8443 текстовую команду CONNECT youtube.com:443 HTTP/1.1. Прокси мгновенно отвечает кодом 200 Connection Established, создавая сквозной туннель.
   2. Безопасный хендшейк на Python 3.14+: Вместо нестабильного низкоуровневого апгрейда сокета на одном порту, поток данных прозрачно перенаправляется на внутренний TLS-порт 8444. Здесь поднимается полноценный TLS-сервер, который терминирует (принимает на себя) шифрование браузера с использованием доверенного самоподписанного SSL-сертификата.
   3. Фильтрация ALPN протоколов: На этапе рукопожатия прокси принудительно сообщает браузеру о поддержке исключительно HTTP/1.1. Это заставляет браузер отказаться от мультиплексирования HTTP/2 в рамках одной сессии, что позволяет прокси легко читать, разбирать и модифицировать заголовки каждого индивидуального запроса.
   4. Магия SNI-Swap: Прокси извлекает из дешифрованного запроса оригинальный заголовок Host (например, googlevideo.com или web.telegram.org), определяет IP апстрима (для Telegram-доменов — адрес релея, DEFAULT_TELEGRAM_RELAYS / YT_PROXY_TELEGRAM_RELAY) и открывает новое TLS-соединение к целевому серверу.
   * Главная хитрость: В параметрах этого исходящего TLS-соединения принудительно выставляется server_hostname = 'google.com'. ТСП/DPI провайдера видит легитимный запрос к разрешенному сервису Google и пропускает трафик. Сервера Google Edge полностью игнорируют SNI и маршрутизируют запрос по заголовку Host (youtube.com → youtube, googlevideo.com → видео). Для Telegram аналогично, но нужен свой релей: нативные A-записи telegram.org (149.154.167.99) блэкхолятся провайдером по IP, поэтому все Telegram-домены уходят на nginx-релей, который отдаёт нужный vhost по Host и принимает SNI=telegram.org. Адрес релея задаётся в DEFAULT_TELEGRAM_RELAYS или через переменную окружения YT_PROXY_TELEGRAM_RELAY=ip1,ip2 (проверка доступности — python3 proxy.py --check-telegram).
   
------------------------------

## 🚀 Инструкция по развертыванию на любой ОС## 1. Требования к системе

* Python версии 3.11, 3.12, 3.13 или 3.14+.
* OpenSSL установленный в системе (используется скриптом для автоматической генерации ключей шифрования при первом старте).

## 2. Установка и запуск скрипта

   1. Клонируйте репозиторий или перенесите код скрипта proxy.py на целевую машину.
   2. Создайте виртуальное окружение и запустите прокси:
   
   python3 -m venv .venv
   source .venv/bin/activate  # Для Linux/macOS# .venv\Scripts\activate   # Для Windows (PowerShell)
   
   python3 proxy.py
   
   3. При первом запуске скрипт автоматически создаст директорию certs/, локальный УЦ и SSL-сертификат со всеми необходимыми альтернативными именами субъектов (SAN), собранными из списков доменов, которые прокси расшифровывает: youtube.com, googlevideo.com, ytimg.com, ggpht.com, youtu.be, youtube-nocookie.com, youtubeeducation.com, yt.be, youtube.googleapis.com, telegram.org, td.ru, t.me, t.gd, tdesktop.com, relay-chat.adw.team, panel.adw.team (каждый домен + wildcard на поддомены).

   Сертификаты проверяются при каждом старте: наличие файлов, срок действия и соответствие key.pem ↔ cert.pem. Битые или отсутствующие файлы пересоздаются автоматически. Отдельные команды:

   python3 proxy.py --check-certs     # только проверка сертификатов, без запуска
   python3 proxy.py --regen-certs     # принудительный перевыпуск (нужно заново импортировать cert.pem!)
   python3 proxy.py --check-telegram  # проверить доступность релея и DC Telegram
   python3 proxy.py --check-gemini    # пускает ли Gemini текущая сеть и релей
   python3 proxy.py --scan-telegram   # найти хоть один незаблокированный адрес DC Telegram

   Директория certs/ добавлена в .gitignore: приватные ключи не попадают в репозиторий.

## 3. Настройка доверия сертификату (Критически важный этап)
Чтобы избежать системных ошибок защиты (NET::ERR_CERT_AUTHORITY_INVALID и HSTS), операционная система должна доверять сгенерированному локальному файлу certs/cert.pem.
##  Инструкция для macOS:

   1. Откройте приложение Связка ключей (Keychain Access).
   2. Перейдите в раздел Система -> Сертификаты.
   3. Перетащите туда файл certs/cert.pem.
   4. Кликните по нему дважды, откройте вкладку Доверие (Trust) и в поле «При использовании этого сертификата» выберите Всегда доверять (Always Trust).

## 🐧 Инструкция для Linux (Ubuntu/Debian):

sudo cp certs/cert.pem /usr/local/share/ca-certificates/yt-proxy.crt
sudo update-ca-certificates

## 🪟 Инструкция для Windows:

   1. Нажмите Win + R, введите certlm.msc (Сертификаты локального компьютера).
   2. Перейдите в папки Доверенные корневые центры сертификации -> Сертификаты.
   3. Нажмите правой кнопкой мыши -> Все задачи -> Импорт.
   4. Укажите путь к файлу certs/cert.pem и завершите импорт, согласившись с предупреждением безопасности.

------------------------------
## 🌐 Интеграция с браузером## Вариант А: Использование расширения SwitchyOmega (Рекомендуется)
Этот метод изолирует прокси внутри браузера, предотвращая перехват стороннего системного трафика (Telegram, СУБД, игры).

   1. Установите расширение Proxy SwitchyOmega в ваш браузер (Chrome, Firefox, Edge).
   2. Создайте профиль типа Proxy, назовите его YouTube-Proxy.
   3. Установите параметры: Protocol — HTTP, Server — 127.0.0.1, Port — 8443. Примените изменения.
   4. Перейдите в профиль auto switch (Автопереключение).
   5. Добавьте правила маршрутизации типа Host wildcard:
   * *.youtube.com ➔ YouTube-Proxy
      * *.googlevideo.com ➔ YouTube-Proxy
      * *.ytimg.com ➔ YouTube-Proxy
      * *.ggpht.com ➔ YouTube-Proxy
      * *.telegram.org ➔ YouTube-Proxy
      * *.td.ru ➔ YouTube-Proxy
      * *.t.me ➔ YouTube-Proxy
      * *.t.gd ➔ YouTube-Proxy
      * *.tdesktop.com ➔ YouTube-Proxy
   6. Правило по умолчанию An unmatched rule оставьте в режиме Direct (Напрямую).
   7. Нажмите Apply changes, кликните по иконке расширения в панели браузера и активируйте режим auto switch.

## Вариант Б: Глобальная настройка на уровне ОС

   1. Перейдите в сетевые настройки вашей операционной системы (Параметры Сети / Свойства Wi-Fi).
   2. Включите HTTPS / Secure Web Proxy.
   3. Введите адрес 127.0.0.1 и порт 8443.
   4. В поле исключений (Bypass/Игнорировать прокси для доменов) обязательно введите *, *.*, localhost, 127.0.0.1, чтобы прокси обрабатывал только прямые запросы из белого списка, не нарушая работу остальных сайтов.

------------------------------
## 🧪 Верификация работы
Для проверки корректности сборки туннеля и подмены заголовков из терминала, выполните следующую команду:

curl -k --proxy-insecure -I -x http://127.0.0.1:8443 https://youtube.com

Ожидаемый ответ:

HTTP/1.1 200 Connection Established
HTTP/1.1 301 Moved Permanently
Location: https://youtube.com
Server: ESF
...

Проверка Telegram:

curl -k --proxy-insecure -I -x http://127.0.0.1:8443 https://web.telegram.org

Ожидаемый ответ:

HTTP/1.1 200 Connection Established
HTTP/1.1 200 OK
Server: nginx/1.21.1
...

Если в логах запущенного Python-скрипта отображается запись 🔀 SNI-Swap Tunnel: youtube.com / web.telegram.org, а команды возвращают ожидаемые заголовки (Server: ESF / Server: nginx/1.21.1) — система полностью готова к работе.

Если Telegram не открывается, а в логах видны строки ⚠️ Апстрим <ip>:443 недоступен, запустите диагностику.
Быстрый вариант — проверка известных адресов; полный вариант — скан всех подсетей DC (около 20–30 секунд):

python3 proxy.py --check-telegram
python3 proxy.py --scan-telegram

Она проверяет доступность релея из YT_PROXY_TELEGRAM_RELAY (или DEFAULT_TELEGRAM_RELAYS), DC-адресов Telegram и DC по IPv6. Если все адреса недоступны, провайдер блэкхолит их по IP — поднимите релей на доступном сервере и укажите его: YT_PROXY_TELEGRAM_RELAY=ip1,ip2 python3 proxy.py

### Telegram без своего сервера: IPv6
Провайдеры блэкхолят IPv4-адреса DC Telegram (149.154.167.99, 149.154.175.50, 91.108.56.130 и т.д.), но IPv6-адреса тех же DC (2001:67c:4e8:f00x::a) обычно открыты. Прокси умеет туннелировать CONNECT [IPv6]:443, а список IPv4-адресов в апстриме теперь разрешается по обеим семьям (IPv4 первым, IPv6 как запасной путь).

Проверка и включение:
   1. На роутере включите IPv6 (режим SLAAC/DHCPv6, у провайдера он должен быть в тарифе).
   2. Убедитесь, что машина получила глобальный адрес: ifconfig | grep "inet6 2" и есть маршрут default.
   3. python3 proxy.py --check-telegram — строка ✅ Telegram DC по IPv6 доступны означает, что Telegram Desktop заработает напрямую (в нём уже включено «Try connecting through IPv6»).
Инструкция полностью оформлена и готова к добавлению в ваш проект. Рад, что прокси завелся и отлично справляется со своей задачью!
Если планируете разворачивать его на удаленном сервере или на домашнем роутере, дайте знать: я подскажу, как правильно изменить параметры привязки адреса (LISTEN_HOST) и настроить защиту прокси авторизацией (логин/пароль), чтобы им не могли воспользоваться посторонние.

### Instagram и TikTok
Эти домены **не** подменяют SNI: их фронты (Meta Edge, Akamai/TikTok) выбирают сайт по SNI и, в отличие от Google Edge, его не игнорируют — с SNI `google.com` такой сайт там просто не обслуживается. Поэтому Instagram и TikTok идут обычным туннелем (TLS остаётся сквозным, HTTP/2 не ломается), а их реальные проблемы прокси решает так:

- **DNS по HTTPS.** Провайдеры подменяют A-записи `instagram.com` на `127.0.0.1` — на живом домашнем подключении это воспроизводится. Прокси отбрасывает петлевые адреса и переспрашивает Cloudflare/Google по HTTPS. `YT_PROXY_DOH=0` выключает, `YT_PROXY_DOH_FIRST=1` — всегда начинать с DoH.
- **Перебор адресов.** Если часть IP заблэкхолена, прокси пробует все адреса (IPv4, затем IPv6) одновременно и повторяет круг: блокировка «дырявая», повтор часто проходит.
- **Резервные адреса.** Когда DNS-ответ заблэкхолен, а другой edge того же сервиса открыт (у Meta это обычная картина), укажите его явно:

      YT_PROXY_EXTRA_IPS='instagram.com,cdninstagram.com,fbcdn.net=157.240.205.174' python3 proxy.py

  Адрес ищется вручную: `--check-instagram` показывает, какие адреса получились из DNS и какие из них ответили; рабочий edge можно взять и с другого сервера, где сервис открыт. Один edge Meta обслуживает по SNI и API, и CDN, поэтому хватает одного адреса на все три домена.

- **Релей.** Когда недоступны и адреса — укажите HTTP-прокси на хосте, которому сервис открыт (например, второй сервер за WireGuard):

      YT_PROXY_RELAY=10.88.0.1:8443 YT_PROXY_RELAY_AUTH=user:pass python3 proxy.py

  Через релей идут только домены из `YT_PROXY_RELAY_DOMAINS` (по умолчанию Instagram, TikTok и их CDN), остальной трафик — напрямую. Список стоит сузить, если через релей сервис недоступен, а напрямую — работает: например, TikTok блокирует IP релея, но пускает узел. Если релей не ответил, прокси пробует прямое подключение.

  Для целей релея и белого списка прокси верит только DoH: провайдеры и хостеры подменяют системный DNS (`web.telegram.org` временами указывал на чужой сервер). Если DoH недоступен, остаётся системный DNS.

  В `YT_PROXY_RELAY_DOMAINS` можно указывать IP и подсети (`149.154.160.0/20`): Telegram ходит не только на имена, но и на адреса дата-центров. Домен, отданный релею, не перехватывается MITM — SNI-swap нужен только на заблокированном пути клиента.

  Релей можно запереть с его стороны: `YT_PROXY_AUTH=user:pass` требует `Proxy-Authorization` (без него — 407), `YT_PROXY_CONNECT_ALLOW=instagram.com,...` разрешает туннели только к перечисленным доменам (иначе — 403), а `YT_PROXY_NO_MITM=1` полностью выключает перехват TLS — релею он не нужен. Пара к `YT_PROXY_AUTH` на клиенте — `YT_PROXY_RELAY_AUTH`.

Диагностика показывает, что вернул системный DNS и DoH и какой адрес отдал HTTP:

    python3 proxy.py --check-instagram
    python3 proxy.py --check-tiktok

Если молчат все адреса — нужен релей или VPN: подмена SNI здесь не поможет.


------------------------------
## 🤖 Gemini API и Gemini CLI

Google отказывает не по SNI, а по **стране IP**: с российского адреса `generativelanguage.googleapis.com` отвечает `403 ACCESS_DENIED` («Permission denied on the service»), а с ключом — `400 FAILED_PRECONDITION` / «User location is not supported for the API use». Ни подмена SNI, ни DNS по HTTPS здесь не помогают: запрос должен физически выйти из поддерживаемой страны. Поэтому домены Gemini прокси отправляет в релей, отдельный от Instagram/Telegram:

    YT_PROXY_GEMINI_RELAY=vps.example.com:8443   # HTTP-прокси на хосте за границей
    YT_PROXY_GEMINI_RELAY_AUTH=user:pass         # если релей просит пароль

Если `YT_PROXY_GEMINI_RELAY` не задан, домены Gemini идут через общий `YT_PROXY_RELAY` — они входят в его список по умолчанию. TLS для Gemini остаётся сквозным: прокси не расшифровывает этот трафик, клиент видит настоящий сертификат Google, поэтому импортировать `certs/cert.pem` для Gemini не нужно.

В релей уходят домены из списка `GEMINI_DOMAINS` в `proxy.py`: `generativelanguage.googleapis.com`, `cloudcode-pa.googleapis.com`, `aiplatform.googleapis.com`, `oauth2.googleapis.com`, `accounts.google.com`, `www.googleapis.com`, `play.googleapis.com`, `cloudresourcemanager.googleapis.com`, `iamcredentials.googleapis.com`, `monitoring.googleapis.com`. Переменная `YT_PROXY_RELAY_DOMAINS` по-прежнему перекрывает список общего релея целиком, но на отдельный релей Gemini она не влияет.

### Диагностика

    python3 proxy.py --check-gemini

Скрипт делает по одному запросу к `/v1beta/models` напрямую и через релей и выносит вердикт: «регион поддерживается», «отказ по региону» или «ключ не принят». Вердикт по региону возможен только с ключом: без него Google одинаково отвечает «Permission denied on the service» и из поддерживаемой страны, и из заблокированной — это отказ анонимному клиенту, а не проверка местоположения. Полноценная проверка:

    GEMINI_API_KEY=AIza... python3 proxy.py --check-gemini

### Куда взять релей, если своего сервера нет

**Вариант 1 — Cloudflare Worker (бесплатно, без карты).** Worker исполняется в дата-центре Cloudflare за пределами РФ и ходит в Google уже оттуда:

   1. dash.cloudflare.com → Workers & Pages → Create → Worker.
   2. Вставить содержимое `cloudflare/gemini-gateway.js`, нажать Deploy. Адрес будет вида `https://gemini-gw.<аккаунт>.workers.dev`.
   3. По желанию: Settings → Variables → секрет `API_KEY` с вашим Gemini-ключом — тогда Worker обслужит только запросы с этим ключом.

Проверить Worker можно до деплоя — тест поднимает локальный апстрим и гоняет запросы через обработчик:

    node cloudflare/gemini-gateway.test.mjs

После деплоя видно, откуда Worker выходит в интернет (именно эту страну видит Google):

    curl -s https://gemini-gw.<аккаунт>.workers.dev/health   # colo — дата-центр Cloudflare
    curl -s https://gemini-gw.<аккаунт>.workers.dev/egress   # ip и country выхода

Если `country` показывает `RU`, включите Smart Placement (`placement = { mode = "smart" }` в `wrangler.toml`) — Worker начнёт исполняться ближе к апстриму, а не к вам.

Gemini CLI через Worker:

    export GOOGLE_GEMINI_BASE_URL=https://gemini-gw.<аккаунт>.workers.dev
    export GEMINI_API_KEY=AIza...
    gemini

**Вариант 2 — свой VPS.** На сервере за границей тот же `proxy.py` работает релеем (без MITM, с паролем и на внешнем адресе):

    YT_PROXY_LISTEN_HOST=0.0.0.0 YT_PROXY_AUTH=user:pass YT_PROXY_NO_MITM=1 python3 proxy.py

На своей машине:

    YT_PROXY_GEMINI_RELAY=<ip-vps>:8443 YT_PROXY_GEMINI_RELAY_AUTH=user:pass python3 proxy.py

Адрес и порты самого прокси настраиваются переменными `YT_PROXY_LISTEN_HOST`, `YT_PROXY_PORT` (по умолчанию 8443) и `YT_PROXY_INTERNAL_PORT` (8444).

### Gemini CLI

Через локальный прокси (нужен релей из варианта 2):

    HTTPS_PROXY=http://127.0.0.1:8443 GEMINI_API_KEY=AIza... gemini

`HTTP_PROXY`/`HTTPS_PROXY` Gemini CLI понимает, а `NO_PROXY=localhost,127.0.0.1` избавит локальные запросы от лишнего круга.

### VS Code, Copilot Chat (BYOK)

Модели Google добавляются в чат через «Manage Models…» в списке моделей. Два пути.

**Через Worker — без локального прокси и без релея.** В «Manage Models…» выберите *Custom Endpoint* (в старых сборках — *OpenAI Compatible*), введите Gemini API key и добавьте модель:

   * id и name: имя модели из ответа API, например `gemini-2.5-flash`;
   * URL: `https://gemini-gw.<аккаунт>.workers.dev/v1beta/openai/chat/completions`;
   * tool calling и vision — включить, `maxInputTokens` — 1048576, `maxOutputTokens` — 65536.

Список доступных моделей и заодно проверка Worker:

    curl -s -H "x-goog-api-key: $GEMINI_API_KEY" \
      https://gemini-gw.<аккаунт>.workers.dev/v1beta/models | head -40

Worker отдаёт OpenAI-совместимый слой Gemini, поэтому VS Code видит обычный Chat Completions-эндпоинт, а модель появляется в списке выбора.

**Через локальный прокси — нужен релей из варианта 2.** В «Manage Models…» выберите *Google* (Gemini) и вставьте ключ, а трафик Copilot направьте в прокси настройками:

    "http.proxy": "http://127.0.0.1:8443",
    "http.proxySupport": "on",
    "http.noProxy": ["localhost", "127.0.0.1"]

Затем `Developer: Reload Window`. Учтите: `http.proxy` действует на весь сетевой слой расширений (включая запросы к GitHub), поэтому прокси должен быть запущен — без него чат не ответит.

**Расширение: модели Gemini прямо в списке чата.** В репозитории лежит маленькое расширение `vscode-extension/` — оно регистрирует свой LanguageModelChatProvider и показывает модели Gemini из вашего Worker в списке моделей, без ручной сборки Custom Endpoint:

    cd vscode-extension && ./install.sh

Затем Command Palette → «Developer: Reload Window» → список моделей → «Gemini (Cloudflare)». Ключ хранится в SecretStorage: Command Palette → «Gemini (Worker): задать API-ключ». Адрес шлюза — настройка `geminiWorker.baseUrl`, состояние и ошибки — команда «Gemini (Worker): статус». Тесты расширения идут без VS Code: `node vscode-extension/test/extension.test.js`.

**Свои приложения** работают с обычным ключом:

    export HTTPS_PROXY=http://127.0.0.1:8443
    export GEMINI_API_KEY=AIza...

Для OpenAI-совместимых клиентов base URL — `https://generativelanguage.googleapis.com/v1beta/openai` (напрямую либо через Worker).
