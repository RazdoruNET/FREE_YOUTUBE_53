"""
YouTube SNI-swap Forward HTTP/HTTPS Proxy for Browsers.
Compatible with Python 3.11 - 3.14+.
Listens on 127.0.0.1:8443, routes through internal TLS on 127.0.0.1:8444.
"""

import asyncio
import ipaddress
import ssl
import os
import re
import logging
import struct
import sys
import socket
import subprocess
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stderr,
)
log = logging.getLogger('yt-proxy')

CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs')
LISTEN_HOST = '127.0.0.1'
PROXY_PORT = 8443        # Порт для настроек браузера/curl
INTERNAL_TLS_PORT = 8444 # Внутренний порт для безопасного хендшейка
UPSTREAM_SNI = 'google.com'
CONNECT_TIMEOUT = 10

CA_KEY_FILE = 'ca.key'
CA_CERT_FILE = 'ca.pem'
SERVER_KEY_FILE = 'key.pem'
SERVER_CERT_FILE = 'cert.pem'
CSR_FILE = 'leaf.csr'
OPENSSL_CONF_FILE = 'openssl.cnf'
CERT_VALID_DAYS = 3650
EXPIRY_WARN_SECONDS = 30 * 24 * 60 * 60
OPENSSL_TIMEOUT = 60

class HeaderParser:
    def __init__(self):
        self.reset()

    def reset(self):
        self.headers_done = False
        self.headers = {}
        self.buf = b''

    def feed(self, data: bytes) -> bool:
        self.buf += data
        end = self.buf.find(b'\r\n\r\n')
        if end == -1:
            return False
        header_block = self.buf[:end].decode('latin-1')
        self.buf = self.buf[end+4:]
        lines = header_block.split('\r\n')
        for line in lines:
            if ':' in line:
                k, v = line.split(':', 1)
                self.headers[k.strip().lower()] = v.strip()
        self.headers_done = True
        return True

    @property
    def body(self) -> bytes:
        return self.buf


# Релей для Telegram-доменов: их нативные A-записи (149.154.167.99) ISP
# блэкхолит по IP, поэтому *.telegram.org / t.me / td.ru идут на свой nginx,
# который отдаёт нужный vhost по заголовку Host.
# ВАЖНО: релей принимает только SNI telegram.org / google.com — SNI вида
# web.telegram.org рвёт TLS-хендшейк.
# Адрес релея можно переопределить без правки кода:
#   YT_PROXY_TELEGRAM_RELAY=10.0.0.1,10.0.0.2 python3 proxy.py
DEFAULT_TELEGRAM_RELAYS = ['81.200.113.186']
TELEGRAM_RELAY_ENV = 'YT_PROXY_TELEGRAM_RELAY'


def telegram_relay_ips() -> list:
    """Список IP релея Telegram из YT_PROXY_TELEGRAM_RELAY (или дефолт)."""
    raw = os.environ.get(TELEGRAM_RELAY_ENV, '')
    ips = [item.strip() for item in raw.replace(';', ',').split(',') if item.strip()]
    return ips or list(DEFAULT_TELEGRAM_RELAYS)

# DC-relay: карта "заблокированный DC IP -> список альтернативных IP того же DC".
# TG-кешка (Desktop) подключается к MTProto по "сырому" IP:443 — у неё нет SNI,
# нет HTTP-заголовков — просто TCP/TLS-туннель. Сервер принимает MTProto-сессию
# с ЛЮБОГО IP данного DC (сессия хранится на стороне DC, а не привязана к IP).
# Поэтому если ISP блэкхолит 194.221.250.50 (DC-2), мы прозрачно рутаим на
# соседний IP того же DC (194.221.250.51) — клиент не заметит разницы.
DC_RELAY = {
    # DC-2 (194.221.250.x)
    '194.221.250.50': ['194.221.250.51', '194.221.250.52'],
}

# Подсети дата-центров Telegram: именно их провайдеры блэкхолят целиком.
TELEGRAM_DC_NETS = [
    '149.154.160.0/20',   # DC1-DC4
    '91.108.56.0/22',     # DC5
    '194.221.250.0/24',   # дополнительные адреса DC из help.getConfig
    '194.221.252.0/24',
    '91.108.4.0/22',      # тестовые DC
]
SCAN_CONCURRENCY = 400
SCAN_CONNECT_TIMEOUT = 1.2

# IPv6-адреса дата-центров Telegram. Их провайдеры обычно не блэкхолят,
# поэтому при наличии IPv6 Telegram Desktop ходит напрямую (CONNECT [v6]:443).
TELEGRAM_DC_V6 = [
    '2001:67c:4e8:f001::a',
    '2001:67c:4e8:f002::a',
    '2001:67c:4e8:f003::a',
    '2001:67c:4e8:f004::a',
    '2001:b28:f23f:f005::a',
]


def relay_candidates(target_host: str, target_port: int) -> list:
    """Возвращает список candidate (ip, port) для попытки соединения.

    Если target_host из DC_RELAY — возвращает альтернативные IP того же DC
    (в порядке списка из DC_RELAY). Иначе — просто один original host.
    """
    host = target_host.lower()
    if host in DC_RELAY:
        # Порт берём из запроса (обычно 443 для MTProto).
        # Альтернативные IP того же DC обслуживают тот же порт.
        return [(ip, target_port) for ip in DC_RELAY[host]]
    return [(target_host, target_port)]


def is_telegram_host(host: str) -> bool:
    host = host.lower()
    return any(host == d or host.endswith('.' + d) for d in TELEGRAM_DOMAINS)


def sni_for_host(host: str) -> str:
    """Возвращает SNI-хост для апстрим-подключения исходя из целевого домена.
    Telegram: nginx выбирает vhost по SNI, поэтому нужно прислать telegram.org.
    YouTube: Google Edge игнорирует SNI и роутит по Host — гуглим google.com."""
    return 'telegram.org' if is_telegram_host(host) else UPSTREAM_SNI


def resolve_ips(host: str) -> list:
    """Возвращает список IP апстрима в порядке попыток.

    Telegram-домены идут на релей (их собственные A-записи заблэкхолены),
    остальные — DNS-разрешение по обеим семьям: сначала IPv4, затем IPv6
    (нужен, когда IPv4 заблэкхолен, а IPv6 у провайдера проходит).
    """
    if is_telegram_host(host):
        return telegram_relay_ips()
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except Exception:
        return [host]
    v4, v6 = [], []
    for family, _, _, _, sockaddr in infos:
        addr = sockaddr[0]
        if addr.startswith('::ffff:'):      # IPv4-mapped IPv6 — это тот же IPv4
            addr = addr[7:]
        bucket = v4 if family == socket.AF_INET or ':' not in addr else v6
        if addr not in bucket:
            bucket.append(addr)
    return v4 + v6 or [host]


def parse_host_port(target: str, default_port: int = 443) -> tuple:
    """Разбирает "host:port" из строки CONNECT, включая "[IPv6]:port"."""
    target = target.strip()
    if target.startswith('['):
        end = target.find(']')
        if end == -1:
            return target.strip('[]'), default_port
        host = target[1:end]
        port_part = target[end + 1:]
        if port_part.startswith(':') and port_part[1:].isdigit():
            return host, int(port_part[1:])
        return host, default_port
    if target.count(':') > 1:          # голый IPv6 без порта
        return target, default_port
    if ':' in target:
        host, _, port_part = target.rpartition(':')
        if port_part.isdigit():
            return host, int(port_part)
        return host, default_port
    return target, default_port


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Связывает два стрима сквозным пайпом."""
    try:
        while True:
            chunk = await reader.read(16384)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()
YOUTUBE_DOMAINS = [
    'youtube.com',
    'googlevideo.com',
    'ytimg.com',
    'ggpht.com',
    'youtu.be',
    'youtube-nocookie.com',
    'youtubeeducation.com',
    'yt.be',
    'youtube.googleapis.com',
]
# Telegram: основной сайт живёт на том же nginx-хосте td.ru
# (81.200.113.186), SNI DPI резал именно telegram.org.
TELEGRAM_DOMAINS = [
    'telegram.org',
    'td.ru',
    't.me',
    't.gd',
    'tdesktop.com',
    'relay-chat.adw.team',
    'panel.adw.team',
]
MITM_DOMAINS = YOUTUBE_DOMAINS + TELEGRAM_DOMAINS

# Apex-домены CDN, к которым браузер не обращается напрямую (только поддомены):
# их отсутствие в SAN не считается проблемой.
APEX_SAN_EXEMPT = {'ytimg.com', 'ggpht.com'}


def is_mitm_host(host: str) -> bool:
    """Проверяет, относится ли хост к доменам MITM (YouTube/Telegram и т.д.)."""
    host = host.lower()
    for domain in MITM_DOMAINS:
        if host == domain or host.endswith('.' + domain):
            return True
    return False
async def handle_connect_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Принимает CONNECT от браузера. Если запрос идет к YouTube, перенаправляет поток на внутренний TLS лисенер (MITM). Иначе идет напрямую к хосту."""
    try:
        initial_line = await reader.readuntil(b'\r\n')
        line = initial_line.decode('latin-1').strip()
        
        if not line.startswith('CONNECT'):
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return

        parts = line.split()
        if len(parts) < 2:
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return

        target_host, target_port = parse_host_port(parts[1])

        # Вычитываем заголовки CONNECT
        while True:
            header_line = await reader.readuntil(b'\r\n')
            if header_line == b'\r\n':
                break

        is_mitm = is_mitm_host(target_host)

        if is_mitm:
            log.info(f"🎯 Направление трафика на MITM (внутренний TLS): {target_host}:{target_port}")
            try:
                upstream_reader, upstream_writer = await asyncio.open_connection(LISTEN_HOST, INTERNAL_TLS_PORT)
            except Exception as e:
                log.error(f"❌ Не удалось связаться с внутренним TLS сервером: {e}")
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
                return
        else:
            candidates = relay_candidates(target_host, target_port)
            upstream_reader = upstream_writer = None
            for idx, (ip, port) in enumerate(candidates):
                if idx > 0:
                    log.info(f"🔁 DC-relay: пробуем {ip}:{port} (попытка {idx + 1})")
                else:
                    log.info(f"🟢 Обход MITM (напрямую): {ip}:{port}")
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=CONNECT_TIMEOUT
                    )
                    if idx > 0:
                        log.info(f"✅ DC-relay: соединение установлено через {ip}:{port}")
                    break
                except Exception as e:
                    log.warning(f"⚠️ Не удалось подключиться к {ip}:{port}: {e!r}")
                    if idx == len(candidates) - 1:
                        log.error(f"❌ Все candidate для {target_host}:{target_port} исчерпаны")
                        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        await writer.drain()
                        return

        # Сообщаем браузеру, что туннель построен
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # Запускаем мост между браузером и апстримом (или внутренним TLS)
        await asyncio.gather(
            pipe(reader, upstream_writer),
            pipe(upstream_reader, writer),
            return_exceptions=True
        )

    except Exception as e:
        log.debug(f"Connect handler error: {e}")
    finally:
        writer.close()


async def handle_tls_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Принимает уже расшифрованный поток данных, делает SNI-swap к Google Edge."""
    buffer = b''
    request_line = None
    parser = HeaderParser()

    try:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                return
            buffer += chunk
            if b'\r\n\r\n' in buffer:
                header_part, body_part = buffer.split(b'\r\n\r\n', 1)
                lines = header_part.split(b'\r\n')
                if lines:
                    request_line = lines[0].decode('latin-1')
                parser.feed(buffer)
                break

        if not request_line or not parser.headers_done:
            writer.close()
            return

        parts = request_line.split(' ')
        if len(parts) < 2:
            writer.close()
            return
        method, path = parts[0], parts[1]

        raw_host = parser.headers.get('host', 'unknown')
        clean_host, _ = parse_host_port(raw_host)
        sni = sni_for_host(clean_host)

        # Подключаемся к апстриму с корректным SNI для vhost-подбора nginx
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        upstream_reader = upstream_writer = None
        last_error = None
        for ip in resolve_ips(clean_host):
            log.info(f'🔀 SNI-Swap Tunnel: {clean_host} -> {ip} (SNI={sni})')
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=sni),
                    timeout=CONNECT_TIMEOUT
                )
                break
            except Exception as exc:
                last_error = exc
                log.warning(f'⚠️ Апстрим {ip}:443 недоступен: {exc!r}')
        if upstream_writer is None:
            log.error(f"❌ Ошибка соединения с апстримом (handle_tls_client): {last_error!r}")
            writer.close()
            return
    except Exception as e:
        log.error(f"❌ Ошибка соединения с апстримом (handle_tls_client): {e!r}")
        writer.close()
        return

    # Пересобираем запрос
    req = f'{method} {path} HTTP/1.1\r\n'
    for k, v in parser.headers.items():
        if k.lower() == 'host':
            req += f'Host: {raw_host}\r\n'
        elif k.lower() in ('proxy-connection', 'proxy-authorization', 'connection'):
            continue
        else:
            req += f'{k}: {v}\r\n'
    req += 'Connection: close\r\n\r\n'

    try:
        upstream_writer.write(req.encode('latin-1'))
        if parser.body:
            upstream_writer.write(parser.body)
        await upstream_writer.drain()

        # Транслируем данные туда-обратно между Google и браузером
        await asyncio.gather(
            pipe(upstream_reader, writer),
            pipe(reader, upstream_writer),
            return_exceptions=True
        )
    except Exception as e:
        log.debug(f"Data transfer tunnel closed: {e}")
    finally:
        upstream_writer.close()


class CertError(RuntimeError):
    """Ошибка генерации/проверки локальных сертификатов."""


def cert_path(name: str) -> str:
    return os.path.join(CERTS_DIR, name)


def san_names() -> list:
    """SAN для сертификата прокси: каждый домен MITM + wildcard на поддомены."""
    names = []
    for domain in MITM_DOMAINS:
        for name in (domain, '*.' + domain):
            if name not in names:
                names.append(name)
    return names


def _openssl_config() -> str:
    alt_names = '\n'.join(
        f'DNS.{i} = {name}' for i, name in enumerate(san_names(), 1)
    )
    return f"""\
[ req ]
distinguished_name = dn
prompt             = no

[ dn ]
CN = YT-Proxy

[ v3_req ]
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @alt_names

[ alt_names ]
{alt_names}

[ v3_ca ]
basicConstraints     = critical, CA:TRUE
keyUsage             = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
"""


def _openssl(args: list, check: bool = True) -> subprocess.CompletedProcess:
    try:
        res = subprocess.run(
            ['openssl', *args],
            capture_output=True,
            text=True,
            timeout=OPENSSL_TIMEOUT,
        )
    except FileNotFoundError:
        raise CertError("openssl не найден в PATH — установите OpenSSL и повторите запуск")
    except subprocess.TimeoutExpired:
        raise CertError(f"openssl не ответил за {OPENSSL_TIMEOUT} с")
    if check and res.returncode != 0:
        details = (res.stderr or res.stdout or '').strip().splitlines()
        reason = details[-1] if details else 'неизвестная ошибка'
        raise CertError(f"openssl {args[0]}: {reason}")
    return res


def _openssl_text(args: list) -> str:
    return _openssl(args).stdout


def _cert_not_after(cert_file: str) -> str:
    raw = _openssl_text(['x509', '-in', cert_file, '-noout', '-enddate']).strip()
    return raw.split('=', 1)[1] if '=' in raw else raw


def _cert_sans(cert_file: str) -> list:
    text = _openssl_text(['x509', '-in', cert_file, '-noout', '-text'])
    marker = 'Subject Alternative Name'
    start = text.find(marker)
    if start == -1:
        return []
    block = text[start + len(marker):]
    end = block.find('X509v3')
    if end != -1:
        block = block[:end]
    return re.findall(r'DNS:([^,\s]+)', block)


def _san_covered(name: str, sans: list) -> bool:
    if name in sans:
        return True
    parts = name.split('.')
    return any('*.' + '.'.join(parts[i:]) in sans for i in range(1, len(parts)))


def generate_certs() -> None:
    """Создаёт локальный CA и листовой сертификат со всеми SAN доменов MITM."""
    os.makedirs(CERTS_DIR, exist_ok=True)
    conf_file = cert_path(OPENSSL_CONF_FILE)
    with open(conf_file, 'w', encoding='utf-8') as fh:
        fh.write(_openssl_config())

    ca_key, ca_cert = cert_path(CA_KEY_FILE), cert_path(CA_CERT_FILE)
    srv_key = cert_path(SERVER_KEY_FILE)
    srv_csr, srv_cert = cert_path(CSR_FILE), cert_path(SERVER_CERT_FILE)
    days = str(CERT_VALID_DAYS)

    log.info("🔐 Генерация локального УЦ (certs/ca.pem)...")
    _openssl(['genrsa', '-out', ca_key, '2048'])
    _openssl([
        'req', '-x509', '-new', '-key', ca_key, '-sha256', '-days', days,
        '-out', ca_cert, '-subj', '/CN=YT-Proxy-CA',
        '-config', conf_file, '-extensions', 'v3_ca',
    ])

    log.info("🔐 Генерация сертификата прокси (certs/cert.pem)...")
    _openssl([
        'req', '-new', '-nodes', '-newkey', 'rsa:2048',
        '-keyout', srv_key, '-out', srv_csr, '-subj', '/CN=YT-Proxy',
        '-config', conf_file,
    ])
    _openssl([
        'x509', '-req', '-in', srv_csr, '-CA', ca_cert, '-CAkey', ca_key,
        '-CAcreateserial', '-sha256', '-days', days, '-out', srv_cert,
        '-extfile', conf_file, '-extensions', 'v3_req',
    ])

    for path in (ca_key, srv_key):
        os.chmod(path, 0o600)
    log.info(f"✅ Сертификаты созданы в {CERTS_DIR}")


def inspect_certs() -> tuple:
    """Проверяет сертификаты. Возвращает (ошибки, предупреждения)."""
    errors, warnings = [], []
    srv_cert, srv_key = cert_path(SERVER_CERT_FILE), cert_path(SERVER_KEY_FILE)
    ca_cert, ca_key = cert_path(CA_CERT_FILE), cert_path(CA_KEY_FILE)

    for path in (srv_cert, srv_key):
        if not os.path.exists(path):
            errors.append(f"нет файла {os.path.basename(path)}")
    if errors:
        return errors, warnings

    try:
        if _openssl(['x509', '-in', srv_cert, '-noout', '-checkend', '0'], check=False).returncode != 0:
            errors.append("срок действия cert.pem истёк")
        elif _openssl(
            ['x509', '-in', srv_cert, '-noout', '-checkend', str(EXPIRY_WARN_SECONDS)],
            check=False,
        ).returncode != 0:
            warnings.append(f"cert.pem истекает {_cert_not_after(srv_cert)}")

        cert_pub = _openssl_text(['x509', '-in', srv_cert, '-noout', '-pubkey']).strip()
        key_pub = _openssl_text(['rsa', '-in', srv_key, '-pubout']).strip()
        if cert_pub != key_pub:
            errors.append("key.pem не соответствует cert.pem")

        sans = _cert_sans(srv_cert)
        missing = [
            name for name in san_names()
            if name not in APEX_SAN_EXEMPT and not _san_covered(name, sans)
        ]
        if missing:
            shown = ', '.join(missing[:5]) + (' ...' if len(missing) > 5 else '')
            warnings.append(f"в cert.pem нет SAN: {shown} (пересоздайте: --regen-certs)")
    except CertError as exc:
        errors.append(str(exc))
        return errors, warnings

    if not (os.path.exists(ca_cert) and os.path.exists(ca_key)):
        warnings.append("нет ca.pem/ca.key — сертификат нельзя продлить без перевыпуска")

    return errors, warnings


def ensure_certs(force: bool = False) -> None:
    """Проверяет сертификаты и создаёт их, если файлов нет или они невалидны."""
    if not force:
        errors, warnings = inspect_certs()
        for warning in warnings:
            log.warning(f"⚠️ Сертификаты: {warning}")
        if not errors:
            log.info(
                f"🔐 Сертификаты в порядке, действуют до {_cert_not_after(cert_path(SERVER_CERT_FILE))}"
            )
            return
        log.warning("⚠️ Проблемы с сертификатами: " + '; '.join(errors))
    else:
        log.info("🔐 Принудительный перевыпуск сертификатов (--regen-certs)")

    generate_certs()
    errors, warnings = inspect_certs()
    for warning in warnings:
        log.warning(f"⚠️ Сертификаты: {warning}")
    if errors:
        raise CertError("сертификаты не прошли проверку после генерации: " + '; '.join(errors))


async def main():
    try:
        ensure_certs()
    except CertError as exc:
        log.critical(f"❌ {exc}")
        return 1

    cert_file = cert_path(SERVER_CERT_FILE)
    key_file = cert_path(SERVER_KEY_FILE)

    # 1. Настраиваем официальный стабильный TLS контекст для внутреннего порта
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    ssl_ctx.set_alpn_protocols(['http/1.1'])

    # 2. Запускаем внутренний TLS сервер
    tls_server = await asyncio.start_server(
        handle_tls_client, LISTEN_HOST, INTERNAL_TLS_PORT, ssl=ssl_ctx
    )
    
    # 3. Запускаем внешний CONNECT прокси сервер
    proxy_server = await asyncio.start_server(
        handle_connect_request, LISTEN_HOST, PROXY_PORT
    )
    
    log.info(f"🚀 Прокси успешно запущен!")
    log.info(f"   -> Внешний порт для браузера: {LISTEN_HOST}:{PROXY_PORT}")
    log.info(f"   -> Внутренний TLS обработчик: {LISTEN_HOST}:{INTERNAL_TLS_PORT}")

    async with tls_server, proxy_server:
        await asyncio.gather(
            tls_server.serve_forever(),
            proxy_server.serve_forever()
        )

def probe_tcp(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


async def _scan_open(hosts: list, open_ips: list) -> None:
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)

    async def probe(ip):
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 443), timeout=SCAN_CONNECT_TIMEOUT
                )
                writer.close()
                open_ips.append(ip)
            except Exception:
                pass

    await asyncio.gather(*(probe(ip) for ip in hosts))


async def _is_mtproto(ip: str, timeout: float = 3.0) -> bool:
    """Проверяет, отвечает ли адрес как MTProto-DC (resPQ на req_pq_multi)."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 443), timeout=timeout)
    except Exception:
        return False
    try:
        body = struct.pack('<I', 0xbe7e8ef1) + os.urandom(16)
        msg_id = int(time.time() * (2 ** 32)) & ~3
        writer.write(b'\x00' * 8 + struct.pack('<Q', msg_id) + struct.pack('<I', len(body)) + body)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(32), timeout=timeout)
        return len(data) >= 24 and struct.unpack('<I', data[20:24])[0] == 0x05162463
    except Exception:
        return False
    finally:
        writer.close()


async def _serves_telegram_web(ip: str, timeout: float = 4.0) -> bool:
    """Проверяет, отдаёт ли адрес веб-клиент web.telegram.org."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=ctx, server_hostname='telegram.org'), timeout=timeout
        )
    except Exception:
        return False
    try:
        writer.write(
            b'GET /k/ HTTP/1.1\r\nHost: web.telegram.org\r\n'
            b'User-Agent: yt-proxy\r\nConnection: close\r\n\r\n'
        )
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b'\r\n'), timeout=timeout)
        return head.startswith(b'HTTP/1.1 200')
    except Exception:
        return False
    finally:
        writer.close()


def cli_scan_telegram() -> int:
    """`--scan-telegram`: ищет хоть один незаблокированный адрес DC Telegram."""
    hosts = [str(ip) for net in TELEGRAM_DC_NETS for ip in ipaddress.ip_network(net).hosts()]
    log.info(f"Сканирую {len(hosts)} адресов подсетей DC Telegram, порт 443...")
    open_ips = []
    started = time.time()
    asyncio.run(_scan_open(hosts, open_ips))
    log.info(f"Открыто {len(open_ips)} из {len(hosts)} (за {time.time() - started:.1f} с)")

    if not open_ips:
        log.error("❌ Ни один адрес DC Telegram не отвечает — провайдер блэкхолит")
        log.error("   подсети 149.154.160.0/20, 91.108.56.0/22 и 194.221.25x.0/24 целиком.")
        log.info("💡 Пробить это можно только промежуточным узлом (релей/VPN) или IPv6:"
                 " IPv6-адреса DC обычно не блокируются, прокси их уже умеет.")
        return 1

    mtproto = [ip for ip in open_ips if asyncio.run(_is_mtproto(ip))]
    web = [ip for ip in open_ips if asyncio.run(_serves_telegram_web(ip))]

    if mtproto:
        log.info("✅ MTProto-DC доступны: " + ', '.join(mtproto))
    if web:
        log.info("✅ Отдают web.telegram.org: " + ', '.join(web))
        log.info(f"💡 Пропишите релей: {TELEGRAM_RELAY_ENV}={','.join(web)} python3 proxy.py")
    if not web:
        log.warning("⚠️ Открытые адреса не отдают web.telegram.org — для веб-клиента нужен релей или IPv6")
    return 0 if web else 1


def cli_check_telegram() -> int:
    """`--check-telegram`: проверяет доступность релея и DC Telegram."""
    ok = True
    relays = telegram_relay_ips()
    log.info(f"Релей Telegram ({TELEGRAM_RELAY_ENV}): {', '.join(relays)}")
    for ip in relays:
        if probe_tcp(ip, 443):
            log.info(f"✅ релей {ip}:443 доступен")
        else:
            ok = False
            log.error(f"❌ релей {ip}:443 недоступен — Telegram-домены работать не будут")
    for ip in sorted(DC_RELAY):
        if probe_tcp(ip, 443):
            log.info(f"✅ DC {ip}:443 доступен")
        else:
            log.warning(f"⚠️ DC {ip}:443 заблэкхолен — нужен рабочий IP того же DC")

    reachable_v6 = [ip for ip in TELEGRAM_DC_V6 if probe_tcp(ip, 443, timeout=2.0)]
    if reachable_v6:
        log.info("✅ Telegram DC по IPv6 доступны: " + ', '.join(reachable_v6))
        ok = True
    else:
        log.warning(
            "⚠️ Telegram DC по IPv6 недоступны — включите IPv6 у провайдера/на роутере, "
            "это самый надёжный путь без своего сервера"
        )

    if not ok:
        log.info(f"💡 Альтернатива — доступный релей: {TELEGRAM_RELAY_ENV}=ip1,ip2 python3 proxy.py")
    return 0 if ok else 1


def cli_check_certs() -> int:
    """`--check-certs`: только проверка сертификатов, без запуска прокси."""
    errors, warnings = inspect_certs()
    for warning in warnings:
        log.warning(f"⚠️ Сертификаты: {warning}")
    if errors:
        for error in errors:
            log.error(f"❌ {error}")
        return 1
    log.info(f"✅ Сертификаты в порядке, действуют до {_cert_not_after(cert_path(SERVER_CERT_FILE))}")
    return 0


if __name__ == '__main__':
    args = sys.argv[1:]
    if '--check-certs' in args:
        sys.exit(cli_check_certs())
    if '--check-telegram' in args:
        sys.exit(cli_check_telegram())
    if '--scan-telegram' in args:
        sys.exit(cli_scan_telegram())
    if '--regen-certs' in args:
        try:
            ensure_certs(force=True)
        except CertError as exc:
            log.critical(f"❌ {exc}")
            sys.exit(1)
        sys.exit(0)

    try:
        exit_code = asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Прокси остановлен.")
        exit_code = 0
    sys.exit(exit_code or 0)
