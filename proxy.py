"""
YouTube SNI-swap Forward HTTP/HTTPS Proxy for Browsers.
Compatible with Python 3.11 - 3.14+.
Listens on 127.0.0.1:8443, routes through internal TLS on 127.0.0.1:8444.
"""

import asyncio
import ssl
import os
import logging
import sys
import socket

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
UPSTREAM_SNI = '://google.com'
CONNECT_TIMEOUT = 10

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


def resolve_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host


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


async def handle_connect_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Принимает CONNECT от браузера и перенаправляет поток на внутренний TLS лисенер."""
    try:
        initial_line = await reader.readuntil(b'\r\n')
        line = initial_line.decode('latin-1').strip()
        
        if not line.startswith('CONNECT'):
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return

        # Вычитываем заголовки CONNECT
        while True:
            header_line = await reader.readuntil(b'\r\n')
            if header_line == b'\r\n':
                break

        # Сообщаем браузеру, что туннель построен
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # Подключаемся к нашему собственному TLS-порту (8444)
        try:
            tls_reader, tls_writer = await asyncio.open_connection(LISTEN_HOST, INTERNAL_TLS_PORT)
        except Exception as e:
            log.error(f"❌ Не удалось связаться с внутренним TLS сервером: {e}")
            return

        # Запускаем мост между браузером и нашей TLS-частью скрипта
        await asyncio.gather(
            pipe(reader, tls_writer),
            pipe(tls_reader, writer),
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
            return

        parts = request_line.split(' ')
        if len(parts) < 2:
            return
        method, path = parts[0], parts[1]

        raw_host = parser.headers.get('host', 'youtube.com')
        clean_host = raw_host.split(':')[0]
        ip = resolve_ip(clean_host)

        log.info(f'🔀 SNI-Swap Tunnel: {clean_host} -> {ip} (SNI={UPSTREAM_SNI})')

        # Подключаемся к оригинальному IP Google с фейковым SNI
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=UPSTREAM_SNI),
            timeout=CONNECT_TIMEOUT
        )
    except Exception as e:
        log.error(f"❌ Ошибка соединения с апстримом: {e}")
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


async def main():
    cert_file = os.path.join(CERTS_DIR, 'cert.pem')
    key_file = os.path.join(CERTS_DIR, 'key.pem')
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        log.critical(f"Сертификаты не найдены в {CERTS_DIR}!")
        return

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

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Прокси остановлен.")
