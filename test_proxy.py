import asyncio
import os
import subprocess
import sys

PROXY_PORT = int(os.environ.get("YT_PROXY_PORT", "8443"))

async def read_logs(proc):
    try:
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            print(f"[Proxy Log] {line.decode('utf-8', errors='ignore').strip()}", flush=True)
    except asyncio.CancelledError:
        pass

async def test_domain(proxy_host, proxy_port, target_host, target_port):
    print(f"\nTesting CONNECT to {target_host}:{target_port} via proxy...", flush=True)
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    try:
        connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n\r\n"
        writer.write(connect_req.encode('latin-1'))
        await writer.drain()
        
        resp = await reader.readuntil(b'\r\n\r\n')
        resp_line = resp.decode('latin-1').split('\r\n')[0]
        print(f"Proxy response: {resp_line}", flush=True)
        return resp_line
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

async def main():
    print("Starting proxy...", flush=True)
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "proxy.py",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Read stderr in background
    log_task = asyncio.create_task(read_logs(proc))
    
    # Wait for proxy to start
    await asyncio.sleep(2)
    
    success = True
    try:
        # 1. Test non-YouTube domain (e.g., example.com)
        resp = await test_domain("127.0.0.1", PROXY_PORT, "example.com", 80)
        if "200 Connection Established" not in resp:
            print(f"❌ Failed for example.com: {resp}", flush=True)
            success = False
        
        # 2. Test YouTube domain (e.g., youtube.com)
        resp = await test_domain("127.0.0.1", PROXY_PORT, "youtube.com", 443)
        if "200 Connection Established" not in resp:
            print(f"❌ Failed for youtube.com: {resp}", flush=True)
            success = False

        # 3. Test Telegram domain (e.g., telegram.org)
        resp = await test_domain("127.0.0.1", PROXY_PORT, "telegram.org", 443)
        if "200 Connection Established" not in resp:
            print(f"❌ Failed for telegram.org: {resp}", flush=True)
            success = False

        # 4. Test web.telegram.org (SNI-swap target)
        resp = await test_domain("127.0.0.1", PROXY_PORT, "web.telegram.org", 443)
        if "200 Connection Established" not in resp:
            print(f"❌ Failed for web.telegram.org: {resp}", flush=True)
            success = False

        # 5. Test td.ru domain
        resp = await test_domain("127.0.0.1", PROXY_PORT, "td.ru", 443)
        if "200 Connection Established" not in resp:
            print(f"❌ Failed for td.ru: {resp}", flush=True)
            success = False

        # 6. Test t.me domain
        resp = await test_domain("127.0.0.1", PROXY_PORT, "t.me", 443)
        if "200 Connection Established" not in resp:
            print(f"❌ Failed for t.me: {resp}", flush=True)
            success = False

        # 7. Instagram и TikTok идут обычным туннелем (без MITM). Доступность
        # зависит от сети: часть адресов Meta провайдер блэкхолит, поэтому
        # печатаем результат, но из-за него тест не валим.
        for social in ("www.instagram.com", "www.tiktok.com"):
            resp = await test_domain("127.0.0.1", PROXY_PORT, social, 443)
            print(f"ℹ️ {social}: {resp} (проверка сети, на итог не влияет)", flush=True)

        # 8. Gemini API: тоже без MITM — клиент должен видеть настоящий
        # сертификат Google, иначе ключ попадёт в перехваченный поток.
        resp = await test_domain("127.0.0.1", PROXY_PORT, "generativelanguage.googleapis.com", 443)
        if "200 Connection Established" not in resp:
            print(f"❌ Failed for generativelanguage.googleapis.com: {resp}", flush=True)
            success = False
            
    except Exception as e:
        print(f"❌ Exception occurred during test: {e}", flush=True)
        success = False
    finally:
        print("\nStopping proxy...", flush=True)
        proc.terminate()
        await proc.wait()
        log_task.cancel()
        
    if success:
        print("\n✅ All integration tests completed successfully!", flush=True)
        sys.exit(0)
    else:
        print("\n❌ Tests failed!", flush=True)
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())
