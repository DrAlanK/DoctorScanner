import asyncio
import aiohttp
from aiohttp import web
import json
import time
import random
import ipaddress
import urllib.parse
import base64
import re
import sys
import subprocess

# --- Auto Installer ---
try:
    import aiohttp
except ImportError:
    print("[!] کتابخانه 'aiohttp' یافت نشد. در حال نصب خودکار، لطفاً منتظر بمانید...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "aiohttp"])
        import aiohttp
        print("[+] نصب پیش‌نیازها با موفقیت انجام شد!")
    except Exception as e:
        print(f"[-] خطا در نصب خودکار: {e}")
        print("لطفاً به صورت دستی دستور زیر را وارد کنید:")
        print("pip install aiohttp")
        sys.exit(1)
# ----------------------

PORT = 8080

SURFACE_RANGES = [
    "104.16.0.0/13", "172.64.0.0/13", "108.162.192.0/18"
]

DEEP_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]

# ----------------- Core Network Functions ----------------- #

def sample_ips_from_subnets(subnets, total_needed):
    sampled_ips = set()
    networks = []
    for block in subnets:
        try:
            networks.append(ipaddress.IPv4Network(block.strip()))
        except:
            continue
    if not networks: return []
    max_attempts = total_needed * 5
    attempts = 0
    while len(sampled_ips) < total_needed and attempts < max_attempts:
        attempts += 1
        net = random.choice(networks)
        net_int = int(net.network_address)
        broad_int = int(net.broadcast_address)
        if broad_int - net_int > 2:
            rand_int = random.randint(net_int + 1, broad_int - 1)
            sampled_ips.add(str(ipaddress.IPv4Address(rand_int)))
    return list(sampled_ips)

def parse_manual_data(raw_text):
    extracted_ips = []
    tokens = raw_text.replace(',', '\n').replace(' ', '\n').split('\n')
    for token in tokens:
        token = token.strip()
        if not token: continue
        if '/' in token:
            try:
                net = ipaddress.IPv4Network(token, strict=False)
                if net.num_addresses <= 64:
                    extracted_ips.extend([str(ip) for ip in net.hosts()])
                else:
                    net_int = int(net.network_address)
                    broad_int = int(net.broadcast_address)
                    for _ in range(50):
                        rand_int = random.randint(net_int + 1, broad_int - 1)
                        extracted_ips.append(str(ipaddress.IPv4Address(rand_int)))
            except: continue
        else:
            try:
                ipaddress.IPv4Address(token)
                extracted_ips.append(token)
            except: continue
    return list(set(extracted_ips))

async def verify_cloudflare_ip(session, ip, port, timeout_sec, do_speedtest):
    """
    HTTP/SNI Verification: Checks if the IP actually responds with Cloudflare headers.
    """
    protocol = "http" if port in [80, 8080, 8880, 2052, 2082, 2086, 2095] else "https"
    # Using a small file for ping/header check, and a larger one for speedtest
    chunk_size = 200000 if do_speedtest else 1000
    url = f"{protocol}://{ip}:{port}/__down?bytes={chunk_size}"
    
    headers = {
        "Host": "speed.cloudflare.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DoctorScannerPro"
    }

    try:
        start_time = time.time()
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout_sec), ssl=False) as response:
            server_header = response.headers.get('Server', '').lower()
            
            # Strict verification: Must be a Cloudflare IP
            if 'cloudflare' not in server_header:
                return None
            
            content = await response.read()
            elapsed_time = time.time() - start_time
            ping_ms = int(elapsed_time * 1000)
            
            dl_speed, ul_speed = 0.0, 0.0
            if do_speedtest and elapsed_time > 0:
                # Mbps calculation
                dl_speed = round((len(content) * 8 / 1000000) / elapsed_time, 2)
                # Note: Upload testing via POST /__up is omitted here to prevent CF blocks, 
                # focusing on highly accurate Download/Ping metrics instead.
                
            return {
                "ip": ip, 
                "port": port, 
                "ping": ping_ms,
                "dl_speed": dl_speed,
                "ul_speed": ul_speed
            }
    except Exception:
        return None

# ----------------- Injection Functions ----------------- #

def get_best_ip_for_port(alive_ips, target_port):
    suitable_ips = [ip for ip in alive_ips if ip.get('port') == target_port]
    if not suitable_ips:
        return None
    suitable_ips.sort(key=lambda x: (-x.get('dl_speed', 0), x.get('ping', 9999)))
    return suitable_ips[0]['ip']

def fix_b64_padding(s):
    return s + '=' * (-len(s) % 4)

def robust_config_injector(line, alive_ips):
    try:
        parsed = urllib.parse.urlparse(line)
        scheme = parsed.scheme.lower()
        
        # هندل کردن VMess (دیکود کامل JSON)
        if scheme == 'vmess':
            b64_str = fix_b64_padding(parsed.netloc + parsed.path)
            conf = json.loads(base64.urlsafe_b64decode(b64_str).decode('utf-8'))
            port = int(conf.get('port', 443))
            best_ip = get_best_ip_for_port(alive_ips, port)
            if best_ip:
                conf['add'] = best_ip
                conf['sni'] = conf.get('host', 'speed.cloudflare.com') # اطمینان از تنظیم بودن SNI
                new_b64 = base64.urlsafe_b64encode(json.dumps(conf).encode('utf-8')).decode('utf-8').rstrip('=')
                return f"vmess://{new_b64}"
            return f"{line} # (No valid IP found for port {port})"

        # هندل کردن VLESS, Trojan و اضافه کردن Fragment به عنوان ویژگی جدید
        if scheme in ['vless', 'trojan']:
            port = parsed.port if parsed.port else 443
            best_ip = get_best_ip_for_port(alive_ips, port)
            if best_ip:
                old_netloc = parsed.netloc
                # جایگزینی هوشمندانه هاست (پشتیبانی از IPv4 و IPv6)
                if '@' in old_netloc:
                    user_pass, host_port = old_netloc.split('@', 1)
                    new_netloc = f"{user_pass}@{best_ip}:{port}"
                else:
                    new_netloc = f"{best_ip}:{port}"
                
                # پارس کردن کوئری‌ها و اضافه کردن Fragment
                query_dict = dict(urllib.parse.parse_qsl(parsed.query))
                query_dict['sni'] = query_dict.get('sni', query_dict.get('host', ''))
                # اضافه کردن فرگمنت برای دور زدن فیلترینگ
                if 'fragment' not in query_dict and scheme == 'vless':
                    query_dict['fragment'] = '10-20,10-20,tlshello'
                
                new_query = urllib.parse.urlencode(query_dict)
                new_parsed = parsed._replace(netloc=new_netloc, query=new_query)
                return urllib.parse.urlunparse(new_parsed)
            return f"{line} # (No valid IP found for port {port})"

        return line 
    except Exception as e:
        return line

# ----------------- API Endpoints ----------------- #

async def handle_scan(request):
    try:
        params = await request.json()
    except:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    mode = params.get('mode', 'auto')
    ports_to_test = params.get('ports', [443])
    # استفاده از workers در aiohttp به عنوان محدودکننده کونکارنسی (Semaphore)
    workers = min(int(params.get('workers', 60)), 500) 
    timeout = int(params.get('timeout', 1200)) / 1000.0
    max_count = int(params.get('max_count', 80))
    auto_type = params.get('auto_type', 'surface')
    manual_data = params.get('manual_data', '')
    do_speedtest = params.get('do_speedtest', False)

    final_ips = []
    if mode == 'auto':
        subnets = SURFACE_RANGES if auto_type == 'surface' else DEEP_RANGES
        final_ips = sample_ips_from_subnets(subnets, max_count)
    else:
        parsed_manual = parse_manual_data(manual_data)
        final_ips = random.sample(parsed_manual, max_count) if len(parsed_manual) > max_count else parsed_manual

    tasks_info = [(ip, port) for ip in final_ips for port in ports_to_test]
    alive_results = []

    # اجرای ناهمگام اسکن‌ها با محدودیت کانکشن همزمان
    connector = aiohttp.TCPConnector(limit=workers)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            verify_cloudflare_ip(session, ip, port, timeout, do_speedtest) 
            for ip, port in tasks_info
        ]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                alive_results.append(res)

    if do_speedtest:
        alive_results.sort(key=lambda x: x['dl_speed'], reverse=True)
    else:
        alive_results.sort(key=lambda x: x['ping'])

    headers = {'Access-Control-Allow-Origin': '*'}
    return web.json_response({
        "total_scanned": len(tasks_info),
        "results": alive_results
    }, headers=headers)

async def handle_inject(request):
    try:
        params = await request.json()
    except:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    configs_raw = params.get('configs', '')
    alive_ips = params.get('ips', [])
    injected_list = []

    for line in configs_raw.strip().split('\n'):
        line = line.strip()
        if not line: continue
        injected_list.append(robust_config_injector(line, alive_ips))

    headers = {'Access-Control-Allow-Origin': '*'}
    return web.json_response({"injected": '\n'.join(injected_list)}, headers=headers)

async def handle_options(request):
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    }
    return web.Response(status=200, headers=headers)

# ----------------- Server Setup ----------------- #

async def handle_index(request):
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return web.Response(text=html_content, content_type='text/html')
    except FileNotFoundError:
        return web.Response(text="فایل index.html پیدا نشد!", status=404)

app = web.Application()
app.router.add_get('/', handle_index) 
app.router.add_post('/api/scan', handle_scan)
app.router.add_post('/api/inject', handle_inject)
app.router.add_route('OPTIONS', '/api/scan', handle_options)
app.router.add_route('OPTIONS', '/api/inject', handle_options)

if __name__ == '__main__':
    print("="*60)
    print(f"🔥 Doctor Scanner - Running at http://localhost:{PORT}")
    print("📢 Channel: @Doctor_Scanner")
    print("="*60)
    web.run_app(app, port=PORT, print=None)