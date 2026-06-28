import sys
import subprocess
import importlib

# ==========================================
# 📦 سیستم نصب خودکار کتابخانه‌های خارجی
# ==========================================
REQUIRED_PACKAGES = []

def auto_install_packages():
    if not REQUIRED_PACKAGES:
        return
    print("📦 در حال بررسی پیش‌نیازهای سیستم...")
    for package in REQUIRED_PACKAGES:
        try:
            importlib.import_module(package)
        except ImportError:
            print(f"⚙️ در حال دانلود و نصب کتابخانه [{package}]...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"✅ نصب {package} با موفقیت انجام شد.")
            except Exception as e:
                print(f"❌ خطا در نصب {package}: {e}")
                sys.exit(1)

auto_install_packages()

# ==========================================
# 🚀 وارد کردن کتابخانه‌های استاندارد پایتون
# ==========================================
import json
import time
import random
import string
import ipaddress
import urllib.parse
import urllib.request
import base64
import ssl
import os
import socket
import http.server
import socketserver
import concurrent.futures
import secrets
import webbrowser
import threading

# --- تلاش برای افزایش محدودیت سوکت‌ها ---
try:
    import resource
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    target_limit = min(hard_limit, 8192) if hard_limit != resource.RLIM_INFINITY else 8192
    if soft_limit < target_limit:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, hard_limit))
except Exception:
    pass

PORT = 8080

# --- سیستم امنیت حرفه‌ای مبتنی بر Cookie & Token ---
ADMIN_USER = "admin"
alphabet = string.ascii_letters + string.digits
ADMIN_PASS = ''.join(secrets.choice(alphabet) for _ in range(10))

# --- سیستم دریافت زنده رنج‌ها ---
def fetch_cloudflare_ips():
    print("🌐 در حال دریافت جدیدترین رنج‌های شبکه از سرور کلادفلر...")
    try:
        req = urllib.request.Request(
            "https://www.cloudflare.com/ips-v4", 
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = response.read().decode('utf-8')
            ranges = [line.strip() for line in data.split('\n') if line.strip()]
            if ranges:
                print(f"✅ {len(ranges)} رنج با موفقیت دریافت شد.")
                return ranges
    except Exception as e:
        print(f"⚠️ دریافت آنلاین ناموفق بود ({e}). استفاده از دیتابیس آفلاین...")
    
    # دیتابیس پشتیبان (آفلاین)
    return [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
    ]

CLOUDFLARE_ALL_RANGES = fetch_cloudflare_ips()
SURFACE_BASE_RANGES = [
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", 
    "188.114.96.0/20", "162.158.0.0/15"
]

def expand_to_24_subnets(cidrs):
    subnets_24 = []
    for cidr in cidrs:
        try:
            network = ipaddress.IPv4Network(cidr)
            if network.prefixlen <= 24:
                subnets_24.extend(list(network.subnets(new_prefix=24)))
            else:
                subnets_24.append(network)
        except Exception:
            continue
    return subnets_24

SURFACE_SUBNETS_24 = expand_to_24_subnets(SURFACE_BASE_RANGES)
DEEP_SUBNETS_24 = expand_to_24_subnets(CLOUDFLARE_ALL_RANGES)

def sample_ips_from_subnets(subnets_list, total_needed):
    sampled_ips = set()
    if not subnets_list: 
        return []
    
    max_attempts = total_needed * 10
    attempts = 0
    
    while len(sampled_ips) < total_needed and attempts < max_attempts:
        attempts += 1
        net = random.choice(subnets_list)
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
        if not token: 
            continue
            
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
            except: 
                continue
        else:
            try:
                ipaddress.IPv4Address(token)
                extracted_ips.append(token)
            except: 
                continue
                
    return list(set(extracted_ips))

# ----------------- Core Network Functions ----------------- #

def verify_cloudflare_ip(ip, port, timeout_sec, payload_mb, custom_sni):
    protocol = "https" if port in [443, 8443, 2053, 2083, 2087, 2096] else "http"
    start_time = time.time()
    colo = "???"
    
    try:
        with socket.create_connection((ip, port), timeout=timeout_sec) as sock:
            if protocol == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=custom_sni)
            
            # درخواست هدر برای استخراج دیتاسنتر
            req = f"GET / HTTP/1.1\r\nHost: {custom_sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
            sock.sendall(req)
            header_data = sock.recv(2048)
            
            # استخراج نام دیتاسنتر (Colo) از هدر CF-RAY
            header_str = header_data.decode('utf-8', errors='ignore')
            for line in header_str.split('\r\n'):
                if line.lower().startswith('cf-ray:'):
                    colo = line.split('-')[-1].strip()
                    break

        if b"cloudflare" not in header_data.lower() and b"cf-ray" not in header_data.lower():
            return None
            
        ping_ms = int((time.time() - start_time) * 1000)
        dl_speed, ul_speed = 0.0, 0.0
        
        do_speedtest = payload_mb > 0
        if do_speedtest:
            target_bytes = payload_mb * 1024 * 1024
            try:
                with socket.create_connection((ip, port), timeout=timeout_sec) as dl_sock:
                    if protocol == "https":
                        dl_sock = ctx.wrap_socket(dl_sock, server_hostname=custom_sni)
                    
                    req_dl = f"GET /__down?bytes={target_bytes} HTTP/1.1\r\nHost: {custom_sni}\r\nConnection: close\r\n\r\n".encode()
                    dl_sock.sendall(req_dl)
                    dl_sock.settimeout(timeout_sec)
                    _ = dl_sock.recv(1024) # رد کردن هدرها
                    
                    dl_st_time = time.time()
                    bytes_recv = 0
                    
                    while True:
                        if (time.time() - dl_st_time) > 1.5: 
                            break
                        chunk = dl_sock.recv(32768)
                        if not chunk: 
                            break
                        bytes_recv += len(chunk)
                        
                    el = time.time() - dl_st_time
                    if el > 0 and bytes_recv > 0: 
                        dl_speed = round((bytes_recv * 8 / 1000000) / el, 2)
            except Exception: 
                pass 
        
        return {
            "ip": ip, "port": port, "ping": ping_ms, 
            "dl_speed": dl_speed, "ul_speed": ul_speed, "colo": colo
        }
        
    except Exception: 
        return None

def get_best_ip_for_port(alive_ips, target_port):
    suitable_ips = [ip for ip in alive_ips if ip.get('port') == target_port]
    if not suitable_ips: 
        return None
    suitable_ips.sort(key=lambda x: (-x.get('dl_speed', 0), x.get('ping', 9999)))
    return suitable_ips[0]['ip']

def fix_b64_padding(s): 
    return s + '=' * (-len(s) % 4)

def robust_config_injector(line, alive_ips, custom_sni):
    try:
        parsed = urllib.parse.urlparse(line)
        scheme = parsed.scheme.lower()
        
        if scheme == 'vmess':
            b64_str = fix_b64_padding(parsed.netloc + parsed.path)
            conf = json.loads(base64.urlsafe_b64decode(b64_str).decode('utf-8'))
            port = int(conf.get('port', 443))
            best_ip = get_best_ip_for_port(alive_ips, port)
            
            if best_ip:
                conf['add'] = best_ip
                conf['sni'] = custom_sni # اعمال اتوماتیک SNI
                new_b64 = base64.urlsafe_b64encode(json.dumps(conf).encode('utf-8')).decode('utf-8').rstrip('=')
                return f"vmess://{new_b64}"
            return f"{line} # (No IP for port {port})"

        if scheme in ['vless', 'trojan']:
            port = parsed.port if parsed.port else 443
            best_ip = get_best_ip_for_port(alive_ips, port)
            
            if best_ip:
                user_pass = parsed.netloc.split('@')[0] if '@' in parsed.netloc else ''
                new_netloc = f"{user_pass}@{best_ip}:{port}" if user_pass else f"{best_ip}:{port}"
                
                query_dict = dict(urllib.parse.parse_qsl(parsed.query))
                query_dict['sni'] = custom_sni # اعمال اتوماتیک SNI
                
                if 'fragment' not in query_dict and scheme == 'vless': 
                    query_dict['fragment'] = '10-20,10-20,tlshello'
                
                new_query = urllib.parse.urlencode(query_dict)
                new_parsed = parsed._replace(netloc=new_netloc, query=new_query)
                return urllib.parse.urlunparse(new_parsed)
            return f"{line} # (No IP for port {port})"

        return line 
    except Exception: 
        return line

# ----------------- Pure Python Web Server ----------------- #

class APIHandler(http.server.SimpleHTTPRequestHandler):
    
    def check_auth(self, is_api=False):
        cookie_header = self.headers.get('Cookie', '')
        
        if f"auth_token={ADMIN_PASS}" in cookie_header: 
            return True
            
        if is_api:
            self.send_response(401)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}')
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            login_html = f"""
            <!DOCTYPE html>
            <html lang="fa" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Login | Doctor Scanner Pro</title>
                <style>
                    body {{ background-color: #050505; color: #d4af37; font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
                    .box {{ background: #0f0f0f; padding: 30px; border: 1px solid #d4af37; border-radius: 12px; text-align: center; box-shadow: 0 0 15px rgba(212, 175, 55, 0.2); width: 90%; max-width: 350px; }}
                    h2 {{ margin-top: 0; text-shadow: 0 0 8px rgba(255, 215, 0, 0.4); }}
                    input {{ width: 100%; box-sizing: border-box; padding: 12px; margin: 15px 0; background: #1a1a1a; border: 1px solid #332900; color: #fff; border-radius: 8px; text-align: center; outline: none; font-size: 16px; letter-spacing: 2px; }}
                    input:focus {{ border-color: #ffd700; box-shadow: 0 0 8px rgba(212, 175, 55, 0.3); }}
                    button {{ width: 100%; background: #d4af37; color: #000; border: none; padding: 12px; font-weight: bold; border-radius: 8px; font-size: 15px; cursor: pointer; transition: 0.3s; }}
                    button:hover {{ background: #ffd700; }}
                </style>
            </head>
            <body>
                <div class="box">
                    <h2>🔒 منطقه امنیتی</h2>
                    <p style="color: #888; font-size: 13px;">پسورد موقت را وارد کنید</p>
                    <input type="password" id="pass" placeholder="******" onkeypress="if(event.key === 'Enter') login()">
                    <button onclick="login()">ورود به پنل</button>
                </div>
                <script>
                    function login() {{
                        let p = document.getElementById('pass').value.trim();
                        if(p) {{
                            document.cookie = "auth_token=" + p + "; path=/; max-age=86400";
                            window.location.href = '/';
                        }} else {{
                            alert('لطفا پسورد را وارد کنید!');
                        }}
                    }}
                </script>
            </body>
            </html>
            """
            self.wfile.write(login_html.encode('utf-8'))
        return False

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        
        # هندل کردن لینک جادویی برای ورود خودکار
        if 'token' in query_params and query_params['token'][0] == ADMIN_PASS:
            self.send_response(302)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie', f'auth_token={ADMIN_PASS}; Path=/; Max-Age=86400')
            self.end_headers()
            return

        if not self.check_auth(is_api=False): 
            return
            
        if parsed_path.path == '/':
            self.path = '/index.html'
        else:
            self.path = parsed_path.path
            
        try: 
            return super().do_GET()
        except Exception:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if not self.check_auth(is_api=True): 
            return
            
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try: 
            params = json.loads(post_data.decode('utf-8'))
        except:
            self.send_response(400)
            self.end_headers()
            return

        if self.path == '/api/scan':
            mode = params.get('mode', 'auto')
            ports_to_test = params.get('ports', [443])
            workers = min(int(params.get('workers', 60)), 300) 
            timeout_sec = int(params.get('timeout', 1200)) / 1000.0
            max_count = int(params.get('max_count', 80))
            auto_type = params.get('auto_type', 'surface')
            manual_data = params.get('manual_data', '')
            
            custom_sni = params.get('custom_sni', 'speed.cloudflare.com').strip()
            if not custom_sni: 
                custom_sni = 'speed.cloudflare.com'
            payload_mb = int(params.get('payload_size_mb', 0))

            if mode == 'auto':
                pool = SURFACE_SUBNETS_24 if auto_type == 'surface' else DEEP_SUBNETS_24
                final_ips = sample_ips_from_subnets(pool, max_count)
            else:
                parsed_ips = parse_manual_data(manual_data)
                if len(parsed_ips) > max_count:
                    final_ips = random.sample(parsed_ips, max_count)
                else:
                    final_ips = parsed_ips

            tasks_info = [(ip, port) for ip in final_ips for port in ports_to_test]
            total_tasks = len(tasks_info)

            self.send_response(200)
            self.send_header('Content-Type', 'application/x-ndjson')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            completed_count = 0
            class ScanContext:
                def __init__(self): 
                    self.is_cancelled = False
                    
            current_scan_context = ScanContext()

            def safe_verify(ip, port, timeout, payload, sni, context):
                if context.is_cancelled: 
                    return None
                return verify_cloudflare_ip(ip, port, timeout, payload, sni)

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_ip = {
                    executor.submit(safe_verify, ip, port, timeout_sec, payload_mb, custom_sni, current_scan_context): (ip, port) 
                    for ip, port in tasks_info
                }
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    if current_scan_context.is_cancelled: 
                        break
                        
                    completed_count += 1
                    res = None
                    try: 
                        res = future.result()
                    except Exception: 
                        pass
                    
                    try:
                        chunk_str = json.dumps({"completed": completed_count, "total": total_tasks, "result": res}) + '\n'
                        self.wfile.write(chunk_str.encode('utf-8'))
                        self.wfile.flush()
                    except BrokenPipeError:
                        current_scan_context.is_cancelled = True
                        for f in future_to_ip: 
                            f.cancel()
                        break 

        elif self.path == '/api/inject':
            configs_raw = params.get('configs', '')
            alive_ips = params.get('ips', [])
            custom_sni = params.get('custom_sni', 'speed.cloudflare.com').strip()
            if not custom_sni: 
                custom_sni = 'speed.cloudflare.com'
            
            injected_list = []
            for line in configs_raw.strip().split('\n'):
                line = line.strip()
                if line:
                    injected_list.append(robust_config_injector(line, alive_ips, custom_sni))
                    
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"injected": '\n'.join(injected_list)}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

def auto_update_from_git():
    print("🔄 در حال بررسی آپدیت جدید از مخزن گیت...")
    try:
        res = subprocess.run(["git", "pull"], capture_output=True, text=True)
        if "Already up to date" in res.stdout or "Already up-to-date" in res.stdout: 
            print("✅ اسکریپت شما کاملاً بروز است.")
        elif res.returncode == 0: 
            print("🚀 آپدیت جدید با موفقیت دریافت شد!")
    except Exception: 
        pass

def open_browser_auto(magic_url):
    time.sleep(1.5)
    termux_prefix = os.environ.get("PREFIX", "")
    try:
        if "com.termux" in termux_prefix: 
            os.system(f"termux-open-url '{magic_url}'")
        else: 
            webbrowser.open(magic_url)
    except Exception: 
        pass

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # آپدیت خودکار
    auto_update_from_git()
    
    socketserver.TCPServer.allow_reuse_address = True
    server = ThreadingHTTPServer(('0.0.0.0', PORT), APIHandler)
    
    # تولید لینک ورود مستقیم
    magic_link = f"http://localhost:{PORT}/?token={ADMIN_PASS}"
    
    # باز کردن مرورگر
    threading.Thread(target=open_browser_auto, args=(magic_link,), daemon=True).start()
    
    print("="*60)
    print(f"🔥 Doctor Scanner Pro - Advanced Network Protocol")
    print("-" * 60)
    print(f"🚀 Direct Auto-Login URL:\n   \033[96m{magic_link}\033[0m")
    print("="*60)
    
    try: 
        server.serve_forever()
    except KeyboardInterrupt: 
        sys.exit(0)
