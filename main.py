import sys
import json
import time
import random
import ipaddress
import urllib.parse
import base64
import ssl
import os
import socket
import http.server
import socketserver
import concurrent.futures

PORT = 8080

# لیست کامل ۱۵ بلاک رسمی کلادفلر
CLOUDFLARE_ALL_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]

# رنج‌های طلایی و پرکاربردتر برای اسکن سطحی (سریع)
SURFACE_BASE_RANGES = [
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "188.114.96.0/20", "162.158.0.0/15"
]

# --- تابع تبدیل رنج‌های بزرگ به هزاران ساب‌نت /24 ---
def expand_to_24_subnets(cidrs):
    subnets_24 = []
    for cidr in cidrs:
        try:
            network = ipaddress.IPv4Network(cidr)
            if network.prefixlen <= 24:
                # شکستن رنج‌های بزرگ به /24
                subnets_24.extend(list(network.subnets(new_prefix=24)))
            else:
                subnets_24.append(network)
        except Exception:
            continue
    return subnets_24

# تولید هزاران رنج در زمان اجرای اولیه برنامه (بسیار سریع)
print("⏳ در حال تولید هزاران ساب‌نت کلادفلر...")
SURFACE_SUBNETS_24 = expand_to_24_subnets(SURFACE_BASE_RANGES)
DEEP_SUBNETS_24 = expand_to_24_subnets(CLOUDFLARE_ALL_RANGES)
print(f"✅ ساب‌نت‌های اسکن سطحی: {len(SURFACE_SUBNETS_24)} رنج /24 آماده شد.")
print(f"✅ ساب‌نت‌های اسکن عمیق: {len(DEEP_SUBNETS_24)} رنج /24 آماده شد.")

# ----------------- Core Network Functions ----------------- #

def sample_ips_from_subnets(subnets_list, total_needed):
    sampled_ips = set()
    if not subnets_list: return []
    
    max_attempts = total_needed * 10
    attempts = 0
    
    while len(sampled_ips) < total_needed and attempts < max_attempts:
        attempts += 1
        # ۱. انتخاب کاملا رندوم یک ساب‌نت /24 از بین هزاران ساب‌نت
        net = random.choice(subnets_list)
        
        # ۲. انتخاب یک آی‌پی رندوم از داخل همان ساب‌نت
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

def verify_cloudflare_ip(ip, port, timeout_sec, do_speedtest):
    protocol = "https" if port in [443, 8443, 2053, 2083, 2087, 2096] else "http"
    start_time = time.time()
    
    try:
        sock = socket.create_connection((ip, port), timeout=timeout_sec)
        if protocol == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname="speed.cloudflare.com")
        
        req = b"GET / HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        sock.sendall(req)
        header_data = sock.recv(2048)
        sock.close()

        if b"cloudflare" not in header_data.lower() and b"cf-ray" not in header_data.lower():
            return None
            
        ping_ms = int((time.time() - start_time) * 1000)
        dl_speed, ul_speed = 0.0, 0.0
        
        if do_speedtest:
            # --- تست دانلود ---
            try:
                dl_sock = socket.create_connection((ip, port), timeout=timeout_sec)
                if protocol == "https":
                    dl_sock = ctx.wrap_socket(dl_sock, server_hostname="speed.cloudflare.com")
                
                req_dl = b"GET /__down?bytes=150000 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n"
                dl_sock.sendall(req_dl)
                
                dl_st_time = time.time()
                bytes_recv = 0
                dl_sock.settimeout(1.5) 
                while True:
                    chunk = dl_sock.recv(16384)
                    if not chunk: break
                    bytes_recv += len(chunk)
                el = time.time() - dl_st_time
                if el > 0: dl_speed = round((bytes_recv * 8 / 1000000) / el, 2)
                dl_sock.close()
            except Exception:
                pass 

            # --- تست آپلود ---
            try:
                ul_sock = socket.create_connection((ip, port), timeout=timeout_sec)
                if protocol == "https":
                    ul_sock = ctx.wrap_socket(ul_sock, server_hostname="speed.cloudflare.com")
                
                ul_payload = b"x" * 100000 # ارسال 100 کیلوبایت داده فیک
                req_ul = f"POST /__up HTTP/1.1\r\nHost: speed.cloudflare.com\r\nContent-Length: {len(ul_payload)}\r\nConnection: close\r\n\r\n".encode()
                
                ul_st = time.time()
                ul_sock.sendall(req_ul + ul_payload)
                ul_sock.settimeout(1.5)
                ul_resp = ul_sock.recv(1024)
                
                ul_el = time.time() - ul_st
                if ul_el > 0 and b"HTTP/" in ul_resp:
                    ul_speed = round((len(ul_payload) * 8 / 1000000) / ul_el, 2)
                ul_sock.close()
            except Exception:
                pass
        
        return {
            "ip": ip, "port": port, "ping": ping_ms, 
            "dl_speed": dl_speed, "ul_speed": ul_speed
        }
        
    except Exception:
        return None

# ----------------- Injection Functions ----------------- #

def get_best_ip_for_port(alive_ips, target_port):
    suitable_ips = [ip for ip in alive_ips if ip.get('port') == target_port]
    if not suitable_ips: return None
    suitable_ips.sort(key=lambda x: (-x.get('dl_speed', 0), x.get('ping', 9999)))
    return suitable_ips[0]['ip']

def fix_b64_padding(s):
    return s + '=' * (-len(s) % 4)

def robust_config_injector(line, alive_ips):
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
                conf['sni'] = conf.get('host', 'speed.cloudflare.com')
                new_b64 = base64.urlsafe_b64encode(json.dumps(conf).encode('utf-8')).decode('utf-8').rstrip('=')
                return f"vmess://{new_b64}"
            return f"{line} # (No IP for port {port})"

        if scheme in ['vless', 'trojan']:
            port = parsed.port if parsed.port else 443
            best_ip = get_best_ip_for_port(alive_ips, port)
            if best_ip:
                old_netloc = parsed.netloc
                if '@' in old_netloc:
                    user_pass, host_port = old_netloc.split('@', 1)
                    new_netloc = f"{user_pass}@{best_ip}:{port}"
                else:
                    new_netloc = f"{best_ip}:{port}"
                
                query_dict = dict(urllib.parse.parse_qsl(parsed.query))
                query_dict['sni'] = query_dict.get('sni', query_dict.get('host', ''))
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
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        if self.path == '/':
            self.path = '/index.html'
        try:
            return super().do_GET()
        except Exception:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            params = json.loads(post_data.decode('utf-8'))
        except:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "Invalid JSON"}')
            return

        if self.path == '/api/scan':
            mode = params.get('mode', 'auto')
            ports_to_test = params.get('ports', [443])
            workers = min(int(params.get('workers', 60)), 200) 
            timeout_sec = int(params.get('timeout', 1200)) / 1000.0
            max_count = int(params.get('max_count', 80))
            auto_type = params.get('auto_type', 'surface')
            manual_data = params.get('manual_data', '')
            do_speedtest = params.get('do_speedtest', False)

            if mode == 'auto':
                # استفاده از بانک اطلاعاتی متشکل از هزاران ساب‌نت /24
                subnets_pool = SURFACE_SUBNETS_24 if auto_type == 'surface' else DEEP_SUBNETS_24
                final_ips = sample_ips_from_subnets(subnets_pool, max_count)
            else:
                parsed_manual = parse_manual_data(manual_data)
                final_ips = random.sample(parsed_manual, max_count) if len(parsed_manual) > max_count else parsed_manual

            tasks_info = [(ip, port) for ip in final_ips for port in ports_to_test]
            total_tasks = len(tasks_info)

            # تنظیم هدرها برای استریم کردن دیتا (NDJSON)
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-ndjson')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            completed_count = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_ip = {
                    executor.submit(verify_cloudflare_ip, ip, port, timeout_sec, do_speedtest): (ip, port) 
                    for ip, port in tasks_info
                }
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    completed_count += 1
                    res = None
                    try:
                        res = future.result()
                    except Exception:
                        pass
                    
                    # مخابره لحظه‌ای نتیجه هر آی‌پی به فرانت‌اند
                    chunk = {
                        "completed": completed_count,
                        "total": total_tasks,
                        "result": res
                    }
                    
                    try:
                        self.wfile.write((json.dumps(chunk) + '\n').encode('utf-8'))
                        self.wfile.flush()
                    except BrokenPipeError:
                        # اگر کاربر وسط اسکن تب رو بست، پردازش قطع بشه
                        break

        elif self.path == '/api/inject':
            configs_raw = params.get('configs', '')
            alive_ips = params.get('ips', [])
            injected_list = []

            for line in configs_raw.strip().split('\n'):
                line = line.strip()
                if not line: continue
                injected_list.append(robust_config_injector(line, alive_ips))

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"injected": '\n'.join(injected_list)}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    socketserver.TCPServer.allow_reuse_address = True
    server = ThreadingHTTPServer(('0.0.0.0', PORT), APIHandler)
    
    print("="*60)
    print(f"🔥 Doctor Scanner Pro - Running at http://localhost:{PORT}")
    print("📢 Channel: @Doctor_Scanner")
    print("="*60)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Server stopped.")
        server.server_close()
        sys.exit(0)
