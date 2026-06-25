import http.server
import socketserver
import json
import socket
import time
import random
import ipaddress
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

PORT = 8080

SURFACE_RANGES = [
    "104.16.0.0/13",
    "172.64.0.0/13",
    "108.162.192.0/18"
]

DEEP_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22"
]

def sample_ips_from_subnets(subnets, total_needed):
    sampled_ips = set()
    networks = []
    
    for block in subnets:
        try:
            networks.append(ipaddress.IPv4Network(block.strip()))
        except:
            continue
            
    if not networks:
        return []

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
        if not token:
            continue
        
        if '/' in token:
            try:
                net = ipaddress.IPv4Network(token, strict=False)
                num_hosts = net.num_addresses
                if num_hosts <= 64:
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

def verify_ip_port(ip, port, timeout_ms):
    timeout_sec = timeout_ms / 1000.0
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        sock.connect((ip, port))
        sock.close()
        elapsed = int((time.time() - start) * 1000)
        return {"ip": ip, "port": port, "ping": elapsed}
    except:
        return None

class AdvancedScannerHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/scan':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            params = json.loads(post_data.decode('utf-8'))
            
            mode = params.get('mode', 'auto')
            workers = min(int(params.get('workers', 60)), 300)
            timeout = int(params.get('timeout', 1200))
            max_count = int(params.get('max_count', 80))
            auto_type = params.get('auto_type', 'surface')
            manual_data = params.get('manual_data', '')
            
            raw_ports = params.get('ports', '443')
            ports_to_test = []
            for p in raw_ports.replace(',', ' ').split():
                try:
                    ports_to_test.append(int(p.strip()))
                except:
                    continue
            if not ports_to_test:
                ports_to_test = [443]

            final_ips = []
            if mode == 'auto':
                subnets = SURFACE_RANGES if auto_type == 'surface' else DEEP_RANGES
                final_ips = sample_ips_from_subnets(subnets, max_count)
            else:
                parsed_manual = parse_manual_data(manual_data)
                if len(parsed_manual) > max_count:
                    final_ips = random.sample(parsed_manual, max_count)
                else:
                    final_ips = parsed_manual

            tasks = []
            for ip in final_ips:
                for port in ports_to_test:
                    tasks.append((ip, port))
                    
            total_tasks_count = len(tasks)
            alive_results = []

            if tasks:
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [executor.submit(verify_ip_port, t[0], t[1], timeout) for t in tasks]
                    for fut in futures:
                        res = fut.result()
                        if res:
                            alive_results.append(res)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            output_response = {
                "total_scanned": total_tasks_count,
                "results": alive_results
            }
            self.wfile.write(json.dumps(output_response).encode('utf-8'))
            return
            
        return super().do_GET()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

socketserver.TCPServer.allow_reuse_address = True
try:
    with socketserver.TCPServer(("", PORT), AdvancedScannerHandler) as httpd:
        print("="*60)
        print(f"🔥 Doctor Scanner Pro Launched Successfully!")
        print(f"📡 Local Web Dashboard: http://localhost:{PORT}")
        print("="*60)
        httpd.serve_forever()
except KeyboardInterrupt:
    print("\n[!] Connection closed.")