#!/usr/bin/env python3
"""Remote telemetry collector and authenticated control API."""
import asyncio
import secrets
import uvicorn
import json
import platform
import time
import threading
import psutil
import logging
import sys
import os
import socket 
import requests
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import Optional, Annotated, List
from datetime import datetime, timezone

# --- Try Import Scapy for Sniffing ---
try:
    from scapy.all import sniff, TCP, IP, UDP, Raw
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# --- Configuration Loading ---
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "agent_config.json"
DEFAULT_CONFIG = {
    "agent_port": 8082,
    "master_url": "http://127.0.0.1:8081",
    "master_api_key": "YOUR_SECRET_KEY_HERE",
    "hostname": platform.node(),
    "metric_push_interval": 5,
    "interface": None, 
    "log_files_to_analyze": {},
    "security": {"default_ports_to_scan": "21,22,23,25,53,80,443,3389,8080"}
}

try:
    with open(CONFIG_PATH, "r") as f:
        user_cfg = json.load(f)
    CONFIG = DEFAULT_CONFIG.copy()
    CONFIG.update(user_cfg)
except Exception:
    CONFIG = DEFAULT_CONFIG

# --- Logging Setup ---
logger = logging.getLogger("RemoteAgent")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# --- Globals ---
AGENT_HOSTNAME = CONFIG.get("hostname", platform.node())
MASTER_API_KEY = CONFIG.get("master_api_key")
MASTER_URL = CONFIG.get('master_url', 'http://127.0.0.1:8081').rstrip('/')
REQUEST_BUFFER = [] 
BUFFER_LOCK = threading.Lock()
STOP_EVENT = threading.Event()

# --- Lifespan: replaces deprecated @app.on_event("startup") ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    STOP_EVENT.clear()
    workers = [(push_system_metrics, 'MetricPusher')]
    if SCAPY_AVAILABLE and CONFIG.get('enable_packet_sniffing', False):
        workers += [(start_sniffer, 'PacketSniffer'), (push_requests_buffer, 'RequestFlusher')]
    threads = [threading.Thread(target=fn, daemon=True, name=name) for fn, name in workers]
    for thread in threads:
        thread.start()
    try:
        yield
    finally:
        STOP_EVENT.set()
        for thread in threads:
            await asyncio.to_thread(thread.join, 10)
        logger.info('Agent stopped')

app = FastAPI(title="Server Monitor Agent", lifespan=lifespan)

# --- 1. PACKET SNIFFER LOGIC (Restored) ---
def packet_callback(pkt):
    try:
        if not pkt.haslayer(IP): return
        src_ip = pkt[IP].src
        if pkt.haslayer(TCP):
            proto = 'TCP'; dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = 'UDP'; dst_port = pkt[UDP].dport
        else: return

        method, path, protocol = "-", "-", proto
        
        # Try to decode HTTP
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
                    lines = payload.split("\r\n")
                    first = lines[0].split()
                    if len(first) >= 2: method, path = first[0], first[1]
                    protocol = 'HTTPS' if dst_port == 443 else 'HTTP'
            except: pass

        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": AGENT_HOSTNAME,
            "method": method[:32], "path": path[:8192], "status_code": 200,
            "response_time": 0.0, "size": len(pkt), "src_ip": src_ip,
            "dst_port": dst_port, "protocol": protocol
        }

        with BUFFER_LOCK:
            if len(REQUEST_BUFFER) < 1000: # Limit buffer size
                REQUEST_BUFFER.append(data)
    except: pass

def start_sniffer():
    if not SCAPY_AVAILABLE:
        logger.warning(" Scapy not found. 'Requests' tab will be empty.")
        return
    logger.info("📡 Packet Sniffer Started (Background)")
    try:
        # filter="tcp or udp" avoids ARP/ICMP noise
        while not STOP_EVENT.is_set():
            sniff(iface=CONFIG.get("interface"), prn=packet_callback, filter="tcp or udp", store=0, timeout=2)
    except Exception as e:
        logger.error(f" Sniffer Error: {e}")

# --- 2. DATA PUSHERS (Background Threads) ---
def push_system_metrics():
    """Sends CPU/RAM/Disk/Net rates to Master every X seconds"""
    url = f"{MASTER_URL}/api/agent/submit"
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {MASTER_API_KEY}"})
    
    # Init Counters
    try:
        last_d = psutil.disk_io_counters()
        last_n = psutil.net_io_counters()
        ld_r, ld_w = last_d.read_bytes, last_d.write_bytes
        ln_s, ln_r = last_n.bytes_sent, last_n.bytes_recv
    except: ld_r = ld_w = ln_s = ln_r = 0
    last_t = time.time()

    while not STOP_EVENT.wait(max(1, CONFIG.get("metric_push_interval", 5))):
        try:
            curr_t = time.time(); delta = curr_t - last_t
            if delta <= 0: delta = 1
            
            # --- Current Resources ---
            cpu = psutil.cpu_percent(interval=1.0)
            mem = psutil.virtual_memory().percent
            
            # --- Calculate Disk Usage ---
            try:
                disk_path = 'C:\\' if os.name == 'nt' else '/'
                disk_usage = psutil.disk_usage(disk_path).percent
            except Exception as e:
                logger.error(f"Disk usage error: {e}")
                disk_usage = 0.0

            # --- Calculate Uptime ---
            try:
                uptime = int(time.time() - psutil.boot_time())
            except Exception as e:
                logger.error(f"Uptime error: {e}")
                uptime = 0

            # --- Calculate Total Connections ---
            try:
                total_connections = len(psutil.net_connections(kind='inet'))
            except Exception as e:
                logger.error(f"Connections error: {e}")
                total_connections = 0
            
            # --- Calculate Rates ---
            try:
                cur_d = psutil.disk_io_counters()
                cur_n = psutil.net_io_counters()
                
                d_r_rate = max(0, (cur_d.read_bytes - ld_r) / delta / 1024)
                d_w_rate = max(0, (cur_d.write_bytes - ld_w) / delta / 1024)
                n_s_rate = max(0, (cur_n.bytes_sent - ln_s) / delta / 1024)
                n_r_rate = max(0, (cur_n.bytes_recv - ln_r) / delta / 1024)
                
                ld_r, ld_w = cur_d.read_bytes, cur_d.write_bytes
                ln_s, ln_r = cur_n.bytes_sent, cur_n.bytes_recv
            except Exception as e:
                logger.error(f"Rate calculation error: {e}")
                d_r_rate = d_w_rate = n_s_rate = n_r_rate = 0
            
            last_t = curr_t

            payload = {
                "hostname": AGENT_HOSTNAME,
                "cpu_percent": round(cpu, 2), 
                "memory_percent": round(mem, 2),
                "disk_read_rate": round(d_r_rate, 2), 
                "disk_write_rate": round(d_w_rate, 2),
                "network_sent_rate": round(n_s_rate, 2), 
                "network_recv_rate": round(n_r_rate, 2),
                # --- Extended Stats ---
                "disk_usage": round(disk_usage, 2),
                "uptime": uptime,
                "total_connections": total_connections
            }
            
            logger.info(f" Pushing metrics: CPU={cpu:.1f}%, Mem={mem:.1f}%, Disk={disk_usage:.1f}%, Uptime={uptime}s, Conns={total_connections}")
            
            response = session.post(url, json=payload, timeout=5)
            if response.status_code != 200:
                logger.error(f"Master returned {response.status_code}: {response.text}")
                
        except Exception as e: 
            logger.error(f"Metric Push Error: {e}")
    session.close()

def flush_request_batch(session):
    """Remove a batch only after the master confirms a successful commit."""
    with BUFFER_LOCK:
        batch = REQUEST_BUFFER[:50]
    if not batch:
        return 0
    response = session.post(f'{MASTER_URL}/api/agent/submit_requests', json=batch, timeout=5)
    response.raise_for_status()
    if response.json().get('status') != 'success':
        raise RuntimeError('Master did not acknowledge the traffic batch')
    with BUFFER_LOCK:
        del REQUEST_BUFFER[:len(batch)]
    return len(batch)


def push_requests_buffer():
    with requests.Session() as session:
        session.headers.update({'Authorization': f'Bearer {MASTER_API_KEY}'})
        while not STOP_EVENT.wait(3):
            try:
                flush_request_batch(session)
            except Exception as exc:
                logger.warning('Traffic upload failed; retaining batch for retry: %s', exc)

# --- 3. API ENDPOINTS (For Master Controls) ---
async def verify_key(authorization: Annotated[str | None, Header()] = None):
    """Validates Bearer token. Handles missing or malformed Authorization headers gracefully."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != 'bearer' or MASTER_API_KEY in {'', None, 'YOUR_SECRET_KEY_HERE', 'CHANGE_THIS_SECRET_KEY', 'REPLACE_WITH_MASTER_KEY'} or not secrets.compare_digest(parts[1].encode('utf-8'), str(MASTER_API_KEY).encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid API key")

@app.get("/api/health", dependencies=[Depends(verify_key)])
def health(): return {"status": "healthy", "hostname": AGENT_HOSTNAME}

@app.get("/api/stats", dependencies=[Depends(verify_key)])
def get_stats():
    """Returns current system stats for comparison tab"""
    try:
        cpu = psutil.cpu_percent(interval=1.0)
        mem = psutil.virtual_memory().percent
        
        try:
            disk_path = 'C:\\' if os.name == 'nt' else '/'
            disk_usage = psutil.disk_usage(disk_path).percent
        except:
            disk_usage = 0.0
        
        try:
            uptime = int(time.time() - psutil.boot_time())
        except:
            uptime = 0
        
        try:
            total_connections = len(psutil.net_connections(kind='inet'))
        except:
            total_connections = 0
        
        return {
            "hostname": AGENT_HOSTNAME,
            "cpu": round(cpu, 2),
            "memory": round(mem, 2),
            "disk": round(disk_usage, 2),
            "uptime": uptime,
            "total_connections": total_connections,
            "app_cpu": 0.0,
            "app_memory": 0.0,
            "logged_in_users": [],
            "packet_sniffing_enabled": SCAPY_AVAILABLE,
            "active_alerts_count": 0
        }
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return {"error": str(e), "hostname": AGENT_HOSTNAME}

@app.get("/api/processes", dependencies=[Depends(verify_key)])
def get_procs(limit: int=Query(25, ge=1, le=1000), sort_by: str='cpu'):
    if not isinstance(limit, int):
        limit = 25
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
        try:
            if p.info['pid'] == 0:  # Windows' "System Idle Process" reports idle time, not work
                continue
            d = dict(p.info); d['hostname'] = AGENT_HOSTNAME
            d['cpu'] = d.pop('cpu_percent') or 0
            d['memory'] = d.pop('memory_percent') or 0
            d['user'] = d.pop('username')
            d['ppid'] = p.ppid()
            procs.append(d)
        except: pass
    procs.sort(key=lambda x: x.get(sort_by, 0) or 0, reverse=True)
    return procs[:limit]

from schemas import KillRequest, PortScanRequest

@app.post("/api/processes/kill", dependencies=[Depends(verify_key)])
def kill_proc(req: KillRequest):
    try:
        protected = {0, 1, os.getpid()}
        if req.kill_tree:
            protected.update(p.pid for p in psutil.Process().parents())
        if req.pid in protected:
            return {'status': 'error', 'message': 'The agent process is protected.'}
        p = psutil.Process(req.pid)
        if req.kill_tree:
            for c in p.children(recursive=True): c.kill()
        p.kill()
        return {"status": "success"}
    except Exception as e: return {"status": "error", "message": str(e)}

@app.get("/api/connections", dependencies=[Depends(verify_key)])
def get_conns(limit: int=Query(100, ge=1, le=1000), status: str=None):
    conns = []
    try:
        for c in psutil.net_connections(kind='inet'):
            if status and c.status != status: continue
            if len(conns) >= limit: break
            conns.append({
                "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-",
                "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-",
                "status": c.status, "pid": c.pid, "hostname": AGENT_HOSTNAME
            })
    except: pass
    return conns

@app.get("/api/logs", dependencies=[Depends(verify_key)])
def get_logs(file: str=None, level: str=None):
    paths = CONFIG.get('log_files_to_analyze', {})
    path = paths.get(file) if file else next(iter(paths.values()), None)
    if not path or not os.path.exists(path): return {"logs": []}
    out = []
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f.readlines()[-500:]:
                if level and level not in line.lower(): continue
                lvl = 'error' if 'error' in line.lower() else 'info'
                out.append({"line": line.strip(), "level": lvl})
    except: pass
    return {"logs": out}

@app.get("/api/log-files", dependencies=[Depends(verify_key)])
def list_logs(): return {"log_files": list(CONFIG['log_files_to_analyze'].keys())}



@app.post("/api/security/port-scan", dependencies=[Depends(verify_key)])
def api_port_scan(req: PortScanRequest):
    from concurrent.futures import ThreadPoolExecutor
    try:
        target_ip = socket.gethostbyname(req.target)
    except socket.gaierror:
        return {'status': 'error', 'message': 'Could not resolve target', 'results': []}
    ports = [int(p) for p in (req.ports or '80,443').split(',')]
    def scan(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(1)
                opened = connection.connect_ex((target_ip, port)) == 0
            return {'port': port, 'status': 'open' if opened else 'closed', 'service': '?'}
        except OSError:
            return {'port': port, 'status': 'error', 'service': '?'}
    with ThreadPoolExecutor(max_workers=16) as pool:
        return {'results': list(pool.map(scan, ports))}

@app.get("/api/services", dependencies=[Depends(verify_key)])
def get_services():
    """Returns Windows services status"""
    if os.name != 'nt':
        return []
    
    services = []
    try:
        for svc in psutil.win_service_iter():
            try:
                status = svc.status()
                services.append({
                    "name": svc.name(),
                    "status": "active" if status == "running" else "inactive"
                })
            except:
                pass
    except:
        pass
    
    return services

if __name__ == "__main__":
    port = CONFIG.get("agent_port", 8082)
    print(f" AGENT STARTED on {AGENT_HOSTNAME}:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")