#!/usr/bin/env python3
"""
Server Monitor v15.26 - Universal Agent
=======================================
- FEATURES: CPU/Mem/Disk/Net, Logs, Processes (Kill), Connections, Port Scan.
- NEW: Packet Sniffing (Scapy) enabled for the "Requests" tab.
- FIX: Replaced deprecated on_event(startup) with lifespan context manager.
- FIX: verify_key now handles malformed Authorization headers gracefully.
- COMPATIBILITY: Windows (needs Npcap), Linux (needs Root), Mac.
"""
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
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Annotated, List
from datetime import datetime, timezone

# --- Try Import Scapy for Sniffing ---
try:
    from scapy.all import sniff, TCP, IP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
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

# --- Lifespan: replaces deprecated @app.on_event("startup") ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    threading.Thread(target=push_system_metrics, daemon=True, name="MetricPusher").start()
    if SCAPY_AVAILABLE:
        threading.Thread(target=start_sniffer, daemon=True, name="PacketSniffer").start()
        threading.Thread(target=push_requests_buffer, daemon=True, name="RequestFlusher").start()
    logger.info(f"Agent started: {AGENT_HOSTNAME}")
    yield
    # Shutdown
    logger.info("Agent shutting down.")

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
            "method": method, "path": path, "status_code": 200, 
            "response_time": 0.0, "size": len(pkt), "src_ip": src_ip,
            "dst_port": dst_port, "protocol": protocol
        }

        with BUFFER_LOCK:
            if len(REQUEST_BUFFER) < 1000: # Limit buffer size
                REQUEST_BUFFER.append(data)
    except: pass

def start_sniffer():
    if not SCAPY_AVAILABLE:
        logger.warning("⚠️ Scapy not found. 'Requests' tab will be empty.")
        return
    logger.info("📡 Packet Sniffer Started (Background)")
    try:
        # filter="tcp or udp" avoids ARP/ICMP noise
        sniff(iface=CONFIG.get("interface"), prn=packet_callback, filter="tcp or udp", store=0)
    except Exception as e:
        logger.error(f"❌ Sniffer Error: {e}")

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

    while True:
        time.sleep(CONFIG.get("metric_push_interval", 5))
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
            
            logger.info(f"📊 Pushing metrics: CPU={cpu:.1f}%, Mem={mem:.1f}%, Disk={disk_usage:.1f}%, Uptime={uptime}s, Conns={total_connections}")
            
            response = session.post(url, json=payload, timeout=5)
            if response.status_code != 200:
                logger.error(f"Master returned {response.status_code}: {response.text}")
                
        except Exception as e: 
            logger.error(f"Metric Push Error: {e}")

def push_requests_buffer():
    """Flushes sniffed packets to Master"""
    url = f"{MASTER_URL}/api/agent/submit_requests"
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {MASTER_API_KEY}"})

    while True:
        time.sleep(3)
        batch = []
        with BUFFER_LOCK:
            if not REQUEST_BUFFER: continue
            count = min(len(REQUEST_BUFFER), 50)
            batch = REQUEST_BUFFER[:count]
            del REQUEST_BUFFER[:count]
        
        try:
            if batch: session.post(url, json=batch, timeout=3)
        except: pass

# --- 3. API ENDPOINTS (For Master Controls) ---
async def verify_key(authorization: Annotated[str | None, Header()] = None):
    """Validates Bearer token. Handles missing or malformed Authorization headers gracefully."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != 'bearer' or parts[1] != MASTER_API_KEY:
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
def get_procs(limit: int=25, sort_by: str='cpu'):
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
        try:
            d = p.info; d['hostname'] = AGENT_HOSTNAME
            procs.append(d)
        except: pass
    procs.sort(key=lambda x: x.get(sort_by, 0) or 0, reverse=True)
    return procs[:limit]

class KillRequest(BaseModel):
    pid: int
    kill_tree: bool = False

@app.post("/api/processes/kill", dependencies=[Depends(verify_key)])
def kill_proc(req: KillRequest):
    try:
        p = psutil.Process(req.pid)
        if req.kill_tree:
            for c in p.children(recursive=True): c.kill()
        p.kill()
        return {"status": "success"}
    except Exception as e: return {"status": "error", "message": str(e)}

@app.get("/api/connections", dependencies=[Depends(verify_key)])
def get_conns(limit: int=100, status: str=None):
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
    path = CONFIG['log_files_to_analyze'].get(file)
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

class PortScanRequest(BaseModel):
    target: str
    ports: Optional[str] = None

@app.post("/api/security/port-scan", dependencies=[Depends(verify_key)])
def api_port_scan(req: PortScanRequest):
    # Quick simple scanner logic embedded here to save space
    target_ip = socket.gethostbyname(req.target)
    ports = [int(p) for p in (req.ports or "80,443").split(',') if p.isdigit()]
    results = []
    for p in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                res = s.connect_ex((target_ip, p))
                results.append({'port': p, 'status': 'open' if res==0 else 'closed', 'service': '?'})
        except: pass
    return {"results": results}

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
    print(f"🚀 AGENT STARTED on {AGENT_HOSTNAME}:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")