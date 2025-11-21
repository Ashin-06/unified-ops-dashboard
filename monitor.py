#!/usr/bin/env python3
"""
Server Monitor v15.25 - Core Logic
==================================
- FIX: get_system_stats now retrieves disk/uptime/connections for remote agents.
- FIX: Packet Sniffer writes are non-blocking via database batching.
- FIX: Timeline charts correctly calculate I/O rates.
- FIX: Kill Process functionality enabled.
"""

import os
import sys
import time
import json
import psutil
import threading
import logging
import platform
import socket 
from pathlib import Path
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from collections import defaultdict, deque

# --- Import database ---
try:
    from database import db
except ImportError:
    print("CRITICAL: database.py not found.")
    sys.exit(1)

# --- Try to import scapy ---
try:
    from scapy.all import sniff, TCP, IP, UDP, Raw
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# --- Configuration Loading ---
if os.name == 'nt':
    BASE_DIR = Path(os.getenv('PROGRAMDATA', 'C:/')) / 'ServerMonitor'
else:
    BASE_DIR = Path('/opt/server_monitor')

CONFIG_PATH = BASE_DIR / 'config.json'

DEFAULT_CONFIG = {
    "interface": None, "web_port": 8081,
    "log_file": str(BASE_DIR / 'Logs' / 'monitor.log'),
    "database": str(BASE_DIR / 'Data' / 'monitor.db'),
    "retention_days": 7,
    "performance": {
        "enable_packet_sniffing": True,
        "metric_collection_interval": 5,
        "batch_db_writes": True, "batch_size": 50,
        "frontend_poll_interval": 15,
        "proc_cache_ttl": 5,
        "max_stored_metrics": 50000
    },
    "alerts": {
        "cpu_threshold": 80, "memory_threshold": 80, "disk_threshold": 90,
        "alert_cooldown_seconds": 300
    },
    "services_to_monitor": ["WinRM", "Spooler", "wuauserv", "W3SVC", "MSSQLSERVER"],
    "hostname": platform.node(),
    "integrations": {
        "wazuh": {"enabled": False},
        "zabbix": {"enabled": False},
        "grafana": {"enabled": False, "dashboard_url": ""} 
    },
    "security": {
        "default_ports_to_scan": "21,22,23,25,53,80,110,135,139,443,445,1433,3306,3389,5900,5985,8080"
    },
    "agents": []
}

# Create base directories
BASE_DIR.mkdir(parents=True, exist_ok=True)
(BASE_DIR / 'Logs').mkdir(exist_ok=True)
(BASE_DIR / 'Data').mkdir(exist_ok=True)

# Load configurations
if not Path(CONFIG_PATH).exists():
    with open(CONFIG_PATH, "w") as f: json.dump(DEFAULT_CONFIG, f, indent=4)
with open(CONFIG_PATH, "r") as f:
    try: user_cfg = json.load(f)
    except Exception: user_cfg = {}
CONFIG = DEFAULT_CONFIG.copy()
for key, value in user_cfg.items():
    if key in CONFIG and isinstance(CONFIG[key], dict) and isinstance(value, dict):
        CONFIG[key].update(value)
    else: CONFIG[key] = value

# --- Logging Setup ---
LOG_FILE = Path(CONFIG.get("log_file", BASE_DIR / "Logs" / "monitor.log"))
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.getLogger().handlers.clear()
logger = logging.getLogger("ServerMonitor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(threadName)s - %(message)s"))
    logger.addHandler(handler)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(threadName)s - %(message)s"))
    logger.addHandler(console)

# --- Resilient Integration Wrapper ---
class ResilientIntegration:
    def __init__(self, client, config_name):
        self.client = client
        self.name = config_name
        self.should_be_enabled = CONFIG.get('integrations', {}).get(config_name, {}).get('enabled', False)
        if self.client:
            self.client.enabled = self.should_be_enabled

    @property
    def enabled(self):
        return self.client is not None and self.should_be_enabled

    @enabled.setter
    def enabled(self, value):
        if self.client:
            self.client.enabled = value

    def __getattr__(self, name):
        if self.client is None:
            def dummy_method(*args, **kwargs):
                if 'get_dashboard_stats' in name:
                    return {'enabled': False, 'status': 'disabled', 'error': f'{self.name} module not loaded'}
                return []
            return dummy_method
            
        attr = getattr(self.client, name)
        if not callable(attr): return attr
        
        def wrapper(*args, **kwargs):
            try:
                if self.should_be_enabled: self.client.enabled = True
                return attr(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in {self.name} integration ({name}): {e}")
                if self.should_be_enabled: self.client.enabled = True
                if 'get_dashboard_stats' in name: return {'enabled': True, 'status': 'error', 'message': str(e)}
                return [] 
        return wrapper

# --- Try to import integration modules ---
try:
    from wazuh_integration import WazuhAPI
    WAZUH_AVAILABLE = True
except Exception as e:
    logger.warning(f"Wazuh integration not available: {e}")
    WAZUH_AVAILABLE = False

try:
    from zabbix_integration import ZabbixAPI
    ZABBIX_AVAILABLE = True
except Exception as e:
    logger.warning(f"Zabbix integration not available: {e}")
    ZABBIX_AVAILABLE = False

# --- Initialize Integrations ---
INTEGRATION_CONFIG = CONFIG.get('integrations', {})
wazuh_client_inner = None
zabbix_client_inner = None

if WAZUH_AVAILABLE:
    try:
        wazuh_client_inner = WazuhAPI(INTEGRATION_CONFIG.get('wazuh', {}))
        logger.info("Wazuh module loaded")
    except Exception as e:
        logger.error(f"Wazuh module init failed: {e}")

if ZABBIX_AVAILABLE:
    try:
        zabbix_client_inner = ZabbixAPI(INTEGRATION_CONFIG.get('zabbix', {}))
        logger.info("Zabbix module loaded")
    except Exception as e:
        logger.error(f"Zabbix module init failed: {e}")

wazuh_client = ResilientIntegration(wazuh_client_inner, 'wazuh')
zabbix_client = ResilientIntegration(zabbix_client_inner, 'zabbix')

# --- Helper Classes ---
class TCPSessionTracker:
    def __init__(self):
        self.lock = threading.Lock()
    
    def track_packet(self, pkt):
        return None
    
    def cleanup_old_sessions(self, timeout=300):
        pass 

class PortScanner:
    def __init__(self, timeout=2.0): 
        self.timeout = timeout
        self.port_map = { 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt" }

    def scan_host(self, target_host: str, ports_str: str):
        try: target_ip = socket.gethostbyname(target_host)
        except socket.gaierror: return {"status": "error", "message": f"Could not resolve host: {target_host}"}
        try: ports = [int(p) for p in ports_str.split(',') if p.strip().isdigit()]
        except Exception: return {"status": "error", "message": "Invalid port list."}
        results = []
        
        def _scan(ip, p, res):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((ip, p)) == 0:
                        res.append({'port': p, 'status': 'open', 'service': self.port_map.get(p, 'Unknown')})
                    else:
                        res.append({'port': p, 'status': 'closed', 'service': self.port_map.get(p, 'Unknown')})
            except: res.append({'port': p, 'status': 'closed', 'service': 'Unknown'})

        threads = []
        scan_start = time.time()
        for port in ports:
            t = threading.Thread(target=_scan, args=(target_ip, port, results))
            threads.append(t)
            t.start()
        for t in threads: t.join()
        
        results.sort(key=lambda x: x['port'])
        return {"status": "success", "target": target_host, "ip": target_ip, "scan_time": round(time.time() - scan_start, 2), "results": results}

# --- Main ServerMonitor Class ---
class ServerMonitor:
    def run_port_scan(self, target, ports=None):
        if not ports:
            ports = CONFIG.get('security', {}).get('default_ports_to_scan', '21,22,23,25,53,80,110,135,139,443,445,1433,3306,3389,5900,5985,8080')
        return self.port_scanner.scan_host(target, ports)
    
    def __init__(self):
        self.start_time = time.time()
        self.proc = psutil.Process(os.getpid())
        self.request_count = 0
        self.alert_cooldown = defaultdict(lambda: 0)
        self.lock = threading.Lock()
        self.hostname = CONFIG.get('hostname') or platform.node()
        self.tcp_tracker = TCPSessionTracker()
        self.perf = CONFIG.get('performance', {})
        self.metric_interval = self.perf.get('metric_collection_interval', 10)
        self.packet_sniffing_enabled = self.perf.get('enable_packet_sniffing', True)
        self.last_disk_read, self.last_disk_write, self.last_net_sent, self.last_net_recv = 0, 0, 0, 0
        self.last_metric_time = time.time()
        self._threads_started = False
        
        # --- PROCESS CACHE FOR CPU CALCULATION ---
        self.process_map = {} # {pid: psutil.Process_object}
        
        # Initialize initial counters
        try:
            disk_io = psutil.disk_io_counters()
            net = psutil.net_io_counters()
            self.last_disk_read = getattr(disk_io, 'read_bytes', 0)
            self.last_disk_write = getattr(disk_io, 'write_bytes', 0)
            self.last_net_sent = getattr(net, 'bytes_sent', 0)
            self.last_net_recv = getattr(net, 'bytes_recv', 0)
        except: pass
        
        # Caching dictionaries
        self._cache = {
            'connections': {'ts': 0, 'data': [], 'ttl': max(self.perf.get('conn_cache_ttl', 5), 2)},
            'processes': {'ts': 0, 'data': [], 'ttl': max(self.perf.get('proc_cache_ttl', 5), 2)},
            'requests': {'ts': 0, 'data': [], 'ttl': max(self.perf.get('req_cache_ttl', 10), 5)}
        }
        self.port_scanner = PortScanner()
        
        logger.info(f"ServerMonitor initialized - Hostname: {self.hostname}")

    def monitor_system_resources(self):
        while True:
            try:
                # Interval is small to prevent blocking, but enough to measure CPU
                cpu = psutil.cpu_percent(interval=1.0)
                mem = psutil.virtual_memory()
                net = psutil.net_io_counters()
                disk_io = psutil.disk_io_counters()
                
                # Disk usage for alerts
                try:
                    main_disk_mount = psutil.disk_partitions()[0].mountpoint
                    disk_usage = psutil.disk_usage(main_disk_mount).percent
                except: 
                    disk_usage = 0.0

                current_time = time.time()
                time_delta = current_time - self.last_metric_time
                
                # Default rates
                disk_read_rate = disk_write_rate = net_sent_rate = net_recv_rate = 0.0

                if time_delta > 0:
                    disk_read_now = getattr(disk_io, 'read_bytes', 0)
                    disk_write_now = getattr(disk_io, 'write_bytes', 0)
                    net_sent_now = getattr(net, 'bytes_sent', 0)
                    net_recv_now = getattr(net, 'bytes_recv', 0)
                    
                    # Calculate diffs
                    d_read_diff = disk_read_now - self.last_disk_read
                    d_write_diff = disk_write_now - self.last_disk_write
                    n_sent_diff = net_sent_now - self.last_net_sent
                    n_recv_diff = net_recv_now - self.last_net_recv
                    
                    # Spike Protection: If delta is huge (e.g. > 1GB/s) or negative (overflow), assume 0
                    sanity_threshold = 1 * 1024 * 1024 * 1024 * time_delta # 1 GB/s max rate per tick
                    
                    if d_read_diff < 0 or d_read_diff > sanity_threshold: d_read_diff = 0
                    if d_write_diff < 0 or d_write_diff > sanity_threshold: d_write_diff = 0
                    if n_sent_diff < 0 or n_sent_diff > sanity_threshold: n_sent_diff = 0
                    if n_recv_diff < 0 or n_recv_diff > sanity_threshold: n_recv_diff = 0

                    # Calculate rates (KB/s)
                    disk_read_rate = d_read_diff / time_delta / 1024
                    disk_write_rate = d_write_diff / time_delta / 1024
                    net_sent_rate = n_sent_diff / time_delta / 1024
                    net_recv_rate = n_recv_diff / time_delta / 1024
                    
                    self.last_disk_read, self.last_disk_write = disk_read_now, disk_write_now
                    self.last_net_sent, self.last_net_recv = net_sent_now, net_recv_now
                    self.last_metric_time = current_time
                
                with self.lock:
                    req_count = self.request_count
                    self.request_count = 0
                
                now_utc = datetime.now(timezone.utc).isoformat()
                
                # Sanity check rates before DB insert
                if net_recv_rate > 1000000: net_recv_rate = 0 
                if net_sent_rate > 1000000: net_sent_rate = 0

                db.execute('''
                    INSERT INTO system_metrics (timestamp, hostname, cpu_percent, memory_percent, disk_read, disk_write,
                                                network_sent, network_recv, request_count,
                                                disk_read_rate, disk_write_rate, network_sent_rate, network_recv_rate)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (now_utc, self.hostname, cpu, mem.percent, self.last_disk_read, self.last_disk_write,
                            self.last_net_sent, self.last_net_recv, req_count,
                            disk_read_rate, disk_write_rate, net_sent_rate, net_recv_rate))
                
                self.check_alerts(cpu, mem.percent, disk_usage)

                # Periodically refresh cached views
                try:
                    nowt = time.time()
                    if nowt - self._cache['connections']['ts'] > self._cache['connections']['ttl']:
                        self._refresh_connections_cache(nowt)
                    if nowt - self._cache['processes']['ts'] > self._cache['processes']['ttl']:
                        self._refresh_processes_cache(nowt)
                    if nowt - self._cache['requests']['ts'] > self._cache['requests']['ttl']:
                        self._refresh_requests_cache(nowt)
                except Exception:
                    pass
                
                # Sleep the remainder of the interval
                time.sleep(max(1, self.metric_interval - 1.0))
                
            except Exception as e:
                logger.error("Monitor loop error: %s", e)
                time.sleep(5)

    def _refresh_connections_cache(self, nowt):
        try:
            conns = []
            net_conns = psutil.net_connections(kind='inet')
            for c in net_conns:
                conn = {
                    'local': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A",
                    'remote': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A",
                    'status': c.status,
                    'pid': c.pid,
                    'hostname': self.hostname,
                    'user': None, 'process': None, 'cmdline': None, 'started': None
                }
                try:
                    if c.pid:
                        p = psutil.Process(c.pid)
                        with p.oneshot():
                            conn['user'] = getattr(p, 'username', lambda: None)() if callable(getattr(p, 'username', None)) else getattr(p, 'username', None)
                            conn['process'] = getattr(p, 'name', lambda: None)() if callable(getattr(p, 'name', None)) else getattr(p, 'name', None)
                            try:
                                cmd = p.cmdline() if callable(getattr(p, 'cmdline', None)) else getattr(p, 'cmdline', None)
                                if isinstance(cmd, list): conn['cmdline'] = ' '.join(cmd)
                                else: conn['cmdline'] = cmd
                            except Exception: conn['cmdline'] = None
                            try: conn['started'] = int(p.create_time())
                            except Exception: conn['started'] = None
                except Exception: pass
                conns.append(conn)
            self._cache['connections']['data'] = conns[:1000]
            self._cache['connections']['ts'] = nowt
        except Exception: pass

    def _refresh_processes_cache(self, nowt):
        try:
            # Get current PIDs
            current_pids = set(psutil.pids())
            
            # Remove dead processes from cache
            dead_pids = set(self.process_map.keys()) - current_pids
            for pid in dead_pids:
                del self.process_map[pid]
            
            procs = []
            # Update cache and get stats
            for pid in current_pids:
                if pid == 0: continue
                try:
                    # Get or Create Process Object
                    if pid not in self.process_map:
                        self.process_map[pid] = psutil.Process(pid)
                        # Call cpu_percent once to initialize (returns 0.0)
                        self.process_map[pid].cpu_percent()
                    
                    p = self.process_map[pid]
                    
                    # Get Stats (using oneshot for speed)
                    with p.oneshot():
                        # cpu_percent(interval=None) returns delta since last call on THIS object
                        cpu_val = p.cpu_percent(interval=None)
                        
                        try:
                            io = p.io_counters()
                            disk_read = getattr(io, 'read_bytes', 0)
                            disk_write = getattr(io, 'write_bytes', 0)
                        except Exception: disk_read, disk_write = 0, 0
                        
                        procs.append({
                            'pid': p.pid,
                            'ppid': p.ppid(),
                            'name': p.name(),
                            'cpu': cpu_val,
                            'memory': p.memory_percent(),
                            'uptime': int(time.time() - p.create_time()),
                            'user': p.username(),
                            'cmdline': ' '.join(p.cmdline() or []),
                            'disk_read': disk_read,
                            'disk_write': disk_write
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    if pid in self.process_map: del self.process_map[pid]
                    continue
                    
            procs_sorted = sorted(procs, key=lambda x: x.get('cpu', 0), reverse=True)[:1000]
            self._cache['processes']['data'] = procs_sorted
            self._cache['processes']['ts'] = nowt
        except Exception as e: 
            logger.error(f"Process refresh error: {e}")

    def _refresh_requests_cache(self, nowt):
        try:
            rows = db.query('SELECT timestamp, method, path, status_code, response_time, size, src_ip, dst_port, protocol, hostname FROM requests ORDER BY timestamp DESC LIMIT ?', (500,))
            self._cache['requests']['data'] = [{'timestamp': r[0], 'method': r[1], 'path': r[2], 'status': r[3], 'response_time': r[4], 'size': r[5], 'src_ip': r[6], 'dst_port': r[7], 'protocol': r[8], 'hostname': r[9]} for r in rows]
            self._cache['requests']['ts'] = nowt
        except Exception: pass

    def check_alerts(self, cpu_percent, memory_percent, disk_percent=0, hostname=None):
        # FIX: Allow checking alerts for remote agents
        target_host = hostname if hostname else self.hostname
        
        now = time.time()
        now_utc = datetime.now(timezone.utc).isoformat()
        alerts_cfg = CONFIG.get('alerts', {}) 
        cooldown = alerts_cfg.get('alert_cooldown_seconds', 300)
        
        # Use a unique key for cooldowns per host
        # Format: "hostname_metric" (e.g., "Ubuntu-Web_cpu")
        
        # CPU
        if cpu_percent > alerts_cfg.get('cpu_threshold', 80):
            key = f"{target_host}_cpu"
            if now - self.alert_cooldown[key] > cooldown:
                msg = f"High CPU: {cpu_percent:.1f}%"
                db.execute('INSERT INTO alerts (timestamp, hostname, level, message, category) VALUES (?, ?, ?, ?, ?)',
                          (now_utc, target_host, 'warning', msg, 'system'))
                self.alert_cooldown[key] = now
        
        # Memory
        if memory_percent > alerts_cfg.get('memory_threshold', 80):
            key = f"{target_host}_memory"
            if now - self.alert_cooldown[key] > cooldown:
                msg = f"High Memory: {memory_percent:.1f}%"
                db.execute('INSERT INTO alerts (timestamp, hostname, level, message, category) VALUES (?, ?, ?, ?, ?)',
                          (now_utc, target_host, 'warning', msg, 'system'))
                self.alert_cooldown[key] = now
            
        # Disk
        if disk_percent > alerts_cfg.get('disk_threshold', 90):
            key = f"{target_host}_disk"
            if now - self.alert_cooldown[key] > cooldown:
                msg = f"High Disk Usage: {disk_percent:.1f}%"
                db.execute('INSERT INTO alerts (timestamp, hostname, level, message, category) VALUES (?, ?, ?, ?, ?)',
                          (now_utc, target_host, 'warning', msg, 'system'))
                self.alert_cooldown[key] = now

    def packet_handler(self, pkt):
        if not SCAPY_AVAILABLE: return
        now_utc = datetime.now(timezone.utc).isoformat()
        try:
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                # Determine protocol/port
                if pkt.haslayer(TCP):
                    proto = 'TCP'
                    dst_port = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    proto = 'UDP'
                    dst_port = pkt[UDP].dport
                else:
                    return

                method, path, protocol = "-", "-", proto
                
                # Check for HTTP or other
                if pkt.haslayer(Raw):
                    try:
                        raw = pkt[Raw].load.decode('utf-8', errors='ignore')
                        if raw.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                            # It is HTTP
                            lines = raw.split("\r\n")
                            first = lines[0].split()
                            if len(first) >= 2:
                                method, path = first[0], first[1]
                                protocol = 'HTTPS' if dst_port == 443 else 'HTTP'
                        else:
                            # Non-HTTP Traffic
                            if dst_port == 443 and proto == 'UDP': protocol = 'QUIC'
                            elif dst_port == 53: protocol = 'DNS'
                            else: protocol = f"{proto}_FLOW"
                            method = "TRAFFIC"
                            path = f"Port {dst_port}"
                    except: pass

                with self.lock: self.request_count += 1
                
                size = len(pkt)
                # This insert is now buffered by database.py, so it won't lock!
                db.execute('''
                    INSERT INTO requests (timestamp, hostname, method, path, status_code, response_time, size, src_ip, dst_port, protocol)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (now_utc, self.hostname, method, path, 200, 0.0, size, src_ip, dst_port, protocol))
                        
        except Exception: pass

    def monitor_packets(self):
        if not self.packet_sniffing_enabled or not SCAPY_AVAILABLE: return
        try:
            iface = CONFIG.get('interface', None) 
            threading.Thread(target=lambda: [time.sleep(60), self.tcp_tracker.cleanup_old_sessions()], daemon=True).start()
            # Capture all TCP/UDP.
            sniff(iface=iface, prn=self.packet_handler, filter="tcp or udp", store=0)
        except Exception as e:
            logger.error(f"Packet sniffing error: {e}")

    def cleanup_loop(self):
        retention = CONFIG.get('retention_days', 7)
        while True:
            try:
                cutoff = (datetime.now(timezone.utc) - timedelta(days=retention)).isoformat()
                db.execute('DELETE FROM system_metrics WHERE timestamp < ?', (cutoff,))
                db.execute('DELETE FROM requests WHERE timestamp < ?', (cutoff,))
                db.execute('DELETE FROM alerts WHERE timestamp < ?', (cutoff,))
                db.vacuum()
            except Exception as e: logger.error(f"Cleanup error: {e}")
            time.sleep(21600)

    # --- API Data Functions ---
    def get_system_stats(self, hostname: str = None):
        # --- REMOTE AGENT LOGIC (Updated to pull extended stats) ---
        if hostname and hostname != self.hostname:
            try:
                # Get latest metrics row
                row = db.query(
                    "SELECT cpu_percent, memory_percent, disk_usage, uptime, total_connections "
                    "FROM system_metrics WHERE hostname = ? ORDER BY timestamp DESC LIMIT 1", 
                    (hostname,)
                )
                
                if row and row[0]:
                    cpu_val, mem_val, disk_val, uptime_val, conn_val = row[0]
                    # Ensure no None types (safety fallback)
                    cpu_val = float(cpu_val) if cpu_val is not None else 0.0
                    mem_val = float(mem_val) if mem_val is not None else 0.0
                    disk_val = float(disk_val) if disk_val is not None else 0.0
                    uptime_val = int(uptime_val) if uptime_val is not None else 0
                    conn_val = int(conn_val) if conn_val is not None else 0
                else:
                    cpu_val, mem_val, disk_val, uptime_val, conn_val = (0.0, 0.0, 0.0, 0, 0)
                
                # Count recent alerts (last 24h)
                cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
                alert_rows = db.query("SELECT COUNT(*) FROM alerts WHERE timestamp >= ? AND hostname = ?", (cutoff, hostname))
                alert_count = int(alert_rows[0][0]) if alert_rows and alert_rows[0] else 0
                
                logger.debug(f"Stats for {hostname}: CPU={cpu_val:.1f}%, Mem={mem_val:.1f}%, Disk={disk_val:.1f}%, Uptime={uptime_val}s, Conns={conn_val}, Alerts={alert_count}")

                return {
                    'hostname': hostname,
                    'cpu': cpu_val, 
                    'memory': mem_val, 
                    'disk': disk_val, 
                    'uptime': uptime_val,
                    'app_cpu': 0.0, 'app_memory': 0.0,
                    'total_connections': conn_val, 
                    'active_alerts_count': alert_count,
                    'services_running': 0, 'services_total': 0,
                    'logged_in_users': [],
                    'packet_sniffing_enabled': False,
                    'error': None if row else 'No data yet'
                }
            except Exception as e:
                logger.error(f"Error fetching stats for {hostname}: {e}")
                return {'hostname': hostname, 'cpu': 0, 'memory': 0, 'disk': 0, 'uptime': 0, 'total_connections': 0, 'error': str(e)}

        # --- LOCAL MASTER LOGIC ---
        try:
            # Use OS boot time for uptime so it matches agent logic
            uptime = int(time.time() - psutil.boot_time())
            cpu = psutil.cpu_percent(interval=None) # Non-blocking call
            mem = psutil.virtual_memory()
            try:
                main_disk_mount = psutil.disk_partitions()[0].mountpoint
                disk = psutil.disk_usage(main_disk_mount)
            except: disk = psutil.disk_usage('C:/' if os.name == 'nt' else '/')

            try:
                users = psutil.users()
                logged_in_users = list(set([u.name for u in users]))
                connections = psutil.net_connections(kind='inet')
                total_connections = len(connections)
            except:
                logged_in_users = []; total_connections = 0

            try: app_cpu, app_mem = self.proc.cpu_percent(interval=None), self.proc.memory_percent()
            except: app_cpu, app_mem = 0.0, 0.0
            
            services_running, services_total = 0, 0
            if os.name == 'nt':
                try:
                    services = self.get_services()
                    services_total = len(services)
                    services_running = len([s for s in services if s['status'] == 'active'])
                except: pass

            active_alerts_count = 0
            try:
                cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
                active_alerts_count = db.query("SELECT COUNT(*) FROM alerts WHERE timestamp >= ? AND hostname = ?", (cutoff, self.hostname))[0][0]
            except: pass

            return {
                'cpu': cpu, 'memory': mem.percent, 'disk': disk.percent, 'uptime': uptime,
                'app_cpu': round(app_cpu, 2), 'app_memory': round(app_mem, 2),
                'logged_in_users': logged_in_users, 'total_connections': total_connections, 
                'hostname': self.hostname, 'packet_sniffing_enabled': self.packet_sniffing_enabled,
                'active_alerts_count': active_alerts_count,
                'services_running': services_running, 'services_total': services_total,
                'error': None
            }
        except Exception as e:
            return {'hostname': self.hostname, 'error': str(e)}

    def get_historical_metrics(self, range_code: str = "10m", hostname: str = None):
        # Support finer and longer historical ranges used by the frontend
        mapping = {
            '1m':  timedelta(minutes=1),
            '5m':  timedelta(minutes=5),
            '10m': timedelta(minutes=10),
            '30m': timedelta(minutes=30),
            '60m': timedelta(hours=1),
            '2h':  timedelta(hours=2),
            '3h':  timedelta(hours=3),
            '6h':  timedelta(hours=6),
            '12h': timedelta(hours=12),
            '1d':  timedelta(days=1),
            '1w':  timedelta(weeks=1),
            '1M':  timedelta(days=30),
            '1y':  timedelta(days=365),
        }
        duration = mapping.get(range_code, timedelta(minutes=10))
        cutoff_dt_local = datetime.now() - duration
        cutoff_dt_utc = datetime.now(timezone.utc) - duration
        cutoff_space = cutoff_dt_utc.strftime('%Y-%m-%d %H:%M:%S.%f')
        cutoff_t = cutoff_dt_utc.strftime('%Y-%m-%dT%H:%M:%f')
        query_hostname = hostname if hostname and hostname != 'all' else self.hostname
        
        # Query for both possible string formats (space & 'T')
        rows = db.query('''
            SELECT timestamp, cpu_percent, memory_percent, network_sent_rate, network_recv_rate, 
                   disk_read_rate, disk_write_rate, request_count
            FROM system_metrics
            WHERE hostname = ? AND (timestamp >= ? OR timestamp >= ?)
            ORDER BY timestamp ASC
        ''', (query_hostname, cutoff_space, cutoff_t))

        def _parse_timestamp(s: str):
            if not s: return None
            try:
                if s.endswith('Z'):
                    return datetime.fromisoformat(s.replace('Z', '+00:00'))
                try:
                    return datetime.fromisoformat(s)
                except ValueError:
                    try:
                        return datetime.strptime(s, '%Y-%m-%d %H:%M:%S.%f')
                    except ValueError:
                        try:
                            return datetime.strptime(s, '%Y-%m-%d %H:%M:%S')
                        except Exception:
                            return None
            except Exception:
                return None

        out = []
        for r in rows:
            raw_ts = r[0]
            dt = _parse_timestamp(raw_ts)
            if not dt: continue

            if dt.tzinfo is not None:
                dt_utc = dt.astimezone(timezone.utc)
                if dt_utc < cutoff_dt_utc: continue
            else:
                if dt < cutoff_dt_local: continue

            ts_out = dt.astimezone(timezone.utc).isoformat() if dt.tzinfo else dt.isoformat()

            out.append({
                'timestamp': ts_out,
                'cpu': float(r[1] or 0),
                'memory': float(r[2] or 0),
                'net_sent_rate': float(r[3] or 0),
                'net_recv_rate': float(r[4] or 0),
                'disk_read_rate': float(r[5] or 0),
                'disk_write_rate': float(r[6] or 0),
                'requests': int(r[7] or 0)
            })

        return out

    def get_requests(self, limit: int = 100, port_filter: int = None, hostname: str = None):
        base_sql = "SELECT timestamp, method, path, status_code, response_time, size, src_ip, dst_port, protocol, hostname FROM requests"
        where_clauses, params = [], []
        query_hostname = hostname if hostname and hostname != 'all' else self.hostname
        where_clauses.append("hostname = ?"); params.append(query_hostname)
        if port_filter: where_clauses.append("dst_port = ?"); params.append(port_filter)
        base_sql += " WHERE " + " AND ".join(where_clauses) + " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        rows = db.query(base_sql, tuple(params))
        return [{'timestamp': r[0], 'method': r[1], 'path': r[2], 'status': r[3], 'response_time': r[4], 'size': r[5],
                 'src_ip': r[6], 'dst_port': r[7], 'protocol': r[8], 'hostname': r[9]} for r in rows]

    def get_services(self):
        if os.name != 'nt': return []
        services_to_monitor = CONFIG.get('services_to_monitor', [])
        try: services_found = {s.name(): s for s in psutil.win_service_iter()}
        except: return []
        services = []
        for svc_name in services_to_monitor:
            if svc_name in services_found:
                try:
                    win_status = services_found[svc_name].status()
                    status = 'active' if win_status == 'running' else 'inactive'
                except: status = 'unknown'
                services.append({'name': svc_name, 'status': status})
            else: services.append({'name': svc_name, 'status': 'not_found'})
        return services

    def get_top_processes(self, sort_by: str = 'cpu', limit: int = 25):
        procs = self._cache['processes']['data']
        sort_key = sort_by if sort_by in ['cpu', 'memory', 'disk_read', 'disk_write'] else 'cpu'
        return sorted(procs, key=lambda x: x.get(sort_key, 0), reverse=True)[:limit]

    def get_connections(self, limit: int = 100, status_filter: str = None):
        conns = []
        try: net_conns = psutil.net_connections(kind='inet')
        except: return []
        for c in net_conns:
            if status_filter and c.status != status_filter: continue
            if len(conns) >= limit: break
            conns.append({
                'local': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A",
                'remote': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A",
                'status': c.status, 'pid': c.pid, 'hostname': self.hostname
            })
        return conns

    def get_logs(self, lines: int = 3000, log_file: str = None, log_level: str = None):
        log_files_config = CONFIG.get('log_files_to_analyze', {})
        path = log_files_config.get(log_file, CONFIG.get('log_file'))
        if not path or not Path(path).exists(): return [{'line': 'Log not found', 'level': 'error'}]
        out = []
        try:
            with open(path, 'r', errors='ignore') as f: content = f.readlines()[-lines:]
            for l in content:
                lvl = 'info'
                if 'error' in l.lower(): lvl = 'error'
                elif 'warning' in l.lower(): lvl = 'warning'
                if log_level and lvl != log_level: continue
                out.append({'line': l.rstrip(), 'level': lvl})
        except Exception as e: out = [{'line': str(e), 'level': 'error'}]
        return out

    def get_available_servers(self):
        try:
            rows = db.query("SELECT DISTINCT hostname FROM agents ORDER BY hostname")
            servers = [r[0] for r in rows]
        except: servers = []
        if self.hostname not in servers: servers.insert(0, self.hostname)
        return servers

    def get_alerts(self, hostname: str = None, limit: int = 200):
        try:
            if hostname and hostname != self.hostname:
                rows = db.query('SELECT timestamp, hostname, level, message, category FROM alerts WHERE hostname = ? ORDER BY timestamp DESC LIMIT ?', (hostname, limit))
            else:
                rows = db.query('SELECT timestamp, hostname, level, message, category FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
            return [{'timestamp': r[0], 'hostname': r[1], 'level': r[2], 'message': r[3], 'category': r[4]} for r in rows]
        except Exception as e: return []

    def get_alerts_count(self, since_timestamp: str | None = None):
        try:
            if since_timestamp:
                rows = db.query('SELECT COUNT(*) FROM alerts WHERE timestamp > ?', (since_timestamp,))
            else:
                rows = db.query('SELECT COUNT(*) FROM alerts')
            count = rows[0][0] if rows and rows[0] else 0
            return {'new_alerts': int(count)}
        except: return {'new_alerts': 0}

    def clear_alerts(self, hostname: str = None):
        try:
            if hostname and hostname != 'all':
                db.execute('DELETE FROM alerts WHERE hostname = ?', (hostname,))
            else:
                db.execute('DELETE FROM alerts')
            return {"status": "success"}
        except Exception as e: return {"status": "error", "message": str(e)}

    def get_request_categories(self, hostname: str = None):
        try:
            query_hostname = hostname if hostname and hostname != 'all' else self.hostname
            rows = db.query('SELECT protocol, dst_port, COUNT(*) as cnt FROM requests WHERE hostname = ? GROUP BY protocol, dst_port ORDER BY dst_port ASC', (query_hostname,))
            out = []
            for r in rows:
                proto = r[0] or 'HTTP'
                port = int(r[1] or 0)
                out.append({'protocol': proto, 'port': port, 'count': int(r[2] or 0)})
            return out
        except: return []

    def get_alert_config(self):
        """Returns the full alerts configuration dict."""
        return CONFIG.get('alerts', {})

    def set_alert_config(self, update_data: dict):
        try:
            alerts = CONFIG.setdefault('alerts', {})
            alerts.update(update_data)
            with open(CONFIG_PATH, 'w', encoding='utf-8') as f: json.dump(CONFIG, f, indent=4)
            return {"status": "success", "saved": list(update_data.keys())}
        except Exception as e: return {"status": "error", "message": str(e)}

    def get_log_analysis(self, log_file: str = None, hostname: str = None):
        """Analyzes a log file and returns structured insight data."""
        log_files_config = CONFIG.get('log_files_to_analyze', {})
        path = log_files_config.get(log_file, CONFIG.get('log_file'))
        if not path or not Path(path).exists():
            return {"error": "Log file not found", "errors": 0, "warnings": 0, "info": 0, "top_errors": []}
        
        errors, warnings, infos = 0, 0, 0
        error_messages = []
        try:
            with open(path, 'r', errors='ignore') as f:
                lines = f.readlines()[-2000:]  # Analyze last 2000 lines
            for line in lines:
                ll = line.lower()
                if 'error' in ll or 'critical' in ll or 'exception' in ll:
                    errors += 1
                    msg = line.strip()[:120]
                    if msg and msg not in error_messages:
                        error_messages.append(msg)
                elif 'warning' in ll or 'warn' in ll:
                    warnings += 1
                else:
                    infos += 1
        except Exception as e:
            return {"error": str(e), "errors": 0, "warnings": 0, "info": 0, "top_errors": []}
        
        return {
            "errors": errors,
            "warnings": warnings,
            "info": infos,
            "total_lines": len(lines),
            "top_errors": error_messages[:10],
            "health_score": max(0, 100 - errors * 2 - warnings)
        }

    def get_server_status(self):
        servers = self.get_available_servers()
        status_list = []
        for server in servers:
            try:
                res = db.query("SELECT timestamp FROM system_metrics WHERE hostname = ? ORDER BY timestamp DESC LIMIT 1", (server,))
                if not res: 
                    status_list.append({"hostname": server, "status": "Offline", "last_seen": "Never"})
                    continue
                raw_ts = res[0][0]
                # Robust timestamp parsing for Python 3.8+
                try:
                    last = datetime.fromisoformat(raw_ts.replace('Z', '+00:00'))
                except ValueError:
                    try:
                        last = datetime.strptime(raw_ts, '%Y-%m-%d %H:%M:%S.%f')
                        last = last.replace(tzinfo=timezone.utc)
                    except ValueError:
                        last = datetime.strptime(raw_ts[:19], '%Y-%m-%d %H:%M:%S')
                        last = last.replace(tzinfo=timezone.utc)
                
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                
                diff = (datetime.now(timezone.utc) - last).total_seconds() / 60
                status = "Online" if diff < 5 else ("Warning" if diff < 30 else "Offline")
                last_iso = last.astimezone(timezone.utc).isoformat()
                status_list.append({"hostname": server, "status": status, "last_seen": last_iso})
            except Exception as e:
                logger.warning(f"Server status error for {server}: {e}")
                status_list.append({"hostname": server, "status": "Error", "last_seen": "Error"})
        return status_list

    # --- PROCESS KILL IMPLEMENTATION ---
    def kill_process(self, pid: int, kill_tree: bool = False):
        try:
            if not psutil.pid_exists(pid):
                return {"status": "error", "message": f"Process {pid} not found."}
                
            p = psutil.Process(pid)
            
            if kill_tree:
                children = p.children(recursive=True)
                for child in children:
                    try: child.kill()
                    except psutil.NoSuchProcess: pass
            
            p.kill()
            return {"status": "success", "message": f"Process {pid} killed."}
            
        except psutil.NoSuchProcess:
            return {"status": "error", "message": f"Process {pid} no longer exists."}
        except psutil.AccessDenied:
            return {"status": "error", "message": f"Access denied killing process {pid}."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def load_agents_from_config(self):
        agents = CONFIG.get('agents', [])
        for agent in agents:
            db.execute("INSERT INTO agents (hostname, url, api_key) VALUES (?, ?, ?) ON CONFLICT(hostname) DO UPDATE SET url=excluded.url, api_key=excluded.api_key",
                       (agent['hostname'], agent['url'], agent['api_key']))

    def start_background_threads(self):
        if self._threads_started: return
        self.load_agents_from_config()
        threading.Thread(target=self.monitor_system_resources, daemon=True, name="ResourceMonitor").start()
        threading.Thread(target=self.cleanup_loop, daemon=True, name="CleanupLoop").start()
        if self.packet_sniffing_enabled and SCAPY_AVAILABLE:
            threading.Thread(target=self.monitor_packets, daemon=True, name="PacketSniffer").start()
        self._threads_started = True

# --- Create a single instance for export ---
monitor = ServerMonitor()

# Export these for main.py to use
__all__ = ['monitor', 'CONFIG', 'logger', 'INTEGRATION_CONFIG', 'wazuh_client', 'zabbix_client']