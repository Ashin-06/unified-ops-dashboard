import sqlite3
#!/usr/bin/env python3
"""Unified Ops Dashboard API and lifecycle."""
import asyncio
import secrets
import os
import uvicorn
import json
import time
import threading
import logging
import sys
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Header, HTTPException, Depends, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, Response
from typing import Optional, Annotated, List
from datetime import datetime, timezone
from pydantic import BaseModel, constr, Field

# --- Strict Dependency Check ---
try:
    import httpx
except ImportError:
    print("CRITICAL ERROR: 'httpx' library is missing.")
    print("Please run: pip install httpx")
    sys.exit(1)

# --- Import Core Logic ---
try:
    from monitor import monitor, CONFIG, logger, INTEGRATION_CONFIG, wazuh_client, zabbix_client
    from database import db
except ImportError as e:
    print(f"CRITICAL ERROR: Could not import core modules: {e}")
    sys.exit(1)

# --- Define base directory relative to this file ---
BASE_DIR = Path(__file__).resolve().parent
HTML_FILE = BASE_DIR / "index.html"

# --- Lifespan Event Handler ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("=" * 80)
    logger.info(" FASTAPI LIFESPAN STARTUP")
    logger.info("=" * 80)
    
    if agent_client.client.is_closed:
        agent_client.client = httpx.AsyncClient(timeout=15.0, verify=CONFIG.get('verify_agent_ssl', True))
    if db.batch_enabled:
        db._start_batch_writer()
    monitor.start_background_threads()
    try:
        yield
    finally:
        await asyncio.to_thread(monitor.stop_background_threads)
        await agent_client.client.aclose()
        await asyncio.to_thread(db.close)
        logger.info('Dashboard stopped')

# --- App Initialization ---
app = FastAPI(title="Unified Ops Dashboard", lifespan=lifespan)
app.mount('/static', StaticFiles(directory=BASE_DIR / 'static'), name='static')
CENTRAL_API_KEY = CONFIG.get('master_api_key', '')
PLACEHOLDER_KEYS = {'', None, 'YOUR_SECRET_KEY_HERE', 'CHANGE_THIS_SECRET_KEY', 'REPLACE_WITH_MASTER_KEY'}

# --- Pydantic models ---
from schemas import AlertConfig, PortScanRequest, KillRequest, AgentMetrics, AgentRequest

# Strict timestamp validation regex
ISOTimestampStr = constr(pattern=r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[\+\-]\d{2}:\d{2})$')

# --- Agent Proxy Client ---
AGENT_CACHE = {} 

class AsyncAgentClient:
    def __init__(self):
        # Verify agent certificates unless explicitly opted out in configuration.
        self.client = httpx.AsyncClient(timeout=15.0, verify=CONFIG.get('verify_agent_ssl', True))

    async def get_agent(self, hostname: str):
        if hostname not in AGENT_CACHE:
            try:
                row = db.query("SELECT url, api_key FROM agents WHERE hostname = ?", (hostname,))
                if not row: return None
                AGENT_CACHE[hostname] = {"url": row[0][0], "api_key": row[0][1]}
            except Exception as e:
                logger.error(f"Error querying agent {hostname}: {e}")
                return None
        return AGENT_CACHE[hostname]

    async def proxy_get(self, hostname: str, endpoint: str, params: dict = None):
        agent = await self.get_agent(hostname)
        if not agent:
            # If agent isn't found in DB, try to find it in config list (fallback)
            for a in CONFIG.get('agents', []):
                if a['hostname'] == hostname:
                    agent = {"url": a['url'], "api_key": a['api_key']}
                    break
            if not agent:
                raise HTTPException(status_code=404, detail=f"Agent '{hostname}' not configured.")

        try:
            headers = {"Authorization": f"Bearer {agent['api_key']}"}
            url = f"{agent['url'].rstrip('/')}{endpoint}"
            response = await self.client.get(url, headers=headers, params=params)
            
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as e:
            logger.warning(f"Proxy error for {hostname}: {e}")
            # Return a graceful error structure so frontend doesn't crash
            return {"error": str(e), "status": "unreachable"}

    async def proxy_post(self, hostname: str, endpoint: str, data: dict = None):
        agent = await self.get_agent(hostname)
        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent '{hostname}' not configured.")
        try:
            headers = {"Authorization": f"Bearer {agent['api_key']}"}
            url = f"{agent['url'].rstrip('/')}{endpoint}"
            response = await self.client.post(url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

agent_client = AsyncAgentClient()

# --- Identity and role enforcement ---
from security_store import store
from security_api import router as security_router
app.include_router(security_router)

async def authenticate(authorization):
    if not authorization:
        raise HTTPException(status_code=401, detail='Operator access required')
    try:
        scheme, key = authorization.split()
    except ValueError:
        raise HTTPException(status_code=401, detail='Invalid Authorization header')
    if scheme.lower() != 'bearer':
        raise HTTPException(status_code=401, detail='Invalid Authorization scheme')
    if CENTRAL_API_KEY not in PLACEHOLDER_KEYS and secrets.compare_digest(key.encode('utf-8'), str(CENTRAL_API_KEY).encode('utf-8')):
        return {'id':None,'name':'bootstrap-admin','role':'admin'}
    who = await asyncio.to_thread(store.user_for_token, key)
    if not who:
        raise HTTPException(status_code=401, detail='Invalid or revoked API key')
    return who

async def verify_api_key(authorization: Annotated[str | None, Header()] = None):
    await authenticate(authorization)
    return True

async def record_activity(who, request, outcome):
    try:
        await asyncio.to_thread(store.audit,who['name'],who['role'],request.method,request.url.path,outcome)
        return True
    except sqlite3.Error:
        logger.error('Activity audit could not be saved; check database storage')
        return False

@app.exception_handler(sqlite3.Error)
async def storage_error(request, exc):
    return JSONResponse({'detail':'Storage is unavailable. Check free disk space and database access.'},status_code=503,headers={'Cache-Control':'no-store'})

@app.middleware('http')
async def access_policy(request: Request, call_next):
    path=request.url.path
    mutation=request.method not in {'GET','HEAD','OPTIONS'}
    protected=path.startswith('/api/') and (mutation or path.startswith('/api/soc/') or CONFIG.get('require_auth_for_reads',False))
    who={'name':'anonymous','role':'public','id':None}
    if protected:
        try:
            who=await authenticate(request.headers.get('authorization'))
            admin_only=path.startswith(('/api/soc/users','/api/soc/audit'))
            analyst_action=path.startswith(('/api/soc/incidents/','/api/soc/sync/'))
            if admin_only and who['role']!='admin':raise HTTPException(403,'Administrator role required')
            if mutation and path!='/api/auth/check':
                permitted=who['role']=='admin' or (who['role']=='analyst' and analyst_action)
                if not permitted:raise HTTPException(403,'This role cannot perform that action')
        except HTTPException as exc:
            if mutation and not path.startswith('/api/agent/'):
                await record_activity(who,request,exc.status_code)
            return JSONResponse({'detail':exc.detail},status_code=exc.status_code,headers={'Cache-Control':'no-store'})
        except sqlite3.Error:
            return await storage_error(request,None)
    request.state.identity=who
    response=await call_next(request)
    if mutation and path.startswith('/api/') and not path.startswith('/api/agent/'):
        if not await record_activity(who,request,response.status_code):
            response.headers['X-Audit-Status']='failed'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='same-origin'
    response.headers['X-Frame-Options']='DENY'
    if path.startswith('/api/'):
        response.headers['Cache-Control']='no-store'
    return response

@app.post('/api/auth/check', dependencies=[Depends(verify_api_key)])
def auth_check(request: Request):
    return {'status': 'success', 'name':request.state.identity['name'], 'role':request.state.identity['role']}

@app.get('/robots.txt', include_in_schema=False)
def robots():
    return Response('User-agent: *\nDisallow: /\n', media_type='text/plain')

@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith(('/api/', '/static/')):
        return JSONResponse({'detail': 'Not found'}, status_code=404)
    return HTMLResponse('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>Page not found · Unified Ops</title><link rel="stylesheet" href="/static/dashboard.css"></head><body><main><article class="panel"><div class="empty-state"><div class="empty-symbol">?</div><h1>Page not found</h1><p>This address does not match a page in this workspace.</p><br><a class="button primary" href="/#overview">Back to Overview</a> <a class="button" href="/#help">Help &amp; about</a></div></article></main></body></html>', status_code=404)

# --- HTML Serve ---
@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    try:
        poll_interval_ms = max(5, int(CONFIG.get('performance', {}).get('frontend_poll_interval', 15))) * 1000
        if not HTML_FILE.exists():
            logger.error(f"CRITICAL: index.html missing at {HTML_FILE}")
            return HTMLResponse(content="<h1>Error: index.html not found</h1>", status_code=500)
        with open(HTML_FILE, "r", encoding="utf-8") as f:
            html_content = f.read()
        html_content = html_content.replace("{{ poll_interval_ms }}", str(poll_interval_ms))
        return HTMLResponse(content=html_content)
    except Exception as e:
        import traceback
        logger.error(f"CRITICAL: Failed to serve dashboard. File: {HTML_FILE}, Exists: {HTML_FILE.exists()}")
        logger.error(traceback.format_exc())
        return HTMLResponse(content=f"<h1>Error loading dashboard</h1><p>{e}</p>", status_code=500)

@app.get('/favicon.ico')
async def favicon():
    return Response(status_code=204)

# --- Agent Data Submission ---
@app.post("/api/agent/submit")
def receive_agent_data(data: AgentMetrics, is_authenticated: bool = Depends(verify_api_key)):
    try:
        data = data.model_dump()
        hostname = data['hostname']
        now_utc = datetime.now(timezone.utc).isoformat()
        
        # Get Standard Metrics with type conversion
        cpu = float(data.get('cpu_percent', 0))
        mem = float(data.get('memory_percent', 0))
        
        # Get Rates with type conversion
        d_read = float(data.get('disk_read_rate', 0))
        d_write = float(data.get('disk_write_rate', 0))
        n_sent = float(data.get('network_sent_rate', 0))
        n_recv = float(data.get('network_recv_rate', 0))
        
        # Get Extended Status for Comparison Tab with type conversion
        disk_usage = float(data.get('disk_usage', 0))
        uptime = int(data.get('uptime', 0))
        connections = int(data.get('total_connections', 0))
        
        logger.info(f" Received from {hostname}: CPU={cpu:.1f}%, Mem={mem:.1f}%, Disk={disk_usage:.1f}%, Uptime={uptime}s, Conns={connections}")

        # INSERT including new columns
        db.execute('''
            INSERT INTO system_metrics (
                timestamp, hostname, cpu_percent, memory_percent, 
                disk_read_rate, disk_write_rate, network_sent_rate, network_recv_rate,
                disk_usage, uptime, total_connections
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (now_utc, hostname, cpu, mem, d_read, d_write, n_sent, n_recv, disk_usage, uptime, connections)
        )
        monitor.check_alerts(cpu, mem, disk_usage, hostname=hostname)
        return JSONResponse(content={"status": "success"}, status_code=200)
    except Exception as e:
        logger.error(f"Error in /api/agent/submit: {e}")
        return JSONResponse(content={"status": "error", "message": str(e)}, status_code=500)

@app.post('/api/agent/submit_requests')
def receive_agent_requests(
    requests_list: Annotated[List[AgentRequest], Field(max_length=1000)],
    is_authenticated: bool = Depends(verify_api_key),
):
    if not requests_list:
        return {'status': 'empty'}
    rows = [(
        req.timestamp.astimezone(timezone.utc).isoformat(), req.hostname,
        req.method, req.path, req.status_code, req.response_time,
        req.size, req.src_ip, req.dst_port, req.protocol,
    ) for req in requests_list]
    try:
        db.execute_many('INSERT INTO requests (timestamp, hostname, method, path, status_code, '
                        'response_time, size, src_ip, dst_port, protocol) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', rows)
    except Exception:
        logger.exception('Traffic batch could not be committed')
        raise HTTPException(status_code=503, detail='Traffic storage unavailable; retry the batch')
    return {'status': 'success', 'saved': len(rows)}

# --- System Stats & Metrics ---
@app.get("/api/stats")
async def api_get_system_stats(hostname: Optional[str] = None):
    # Default to local if not specified
    if not hostname or hostname == 'all':
        hostname = monitor.hostname
    
    # If it's localhost, get direct stats
    if hostname == monitor.hostname:
        return await asyncio.to_thread(monitor.get_system_stats, hostname=hostname)
    
    # Try proxying to remote agent first for live data
    try:
        live_data = await agent_client.proxy_get(hostname, "/api/stats")
        if isinstance(live_data, dict) and "error" not in live_data and "detail" not in live_data:
            return live_data
    except Exception:
        pass # Fallback to DB

    # Fallback: Check local DB for last known state
    return await asyncio.to_thread(monitor.get_system_stats, hostname=hostname)

@app.get("/api/metrics")
def api_get_historical_metrics(range: str = "10m", hostname: Optional[str] = None):
    if not hostname or hostname == 'all':
        hostname = monitor.hostname
    return monitor.get_historical_metrics(range, hostname)

# --- Integrations ---
@app.get("/api/integrations/status")
def api_get_integration_status():
    def check_status(client, key):
        cfg = INTEGRATION_CONFIG.get(key, {})
        url = cfg.get(f'{key}_url', '') or cfg.get('url', '')
        enabled = getattr(client, 'enabled', False)
        base_url = url.split('/api')[0].split('/zabbix')[0].rstrip('/')
        return {"enabled": enabled, "url": base_url}

    wazuh_status = check_status(wazuh_client, 'wazuh')
    zabbix_status = check_status(zabbix_client, 'zabbix')
    g_conf = INTEGRATION_CONFIG.get('grafana', {})
    grafana_status = {
        "enabled": g_conf.get('enabled', False),
        "url": g_conf.get('url', ''),
        "dashboard_url": g_conf.get('dashboard_url', ''),
        "embed": g_conf.get('embed', False),
        "reachable": None
    }
    return {"wazuh": wazuh_status, "zabbix": zabbix_status, "grafana": grafana_status}

@app.get("/api/wazuh/stats")
def api_get_wazuh_stats():
    if not wazuh_client.enabled: return {"error": "Wazuh disabled in config", "enabled": False}
    return wazuh_client.get_dashboard_stats()

@app.get("/api/wazuh/agents")
def api_get_wazuh_agents():
    if not wazuh_client.enabled: return []
    result = wazuh_client.get_agents()
    return result if not (isinstance(result, dict) and 'error' in result) else []

@app.get("/api/wazuh/alerts")
def api_get_wazuh_alerts(agent: Optional[str] = None):
    if not wazuh_client.enabled: return []
    return wazuh_client.get_recent_alerts(agent_id=agent)

@app.get("/api/zabbix/stats")
def api_get_zabbix_stats():
    if not zabbix_client.enabled: return {"error": "Zabbix disabled in config", "enabled": False}
    return zabbix_client.get_dashboard_stats()

@app.get("/api/zabbix/problems")
def api_get_zabbix_problems():
    if not zabbix_client.enabled: return []
    return zabbix_client.get_problems()

@app.get("/api/zabbix/triggers")
def api_get_zabbix_triggers(host: Optional[str] = None):
    if not zabbix_client.enabled: return []
    return zabbix_client.get_triggers(host_filter=host)

# --- General Endpoints ---
@app.get("/api/requests")
def api_get_requests(port: Optional[int] = None, hostname: Optional[str] = None, limit: int = Query(100, ge=1, le=1000)):
    if not hostname or hostname == 'all': hostname = monitor.hostname
    return monitor.get_requests(limit=limit, port_filter=port, hostname=hostname)

@app.get("/api/alerts")
def api_get_alerts(hostname: Optional[str] = None):
    if not hostname or hostname == 'all': return monitor.get_alerts(hostname=None)
    return monitor.get_alerts(hostname=hostname)

@app.delete("/api/alerts")
def api_clear_alerts(hostname: Optional[str] = None):
    return monitor.clear_alerts(hostname=hostname)

@app.get("/api/alerts/count")
def api_get_alerts_count(since: Optional[ISOTimestampStr] = None):
    return monitor.get_alerts_count(since_timestamp=since)

@app.get("/api/services")
async def api_get_services(hostname: Optional[str] = None):
    if not hostname: hostname = monitor.hostname
    if hostname == monitor.hostname: return await asyncio.to_thread(monitor.get_services)
    return await agent_client.proxy_get(hostname, "/api/services")

@app.get("/api/processes")
async def api_get_processes(hostname: Optional[str] = None, sort_by: str = 'cpu', limit: int = Query(25, ge=1, le=1000)):
    if not hostname: hostname = monitor.hostname
    if hostname == monitor.hostname: return monitor.get_top_processes(sort_by=sort_by, limit=limit)
    return await agent_client.proxy_get(hostname, "/api/processes", params={"sort_by": sort_by, "limit": limit})

@app.post("/api/processes/kill")
async def api_kill_process(req: KillRequest, hostname: Optional[str] = None):
    if not hostname: hostname = monitor.hostname
    
    # Local Kill
    if hostname == monitor.hostname: 
        return await asyncio.to_thread(monitor.kill_process, req.pid, req.kill_tree)
    
    # Remote Kill
    return await agent_client.proxy_post(hostname, "/api/processes/kill", data=req.model_dump())

@app.get("/api/connections")
async def api_get_connections(status: Optional[str] = None, hostname: Optional[str] = None, limit: int = Query(100, ge=1, le=1000)):
    if not hostname: hostname = monitor.hostname
    if hostname == monitor.hostname: return await asyncio.to_thread(monitor.get_connections, limit=limit, status_filter=status)
    return await agent_client.proxy_get(hostname, "/api/connections", params={"status": status, "limit": limit})

@app.get("/api/logs")
async def api_get_logs(file: Optional[str] = None, level: Optional[str] = None, hostname: Optional[str] = None):
    if not hostname: hostname = monitor.hostname
    if hostname == monitor.hostname: return {"logs": await asyncio.to_thread(monitor.get_logs, log_file=file, log_level=level)}
    return await agent_client.proxy_get(hostname, "/api/logs", params={"file": file, "level": level})

@app.get("/api/log-files")
async def api_get_log_files(hostname: Optional[str] = None):
    if not hostname: hostname = monitor.hostname
    if hostname == monitor.hostname: return {"log_files": list(CONFIG.get('log_files_to_analyze', {}).keys())}
    return await agent_client.proxy_get(hostname, "/api/log-files")

@app.get("/api/servers")
def api_get_servers():
    return {"servers": monitor.get_available_servers(), "local_hostname": monitor.hostname}

@app.get("/api/server-status")
def api_server_status():
    return monitor.get_server_status()

@app.get("/api/config/alerts")
def api_get_alert_config():
    return monitor.get_alert_config()

@app.post("/api/config/alerts")
def api_set_alert_config(config: AlertConfig):
    update_data = config.model_dump(exclude_unset=True, exclude_none=True)
    return monitor.set_alert_config(update_data)

@app.post("/api/security/port-scan")
async def api_port_scan(scan_request: PortScanRequest, hostname: Optional[str] = None):
    try:
        if not hostname: hostname = monitor.hostname
        # Local Scan
        if hostname == monitor.hostname:
            res = await asyncio.to_thread(monitor.run_port_scan, scan_request.target, scan_request.ports)
            if 'results' not in res: res['results'] = []
            return res
        
        # Remote Scan
        res = await agent_client.proxy_post(hostname, "/api/security/port-scan", data=scan_request.model_dump())
        if 'results' not in res: res['results'] = []
        return res
    except Exception as e:
        logger.error(f"Port scan error: {e}")
        return {"status": "error", "message": str(e), "target": scan_request.target, "results": []}

@app.get("/api/health")
def health_check():
    threads = [t.name for t in threading.enumerate()]
    active = 'ResourceMonitor' in threads
    
    try:
        storage = db.health()
    except Exception:
        storage = {'healthy': False, 'pending_writes': None}
    return {
        'status': 'healthy' if active and storage['healthy'] else 'degraded',
        'monitoring_active': active,
        'storage': storage,
        'hostname': monitor.hostname,
        'uptime_seconds': int(time.time() - monitor.start_time),
    }

@app.get("/api/log-analysis")
def api_log_analysis(file: Optional[str] = None, hostname: Optional[str] = None):
    """Analyzes log files and returns structured error/warning/info counts."""
    if not hostname: hostname = monitor.hostname
    # Only supported for local host currently
    if hostname != monitor.hostname:
        return {"error": "Remote log analysis not yet supported", "errors": 0, "warnings": 0, "info": 0}
    return monitor.get_log_analysis(log_file=file, hostname=hostname)

@app.get("/api/ping")
async def api_ping(hostname: Optional[str] = None):
    """Measures round-trip latency to a remote agent."""
    if not hostname or hostname == monitor.hostname:
        return {"hostname": monitor.hostname, "latency_ms": 0, "status": "local"}
    try:
        import httpx as _httpx
        start = time.monotonic()
        live_data = await agent_client.proxy_get(hostname, "/api/health")
        elapsed = (time.monotonic() - start) * 1000
        if isinstance(live_data, dict) and "error" not in live_data and "detail" not in live_data:
            return {"hostname": hostname, "latency_ms": round(elapsed, 1), "status": "online"}
        return {"hostname": hostname, "latency_ms": -1, "status": "error", "detail": live_data.get("error")}
    except Exception as e:
        return {"hostname": hostname, "latency_ms": -1, "status": "unreachable", "detail": str(e)}

if __name__ == "__main__":
    logger.info(f"Starting server on port {CONFIG.get('web_port', 8081)}")
    uvicorn.run(app, host=CONFIG.get("web_host", "127.0.0.1"), port=CONFIG.get("web_port", 8081), log_level="info")