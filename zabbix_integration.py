#!/usr/bin/env python3
"""
Zabbix Integration v2.4
=======================
- FIX: Removed server-side timestamp multiplication (frontend now handles it).
- FIX: Correctly calculates "Active" vs "Total" hosts.
- FIX: Auto-detects legacy vs modern login params.
"""
import logging
import json

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None
    HAS_HTTPX = False

logger = logging.getLogger("ServerMonitor")

class ZabbixAPI:
    def __init__(self, cfg: dict):
        self.cfg = cfg or {}
        self.url = self.cfg.get('zabbix_url', '')
        self.user = self.cfg.get('zabbix_user') or self.cfg.get('username')
        self.password = self.cfg.get('zabbix_password') or self.cfg.get('password')
        self.verify_ssl = self.cfg.get('verify_ssl', True)
        self.token = None
        self.enabled = self.cfg.get('enabled', False) and bool(self.url)
        self.req_id = 1

    def login(self):
        if not HAS_HTTPX:
            raise RuntimeError("Missing 'httpx' library. Run: pip install httpx")
            
        # Try modern parameter 'username' first (Zabbix 6.4+)
        try:
            self._attempt_login(param_user_key="username")
            return
        except Exception as e:
            logger.warning(f"Zabbix login with 'username' failed ({e}). Retrying with 'user'...")

        # Fallback to legacy parameter 'user' (Zabbix < 6.4)
        try:
            self._attempt_login(param_user_key="user")
        except Exception as e:
            raise RuntimeError(f"Zabbix Login Failed (tried both methods): {str(e)}")

    def _attempt_login(self, param_user_key="username"):
        payload = {
            "jsonrpc": "2.0",
            "method": "user.login",
            "params": {
                param_user_key: self.user,
                "password": self.password
            },
            "id": self.req_id
        }
        self.req_id += 1
        
        r = httpx.post(self.url, json=payload, verify=self.verify_ssl, timeout=5.0)
        r.raise_for_status()
        resp = r.json()
        
        if 'error' in resp:
            raise RuntimeError(resp['error'].get('data') or resp['error'].get('message'))
            
        self.token = resp.get('result')

    def _request(self, method, params=None):
        if not self.enabled:
            return {"error": "Zabbix disabled"}
            
        if not self.token:
            try:
                self.login()
            except Exception as e:
                return {"error": str(e)}

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "auth": self.token,
            "id": self.req_id
        }
        self.req_id += 1

        try:
            r = httpx.post(self.url, json=payload, verify=self.verify_ssl, timeout=8.0)
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            
            resp = r.json()
            if 'error' in resp:
                return {"error": resp['error'].get('data') or resp['error'].get('message')}
            
            return resp.get('result')
        except Exception as e:
            return {"error": str(e)}

    def get_dashboard_stats(self):
        # Safe default
        stats = {
            "enabled": self.enabled,
            "status": "unknown",
            "total_hosts": 0,
            "active_hosts": 0
        }

        if not self.enabled:
            stats["status"] = "disabled"
            return stats
        
        # Get Hosts to count them
        hosts = self._request("host.get", {"output": ["status"]})
        
        if isinstance(hosts, dict) and "error" in hosts:
             stats["status"] = "error"
             stats["message"] = hosts["error"]
             return stats
             
        # Zabbix Host Status: 0 = Monitored (Active), 1 = Unmonitored (Disabled)
        total = len(hosts)
        active = len([h for h in hosts if str(h.get('status')) == '0'])
        
        stats["status"] = "connected"
        stats["total_hosts"] = total
        stats["active_hosts"] = active
        return stats

    def get_all_hosts(self):
        return self._request("host.get", {"output": ["hostid", "host", "name", "status"], "selectInterfaces": ["ip"]})

    def get_problems(self):
        # Fetch recent problems
        res = self._request("problem.get", {"output": "extend", "sortfield": ["eventid"], "sortorder": "DESC", "limit": 20})
        # IMPORTANT: Do NOT multiply by 1000 here. 
        # The API returns seconds (Unix), and index.html multiplies by 1000.
        # Doing it twice causes the invalid date bug.
        return res if isinstance(res, list) else []

    def get_triggers(self, host_filter=None):
        params = {"output": ["triggerid", "description", "priority", "value", "lastchange"], "limit": 50, "sortfield": "lastchange", "sortorder": "DESC"}
        if host_filter:
            params["hostids"] = host_filter
        res = self._request("trigger.get", params)
        return res if isinstance(res, list) else []