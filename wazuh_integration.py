#!/usr/bin/env python3
"""
Wazuh Integration v2.3
======================
- FIX: get_dashboard_stats now returns safe default values on failure.
- FIX: Prevents "Cannot read properties of undefined" frontend crash.
- FIX: Auto-detects correct login endpoint (Wazuh 3.x vs 4.x).
"""
import logging
import json
import base64

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None
    HAS_HTTPX = False

logger = logging.getLogger("ServerMonitor")

class WazuhAPI:
    def __init__(self, cfg: dict):
        self.cfg = cfg or {}
        # Clean up URL: remove trailing slashes
        url = self.cfg.get('wazuh_url', '').rstrip('/')
        # If user accidentally put /api/x at the end, strip it slightly to find base
        if url.endswith('/api'):
            url = url[:-4]
        self.base = url
        
        self.user = self.cfg.get('wazuh_user') or self.cfg.get('username')
        self.password = self.cfg.get('wazuh_password') or self.cfg.get('password')
        self.verify_ssl = self.cfg.get('verify_ssl', True) # Default to False for self-signed
        self.token = None
        self.enabled = self.cfg.get('enabled', False) and bool(self.base)

    def _get_headers(self):
        h = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        if self.token:
            h['Authorization'] = f'Bearer {self.token}'
        return h

    def login(self):
        if not HAS_HTTPX:
            raise RuntimeError("Missing 'httpx' library. Run: pip install httpx")
        
        if not self.user or not self.password:
            raise RuntimeError("Wazuh credentials missing in config.json")

        # List of known auth endpoints for different Wazuh versions
        # 1. /security/user/authenticate (Wazuh 4.x)
        # 2. /security/authenticate (Older versions)
        # 3. /jwt/login (Some specific configs)
        candidates = [
            "/security/user/authenticate",
            "/security/authenticate",
            "/jwt/login"
        ]
        
        last_error = None
        
        for endpoint in candidates:
            try:
                # Basic Auth is required to get the JWT
                r = httpx.post(
                    f"{self.base}{endpoint}",
                    auth=(self.user, self.password),
                    verify=self.verify_ssl,
                    timeout=5.0, # Short timeout to avoid UI lag
                    headers={'Content-Type': 'application/json'}
                )
                
                if r.status_code == 200:
                    data = r.json()
                    # Token extraction logic
                    if 'data' in data and isinstance(data['data'], dict) and 'token' in data['data']:
                        self.token = data['data']['token']
                        return
                    elif 'token' in data:
                        self.token = data['token']
                        return
                    elif 'data' in data and isinstance(data['data'], str):
                        # Sometimes data IS the token
                        self.token = data['data'].strip()
                        return
            except Exception as e:
                last_error = e
                # Continue to next candidate
        
        if last_error:
            raise RuntimeError(f"Wazuh Login Failed (Connection Error): {str(last_error)}")
        raise RuntimeError("Wazuh Login Failed: Invalid credentials or URL path.")

    def _request(self, method, endpoint, params=None):
        if not self.enabled:
            return {"error": "Wazuh disabled"}
        
        if not self.token:
            try:
                self.login()
            except Exception as e:
                return {"error": str(e)}

        url = f"{self.base}{endpoint}"
        
        try:
            r = httpx.request(
                method, 
                url, 
                headers=self._get_headers(), 
                params=params, 
                verify=self.verify_ssl, 
                timeout=8.0
            )
            
            # If 401, token expired. Refresh and retry once.
            if r.status_code == 401:
                self.login()
                r = httpx.request(
                    method, 
                    url, 
                    headers=self._get_headers(), 
                    params=params, 
                    verify=self.verify_ssl, 
                    timeout=8.0
                )
            
            if r.status_code != 200:
                return {"error": f"API Error {r.status_code}", "detail": r.text}
            
            return r.json()
            
        except Exception as e:
            return {"error": "Connection Error", "detail": str(e)}

    def get_dashboard_stats(self):
        # Default safe response structure
        safe_response = {
            "enabled": self.enabled,
            "status": "unknown",
            "agents": {"total": 0, "active": 0, "disconnected": 0},
            "sca": {"policies": 0, "passed": 0, "failed": 0}
        }

        if not self.enabled:
            safe_response["status"] = "disabled"
            return safe_response
        
        # We query agents summary to check system health
        res = self._request("GET", "/agents/summary/status")
        
        if "error" in res:
            safe_response["status"] = "error"
            safe_response["message"] = res.get("detail") or res.get("error")
            return safe_response
            
        data = res.get("data", {})
        
        # Populate with real data
        safe_response["status"] = "connected"
        safe_response["agents"]["total"] = data.get("total", 0)
        safe_response["agents"]["active"] = data.get("active", 0)
        safe_response["agents"]["disconnected"] = data.get("disconnected", 0)
        
        return safe_response

    def get_agents(self):
        res = self._request("GET", "/agents")
        if "error" in res:
            return [{"id": "err", "name": "Error", "ip": "0.0.0.0", "status": "error", "version": res["error"]}]
        
        # Standard Wazuh response: { data: { affected_items: [...] } }
        items = res.get("data", {}).get("affected_items", [])
        return items

    def get_recent_alerts(self, agent_id=None):
        # Note: Not all Wazuh API installs support direct alert querying without Elastic/Indexer.
        # This endpoint works if the manager API is configured to read alerts.json
        endpoint = "/alerts"
        params = {"limit": 10}
        if agent_id and agent_id != 'all':
            params['agents_list'] = agent_id

        res = self._request("GET", endpoint, params=params)
        
        if "error" in res:
            # Return empty list on error to prevent UI issues
            return []
            
        return res.get("data", {}).get("affected_items", [])