# Unified Ops Dashboard

A self-hosted operations workspace for live system metrics, server health, alerts, processes, logs, and Wazuh, Zabbix, and Grafana integrations.

The v16 interface includes responsive navigation, light/dark themes, local SVG charts, search, CSV reports, explicit stale/error states, and authenticated operator actions. No frontend build step, fonts, or chart CDNs are required.

## Quick start

Requires **Python 3.10+**. Windows is the primary supported platform; resource monitoring also works on Linux and macOS. Windows services are Windows-only.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python main.py
```

Open **http://127.0.0.1:8081**. On Windows, subsequent launches can use `start_dashboard.bat`. The launcher does not request administrator access.

On Linux/macOS, use `.venv/bin/python` instead. A single application process is required: multiple workers would each run a collector.

At first start, the application generates a random `master_api_key` in `config.json`. Data lives in `Data/monitor.db`; logs live in `Logs/monitor.log`, beside the application. These files are ignored by Git. History is collected over time; the dashboard does not create sample infrastructure or synthetic metrics.

## Configuration

Optionally copy `config.example.json` to `config.json` **before first launch**, or merge its settings into an existing configuration. A missing key is generated automatically. Do not overwrite an existing key after enrolling agents.

- `web_host` / `web_port`: default `127.0.0.1:8081`.
- `performance.frontend_poll_interval`: seconds between UI refreshes; minimum 5.
- `performance.metric_collection_interval`: seconds between resource samples.
- `performance.enable_packet_sniffing`: defaults to `false`.
- `alerts`: CPU, memory, disk thresholds and repeat-alert cooldown.
- `retention_days`: history retention, default 7 days.
- `agents`: remote hostnames, URLs and API keys.
- `log_files_to_analyze`: friendly-name-to-path mapping.
- `integrations`: tool URLs and credentials. Explicitly enable each tool.

Environment overrides:

| Variable | Purpose |
| --- | --- |
| `OPS_DATA_DIR` | Alternate directory for the master database and logs |
| `OPS_CONFIG` | Explicit path to the master configuration |
| `OPS_API_KEY` | Override the master API key for this process |

Relative database/log paths resolve under `OPS_DATA_DIR` (or the application directory). Invalid JSON fails explicitly instead of silently using defaults.

### Operator access

Opening the local dashboard is read-only until you unlock an operator session in **Settings** using the key from `config.json`. The key stays in browser memory and is discarded on reload. All API mutations require `Authorization: Bearer <key>`, including alert changes, clearing alerts, process termination, port scans, and agent submissions. Known placeholder keys are rejected.

For access beyond your own machine, use TLS through a reverse proxy, set `require_auth_for_reads` to `true`, and restrict network access. The HTML shell stays public so the Settings unlock flow works. Read-only access exposes system and log information when this option is false. The app has a shared operator key, not individual user accounts or role-based authorization.

### Remote agents

On each monitored host, copy `agent_config.example.json` to `agent_config.json`, set `master_url`, a unique `hostname`, and the master's key. Install the dependencies and run:

```powershell
python agent.py
```

On the master, add the host to `config.json`, then restart:

```json
{
  "agents": [
    {"hostname": "server-01", "url": "http://192.168.1.10:8082", "api_key": "YOUR_GENERATED_MASTER_KEY"}
  ]
}
```

The agent listens on port 8082 and authenticates its endpoints. Restrict it to the master using network controls. Use HTTPS for traffic across untrusted networks. Agent certificates are verified by default; `verify_agent_ssl: false` is an explicit opt-out for a trusted test environment.

### Integrations

Use `username` and `password` in the example configuration. The older `wazuh_user` / `wazuh_password` and `zabbix_user` / `zabbix_password` keys remain supported. Configure trusted certificates; TLS verification is enabled by default. Integration cards distinguish configured tools from successful connectivity checks. Grafana opens its configured dashboard in a new tab. Wazuh alert retrieval depends on manager API support; some deployments require an indexer integration that this project does not implement.

### Optional packet capture

```powershell
python -m pip install -r requirements-capture.txt
```

Enable capture explicitly in the master or agent configuration. Windows requires Npcap; elevated capture permissions may be needed. Captured traffic is packet metadata and readable HTTP data. It does not decrypt HTTPS. Ordinary metrics and the dashboard do not require capture privileges.

## Workspace views

- **Overview:** live metrics, CPU/memory history, network rates, server freshness, recent alerts.
- **Servers:** host status and resource comparison for up to 20 hosts.
- **Processes:** CPU/memory sorting, search, and confirmed authenticated termination.
- **Services:** configured Windows service status.
- **Connections / Traffic:** searchable network and captured-request records.
- **Alerts:** host-scoped signals, CSV export, and confirmed clearing.
- **Logs:** file selection, level/search filters, and rule-based log summaries.
- **Integrations:** connectivity summaries and links to configured tools.
- **Port scanner:** validated and authenticated checks on authorized targets.
- **Settings:** alert thresholds and operator-session controls.

Live refresh can be paused and stops while the tab is hidden. Settings and scan forms are not replaced by background polling. Failed updates retain the last successful view and label it stale. CSV exports neutralize spreadsheet formula prefixes.

## Validation

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
node --check static/dashboard.js
```

Node is only needed for the optional JavaScript syntax check. Tests use an isolated temporary configuration and database; no actual processes are terminated or external hosts scanned. Coverage includes API authentication, validation, agent metrics, host filtering, UTC history, database retries, TLS defaults, and remote process compatibility.

## Migration from v15

Old installations read configuration from `C:\ProgramData\ServerMonitor` or `/opt/server_monitor`. Set `OPS_DATA_DIR` to that directory to continue using its data, or copy your configuration and database into this project deliberately. Review the example for the supported performance setting names. Administrative API calls now require authentication. Bind address defaults to loopback; remote access must be configured intentionally. Scapy is optional and capture is off by default. The browser UI is now split into `index.html`, `static/dashboard.css`, and `static/dashboard.js`; the old `templates/index.html` is not served.

## Project layout

`main.py` serves the FastAPI application; `monitor.py` collects data; `database.py` manages SQLite and retryable batches; `settings.py` resolves configuration; `schemas.py` validates requests; `agent.py` runs on remote hosts. Integration clients are in `wazuh_integration.py` and `zabbix_integration.py`.

Licensed under MIT. See `LICENSE`.

## Audit follow-up

See `AUDIT.md` for the follow-up findings, fixes, validation, and remaining deployment limits. The regression suite now has 63 cases. An optional browser audit is available at `tests/browser_audit.cjs`; it requires Playwright and a running local dashboard. It uses intercepted data to verify host changes and stale responses without terminating processes.


## Everyday website features

- Search pages and servers with the header search button or Ctrl/Cmd+K.
- Help & about provides onboarding, troubleshooting, keyboard hints and a source-project link.
- Privacy explains local storage, collected data, configured integrations and exports.
- Settings includes browser-only appearance, refresh interval and page-size preferences, plus reset controls. History range is remembered too.
- Long lists have previous/next pagination; search and CSV export cover all fetched matching records, not just the visible page.
- Operator access and session locking are available in the header.
- Connection loss has a visible notice and retry control; automatic reconnect refreshes available data.
- Mobile navigation is removed from keyboard focus when closed. Dialog labels, skip navigation, print styles, no-JavaScript guidance and a useful 404 page are included.
- Search-engine indexing is disabled for this private operations workspace.

Optional browser checks: `node tests/browser_website.cjs` and `node tests/browser_audit.cjs` (Playwright and Microsoft Edge required; run the dashboard first). Python verification: `python -m pytest`. Both browser scripts use isolated browser sessions.

## Native investigation workspace

Incident inbox, Anomaly insights, Operations brief, Team access and Activity audit work with the dashboard's own data. Investigate grouped local signals, use an explained priority queue, assign owners and download handover reports. See [SECURITY_WORKSPACE.md](SECURITY_WORKSPACE.md) for usage and limits. Newly introduced vendor adapters have been removed.

Run `python -m pytest -q` for backend tests. Browser suites: `tests/browser_audit.cjs`, `tests/browser_website.cjs`, `tests/browser_security.cjs` (Playwright with Edge and the local server on port 8081).

Native **Detections** adds explainable traffic-pattern rules, adjustable thresholds, evidence references and deduplicated incident creation. See SECURITY_WORKSPACE.md for coverage requirements and limitations.
