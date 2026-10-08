# Audit and fixes — 2026-10-08

This audit covers the local v16 application, remote-agent code, browser workflows, and database handling. All findings below were corrected locally.

| Priority | Finding | Resolution |
| --- | --- | --- |
| High | Changing servers left previous process controls visible; an action could target the wrong server's PID. | Clear scoped data immediately, bind actions to the rendered host, and reject responses from an earlier selection. |
| High | Unvalidated traffic fields could poison the shared database batch queue. | Validate complete batches, restrict sizes/types/timestamps, and commit traffic uploads atomically before acknowledging them. |
| High | Agent traffic was discarded before the master acknowledged delivery. | Keep failed batches and retry; dequeue only after successful acknowledgment. |
| High | Terminating a parent process tree could terminate the dashboard/agent itself. | Protect the current process and its ancestors for tree termination. |
| Medium | Remote metric submissions did not trigger threshold alerts. | Evaluate thresholds with the submitting hostname. |
| Medium | Saved remote metrics looked like live readings; remote 404/error bodies could be treated as valid data. | Mark stored metrics explicitly and reject HTTP errors or invalid JSON before falling back. |
| Medium | Health checks ignored database failures. | Probe storage and expose failed writes and queue depth; show degraded health in the UI. |
| Medium | Non-ASCII bearer values could raise an unhandled comparison error. | Compare encoded token bytes and return authentication failures cleanly. |
| Medium | Repeated startup/shutdown reused closed clients; agent background threads did not stop. | Recreate closed clients, restart the writer safely, and stop agent workers on shutdown. |
| Medium | Remote port scans ran sequentially and could outlast the proxy timeout. | Use bounded concurrency and handle DNS failures explicitly. |

## Verification

- **63 Python regression cases passed**, including audit cases and website fallback checks.
- Browser regression cases passed for host-bound actions, failed-host isolation, delayed responses, safe exports and HTML escaping.
- Full browser smoke checks passed for navigation, search, sorting, comparison, log analysis, confirmation cancellation, authentication, themes, mobile navigation, CSV export and error recovery. No JavaScript page errors were observed.
- JavaScript syntax and Git whitespace checks passed.
- Tests use temporary databases, mocks and intercepted browser requests for destructive operations. No real processes were terminated by test actions and no external hosts were scanned.

## Remaining deployment limits

External Wazuh/Zabbix/Grafana installations and real remote hosts still require end-to-end checks with their configuration. Named viewer, analyst and administrator keys are supported; the bootstrap key remains an administrator credential. Metric writes remain buffered in memory and can be lost on abrupt process failure. Traffic retries may duplicate a batch if the master commits it but the acknowledgment is lost; this is not an exactly-once delivery system. Capture buffers are bounded and can drop newly captured packets during a prolonged outage. The existing test environment emits one upstream Starlette/httpx deprecation warning.

The source archive excludes runtime keys, configuration, logs and collected telemetry.


## Website completeness follow-up

Added searchable navigation, Help/About and Privacy views, persistent display preferences, table pagination, header session controls, offline/retry behavior, keyboard-accessible mobile navigation, native labeled dialogs, print styles, JavaScript-disabled guidance, and HTML/API-appropriate 404 responses. Browser checks passed for these additions, persisted settings across reload, preference reset, mobile overflow, and the previous audit regressions. The full operations smoke suite also passed without JavaScript errors.

## Native investigation validation

Regression coverage includes roles/revocation, audit redaction, deduplication/grouping, anomaly baselines, removal of vendor adapter endpoints, and Operations brief ranking/recalculation. Browser coverage checks safe evidence, investigation forms, one-time key clearing, brief downloads and responsive navigation. Startup initializes after deferred scripts load.

The newly added vendor adapters and connector hub are removed. Local security history remains intact and has manual retention. The activity audit is not tamper-proof. See SECURITY_WORKSPACE.md for feature boundaries.

## Detection validation

Detection tests cover evidence, deduplication, rule tuning, stale/missing HTTP data and permissions. Storage-error regressions cover failed reads, failed audit writes and preserved access denial. Detection timestamps are ordered by actual UTC time.

Final local verification: 75 backend tests passed. All three browser suites and the full operations smoke check passed against the restarted application. JavaScript syntax checks and Git whitespace checks passed. An earlier run was interrupted by a full C: drive; the final run succeeded after storage became available. Maintain free disk space for telemetry and audit persistence. One upstream Starlette/httpx deprecation warning remains.
