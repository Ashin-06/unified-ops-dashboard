# v16 update

## Interface

- Replaced the monolithic dashboard with a responsive operations workspace and local CSS/JavaScript/SVG assets.
- Added dark mode, explicit loading/error/empty states, pause/resume, CSV export, host filtering, and persistent theme preference.
- Added server comparison, service status, searchable process/network views, log-file selection and rule-based summaries.
- Escaped API-provided content and neutralized CSV formula prefixes.
- Added keyboard focus styles, labeled controls, a skip link, and native confirmation dialogs.

## Correctness and reliability

- Unified portable configuration and corrected mismatched integration credentials and performance settings.
- Fixed remote process metric field names and sorting, local-host alert filtering, and UTC history filtering.
- Closed SQLite connections deterministically, retained failed batches for retry, bounded the queue, and surfaced immediate write failures.
- Added collector shutdown and final database flushing; moved blocking API work off the asynchronous request loop where applicable.
- Made alert-setting persistence atomic without writing environment-provided secrets into configuration.

## Access and setup

- Required bearer authentication for administrative actions and added optional read authentication.
- Generated random installation keys; rejected known placeholder keys; validated agent metrics, thresholds, limits and port lists.
- Enabled certificate verification by default and bound the dashboard to loopback by default.
- Disabled packet capture by default and moved Scapy into an optional dependency file.
- Removed mandatory administrator elevation from the Windows launcher.
- Added regression tests and a Windows/Linux CI matrix, plus current setup and migration instructions.

## Validation and limits

40 regression cases pass locally. Frontend syntax and Git whitespace checks pass. Browser checks cover real local monitoring data; external Wazuh, Zabbix, Grafana and remote-agent deployments require credentials and infrastructure to validate end to end. CI is provided but has not been run on GitHub. The application uses one shared operator key, not per-user roles.


## Website completeness update

Added workspace search (Ctrl/Cmd+K), Help/About, Privacy, browser preferences, pagination, session controls, offline/retry handling, mobile keyboard fixes, print styling, no-JavaScript messaging, and custom 404 pages. Validation now includes 63 Python cases and browser coverage for the new flows. See AUDIT.md for the final audit summary and deployment limitations.

## Native investigation extension

- Added incident deduplication, local signal grouping, assignment, notes and timelines.
- Added explainable CPU/memory anomaly findings and collection of local alerts.
- Added named viewer/analyst/admin keys, revocation and a mutation audit.
- Added an Operations brief with explained priority scores, next steps and a downloadable handover.
- Removed the newly added seven vendor adapters, Connector hub and their configuration.
- Corrected a deferred-script startup race and added native workflow regression coverage.

## Native detections

- Added HTTP denial bursts, destination-port diversity and HTTP server-error rules over collected traffic.
- Added administrator rule tuning, evidence references, coverage warnings and deduplicated incident saving.
- Added permission, threshold, stale-data and repeated-run regression tests.
