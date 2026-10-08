# Native security and operations features

This workspace works with this dashboard's own collected signals. The newly added vendor adapters and Connector hub have been removed. Existing integrations from before that addition are unchanged.

## Investigate and hand over

- **Incident inbox:** collect the latest 500 local threshold alerts, suppress duplicates, search incidents and filter by status. Repeated collection updates existing evidence without inflating counts.
- **Anomaly insights:** explain CPU and memory spikes using a median baseline and median absolute deviation over 12–60 prior samples. The latest sample must be no older than 15 minutes, and increases must exceed at least 15 percentage points. Add findings to the incident inbox when useful.
- **Operations brief:** rank open investigations, explain every priority score, suggest investigation steps and download a plain-text handover checklist. Uses the latest 2,000 incidents and displays the top 50 open investigations; limits are visible. Scores are a triage aid, not threat probabilities.
- **Investigation workflow:** assign an owner, add notes, move from new to investigating to resolved, and review the actor-attributed timeline. Known assets with matching categories are grouped within 24 hours of incident creation; unknown assets remain separate. Grouping is a heuristic, not a root-cause verdict.
- **Team access:** individual viewer, analyst and administrator keys, shown once, stored as hashes and immediately revocable on subsequent requests.
- **Activity audit:** latest 500 API mutation attempts, including denied changes, excluding routine agent submissions. Keys and request bodies are excluded. This is a local record, not a tamper-proof archive.

## Priority calculation

Severity contributes 5/15/35/60/80 points for informational/low/medium/high/critical. Unassigned incidents add 10; at least three signals add 5; incidents open for at least 24 hours add 5. Scores are capped at 100. Resolving an incident removes it from the queue; assigning an owner removes the assignment penalty. Equal scores put older incidents first. Suggested steps are rule-based guidance, not automated remediation.

## Access and storage

Unlock with the bootstrap master_api_key from config.json, then create named keys in Team access. Viewers read; analysts collect local signals and update investigations; administrators also manage keys and existing system operations. All security endpoints require authentication. Existing operational reads follow require_auth_for_reads. Keys stay in tab memory and are cleared on reload. No SSO, MFA, password login or per-host isolation is implemented.

Security history lives in the local SQLite soc_* tables and has manual retention, separate from metric retention. Existing evidence is preserved when adapters are removed. Inbox results are limited to 200 matching incidents; details contain the latest 500 events and timeline entries. Reports contain operational data and are downloaded only on request. No vendor credentials are needed for these features.

## Validation

Backend tests cover permissions, revocation, deduplication, grouping, anomaly baselines, removed adapter routes and priority recalculation. Browser checks cover evidence escaping, incident updates, key clearing, operations-brief downloads and mobile layout. These native features do not reproduce proprietary endpoint prevention engines.

## Native detection rules

Open Detections to evaluate the latest 10,000 traffic records in a rolling 15-minute window. The initial rules flag 10 HTTP 401/403 responses, 20 distinct destination ports, or 20 HTTP 500–599 responses per host and observed source IP. Administrators can enable/disable each rule and set a threshold from 2 to 10,000; changes are stored locally and audited. Analysts can save matching findings to incidents. Viewers can inspect results.

Checks are on demand when the page opens/refreshes or findings are saved, not a background detection service. Saving re-evaluates current data. Stable identifiers include rule, host, observed source and the newest evidence's 15-minute bucket; repeated saves in the same bucket update evidence. A new bucket can create a new event. Findings retain up to 20 evidence record IDs; traffic retention can later remove those records.

Missing traffic is shown explicitly. HTTP rules require real status codes and cannot infer login failures from encrypted packets or status 0. Port diversity is not proof of a scan, and observed source addresses can represent NAT/proxy traffic. Denials may be expired sessions; server errors may be ordinary outages. Thresholds are initial heuristics, not validated threat models. Nothing is automatically blocked, killed or quarantined. Endpoint malware scanning and prevention are not implemented.
