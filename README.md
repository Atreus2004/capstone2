# FIM Agent – File Integrity Monitoring

A lightweight file integrity monitoring (FIM) agent that builds a baseline of monitored directories, watches for changes in real time, scores risk, and can escalate alerts to a small FastAPI-powered web UI for review.

## Features
- **Baseline creation**: Hashes all files in configured directories so later changes can be compared against the known-good state (`init-baseline`).
- **Real-time monitoring**: Uses `watchdog` observers to emit events for creates, modifies, deletes, renames, and moves inside monitored directories (`run-agent`).
- **Risk scoring & severity**: Applies rule-based risk scoring, severity mapping, and MITRE-style tags to every event, boosting scores for high-risk extensions, sensitive locations, and content inspection results.【F:fim_agent/core/events.py†L39-L121】【F:fim_agent/core/content_inspector.py†L10-L123】
- **Content inspection**: Performs lightweight static inspection (keywords, suspicious extensions, base64 blobs, entropy heuristics) and classifies content as public/internal/private/secret with matched indicators.【F:fim_agent/core/content_inspector.py†L10-L164】
- **AI enrichment (optional)**: If `OPENAI_API_KEY` is set, high-risk events are summarized with an AI classification, risk score, and remediation guidance.【F:fim_agent/core/ai_client.py†L1-L91】
- **Governance controls**: Marks sensitive tamper events as alerts and can require admin approval for risky changes depending on thresholds and prior history.【F:fim_agent/core/governance.py†L1-L205】
- **Alerting & logging**: Writes JSON/text/Wazuh-style logs, flags alerts based on configurable thresholds, and stores all events in SQLite for later review.【F:fim_agent/cli/main.py†L60-L134】【F:fim_agent/core/storage.py†L1-L180】
- **Timeline queries**: Query historical events from SQLite via CLI or the REST API with filters for severity, path, risk, and admin-approval state.【F:fim_agent/cli/main.py†L98-L157】【F:fim_agent/web/api.py†L41-L139】
- **Web dashboard & approvals**: FastAPI app serves recent events, stats, and an approval endpoint; optional cookie auth gates the dashboard when `FIM_DASHBOARD_PASSWORD` is set.【F:fim_agent/web/api.py†L17-L154】

## Quickstart
1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Create a configuration file**
   Create `config/config.yaml` (the agent falls back to `config/config_example.yaml` if present) with at least:
   ```yaml
   monitored_directories:
     - ./watched
   exclude_directories: []
   exclude_extensions: []
   database_path: ./data/fim.sqlite3
   log_file: ./logs/fim_agent.log
   log_format: json  # json | text | wazuh
   alert_min_risk_score: 70
   alert_min_ai_risk_score: 70
   require_admin_for_alerts: true
   admin_min_risk_score: 80
   admin_min_ai_risk_score: 75
   admin_password_env_var: FIM_ADMIN_PASSWORD
   ```

3. **Build the baseline**
   ```bash
   python -m fim_agent.cli.main init-baseline --config config/config.yaml
   ```

4. **Run the agent**
   ```bash
   python -m fim_agent.cli.main run-agent --config config/config.yaml
   ```
   - Events are logged to the configured file and stored in SQLite.
   - Admin approval prompts appear only in the web UI; set `FIM_ADMIN_PASSWORD` or `FIM_DASHBOARD_PASSWORD` to enable approvals.

5. **Review history**
   - CLI timeline:
     ```bash
     python -m fim_agent.cli.main timeline --severity high --path-filter /watched
     ```
   - REST API and docs (FastAPI + Swagger):
     ```bash
     python -m fim_agent.cli.main serve-web --host 0.0.0.0 --port 8000
     # Visit http://localhost:8000/docs
     ```

6. **Enable AI enrichment (optional)**
   ```bash
   export OPENAI_API_KEY="sk-..."
   ```
   High-risk events will be sent for AI classification and remediation suggestions.

## Project layout
- `fim_agent/core/` – configuration, hashing/baseline, watcher, governance rules, content inspection, and storage.
- `fim_agent/cli/` – CLI commands for baseline creation, runtime monitoring, and timeline queries.
- `fim_agent/web/` – FastAPI application exposing the REST API, dashboard auth, and admin approval endpoints.
- `tests/` – Unit tests for hashing, event handling, and AI client plumbing.
- `data/` and `logs/` – Default locations for the SQLite event store and log output (created automatically).

## Testing
Run the automated suite with:
```bash
pytest
```

> **Note:** Some tests currently fail around AI client mocking and admin-approval alert expectations. Investigate `tests/test_ai_client.py` and `tests/test_events.py` for details before shipping to production.
