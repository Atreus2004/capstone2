# FIM Agent

A file integrity monitoring (FIM) agent that builds a cryptographic baseline of important files, watches for realtime changes, and enriches events with content inspection, MITRE-style tagging, and AI-assisted risk analysis.

## Key features
- **Baseline hashing:** Hashes monitored directories and stores digests in SQLite for later comparison, respecting directory/extension exclusions defined in the config.【F:fim_agent/core/hasher.py†L12-L64】【F:fim_agent/core/config.py†L15-L58】
- **Realtime watcher:** Uses `watchdog` to track create/modify/delete/move events, correlates moves, and updates the baseline accordingly.【F:fim_agent/core/watcher.py†L42-L206】【F:fim_agent/core/watcher.py†L230-L307】
- **Risk scoring and alerting:** Computes severity, risk scores, MITRE-style tags, and flags alerts when risk thresholds are met.【F:fim_agent/core/events.py†L17-L120】【F:fim_agent/core/watcher.py†L296-L320】
- **Content and AI analysis:** Performs lightweight content inspection, rule-based AI classification, and optionally calls OpenAI for deeper review of interesting events.【F:fim_agent/core/watcher.py†L268-L320】【F:fim_agent/core/watcher.py†L322-L343】
- **Admin approval workflow:** Marks tamper-sensitive actions for admin approval and surfaces pending approvals in logs and the web UI (password provided via environment variable).【F:fim_agent/core/watcher.py†L320-L333】【F:fim_agent/web/api.py†L64-L132】
- **Logging options:** Supports JSON, text, and Wazuh-compatible log formats with file-based logging configured from YAML.【F:fim_agent/core/cli/main.py†L13-L96】
- **Web API:** FastAPI server exposes event queries, statistics, and admin approval endpoints secured by an optional dashboard password.【F:fim_agent/web/api.py†L17-L185】
- **Timeline reporting:** CLI timeline command prints chronological events with filtering by severity, path, and date ranges from the SQLite store.【F:fim_agent/cli/main.py†L99-L162】

## Setup
1. Install dependencies (ideally in a virtual environment):
   ```bash
   pip install -r requirements.txt
   ```
2. Copy the example config and adjust paths for your environment:
   ```bash
   cp config/config_example.yaml config/config.yaml
   ```
3. Optional: set a dashboard/admin password for approving high-risk events in the web UI:
   ```bash
   export FIM_DASHBOARD_PASSWORD="your-strong-password"
   # or use FIM_ADMIN_PASSWORD as configured in the YAML
   ```

## Configuration
Key settings in `config/config.yaml` (see `config/config_example.yaml` for defaults):
- `monitored_directories`: list of directories to hash and watch.
- `exclude_directories` / `exclude_extensions`: paths and extensions to ignore.
- `database_path`: SQLite file for baselines/events.
- `log_file` and `log_format`: output location and format (`json`, `text`, or `wazuh`).
- `alert_min_risk_score` / `alert_min_ai_risk_score`: thresholds that mark events as alerts.
- `require_admin_for_alerts`, `admin_min_risk_score`, `admin_min_ai_risk_score`, `admin_password_env_var`: control when admin approval is required and how passwords are supplied.
【F:config/config_example.yaml†L1-L34】【F:fim_agent/core/config.py†L15-L58】

## CLI usage
Run commands from the project root:

- Initialize the baseline (hash all monitored files):
  ```bash
  python -m fim_agent.cli.main init-baseline
  ```
- Start the realtime agent (prints/logs events as they occur):
  ```bash
  python -m fim_agent.cli.main run-agent
  ```
- View event timeline with optional filters:
  ```bash
  python -m fim_agent.cli.main timeline --severity high --path-filter /etc
  ```
- Launch the web API server:
  ```bash
  python -m fim_agent.cli.main serve-web --host 0.0.0.0 --port 8000
  ```
【F:fim_agent/cli/main.py†L19-L167】

### Windows/PowerShell quick start
If you're running the agent from Windows with PowerShell, you can set environment variables and launch the agent and web server with:

```powershell
py -m fim_agent.cli.main --config config\config.yaml run-agent
$env:FIM_ADMIN_PASSWORD      = "Secret123!"
$env:FIM_DASHBOARD_PASSWORD  = "Secret123!"
$env:OPENAI_API_KEY="fLOLostkwd0P_fVkkl0NEIIu87sHUkH_aX5eep87q_ZcbX2mc_FS2r6K3O5XI1_HhcT3BlbkFJlrI0GmytOjelYwYLSgcMTmwRa6abT7HxKJns2SbQMssv72yty5BQuEkOFrBr7vL_ezZw_dbx0A"
py -m fim_agent.cli.main --config config\config.yaml serve-web --host 0.0.0.0 --port 8000
```

## Web API highlights
Start the API with `serve-web` and browse `/docs` for interactive documentation. Core endpoints include:
- `GET /api/events`: list events with filters for severity, classification, risk scores, path substring, pagination, and admin-approval flags.
- `GET /api/events/{id}`: fetch a single event by database ID.
- `POST /api/events/{id}/approve`: approve pending events (requires dashboard/admin password if configured).
- `GET /api/stats/summary`: retrieve aggregate event counts for dashboards.
Auth is enforced only when `FIM_DASHBOARD_PASSWORD` (or the configured admin env var) is set; otherwise authentication is skipped for local use.【F:fim_agent/web/api.py†L33-L135】【F:fim_agent/web/api.py†L156-L185】

## Operational notes
- Events marked as alerts or requiring admin approval are logged with their approval status; approvals are handled through the web UI rather than the CLI.【F:fim_agent/cli/main.py†L67-L117】
- High-risk executable drops, tamper events, and moves into monitored areas are automatically scored higher and may demand admin approval depending on thresholds.【F:fim_agent/core/events.py†L53-L120】【F:fim_agent/core/watcher.py†L230-L333】
- Baseline and event data live in SQLite (`data/fim.sqlite3` by default); logs default to `logs/fim_agent.log`.

## Development
- Run the watcher and web API locally using the CLI commands above.
- Tests (where present) can be executed with `pytest`.
