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

### JSON logging (JSON Lines)
All application logs are emitted as JSON when `log_format` is set to `json` in `config/config.yaml` (default). Logs are written to the file specified by `log_file` and also streamed to stdout with the same structured format.【F:config/config.yaml†L21-L29】【F:fim_agent/core/logging_utils.py†L195-L217】

Example `config/config.yaml` snippet:

```yaml
log_file: "./logs/fim_agent.log"
log_format: "json"
```

Enable JSON logging before starting the agent/web server:

- Bash (Linux/macOS):
  ```bash
  # ensure the config uses JSON format
  sed -n '21,40p' config/config.yaml

  python -m fim_agent.cli.main --config config/config.yaml run-agent
  python -m fim_agent.cli.main --config config/config.yaml serve-web --host 0.0.0.0 --port 8000
  ```
- PowerShell (Windows):
  ```powershell
  # ensure the config uses JSON format
  Get-Content -Path config/config.yaml -TotalCount 20

  py -m fim_agent.cli.main --config config\config.yaml run-agent
  py -m fim_agent.cli.main --config config\config.yaml serve-web --host 0.0.0.0 --port 8000
  ```

Verification (JSON Lines): view a few lines to confirm each line is a JSON object.

- Bash:
  ```bash
  tail -n 5 logs/fim_agent.log
  ```
- PowerShell:
  ```powershell
  Get-Content -Path logs/fim_agent.log -Tail 5
  ```

## CLI usage
Run commands from the project root with a valid `config/config.yaml` in place.【F:fim_agent/cli/main.py†L19-L167】

### Example environment (Codespaces / Linux Bash)
Commands in this README mirror a typical GitHub Codespaces or devcontainer shell prompt such as `/workspaces/<repo>` on Linux Bash. Paths use forward slashes and assume the repo root as the working directory.

### Linux/macOS (Bash/Zsh)
```bash
export FIM_DASHBOARD_PASSWORD="your-strong-password"
export FIM_ADMIN_PASSWORD="your-strong-password"
export OPENAI_API_KEY="your-openai-api-key"

python -m fim_agent.cli.main --config config/config.yaml init-baseline
python -m fim_agent.cli.main --config config/config.yaml run-agent
python -m fim_agent.cli.main --config config/config.yaml timeline --severity high --path-filter /etc
python -m fim_agent.cli.main --config config/config.yaml serve-web --host 0.0.0.0 --port 8000
```

### Windows (PowerShell)
```powershell
$env:FIM_DASHBOARD_PASSWORD = "your-strong-password"
$env:FIM_ADMIN_PASSWORD     = "your-strong-password"
$env:OPENAI_API_KEY         = "your-openai-api-key"

py -m fim_agent.cli.main --config config\config.yaml init-baseline
py -m fim_agent.cli.main --config config\config.yaml run-agent
py -m fim_agent.cli.main --config config\config.yaml timeline --severity high --path-filter C:\\Windows
py -m fim_agent.cli.main --config config\config.yaml serve-web --host 0.0.0.0 --port 8000
```

### Other environments

#### Windows (CMD)
```bat
set FIM_DASHBOARD_PASSWORD=your-strong-password
set FIM_ADMIN_PASSWORD=your-strong-password
set OPENAI_API_KEY=your-openai-api-key

py -m fim_agent.cli.main --config config\config.yaml init-baseline
py -m fim_agent.cli.main --config config\config.yaml run-agent
py -m fim_agent.cli.main --config config\config.yaml timeline --severity high --path-filter C:\Windows
py -m fim_agent.cli.main --config config\config.yaml serve-web --host 0.0.0.0 --port 8000
```

#### Fish shell
```fish
set -x FIM_DASHBOARD_PASSWORD "your-strong-password"
set -x FIM_ADMIN_PASSWORD "your-strong-password"
set -x OPENAI_API_KEY "your-openai-api-key"

python -m fim_agent.cli.main --config config/config.yaml init-baseline
python -m fim_agent.cli.main --config config/config.yaml run-agent
python -m fim_agent.cli.main --config config/config.yaml timeline --severity high --path-filter /etc
python -m fim_agent.cli.main --config config/config.yaml serve-web --host 0.0.0.0 --port 8000
```

Security reminder: Never commit API keys; keep credentials in environment variables or a secrets manager.

## Run everything with one command

Start both the agent and web server in the background with a single call, keeping the shell alive so logs can stream and you can stop everything with Ctrl+C.

### Bash (Linux / macOS / Codespaces)

One-liner that sets env vars, starts both processes, and waits:

```bash
FIM_DASHBOARD_PASSWORD="your-strong-password" \
FIM_ADMIN_PASSWORD="your-strong-password" \
OPENAI_API_KEY="your-openai-api-key" \
bash -c "python -m fim_agent.cli.main --config config/config.yaml run-agent & \
         python -m fim_agent.cli.main --config config/config.yaml serve-web --host 0.0.0.0 --port 8000 & \
         wait"
```

Scripted option with clean shutdown handling:

```bash
FIM_DASHBOARD_PASSWORD="your-strong-password" \
FIM_ADMIN_PASSWORD="your-strong-password" \
OPENAI_API_KEY="your-openai-api-key" \
bash scripts/run_all.sh
```

`scripts/run_all.sh` sets `CONFIG_PATH`, `HOST`, and `PORT` defaults, installs signal traps to stop both processes, and waits so the session stays open.

### PowerShell (Windows)

Launch both commands in the background using `Start-Process` so the terminal is free for other work:

```powershell
$env:FIM_DASHBOARD_PASSWORD = "your-strong-password"
$env:FIM_ADMIN_PASSWORD     = "your-strong-password"
$env:OPENAI_API_KEY         = "your-openai-api-key"

Start-Process py -ArgumentList "-m fim_agent.cli.main --config config\config.yaml run-agent"
Start-Process py -ArgumentList "-m fim_agent.cli.main --config config\config.yaml serve-web --host 0.0.0.0 --port 8000"
```

Or run the helper script (takes parameters or existing env vars and returns immediately while both processes keep running):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_all.ps1 `
  -DashboardPassword "your-strong-password" `
  -AdminPassword "your-strong-password" `
  -OpenAiApiKey "your-openai-api-key"
```

Security notes: Never commit real passwords or API keys. Keep sensitive values in environment variables, secrets managers, or your shell profile instead of source control.

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
