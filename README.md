# ChainFire

A web-based security testing platform that chains **Semgrep** (SAST) and **Nuclei** (DAST) into a single browser-driven workflow. Semgrep analyses source code to find vulnerability patterns; those findings automatically select the Nuclei templates that probe the running application over HTTP.

## Features

- **Chained Scan** — Semgrep findings automatically drive Nuclei template selection. No manual tag configuration.
- **Custom Rules mode** — Run a specific Semgrep rule and Nuclei template for precise control.
- **Scheduled scans** — Run any scan on a recurring schedule (15 min → 7 days). Fires automatically in the background.
- **Authentication** — Session-based login with admin approval workflow and security-question password reset.
- **PDF export** — Download a formatted report of any completed scan.
- **Resource management** — Create and edit Semgrep rules, Nuclei templates, and wordlists directly in the browser.

## Architecture

```
┌─────────────────────────────────────────────┐
│  Browser  ─→  http://localhost:1337         │
└─────────────────────┬───────────────────────┘
                      │
       ┌──────────────▼──────────────┐
       │  frontend (nginx, port 80)  │
       │  React SPA                  │
       │  /api/* → backend:8000      │
       └──────────────┬──────────────┘
                      │
       ┌──────────────▼──────────────┐
       │  backend (Django, port 8000)│
       │  Semgrep + Nuclei binaries  │
       │  SQLite database            │
       └─────────────────────────────┘
```

Two containers managed by Docker Compose:

| Container  | Role                                             |
|------------|--------------------------------------------------|
| `frontend` | nginx serving the React app on port 1337         |
| `backend`  | Django REST API + Semgrep + Nuclei + scan runner |

Scans run in background threads so the API stays responsive. The frontend polls scan status every 3 seconds until completion.

## Prerequisites

- Docker & Docker Compose v2

## Quick Start

**1. Mount your source code**

Create a `.env` file next to `docker-compose.yml`. Set `SOURCE_DIR` to the root directory you want to make available for scanning. Setting it to `/Users` lets you pass any subdirectory path at scan time without restarting.

```bash
echo 'SOURCE_DIR=/Users' > /path/to/dast/.env
```

**2. Start the stack**

```bash
cd /path/to/dast
docker compose up --build -d
```

Open **http://localhost:1337**.

> First build downloads Nuclei and installs Semgrep — allow a few minutes. Subsequent builds use the layer cache and are fast.

**3. Create an account**

The first user to register is automatically granted admin access. All subsequent registrations require admin approval from the Admin panel before the user can log in.

## Authentication

### Registration

- Navigate to `http://localhost:1337` and click **Create account**.
- Choose a username, password (min 6 characters), and a security question with an answer.
- The **first account registered becomes the administrator** and is logged in immediately.
- All subsequent accounts are pending until an admin approves them in the Admin panel.

### Password Reset

1. Click **Forgot password?** on the login page.
2. Enter your username — the system looks up your security question.
3. Answer the question and set a new password.

### Admin Panel

Admins can access `/admin` (via the sidebar) to:
- **Approve** or **reject** pending user registrations.
- **Revoke** access from existing users.
- **Delete** user accounts.

## Scanning Source Code

The backend container mounts `SOURCE_DIR` from your Mac at `/workspace/source`. In the scan form you can enter either:

- **The full Mac path** — e.g. `/Users/alex/Desktop/myapp`. The backend rewrites it to the correct container path automatically.
- **The container path** — `/workspace/source` or any subdirectory beneath it.

`127.0.0.1` and `localhost` in the Target URL field are also rewritten to `host.docker.internal` automatically so Docker can reach services running on your Mac.

## Scan Modes

### Chained Scan (recommended)

The two-phase pipeline:

1. **Semgrep** scans the source directory using its full auto-detected ruleset plus all of your saved custom rules.
2. Findings are mapped to Nuclei tags via a keyword table (e.g. `pickle.loads` → `rce`, `deserialization`).
3. **Nuclei** runs community templates that match those tags, plus any of your saved custom Nuclei templates whose tags overlap.

If Semgrep produces no findings, Nuclei is skipped — the scan does not fall back to running every template.

### Custom Rules

Run a specific Semgrep rule against the source code and a specific Nuclei template against the target. Use this when you want precise control over what runs.

## Scheduled Scans

Navigate to **Scheduled Scans** and click **+ New Schedule**.

| Field            | Description                                                  |
|------------------|--------------------------------------------------------------|
| Label            | Optional display name                                        |
| Target URL       | Base URL of the app under test                               |
| Source Code Path | Optional path for Semgrep SAST                               |
| Interval         | 15 minutes / 1 hour / 6 hours / 24 hours / 7 days           |
| Scan Mode        | Chained Scan or Custom Rules                                 |
| Semgrep Rule     | Used in Custom Rules mode                                    |
| Nuclei Template  | Used in Custom Rules mode                                    |
| Wordlist         | Expands the target into an endpoint list                     |
| Min Severity     | Minimum Semgrep severity for tag mapping                     |

A background thread checks every 60 seconds for due schedules and creates a regular scan record for each one. Results appear in the **Results** page. Schedules can be individually enabled, disabled, or deleted.

## Usage

### 1. Semgrep Rules

Navigate to **Semgrep Rules** to create or edit rules using standard [semgrep rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax/). Example:

```yaml
rules:
  - id: pickle-load
    pattern-either:
      - pattern: pickle.load($DATA)
      - pattern: pickle.loads($DATA)
    message: Unsafe pickle deserialization — use JSON instead.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-502"
```

Note: use `pattern-either` (OR logic) when matching multiple patterns. `patterns` is AND logic and requires all entries to match the same location simultaneously.

### 2. Nuclei Templates

Navigate to **Nuclei Templates** to create or edit templates using standard [Nuclei template format](https://docs.projectdiscovery.io/templates/introduction). Tags control which templates are automatically selected in Chained Scan mode. Example:

```yaml
id: pickle-deserialization-rce

info:
  name: Python Pickle Deserialization RCE
  severity: critical
  tags: deserialization,rce,python,pickle

http:
  - method: POST
    path:
      - "{{BaseURL}}/api/deserialize"
    headers:
      Content-Type: application/json
    body: '{"data":"gAVLKi4="}'
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["42"]
        part: body
```

Custom templates hardcode their own paths (`{{BaseURL}}/api/foo`). Do not combine them with a wordlist — the wordlist is for community templates only.

### 3. Wordlists

Navigate to **Wordlists** and enter one path per line. Lines beginning with `#` are comments. The paths are combined with the target URL to form the Nuclei target list — used with community templates in Chained Scan mode.

```
/api/v1/users
/api/v1/users/1
/api/v1/admin
# Auth
/api/v1/login
/api/v1/register
```

### 4. Run a Scan

Navigate to **Scanner**:

| Field            | Required | Description                                                              |
|------------------|----------|--------------------------------------------------------------------------|
| Scan Mode        | Yes      | Chained Scan or Custom Rules                                             |
| Target URL       | Yes      | Base URL of the app under test. `127.0.0.1`/`localhost` are auto-rewritten |
| Wordlist         | No       | Expands the target into a list of endpoints for community templates      |
| Source Code Path | No       | Mac path or container path to scan with Semgrep                          |
| Semgrep Rule     | Custom   | Rule to run in Custom Rules mode                                         |
| Nuclei Template  | No       | Template to run in Custom Rules mode                                     |
| Min Severity     | No       | Minimum Semgrep severity for tag mapping (default: info)                 |

### 5. Results

Navigate to **Results**. Click any row to expand findings. Semgrep and Nuclei findings are shown in separate tabs. Rows pulse while a scan is running.

For any completed scan, click **↓ Export PDF** to download a formatted report containing scan metadata, all Semgrep findings, and all Nuclei findings with severity colour coding.

## Semgrep → Nuclei Tag Mapping

The tag mapper tokenises each Semgrep rule ID on `[.-_/]` and looks up tokens in a keyword table. Examples:

| Semgrep rule ID token | Nuclei tags              |
|-----------------------|--------------------------|
| `pickle`              | `rce`                    |
| `deserializ`          | `deserialization`        |
| `sql`, `sqli`         | `sqli`, `time-based-sqli`|
| `xss`, `reflected`    | `xss`                    |
| `ssrf`                | `ssrf`                   |
| `command`, `exec`     | `rce`, `cmdi`            |
| `path`, `traversal`   | `lfi`                    |

Custom Nuclei templates are matched against derived tags using their `tags:` field — no manual selection needed in Chained Scan mode.

## Project Structure

```
dast/
├── .env                             # SOURCE_DIR mount point (not committed)
├── docker-compose.yml
├── backend/
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── requirements.txt
│   ├── manage.py
│   ├── config/                      # Django settings & URL root
│   ├── accounts/                    # Auth app
│   │   ├── models.py                # UserProfile (approval status, security question)
│   │   ├── permissions.py           # IsApprovedUser DRF permission
│   │   ├── views.py                 # register, login, logout, reset, admin endpoints
│   │   └── urls.py
│   └── scanner/
│       ├── models.py                # SemgrepRule, NucleiTemplate, Wordlist, Scan, ScheduledScan
│       ├── serializers.py
│       ├── views.py                 # DRF ViewSets + health endpoint
│       ├── urls.py
│       ├── apps.py                  # Starts background scheduler on startup
│       ├── management/commands/
│       │   └── seed_defaults.py     # Default rules, templates, wordlists
│       └── services/
│           ├── scheduler.py         # Background thread — fires due ScheduledScans
│           ├── tag_mapper.py        # Semgrep finding → Nuclei tag mapping
│           ├── semgrep_service.py   # Semgrep subprocess wrapper
│           ├── nuclei_service.py    # Nuclei subprocess wrapper
│           └── scan_runner.py       # Background scan pipeline + path/URL translation
└── frontend/
    ├── Dockerfile
    ├── nginx.conf
    ├── package.json
    └── src/
        ├── api/client.js            # Axios instance with CSRF + session handling
        ├── context/
        │   └── AuthContext.jsx      # Auth state provider
        ├── components/
        │   ├── Layout.jsx           # Sidebar nav + user/logout footer
        │   ├── ResourceManager.jsx
        │   └── FindingsTable.jsx
        ├── utils/
        │   └── exportPdf.js         # jsPDF scan report generator
        └── pages/
            ├── LoginPage.jsx
            ├── RegisterPage.jsx
            ├── ForgotPasswordPage.jsx
            ├── AdminPage.jsx
            ├── ScannerPage.jsx
            ├── ResultsPage.jsx
            ├── ScheduledScansPage.jsx
            ├── SemgrepRulesPage.jsx
            ├── NucleiTemplatesPage.jsx
            └── WordlistsPage.jsx
```

## API Reference

All endpoints under `/api/` require an authenticated, approved session except where noted.

### Auth (`/api/auth/`) — public

| Method | Path                           | Description                              |
|--------|--------------------------------|------------------------------------------|
| GET    | `/api/auth/csrf/`              | Set CSRF cookie (call before POST requests) |
| GET    | `/api/auth/me/`                | Current session info                     |
| POST   | `/api/auth/register/`          | Register new account                     |
| POST   | `/api/auth/login/`             | Log in                                   |
| POST   | `/api/auth/logout/`            | Log out                                  |
| POST   | `/api/auth/security-question/` | Look up a user's security question       |
| POST   | `/api/auth/reset-password/`    | Reset password via security question     |

### Admin (`/api/auth/`) — admin only

| Method | Path                              | Description          |
|--------|-----------------------------------|----------------------|
| GET    | `/api/auth/users/`                | List all users       |
| POST   | `/api/auth/users/{id}/approve/`   | Approve a user       |
| POST   | `/api/auth/users/{id}/revoke/`    | Revoke user access   |
| DELETE | `/api/auth/users/{id}/`           | Delete a user        |

### Scanner (`/api/`) — authenticated

| Method | Path                                   | Description                        |
|--------|----------------------------------------|------------------------------------|
| GET    | `/api/semgrep-rules/`                  | List semgrep rules                 |
| POST   | `/api/semgrep-rules/`                  | Create semgrep rule                |
| PUT    | `/api/semgrep-rules/{id}/`             | Update semgrep rule                |
| DELETE | `/api/semgrep-rules/{id}/`             | Delete semgrep rule                |
| GET    | `/api/nuclei-templates/`               | List nuclei templates              |
| POST   | `/api/nuclei-templates/`               | Create nuclei template             |
| PUT    | `/api/nuclei-templates/{id}/`          | Update nuclei template             |
| DELETE | `/api/nuclei-templates/{id}/`          | Delete nuclei template             |
| GET    | `/api/wordlists/`                      | List wordlists                     |
| POST   | `/api/wordlists/`                      | Create wordlist                    |
| PUT    | `/api/wordlists/{id}/`                 | Update wordlist                    |
| DELETE | `/api/wordlists/{id}/`                 | Delete wordlist                    |
| GET    | `/api/scans/`                          | List scans                         |
| POST   | `/api/scans/`                          | Start a new scan                   |
| GET    | `/api/scans/{id}/`                     | Get scan detail + findings         |
| DELETE | `/api/scans/{id}/`                     | Delete scan                        |
| GET    | `/api/scheduled-scans/`               | List scheduled scans               |
| POST   | `/api/scheduled-scans/`               | Create scheduled scan              |
| PUT    | `/api/scheduled-scans/{id}/`          | Update scheduled scan              |
| DELETE | `/api/scheduled-scans/{id}/`          | Delete scheduled scan              |
| POST   | `/api/scheduled-scans/{id}/toggle/`   | Enable / disable scheduled scan    |
| GET    | `/api/health/`                         | Binary availability check (public) |

## Security Notes

- This tool is for **authorised testing only**. Only scan applications you own or have explicit permission to test.
- The backend is not hardened for public exposure. Run it on localhost or behind a VPN.
- The default `DJANGO_SECRET_KEY` is insecure. Set a real value in `.env` before exposing the service to any network.
- Nuclei actively sends attack payloads to the target. Never point it at production systems without explicit authorisation.
