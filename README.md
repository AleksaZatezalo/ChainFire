# ChainFire

A web-based security testing platform that chains **Semgrep** (SAST) and **Nuclei** (DAST) into a single browser-driven workflow. Semgrep analyses source code to find vulnerability patterns; those findings automatically select the Nuclei templates that probe the running application over HTTP.

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

Run a specific semgrep rule against the source code and a specific Nuclei template against the target. Use this when you want precise control over what runs.

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

Navigate to **Wordlists** and enter one path per line. Lines beginning with `#` are comments. The paths are combined with the target URL to form the nuclei target list — used with community templates in Chained Scan mode.

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
│   └── scanner/
│       ├── models.py                # SemgrepRule, NucleiTemplate, Wordlist, Scan
│       ├── serializers.py
│       ├── views.py                 # DRF ViewSets + health endpoint
│       ├── urls.py
│       ├── management/commands/
│       │   └── seed_defaults.py     # Default rules, templates, wordlists
│       └── services/
│           ├── tag_mapper.py        # Semgrep finding → Nuclei tag mapping
│           ├── semgrep_service.py   # Semgrep subprocess wrapper
│           ├── nuclei_service.py    # Nuclei subprocess wrapper
│           └── scan_runner.py       # Background scan pipeline + path/URL translation
└── frontend/
    ├── Dockerfile
    ├── nginx.conf
    ├── package.json
    └── src/
        ├── api/client.js
        ├── components/
        │   ├── Layout.jsx
        │   ├── ResourceManager.jsx
        │   └── FindingsTable.jsx
        └── pages/
            ├── ScannerPage.jsx
            ├── ResultsPage.jsx
            ├── SemgrepRulesPage.jsx
            ├── NucleiTemplatesPage.jsx
            └── WordlistsPage.jsx
```

## API Reference

All endpoints are prefixed with `/api/`.

| Method | Path                          | Description                |
|--------|-------------------------------|----------------------------|
| GET    | `/api/semgrep-rules/`         | List semgrep rules         |
| POST   | `/api/semgrep-rules/`         | Create semgrep rule        |
| PUT    | `/api/semgrep-rules/{id}/`    | Update semgrep rule        |
| DELETE | `/api/semgrep-rules/{id}/`    | Delete semgrep rule        |
| GET    | `/api/nuclei-templates/`      | List nuclei templates      |
| POST   | `/api/nuclei-templates/`      | Create nuclei template     |
| PUT    | `/api/nuclei-templates/{id}/` | Update nuclei template     |
| DELETE | `/api/nuclei-templates/{id}/` | Delete nuclei template     |
| GET    | `/api/wordlists/`             | List wordlists             |
| POST   | `/api/wordlists/`             | Create wordlist            |
| PUT    | `/api/wordlists/{id}/`        | Update wordlist            |
| DELETE | `/api/wordlists/{id}/`        | Delete wordlist            |
| GET    | `/api/scans/`                 | List scans                 |
| POST   | `/api/scans/`                 | Start a new scan           |
| GET    | `/api/scans/{id}/`            | Get scan detail + findings |
| DELETE | `/api/scans/{id}/`            | Delete scan                |
| GET    | `/api/health/`                | Binary availability check  |

## Security Notes

- This tool is for **authorised testing only**. Only scan applications you own or have explicit permission to test.
- The backend is not hardened for public exposure. Run it on localhost or behind a VPN.
- The default `DJANGO_SECRET_KEY` is insecure. Set a real value in `.env` before exposing the service to any network.
- Nuclei actively sends attack payloads to the target. Never point it at production systems without explicit authorisation.
