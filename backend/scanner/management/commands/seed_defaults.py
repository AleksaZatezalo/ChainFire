"""
Management command: seed_defaults

Populates the database with a curated set of starter Semgrep rules,
Nuclei templates, and API wordlists if they don't already exist.
Running this command multiple times is safe — existing records are never
overwritten.
"""
from django.core.management.base import BaseCommand
from scanner.models import NucleiTemplate, SemgrepRule, Wordlist


# ── Default Semgrep Rules ──────────────────────────────────────────────────────

SEMGREP_RULES = [
    {
        "name": "sql-injection",
        "content": """\
rules:
  - id: sql-injection
    patterns:
      - pattern: |
          $QUERY = "..." + $INPUT
      - pattern-not: |
          $QUERY = "..." + sanitize($INPUT)
    message: >
      Possible SQL injection: user-controlled data concatenated directly
      into a SQL query string. Use parameterised queries instead.
    languages: [python, java, javascript, go, php]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-89"
      owasp: "A03:2021 - Injection"
      confidence: MEDIUM
""",
    },
    {
        "name": "command-injection",
        "content": """\
rules:
  - id: command-injection
    patterns:
      - pattern: subprocess.run($CMD, shell=True, ...)
      - pattern: os.system($CMD)
      - pattern: os.popen($CMD)
      - pattern: subprocess.Popen($CMD, shell=True, ...)
    message: >
      Possible command injection: user-controlled data passed to a shell.
      Avoid shell=True; pass arguments as a list instead.
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-78"
      owasp: "A03:2021 - Injection"
""",
    },
    {
        "name": "hardcoded-secrets",
        "content": """\
rules:
  - id: hardcoded-password
    patterns:
      - pattern: password = "..."
      - pattern: PASSWORD = "..."
      - pattern: secret = "..."
      - pattern: SECRET_KEY = "..."
      - pattern: api_key = "..."
    message: >
      Hardcoded secret detected. Store secrets in environment variables
      or a secrets manager, never in source code.
    languages: [python, javascript, java, go, ruby]
    severity: WARNING
    metadata:
      category: security
      cwe: "CWE-798"
      owasp: "A07:2021 - Identification and Authentication Failures"

  - id: hardcoded-token
    pattern: |
      $X = "..."
    pattern-regex: '(?i)(token|api[-_]?key|secret|password|passwd|pwd)\s*=\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']'
    message: >
      Possible hardcoded credential or token found in source code.
    languages: [python, javascript, java]
    severity: WARNING
    metadata:
      category: security
      cwe: "CWE-798"
""",
    },
    {
        "name": "xss-reflected",
        "content": """\
rules:
  - id: xss-flask-reflected
    patterns:
      - pattern: |
          @app.route(...)
          def $HANDLER(...):
            ...
            return $INPUT
      - pattern-not: |
          return escape($INPUT)
      - pattern-not: |
          return render_template(...)
    message: >
      Possible reflected XSS: user input returned directly in a Flask
      response without escaping. Use render_template() or markupsafe.escape().
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-79"
      owasp: "A03:2021 - Injection"

  - id: xss-django-mark-safe
    pattern: mark_safe($X)
    message: >
      Django mark_safe() called — ensure the argument cannot contain
      user-controlled HTML. Prefer template auto-escaping instead.
    languages: [python]
    severity: WARNING
    metadata:
      category: security
      cwe: "CWE-79"
""",
    },
    {
        "name": "path-traversal",
        "content": """\
rules:
  - id: path-traversal-open
    patterns:
      - pattern: open($PATH, ...)
      - pattern-not: open(os.path.join($BASE, ...), ...)
    message: >
      Potential path traversal: file path constructed from user input
      without canonicalisation. Use os.path.realpath() and verify the
      result is within the expected base directory.
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-22"
      owasp: "A01:2021 - Broken Access Control"

  - id: path-traversal-send-file
    patterns:
      - pattern: send_file($PATH, ...)
    message: >
      Flask send_file() called with a potentially user-controlled path.
      Use send_from_directory() with a fixed base directory.
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-22"
""",
    },
    {
        "name": "ssrf-requests",
        "content": """\
rules:
  - id: ssrf-requests-get
    patterns:
      - pattern: requests.get($URL, ...)
      - pattern: requests.post($URL, ...)
      - pattern: requests.request($METHOD, $URL, ...)
      - pattern: urllib.request.urlopen($URL)
    message: >
      Potential SSRF: HTTP request made to a URL that may be
      user-controlled. Validate and allowlist target URLs before
      making outbound requests.
    languages: [python]
    severity: WARNING
    metadata:
      category: security
      cwe: "CWE-918"
      owasp: "A10:2021 - Server-Side Request Forgery"
""",
    },
    {
        "name": "insecure-deserialization",
        "content": """\
rules:
  - id: pickle-load
    pattern-either:
      - pattern: pickle.load($DATA)
      - pattern: pickle.loads($DATA)
      - pattern: cPickle.load($DATA)
      - pattern: cPickle.loads($DATA)
    message: >
      Deserialization with pickle is unsafe when the data source is
      untrusted. An attacker can craft a payload that executes arbitrary
      code. Use a safe format like JSON instead.
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-502"
      owasp: "A08:2021 - Software and Data Integrity Failures"

  - id: yaml-unsafe-load
    pattern: yaml.load($DATA)
    message: >
      yaml.load() without Loader is unsafe. Use yaml.safe_load() or
      yaml.load($DATA, Loader=yaml.SafeLoader).
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-502"
""",
    },
    {
        "name": "jwt-weak-config",
        "content": """\
rules:
  - id: jwt-none-algorithm
    patterns:
      - pattern: jwt.decode($TOKEN, algorithms=["none"])
      - pattern: jwt.decode($TOKEN, options={"verify_signature": False})
    message: >
      JWT decoded with the 'none' algorithm or with signature
      verification disabled. An attacker can forge arbitrary tokens.
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-347"
      owasp: "A02:2021 - Cryptographic Failures"

  - id: jwt-hardcoded-secret
    pattern: jwt.encode($PAYLOAD, "...")
    message: >
      JWT signed with a hardcoded secret. Rotate to a randomly generated
      secret stored in an environment variable.
    languages: [python]
    severity: WARNING
    metadata:
      category: security
      cwe: "CWE-798"
""",
    },
]


# ── Default Nuclei Templates ───────────────────────────────────────────────────

NUCLEI_TEMPLATES = [
    {
        "name": "open-redirect",
        "content": """\
id: open-redirect-generic

info:
  name: Open Redirect
  author: chainfire
  severity: medium
  description: >
    Checks whether the application reflects a redirect parameter to an
    external URL without validation, enabling phishing attacks.
  tags: redirect,dast,owasp

http:
  - method: GET
    path:
      - "{{BaseURL}}/?next=https://evil.example.com"
      - "{{BaseURL}}/?redirect=https://evil.example.com"
      - "{{BaseURL}}/?url=https://evil.example.com"
      - "{{BaseURL}}/?return_to=https://evil.example.com"

    matchers-condition: or
    matchers:
      - type: regex
        regex:
          - "(?i)location:\\s*https://evil\\.example\\.com"
        part: header

      - type: word
        words:
          - "https://evil.example.com"
        part: body
""",
    },
    {
        "name": "cors-misconfiguration",
        "content": """\
id: cors-arbitrary-origin

info:
  name: CORS Arbitrary Origin Reflection
  author: chainfire
  severity: medium
  description: >
    Tests whether the server reflects arbitrary Origin headers in
    Access-Control-Allow-Origin, which allows any domain to make
    credentialed cross-origin requests.
  tags: cors,misconfig,dast

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
      - "{{BaseURL}}/api/"
      - "{{BaseURL}}/api/v1/"

    headers:
      Origin: https://evil.example.com

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "https://evil.example.com"
        part: header

      - type: word
        words:
          - "Access-Control-Allow-Origin"
        part: header
""",
    },
    {
        "name": "xss-reflected",
        "content": """\
id: xss-reflected-params

info:
  name: Reflected XSS via Query Parameters
  author: chainfire
  severity: high
  description: >
    Injects a simple XSS payload into common query string parameters and
    checks whether it is reflected unescaped in the response body.
  tags: xss,dast,owasp

http:
  - method: GET
    path:
      - "{{BaseURL}}/?q=<script>alert(1)</script>"
      - "{{BaseURL}}/?search=<script>alert(1)</script>"
      - "{{BaseURL}}/?query=<script>alert(1)</script>"
      - "{{BaseURL}}/?name=<script>alert(1)</script>"
      - "{{BaseURL}}/?input=<script>alert(1)</script>"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "<script>alert(1)</script>"
        part: body

      - type: status
        status:
          - 200
""",
    },
    {
        "name": "sql-injection-error-based",
        "content": """\
id: sqli-error-based

info:
  name: SQL Injection — Error-Based Detection
  author: chainfire
  severity: high
  description: >
    Appends common SQL injection payloads to query parameters and looks
    for database error messages in the response, indicating that user
    input reaches a SQL query without sanitisation.
  tags: sqli,dast,owasp

http:
  - method: GET
    path:
      - "{{BaseURL}}/?id=1'"
      - "{{BaseURL}}/?user=1'"
      - "{{BaseURL}}/?page=1'"
      - "{{BaseURL}}/?q=1'"
      - "{{BaseURL}}/?search=1'"

    matchers-condition: or
    matchers:
      - type: regex
        regex:
          - "(?i)(sql syntax|mysql_fetch|ORA-[0-9]{5}|pg_query|sqlite3\\.OperationalError|Unclosed quotation mark|syntax error.*SQL|You have an error in your SQL)"
        part: body

      - type: word
        words:
          - "Warning: mysql_"
          - "Warning: pg_"
          - "Microsoft OLE DB Provider for SQL"
          - "Unclosed quotation mark after the character string"
          - "quoted string not properly terminated"
        condition: or
        part: body
""",
    },
    {
        "name": "http-security-headers",
        "content": """\
id: missing-security-headers

info:
  name: Missing HTTP Security Headers
  author: chainfire
  severity: low
  description: >
    Checks for the absence of recommended HTTP security response headers
    that help protect against common browser-based attacks.
  tags: misconfig,headers,dast

http:
  - method: GET
    path:
      - "{{BaseURL}}/"

    matchers-condition: or
    matchers:
      - type: word
        words:
          - "X-Content-Type-Options"
        negative: true
        part: header
        name: missing-x-content-type-options

      - type: word
        words:
          - "X-Frame-Options"
        negative: true
        part: header
        name: missing-x-frame-options

      - type: word
        words:
          - "Strict-Transport-Security"
        negative: true
        part: header
        name: missing-hsts
""",
    },
    {
        "name": "sensitive-files-exposure",
        "content": """\
id: sensitive-file-exposure

info:
  name: Sensitive File Exposure
  author: chainfire
  severity: high
  description: >
    Checks for publicly accessible files that should never be exposed,
    such as environment files, git metadata, configuration files, and
    backup archives.
  tags: exposure,misconfig,dast

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.env.local"
      - "{{BaseURL}}/.env.production"
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/.git/HEAD"
      - "{{BaseURL}}/config.php"
      - "{{BaseURL}}/wp-config.php"
      - "{{BaseURL}}/web.config"
      - "{{BaseURL}}/database.yml"
      - "{{BaseURL}}/settings.py"
      - "{{BaseURL}}/config/database.yml"
      - "{{BaseURL}}/backup.sql"
      - "{{BaseURL}}/dump.sql"
      - "{{BaseURL}}/phpinfo.php"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: regex
        regex:
          - "(?i)(DB_PASSWORD|SECRET_KEY|database_password|\\[core\\]|repositoryformatversion|<\\?php phpinfo|APP_KEY=|AWS_SECRET)"
        part: body
""",
    },
    {
        "name": "idor-user-enumeration",
        "content": """\
id: idor-user-id-enumeration

info:
  name: IDOR — User ID Enumeration
  author: chainfire
  severity: medium
  description: >
    Tests whether incrementing a numeric user ID in common API paths
    exposes other users' data without authorisation checks.
  tags: idor,dast,owasp

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/users/1"
      - "{{BaseURL}}/api/users/2"
      - "{{BaseURL}}/api/v1/users/1"
      - "{{BaseURL}}/api/v1/profile/1"
      - "{{BaseURL}}/user/1/profile"
      - "{{BaseURL}}/account/1"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: regex
        regex:
          - "(?i)(email|username|user_id|phone|address|first_name|last_name)"
        part: body
""",
    },
    {
        "name": "ssrf-internal-network",
        "content": """\
id: ssrf-internal-ip-access

info:
  name: SSRF — Internal Network Access via URL Parameter
  author: chainfire
  severity: high
  description: >
    Tests whether the application fetches a URL provided in a query
    parameter, which may allow an attacker to probe the internal network.
  tags: ssrf,dast,owasp

http:
  - method: GET
    path:
      - "{{BaseURL}}/fetch?url=http://169.254.169.254/latest/meta-data/"
      - "{{BaseURL}}/proxy?url=http://169.254.169.254/"
      - "{{BaseURL}}/redirect?url=http://127.0.0.1/"
      - "{{BaseURL}}/load?src=http://localhost/"
      - "{{BaseURL}}/image?url=http://169.254.169.254/"

    matchers-condition: or
    matchers:
      - type: regex
        regex:
          - "(?i)(ami-id|instance-id|local-ipv4|security-credentials|iam/)"
        part: body

      - type: word
        words:
          - "169.254.169.254"
        part: body
""",
    },
    {
        "name": "python-pickle-deserialization",
        "content": """\
id: python-pickle-deserialization

info:
  name: Python Pickle Deserialization (Safe Canary)
  author: chainfire
  severity: critical
  description: >
    Sends a benign pickle payload (pickle.dumps(42), base64-encoded) to common
    deserialization endpoints. A 200 response containing "42" confirms the
    endpoint executes untrusted pickle data — a critical RCE vector (CWE-502).
  tags: deserialization,rce,dast,python,pickle

http:
  # ── Test 1: JSON wrapper — POST /api/deserialize ─────────────────────────
  - method: POST
    path:
      - "{{BaseURL}}/api/deserialize"

    headers:
      Content-Type: application/json

    body: '{"data":"gAVLKi4="}'

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "42"
        part: body

  # ── Test 2: Cookie-based — GET /dashboard ───────────────────────────────
  - method: GET
    path:
      - "{{BaseURL}}/dashboard"

    headers:
      Cookie: "session=gAVLKi4="

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "42"
        part: body
""",
    },
]


# ── Default Wordlists ──────────────────────────────────────────────────────────

WORDLISTS = [
    {
        "name": "common-api-endpoints",
        "content": """\
# Common REST API endpoints
/api
/api/v1
/api/v2
/api/v1/users
/api/v1/users/1
/api/v1/me
/api/v1/profile
/api/v1/admin
/api/v1/login
/api/v1/logout
/api/v1/register
/api/v1/signup
/api/v1/token
/api/v1/refresh
/api/v1/reset-password
/api/v1/forgot-password
/api/v1/products
/api/v1/items
/api/v1/orders
/api/v1/payments
/api/v1/settings
/api/v1/config
/api/v1/health
/api/v1/status
/api/v1/metrics
/api/v1/search
""",
    },
    {
        "name": "admin-panels",
        "content": """\
# Admin and management interfaces
/admin
/admin/
/administrator
/admin/login
/wp-admin
/wp-login.php
/panel
/dashboard
/management
/manage
/control
/backend
/superuser
/root
/console
/phpmyadmin
/pma
/adminer
/dbadmin
/database
/sqlmanager
""",
    },
    {
        "name": "sensitive-files",
        "content": """\
# Files that should never be publicly accessible
/.env
/.env.local
/.env.production
/.env.staging
/.git/config
/.git/HEAD
/.gitignore
/.htaccess
/.htpasswd
/web.config
/config.php
/wp-config.php
/settings.py
/config.yml
/config.yaml
/database.yml
/secrets.yml
/phpinfo.php
/info.php
/server-status
/server-info
/robots.txt
/sitemap.xml
/backup.sql
/dump.sql
/db.sql
""",
    },
    {
        "name": "graphql-endpoints",
        "content": """\
# GraphQL common endpoints
/graphql
/graphiql
/api/graphql
/query
/gql
/v1/graphql
/v2/graphql
/api/query
/graphql/console
/graphql/playground
""",
    },
    {
        "name": "vulnerable-flask-server",
        "content": """\
# Endpoints for the intentionally vulnerable Flask server (vulnerable_server.py)
# Target: http://127.0.0.1:5000

# Deserialization endpoints
/api/deserialize
/api/load

# Cookie-based session deserialization
/dashboard
""",
    },
]


# ── Command ────────────────────────────────────────────────────────────────────

class Command(BaseCommand):
    help = "Seed the database with default Semgrep rules, Nuclei templates, and wordlists."

    def handle(self, *args, **options):
        self._seed(SemgrepRule, SEMGREP_RULES, "Semgrep rules")
        self._seed(NucleiTemplate, NUCLEI_TEMPLATES, "Nuclei templates")
        self._seed(Wordlist, WORDLISTS, "Wordlists")

    def _seed(self, model, items, label):
        created = 0
        for item in items:
            _, was_created = model.objects.get_or_create(
                name=item["name"],
                defaults={"content": item["content"]},
            )
            if was_created:
                created += 1

        if created:
            self.stdout.write(
                self.style.SUCCESS(f"  ✓ Created {created} {label}")
            )
        else:
            self.stdout.write(f"  · {label}: already seeded, skipping")
