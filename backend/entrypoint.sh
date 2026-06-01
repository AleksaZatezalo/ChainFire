#!/bin/bash
set -e

echo "Running database migrations..."
python manage.py migrate --run-syncdb

echo "Applying schema updates for existing databases..."
python - <<'PYEOF'
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
import django
django.setup()
from django.db import connection

# Each entry is (column_name, ALTER TABLE SQL).
# These are idempotent: silently ignored if the column already exists.
schema_updates = [
    (
        "use_all_rules",
        "ALTER TABLE scanner_scan ADD COLUMN use_all_rules INTEGER NOT NULL DEFAULT 1",
    ),
    (
        "scan_mode",
        "ALTER TABLE scanner_scan ADD COLUMN scan_mode VARCHAR(20) NOT NULL DEFAULT 'all'",
    ),
    (
        "report_status",
        "ALTER TABLE scanner_scan ADD COLUMN report_status VARCHAR(20) NOT NULL DEFAULT ''",
    ),
    (
        "ai_report",
        "ALTER TABLE scanner_scan ADD COLUMN ai_report TEXT NOT NULL DEFAULT ''",
    ),
]

# Create ScheduledScan table if it doesn't exist
cursor2 = connection.cursor()
cursor2.execute("""
    CREATE TABLE IF NOT EXISTS scanner_scheduledscan (
        id VARCHAR(36) PRIMARY KEY,
        label VARCHAR(255) NOT NULL DEFAULT '',
        target_url VARCHAR(200) NOT NULL,
        source_path VARCHAR(512) NOT NULL DEFAULT '',
        scan_mode VARCHAR(20) NOT NULL DEFAULT 'semgrep_all',
        semgrep_rule_id VARCHAR(36) REFERENCES scanner_semgregrule(id) ON DELETE SET NULL,
        nuclei_template_id VARCHAR(36) REFERENCES scanner_nucleitemplate(id) ON DELETE SET NULL,
        wordlist_id VARCHAR(36) REFERENCES scanner_wordlist(id) ON DELETE SET NULL,
        min_severity VARCHAR(20) NOT NULL DEFAULT 'info',
        interval VARCHAR(10) NOT NULL DEFAULT '24h',
        enabled INTEGER NOT NULL DEFAULT 1,
        last_run DATETIME,
        next_run DATETIME,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
""")
cursor2.close()
print("  ScheduledScan table ready")

with connection.cursor() as cursor:
    for col, sql in schema_updates:
        try:
            cursor.execute(sql)
            print(f"  Added column: {col}")
        except Exception:
            pass  # Column already exists — safe to ignore
PYEOF

echo "Seeding default rules, templates, and wordlists..."
python manage.py seed_defaults

echo "Starting Django development server..."
exec python manage.py runserver 0.0.0.0:8000
