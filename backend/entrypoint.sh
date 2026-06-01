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
]

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
