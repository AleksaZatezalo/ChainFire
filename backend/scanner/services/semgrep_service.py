"""
Runs a semgrep SAST scan and returns normalised findings.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile

_SEVERITY_NORMALISE: dict[str, str] = {
    "critical": "critical",
    "error":    "error",
    "warning":  "warning",
    "info":     "info",
    "note":     "info",
    "none":     "info",
}


def run_semgrep_all_rules(source_path: str) -> tuple[list[dict], str | None]:
    """
    Run semgrep with the 'auto' config — semgrep's full recommended ruleset,
    auto-detected per language. Used when use_all_rules=True.

    Returns (findings, warning) where warning is None on success or a string
    describing the problem if semgrep could not be run / errored.
    """
    if not source_path or not os.path.exists(source_path):
        return [], f"Semgrep skipped: source path not found ({source_path!r})"

    cmd = ["semgrep", "--json", "--config", "auto", source_path]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode not in (0, 1):
        warning = f"semgrep exited {result.returncode}: {result.stderr[:500]}"
        return [], warning
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return [], f"semgrep output parse error: {exc}"
    return _normalise(data.get("results", [])), None


def run_semgrep_scan(source_path: str, rule_content: str) -> tuple[list[dict], str | None]:
    """
    Write rule_content to a temporary YAML file, invoke semgrep against
    source_path, and return (findings, warning).

    warning is None on success, or a string describing the problem if semgrep
    could not be run / errored (non-fatal — caller should continue to nuclei).
    """
    if not source_path or not os.path.exists(source_path):
        return [], f"Semgrep skipped: source path not found ({source_path!r})"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as rule_file:
        rule_file.write(rule_content)
        rule_path = rule_file.name

    try:
        cmd = ["semgrep", "--json", "--config", rule_path, source_path]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        if result.returncode not in (0, 1):
            return [], f"semgrep exited {result.returncode}: {result.stderr[:500]}"
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            return [], f"semgrep output parse error: {exc}"
        return _normalise(data.get("results", [])), None
    finally:
        os.unlink(rule_path)


def _normalise(raw_results: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for r in raw_results:
        extra = r.get("extra") or {}
        start = r.get("start") or {}
        raw_sev = extra.get("severity", "info").lower()
        findings.append(
            {
                "check_id": r.get("check_id", ""),
                "severity": _SEVERITY_NORMALISE.get(raw_sev, "info"),
                "location": {
                    "file_path": r.get("path", ""),
                    "line": start.get("line"),
                },
                "message": extra.get("message", ""),
                "metadata": extra.get("metadata", {}),
            }
        )
    return findings
