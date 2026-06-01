"""
Executes a full scan pipeline in a background thread.

Three modes controlled by Scan.scan_mode:

  "all" (default)
    Semgrep: auto-config (full recommended ruleset), only if source_path set.
    Nuclei:  all available templates — maximum coverage, slower.

  "semgrep_all"
    Semgrep: auto-config, only if source_path set.
    Nuclei:  tag-mapped from semgrep findings — targeted, faster.
             Semgrep findings drive which nuclei templates run.

  "custom"
    Semgrep: user-selected custom rule, only if source_path set.
    Nuclei:  user-selected custom template and/or tags from semgrep findings.
"""
from __future__ import annotations

import threading

import os
import re
from django.db import connection
from django.utils import timezone

from .semgrep_service import run_semgrep_all_rules, run_semgrep_scan
from .nuclei_service import run_nuclei_scan
from .tag_mapper import map_findings_to_tags


def _resolve_target_url(url: str) -> str:
    """Replace localhost/127.0.0.1 with host.docker.internal so nuclei can reach the host."""
    return re.sub(r"(https?://)(?:127\.0\.0\.1|localhost)", r"\1host.docker.internal", url)


def _resolve_source_path(path: str) -> str:
    """Translate a host-machine path to its container mount point using SOURCE_DIR."""
    source_dir = os.environ.get("SOURCE_DIR", "").rstrip("/")
    if source_dir and path.startswith(source_dir):
        return "/workspace/source" + path[len(source_dir):]
    return path


def _custom_templates_matching(nuclei_tags: set[str]) -> list:
    """Return NucleiTemplate objects whose tags intersect with nuclei_tags."""
    from scanner.models import NucleiTemplate  # noqa: PLC0415
    matches = []
    for tmpl in NucleiTemplate.objects.all():
        try:
            # Extract the tags: line without a full YAML parse
            m = re.search(r"^\s*tags\s*:\s*(.+)$", tmpl.content, re.MULTILINE)
            if not m:
                continue
            tmpl_tags = {t.strip() for t in m.group(1).split(",") if t.strip()}
            if tmpl_tags & nuclei_tags:
                matches.append(tmpl)
        except Exception:
            pass
    return matches


def start_scan(scan_id: str) -> None:
    """Spawn a daemon thread to execute the scan pipeline."""
    thread = threading.Thread(
        target=_execute,
        args=(scan_id,),
        daemon=True,
        name=f"scan-{scan_id[:8]}",
    )
    thread.start()


def _execute(scan_id: str) -> None:
    from scanner.models import Scan  # noqa: PLC0415

    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = Scan.STATUS_RUNNING
        scan.started_at = timezone.now()
        scan.target_url = _resolve_target_url(scan.target_url)
        if scan.source_path:
            scan.source_path = _resolve_source_path(scan.source_path)
        scan.save(update_fields=["status", "started_at", "target_url", "source_path"])

        wordlist_content = scan.wordlist.content if scan.wordlist else None

        if scan.scan_mode == Scan.SCAN_MODE_SEMGREP_ALL:
            _run_semgrep_all(scan, wordlist_content)
        else:
            _run_custom(scan, wordlist_content)

    except Exception as exc:  # noqa: BLE001
        _mark_failed(scan_id, str(exc))
    finally:
        connection.close()


# ── Mode implementations ───────────────────────────────────────────────────────

def _run_semgrep_all(scan, wordlist_content: str | None) -> None:
    """
    All Semgrep Rules: semgrep auto-config, then nuclei guided by the findings.

    Semgrep findings are mapped to nuclei tags so only relevant templates
    are selected — more targeted than 'all' but still uses the full semgrep
    ruleset rather than a single custom rule.
    """
    semgrep_findings: list[dict] = []
    nuclei_tags: set[str] = set()

    if scan.source_path:
        from scanner.models import SemgrepRule  # noqa: PLC0415

        # Auto-config scan
        semgrep_findings, warning = run_semgrep_all_rules(scan.source_path)
        if warning:
            scan.error_message = warning

        # Also run every custom semgrep rule and merge findings
        seen_ids: set[str] = {f["check_id"] for f in semgrep_findings}
        for rule in SemgrepRule.objects.all():
            extra, _ = run_semgrep_scan(scan.source_path, rule.content)
            for f in extra:
                if f["check_id"] not in seen_ids:
                    semgrep_findings.append(f)
                    seen_ids.add(f["check_id"])

        scan.semgrep_findings = semgrep_findings
        scan.save(update_fields=["semgrep_findings", "error_message"])

        if semgrep_findings:
            nuclei_tags, _ = map_findings_to_tags(semgrep_findings, scan.min_severity)

    if not nuclei_tags:
        # No semgrep findings → no tags → nothing to guide nuclei.
        # Running all templates would defeat the purpose of this mode.
        if not scan.error_message:
            scan.error_message = (
                "No semgrep findings produced nuclei tags — nuclei skipped. "
                "Provide a source path with scannable code to enable tag-guided DAST."
            )
            scan.save(update_fields=["error_message"])
        _finish(scan, [], nuclei_tags=[])
        return

    # 1. Community templates filtered by derived tags
    nuclei_findings = run_nuclei_scan(
        target_url=scan.target_url,
        template_content=None,
        wordlist_content=wordlist_content,
        tags=nuclei_tags,
    )

    # 2. Custom templates whose tags overlap with derived tags
    for tmpl in _custom_templates_matching(nuclei_tags):
        custom_findings = run_nuclei_scan(
            target_url=scan.target_url,
            template_content=tmpl.content,
            wordlist_content=None,  # custom templates hardcode their own paths
            tags=None,
        )
        nuclei_findings = nuclei_findings + custom_findings

    _finish(scan, nuclei_findings, nuclei_tags=sorted(nuclei_tags))


def _run_custom(scan, wordlist_content: str | None) -> None:
    """
    Custom Rules: specific semgrep rule + specific nuclei template.

    Semgrep findings are still mapped to nuclei tags, which combine with
    the selected template for maximum custom coverage.
    """
    semgrep_findings: list[dict] = []
    nuclei_tags: set[str] = set()

    if scan.source_path and scan.semgrep_rule:
        semgrep_findings, warning = run_semgrep_scan(
            scan.source_path, scan.semgrep_rule.content
        )
        scan.semgrep_findings = semgrep_findings
        if warning:
            scan.error_message = warning
        scan.save(update_fields=["semgrep_findings", "error_message"])

        if semgrep_findings:
            nuclei_tags, _ = map_findings_to_tags(semgrep_findings, scan.min_severity)

    template_content = (
        scan.nuclei_template.content if scan.nuclei_template else None
    )

    # Custom templates hardcode their own paths ({{BaseURL}}/api/foo).
    # Passing wordlist URLs as targets causes double-path duplication
    # (e.g. /api/foo/api/foo → 404).  Use the plain base URL only.
    nuclei_findings = run_nuclei_scan(
        target_url=scan.target_url,
        template_content=template_content,
        wordlist_content=None,
        tags=nuclei_tags if nuclei_tags else None,
    )

    _finish(scan, nuclei_findings, nuclei_tags=sorted(nuclei_tags))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _finish(scan, nuclei_findings: list[dict], nuclei_tags: list[str]) -> None:
    scan.nuclei_findings = nuclei_findings
    scan.nuclei_tags = nuclei_tags
    scan.status = scan.STATUS_COMPLETED
    scan.completed_at = timezone.now()
    scan.save(update_fields=["nuclei_findings", "nuclei_tags", "status", "completed_at"])


def _mark_failed(scan_id: str, error: str) -> None:
    from scanner.models import Scan  # noqa: PLC0415

    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = Scan.STATUS_FAILED
        scan.error_message = error[:2000]
        scan.completed_at = timezone.now()
        scan.save(update_fields=["status", "error_message", "completed_at"])
    except Exception:  # noqa: BLE001
        pass
