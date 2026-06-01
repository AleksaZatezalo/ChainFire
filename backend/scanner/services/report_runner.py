"""
AI-powered remediation report generation.

Uses Claude to analyse Semgrep and Nuclei findings and produce a detailed
markdown report explaining each vulnerability and how to fix it.
"""
from __future__ import annotations

import logging
import threading

logger = logging.getLogger(__name__)

_MODEL = "claude-opus-4-6"

_SYSTEM_PROMPT = """\
You are a senior application security engineer writing a remediation report for \
a development team.

You will be given the findings from a SAST scan (Semgrep) and a DAST scan (Nuclei) \
of a web application.

Produce a clear, actionable markdown report with the following structure:

# Security Scan Report

## Executive Summary
A 2-4 sentence overview of the most critical issues found and overall risk posture.

## Semgrep Findings (SAST)
For each finding, include a subsection:
### [Severity] Rule: <check_id>
- **What it is:** One sentence description.
- **Why it matters:** One sentence on the impact.
- **Location:** File and line.
- **How to fix:** Concrete fix with a before/after code snippet where possible.

## Nuclei Findings (DAST)
For each finding, include a subsection:
### [Severity] <vulnerability name>
- **What it is:** One sentence description.
- **Why it matters:** One sentence on the impact.
- **Matched at:** URL or endpoint.
- **How to fix:** Concrete remediation steps.

## Remediation Priority
A numbered list of the top issues to address first, ordered by severity and exploitability.

Rules:
- Be specific and technical — your audience is software engineers, not managers.
- Include code snippets where they make the fix clearer.
- Do not include generic security advice unrelated to the findings.
- If there are no findings for a section, say "No findings." and move on.
"""


def _build_user_message(scan_label: str, target_url: str,
                         semgrep_findings: list, nuclei_findings: list) -> str:
    parts = [
        f"**Scan:** {scan_label}",
        f"**Target:** {target_url}",
        "",
    ]

    parts.append(f"## Semgrep Findings ({len(semgrep_findings)} total)")
    if semgrep_findings:
        for i, f in enumerate(semgrep_findings):
            loc = f.get("location") or {}
            file_path = loc.get("file_path", "—")
            line = loc.get("line", "")
            loc_str = f"{file_path}:{line}" if line else file_path
            parts.append(
                f"\n### Finding {i+1}\n"
                f"- Check ID: {f.get('check_id', '—')}\n"
                f"- Severity: {f.get('severity', '—')}\n"
                f"- Location: {loc_str}\n"
                f"- Message: {(f.get('message') or '')[:400]}"
            )
    else:
        parts.append("No Semgrep findings.")

    parts.append(f"\n## Nuclei Findings ({len(nuclei_findings)} total)")
    if nuclei_findings:
        for i, f in enumerate(nuclei_findings):
            info = f.get("info") or {}
            parts.append(
                f"\n### Finding {i+1}\n"
                f"- Template: {f.get('template-id', '—')}\n"
                f"- Name: {info.get('name', '—')}\n"
                f"- Severity: {info.get('severity', '—')}\n"
                f"- Matched at: {f.get('matched-at') or f.get('host', '—')}\n"
                f"- Description: {(info.get('description') or '')[:300]}"
            )
    else:
        parts.append("No Nuclei findings.")

    return "\n".join(parts)


def _generate_report(scan_label: str, target_url: str,
                      semgrep_findings: list, nuclei_findings: list,
                      api_key: str) -> str:
    import anthropic as _anthropic

    client = _anthropic.Anthropic(api_key=api_key)
    user_msg = _build_user_message(scan_label, target_url, semgrep_findings, nuclei_findings)

    response = client.messages.create(
        model=_MODEL,
        max_tokens=4096,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )

    return response.content[0].text


def _run_in_thread(scan_id: str) -> None:
    from django.db import connection
    from scanner.models import Scan
    from accounts.models import ApiKey

    scan = None
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.report_status = Scan.REPORT_STATUS_RUNNING
        scan.save(update_fields=["report_status"])

        api_key_obj = ApiKey.objects.filter(provider=ApiKey.PROVIDER_ANTHROPIC).first()
        if not api_key_obj:
            raise ValueError("No Anthropic API key configured.")

        scan_label       = scan.label or scan.target_url
        target_url       = scan.target_url
        semgrep_findings = list(scan.semgrep_findings or [])
        nuclei_findings  = list(scan.nuclei_findings or [])
        api_key          = api_key_obj.key_value

        report = _generate_report(scan_label, target_url, semgrep_findings, nuclei_findings, api_key)

        scan.ai_report     = report
        scan.report_status = Scan.REPORT_STATUS_COMPLETED
        scan.save(update_fields=["ai_report", "report_status"])
        logger.info("Report generated for scan %s", scan_id)

    except Exception as exc:
        logger.exception("Report generation failed for scan %s: %s", scan_id, exc)
        if scan is not None:
            try:
                scan.report_status = Scan.REPORT_STATUS_FAILED
                scan.ai_report     = str(exc)
                scan.save(update_fields=["report_status", "ai_report"])
            except Exception:
                pass
    finally:
        connection.close()


def start_report_generation(scan_id: str) -> None:
    thread = threading.Thread(
        target=_run_in_thread,
        args=(scan_id,),
        daemon=True,
        name=f"report-{scan_id[:8]}",
    )
    thread.start()
