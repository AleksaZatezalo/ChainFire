"""
Runs a nuclei DAST scan and returns parsed findings.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Optional


def run_nuclei_scan(
    target_url: str,
    template_content: Optional[str],
    wordlist_content: Optional[str],
    tags: Optional[set[str]] = None,
) -> list[dict]:
    """
    Execute a nuclei scan against target_url.

    - template_content: raw YAML of a custom nuclei template (written to a temp file).
    - wordlist_content: newline-separated API paths combined with target_url into a
      full target list.
    - tags: nuclei tag filter derived from semgrep findings (used when no custom
      template is provided, or in addition to one).

    Returns a list of nuclei finding dicts.
    Raises RuntimeError on non-recoverable failures.
    """
    temp_files: list[str] = []
    try:
        template_path = _write_template(template_content, temp_files)
        targets_path = _build_target_list(target_url, wordlist_content, temp_files)
        output_path = _make_temp_file(".jsonl", temp_files)

        cmd = _build_command(
            target_url, template_path, targets_path, tags, output_path
        )

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600
        )
        # nuclei exits 0 (no findings) or 1 (findings found)
        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"nuclei exited {result.returncode}: {result.stderr[:500]}"
            )

        return _parse_jsonl(output_path)
    finally:
        for path in temp_files:
            try:
                os.unlink(path)
            except OSError:
                pass


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_template(
    content: Optional[str], temp_files: list[str]
) -> Optional[str]:
    if not content:
        return None
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as f:
        f.write(content)
        temp_files.append(f.name)
        return f.name


def _build_target_list(
    base_url: str, wordlist_content: Optional[str], temp_files: list[str]
) -> Optional[str]:
    if not wordlist_content:
        return None

    base = base_url.rstrip("/")
    targets = [
        base + line.strip()
        for line in wordlist_content.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not targets:
        return None

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as f:
        f.write("\n".join(targets) + "\n")
        temp_files.append(f.name)
        return f.name


def _make_temp_file(suffix: str, temp_files: list[str]) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    temp_files.append(path)
    return path


def _build_command(
    target_url: str,
    template_path: Optional[str],
    targets_path: Optional[str],
    tags: Optional[set[str]],
    output_path: str,
) -> list[str]:
    cmd = ["nuclei", "-silent", "-nc", "-o", output_path, "-jsonl"]

    if targets_path:
        cmd += ["-l", targets_path]
    else:
        cmd += ["-u", target_url]

    if template_path:
        cmd += ["-t", template_path]

    if tags:
        cmd += ["-tags", ",".join(sorted(tags))]

    return cmd


def _parse_jsonl(path: str) -> list[dict]:
    findings: list[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except FileNotFoundError:
        pass
    return findings
