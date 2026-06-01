#!/usr/bin/env python3
"""
dast.py — Semgrep → Nuclei DAST pipeline.

Subcommands
-----------
  scan      Run Semgrep locally and write a findings JSON.
  validate  Map a findings JSON to Nuclei tags and run Nuclei.
  run       scan + validate in one step.

Usage
-----
  python dast.py scan     --path ~/code/myapp --url http://target.com
  python dast.py validate --findings findings.json
  python dast.py run      --path ~/code/myapp --url http://target.com

Install
-------
  brew install semgrep nuclei   (or pip install semgrep)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Shared constants
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "error":    1,
    "warning":  2,
    "info":     3,
    "unknown":  4,
}

# ANSI helpers
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_COLORS = {
    "critical": "\033[95m",
    "error":    "\033[91m",
    "warning":  "\033[93m",
    "info":     "\033[96m",
}


def _color(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if sys.stdout.isatty() else text


def _severity_color(text: str, severity: str) -> str:
    return _color(text, _COLORS.get(severity, ""))


# ─────────────────────────────────────────────────────────────────────────────
# Semgrep — scan
# ─────────────────────────────────────────────────────────────────────────────

# Semgrep CLI emits uppercase severity; normalise to lowercase.
_SEVERITY_NORMALISE: dict[str, str] = {
    "critical": "critical",
    "error":    "error",
    "warning":  "warning",
    "info":     "info",
    "note":     "info",
    "none":     "info",
}


def _require_semgrep() -> None:
    if not shutil.which("semgrep"):
        sys.exit(
            "\n❌  'semgrep' not found on PATH.\n"
            "    Install: brew install semgrep  OR  pip install semgrep\n"
        )


def run_semgrep(path: str, config: str, extra_args: list[str]) -> dict:
    """Invoke the semgrep binary and return the parsed JSON output."""
    _require_semgrep()
    cmd = ["semgrep", "--json", "--config", config, path] + extra_args
    print(f"  Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    # semgrep exits 0 (clean) or 1 (findings found); anything else is an error.
    if result.returncode not in (0, 1):
        print(result.stderr[:2000], file=sys.stderr)
        sys.exit(f"\n❌  semgrep exited with code {result.returncode}\n")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        sys.exit(f"\n❌  Failed to parse semgrep output: {exc}\n")


def normalise_findings(
    raw_results: list[dict],
    package: str,
    severity_filter: Optional[list[str]],
) -> list[dict]:
    """
    Convert semgrep CLI result objects into the normalised shape used
    throughout this tool (mirrors the Semgrep AppSec API format).
    """
    allowed = set(severity_filter) if severity_filter else None
    normalised: list[dict] = []

    for r in raw_results:
        raw_sev = (r.get("extra") or {}).get("severity", "info").lower()
        sev = _SEVERITY_NORMALISE.get(raw_sev, "info")
        if allowed and sev not in allowed:
            continue
        extra = r.get("extra") or {}
        start = r.get("start") or {}
        normalised.append({
            "check_id":    r.get("check_id", ""),
            "severity":    sev,
            "triage_state": "open",
            "repository":  {"name": package},
            "location": {
                "file_path": r.get("path", ""),
                "line":      start.get("line"),
            },
            "message":  extra.get("message", ""),
            "metadata": extra.get("metadata", {}),
        })

    return normalised


def save_findings(
    findings: list[dict],
    path: str,
    scan_path: str,
    config: str,
    package: str,
    target_url: Optional[str],
    severity_filter: Optional[list[str]],
) -> None:
    payload = {
        "generated_at":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source":         "local",
        "scan_path":      scan_path,
        "config":         config,
        "package":        package,
        "target_url":     target_url,
        "total_findings": len(findings),
        "filters":        {"severity": severity_filter},
        "findings":       findings,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)


def print_scan_summary(findings: list[dict]) -> None:
    sev_counts:  dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    file_counts: dict[str, int] = {}

    for f in findings:
        sev  = f.get("severity", "unknown")
        rule = f.get("check_id", "unknown")
        fp   = (f.get("location") or {}).get("file_path", "unknown")
        sev_counts[sev]   = sev_counts.get(sev, 0) + 1
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
        file_counts[fp]   = file_counts.get(fp, 0) + 1

    print("\n╔══════════════════════════════════════╗")
    print(f"║  Total findings: {len(findings):<19}║")
    print("╚══════════════════════════════════════╝")

    print("\n  By Severity:")
    for sev in ("critical", "error", "warning", "info", "unknown"):
        if sev not in sev_counts:
            continue
        count = sev_counts[sev]
        print(f"    {_severity_color(f'{sev:<10}', sev)}  {count:>5}  {'█' * min(count, 40)}")

    print("\n  Top Rules:")
    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"    {rule.split('.')[-1][:55]:<55}  {count:>5}")

    print("\n  Top Files:")
    for fp, count in sorted(file_counts.items(), key=lambda x: -x[1])[:10]:
        short = fp[-60:] if len(fp) > 60 else fp
        print(f"    {short:<60}  {count:>5}")
    print()


def print_scan_table(findings: list[dict], limit: int = 25) -> None:
    rows = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "unknown"), 99))
    print(f"{'Severity':<10}{'Rule':<50}Location")
    print("─" * 110)
    for f in rows[:limit]:
        sev  = f.get("severity", "")
        rule = (f.get("check_id") or "")[:50].ljust(50)
        loc  = f.get("location") or {}
        fp   = loc.get("file_path", "")
        line = loc.get("line", "")
        print(f"{_severity_color(sev.ljust(10), sev)}{rule}{fp}:{line}" if line else
              f"{_severity_color(sev.ljust(10), sev)}{rule}{fp}")
    if len(findings) > limit:
        print(f"\n  … and {len(findings) - limit} more.")


# ─────────────────────────────────────────────────────────────────────────────
# Nuclei — validate
# ─────────────────────────────────────────────────────────────────────────────

# Maps lowercase tokens extracted from a Semgrep rule ID to Nuclei tags.
# Tags are drawn from the real nuclei-templates tag corpus.
KEYWORD_TO_TAGS: dict[str, list[str]] = {
    # SQL / NoSQL injection
    "sql":          ["sqli", "time-based-sqli"],
    "sqli":         ["sqli", "time-based-sqli"],
    "nosql":        ["sqli"],
    "xpath":        ["sqli"],
    # Generic injection (broad — sweeps sqli + rce + xss)
    "injection":    ["sqli", "rce", "xss"],
    "tainted":      ["sqli", "xss"],
    # Command / code execution
    "exec":         ["rce"],
    "command":      ["rce", "cmdi"],
    "rce":          ["rce"],
    "shell":        ["rce"],
    "eval":         ["rce"],
    # SSTI
    "ssti":         ["ssti"],
    "template":     ["ssti"],
    "jinja":        ["ssti"],
    "twig":         ["ssti"],
    "freemarker":   ["ssti"],
    "velocity":     ["ssti"],
    # XXE / XML
    "xxe":          ["xxe"],
    "xml":          ["xxe"],
    # XSS
    "xss":          ["xss"],
    "dom":          ["xss"],
    "reflected":    ["xss"],
    "stored":       ["xss"],
    # LFI / path traversal
    "lfi":          ["lfi"],
    "traversal":    ["lfi"],
    "path":         ["lfi"],
    "directory":    ["lfi"],
    "include":      ["lfi"],
    # SSRF
    "ssrf":         ["ssrf"],
    "fetch":        ["ssrf"],
    "url":          ["ssrf", "redirect"],
    # Open redirect
    "redirect":     ["redirect"],
    "forward":      ["redirect"],
    # Auth / access control
    "auth":         ["auth-bypass"],
    "authorization": ["auth-bypass"],
    "bypass":       ["auth-bypass"],
    "csrf":         ["csrf"],
    "jwt":          ["jwt"],
    "idor":         ["idor"],
    # Secrets / crypto
    "hardcoded":    ["exposure"],
    "secret":       ["exposure"],
    "password":     ["exposure"],
    "credential":   ["exposure"],
    "key":          ["exposure"],
    "token":        ["exposure"],
    "crypto":       ["exposure"],
    "weak":         ["exposure", "misconfig"],
    # Deserialization
    "deserializ":   ["deserialization"],
    "pickle":       ["rce"],
    "marshal":      ["rce"],
    # Misconfiguration / exposure
    "debug":        ["exposure", "misconfig"],
    "cors":         ["misconfig"],
    "csp":          ["misconfig"],
    "hsts":         ["misconfig"],
    "crlf":         ["crlf"],
    "header":       ["misconfig"],
    # TLS / network
    "tls":          ["misconfig", "exposure"],
    "ssl":          ["misconfig", "exposure"],
    # LDAP
    "ldap":         ["ldap"],
    # Frameworks (adds tech-specific templates on top of vuln templates)
    "django":       ["django"],
    "flask":        ["flask"],
    "rails":        ["rails"],
    "spring":       ["spring"],
    "struts":       ["struts"],
    "laravel":      ["laravel"],
    "wordpress":    ["wordpress"],
    "drupal":       ["drupal"],
    "joomla":       ["joomla"],
    "node":         ["node"],
    "express":      ["node"],
    "react":        ["xss"],
    "angular":      ["xss"],
}

# Tags considered too broad to include unless at least one specific tag exists.
_BROAD_TAGS: frozenset[str] = frozenset({"exposure", "misconfig", "rce"})


def _tokenise_rule_id(rule_id: str) -> list[str]:
    return [t for t in re.split(r"[.\-_/]", rule_id.lower()) if t]


def map_findings_to_tags(
    findings: list[dict],
    min_severity: str,
) -> tuple[set[str], list[str]]:
    """
    Derive a set of Nuclei tags from Semgrep rule IDs.

    Returns (tags, matched_rule_ids).
    """
    min_rank = SEVERITY_ORDER.get(min_severity.lower(), 4)
    matched_tags:  set[str]  = set()
    matched_rules: list[str] = []
    seen_rules:    set[str]  = set()

    for finding in findings:
        sev = finding.get("severity", "unknown").lower()
        if SEVERITY_ORDER.get(sev, 4) > min_rank:
            continue

        rule_id: str = finding.get("check_id") or finding.get("rule_id") or ""
        if not rule_id or rule_id in seen_rules:
            continue
        seen_rules.add(rule_id)

        rule_tags: set[str] = set()
        for token in _tokenise_rule_id(rule_id):
            if token in KEYWORD_TO_TAGS:
                rule_tags.update(KEYWORD_TO_TAGS[token])
            else:
                for keyword, tags in KEYWORD_TO_TAGS.items():
                    if len(keyword) >= 4 and (token.startswith(keyword) or keyword in token):
                        rule_tags.update(tags)

        if rule_tags:
            matched_tags.update(rule_tags)
            matched_rules.append(rule_id)

    return matched_tags, matched_rules


def build_target_list(url: str, wordlist_path: str) -> str:
    """
    Combine a base URL with a path-per-line wordlist into a temp file of
    full target URLs. Returns the temp file path (caller must delete it).
    """
    base = url.rstrip("/")
    targets: list[str] = []
    with open(wordlist_path, encoding="utf-8") as fh:
        for line in fh:
            path = line.strip()
            if path and not path.startswith("#"):
                targets.append(base + path)
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    )
    tmp.write("\n".join(targets) + "\n")
    tmp.close()
    return tmp.name


def build_nuclei_cmd(
    url: Optional[str],
    tags: set[str],
    templates_dir: Optional[str],
    output_file: Optional[str],
    extra_args: list[str],
    targets_file: Optional[str] = None,
    concurrency: int = 25,
) -> list[str]:
    # -l (target list) takes priority over -u (single URL)
    if targets_file:
        cmd = ["nuclei", "-l", targets_file]
    else:
        cmd = ["nuclei", "-u", url]
    if templates_dir:
        cmd += ["-t", templates_dir]
    if tags:
        cmd += ["-tags", ",".join(sorted(tags))]
    cmd += ["-c", str(concurrency), "-bs", str(concurrency)]
    cmd += ["-dast"]
    cmd += ["-silent", "-nc"]
    if output_file:
        cmd += ["-o", output_file, "-jsonl"]
    return cmd + extra_args


# Template IDs whose raw JSONL lines are suppressed from terminal output.
# These are OOB/callback-based confirmations of vulns already reported by
# inline templates (e.g. jinja2-oob duplicates reflection-ssti findings).
_SUPPRESS_TEMPLATE_IDS: frozenset[str] = frozenset({
    "jinja2-oob",
})


_NUCLEI_SEV_COLORS: dict[str, str] = {
    "critical": "\033[95m",
    "high":     "\033[91m",
    "medium":   "\033[93m",
    "low":      "\033[96m",
    "info":     "\033[37m",
}

_NUCLEI_SEV_ORDER: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


def _print_nuclei_finding(obj: dict, index: int) -> None:
    """Print a single nuclei finding in a human-readable block."""
    info     = obj.get("info") or {}
    sev      = info.get("severity", "info").lower()
    name     = info.get("name", obj.get("template-id", "unknown"))
    tid      = obj.get("template-id", "")
    matched  = obj.get("matched-at", obj.get("host", ""))
    param    = obj.get("fuzzing_parameter") or obj.get("fuzzing-parameter") or ""
    method   = obj.get("fuzzing_method") or obj.get("fuzzing-method") or obj.get("type", "")
    tags     = ", ".join(info.get("tags", []))

    col   = _NUCLEI_SEV_COLORS.get(sev, "")
    reset = _RESET if sys.stdout.isatty() else ""
    bold  = _BOLD  if sys.stdout.isatty() else ""
    sev_label = f"{col}{sev.upper():8}{reset}" if sys.stdout.isatty() else sev.upper().ljust(8)

    print(f"{bold}[{index}] {sev_label}  {name}{reset}")
    print(f"       Template : {tid}")
    print(f"       Matched  : {matched}")
    if param:
        print(f"       Parameter: {param}  [{method}]")
    if tags:
        print(f"       Tags     : {tags}")
    print()


def run_nuclei(cmd: list[str]) -> tuple[int, list[dict]]:
    """Run nuclei, pretty-print findings to stdout, return (exit_code, findings)."""
    print(f"\n  Running: {' '.join(cmd)}\n")

    findings: list[dict] = []
    non_json_lines: list[str] = []

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, text=True)
    assert proc.stdout is not None
    for raw_line in proc.stdout:
        line = raw_line.rstrip("\n")
        if not line:
            continue
        try:
            obj = json.loads(line)
            if obj.get("template-id") not in _SUPPRESS_TEMPLATE_IDS:
                findings.append(obj)
        except (json.JSONDecodeError, AttributeError):
            non_json_lines.append(line)
    proc.wait()

    # Print any non-JSON output (warnings etc.) first.
    for line in non_json_lines:
        print(line)

    # Sort findings by severity then print.
    findings.sort(key=lambda f: _NUCLEI_SEV_ORDER.get(
        (f.get("info") or {}).get("severity", "info").lower(), 99))

    if findings:
        print(_color("─" * 60, _BOLD))
        print(_color(f"  Nuclei — {len(findings)} finding(s)", _BOLD))
        print(_color("─" * 60, _BOLD) + "\n")
        for i, f in enumerate(findings, 1):
            _print_nuclei_finding(f, i)
    else:
        print("  Nuclei — no findings.\n")

    return proc.returncode, findings


def parse_nuclei_jsonl(path: str) -> list[dict]:
    """Parse a nuclei JSONL output file into a list of finding dicts."""
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


# ─────────────────────────────────────────────────────────────────────────────
# Claude Code reporting
# ─────────────────────────────────────────────────────────────────────────────

def build_claude_prompt(semgrep_findings: list[dict], nuclei_findings: list[dict]) -> str:
    lines: list[str] = [
        "You are a security engineer reviewing SAST and DAST pipeline results.",
        "Produce a numbered, prioritised fix list. For each item include:",
        "  Severity | Title | Why it matters | Concrete fix with code snippet where applicable.",
        "",
        "=" * 60,
        "SEMGREP STATIC FINDINGS",
        "=" * 60,
    ]

    for f in semgrep_findings[:50]:
        sev  = f.get("severity", "?").upper()
        rule = f.get("check_id", "unknown")
        loc  = f.get("location") or {}
        fp   = loc.get("file_path", "")
        line = loc.get("line", "")
        msg  = (f.get("message") or "")[:300]
        location = f"{fp}:{line}" if line else fp
        lines += [f"[{sev}] {rule}", f"  Location : {location}", f"  Message  : {msg}", ""]

    if not semgrep_findings:
        lines.append("  (none)")
        lines.append("")

    lines += [
        "=" * 60,
        "NUCLEI DYNAMIC FINDINGS",
        "=" * 60,
    ]

    for n in nuclei_findings:
        info    = n.get("info") or {}
        sev     = info.get("severity", "?").upper()
        tid     = n.get("template-id", "unknown")
        name    = info.get("name", "")
        matched = n.get("matched-at", n.get("host", ""))
        lines += [f"[{sev}] {tid}", f"  Name     : {name}", f"  Matched  : {matched}", ""]

    if not nuclei_findings:
        lines.append("  (none)")
        lines.append("")

    return "\n".join(lines)


def run_claude_fixes(semgrep_findings: list[dict], nuclei_findings: list[dict]) -> None:
    """Run Claude Code CLI and stream the security report to stdout."""
    if not shutil.which("claude"):
        print(f"\n{_color('⚠  claude CLI not found on PATH — skipping AI report.', _YELLOW)}")
        print("    Install Claude Code: https://claude.ai/code\n")
        return

    prompt = build_claude_prompt(semgrep_findings, nuclei_findings)

    print(f"\n{_color('━' * 60, _BOLD)}")
    print(_color("  Claude Code — Security Report", _BOLD))
    print(_color('━' * 60, _BOLD) + "\n")

    subprocess.run(["claude", "-p", prompt, "--output-format", "text"])


def load_findings_file(path: Path) -> tuple[list[dict], Optional[str]]:
    """Load a findings JSON. Returns (findings, target_url)."""
    if not path.exists():
        sys.exit(f"\n❌  File not found: {path}\n")
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data, None
    return data.get("findings", []), data.get("target_url")


def print_mapping_report(
    findings: list[dict],
    matched_rules: list[str],
    tags: set[str],
    url: Optional[str],
    min_severity: str,
    wordlist: Optional[str] = None,
) -> None:
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "unknown").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    print(_color("\n╔══════════════════════════════════════════════════╗", _BOLD))
    print(_color("║           Semgrep → Nuclei Mapping Report        ║", _BOLD))
    print(_color("╚══════════════════════════════════════════════════╝", _BOLD))
    if wordlist:
        print(f"\n  Wordlist      : {_color(wordlist, _CYAN)}")
    else:
        print(f"\n  Target URL    : {_color(url, _CYAN)}")
    print(f"  Min severity  : {min_severity}")
    print(f"  Findings      : {len(findings)}")
    print( "  Breakdown     :")
    for sev in ("critical", "error", "warning", "info", "unknown"):
        if sev in sev_counts:
            print(f"      {sev:<12} {sev_counts[sev]}")

    print(f"\n  Matched rules ({len(matched_rules)}):")
    for r in matched_rules[:20]:
        print(f"      {r}")
    if len(matched_rules) > 20:
        print(f"      … and {len(matched_rules) - 20} more")

    print(f"\n  {_color('Nuclei tags selected', _BOLD)} ({len(tags)}):")
    for tag in sorted(tags):
        print(f"      {_color(tag, _GREEN)}")
    if not tags:
        print(f"  {_color('⚠  No tags matched.', _YELLOW)}")


# ─────────────────────────────────────────────────────────────────────────────
# Subcommand handlers
# ─────────────────────────────────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> Optional[list[dict]]:
    """Run Semgrep locally. Returns the normalised findings list."""
    scan_path = str(Path(args.path).expanduser().resolve())
    if not os.path.exists(scan_path):
        sys.exit(f"\n❌  Path not found: {scan_path}\n")

    package = args.package or Path(scan_path).name
    print(f"\nScanning '{scan_path}' with ruleset '{args.config}'…")

    raw      = run_semgrep(scan_path, args.config, args.semgrep_args.split() if args.semgrep_args else [])
    errors   = raw.get("errors", [])
    if errors:
        print(f"  ⚠  {len(errors)} semgrep error(s) — results may be partial.")

    findings = normalise_findings(raw.get("results", []), package, args.severity)
    print(f"  Findings after filter: {len(findings)}")

    if not findings:
        print("No findings matched your filters.")
        return None

    print_scan_summary(findings)
    print_scan_table(findings)

    output_path = args.output or ("findings.json" if args.url else None)
    if output_path:
        save_findings(findings, output_path, scan_path, args.config, package, args.url, args.severity)
        print(f"\n✅  Saved {len(findings)} findings to {output_path}")

    return findings


def cmd_validate(args: argparse.Namespace, findings: Optional[list[dict]] = None) -> None:
    """Map findings to Nuclei tags and run Nuclei."""
    # Accept findings passed in-memory (from cmd_scan) or load from disk.
    if findings is None:
        findings, stored_url = load_findings_file(Path(args.findings))
    else:
        stored_url = getattr(args, "url", None)

    if not findings:
        sys.exit("\n❌  No findings to validate.\n")

    wordlist = getattr(args, "wordlist", None)
    url      = getattr(args, "url", None) or stored_url

    if not wordlist and not url:
        sys.exit(
            "\n❌  No target specified.\n"
            "    Pass --url <URL>, --wordlist <file>, or both.\n"
        )

    if wordlist and not Path(wordlist).exists():
        sys.exit(f"\n❌  Wordlist not found: {wordlist}\n")

    # Build the target list nuclei will receive.
    # Both provided  → combine base URL + paths into a temp file.
    # Wordlist only  → pass it directly (assumed to contain full URLs).
    # URL only       → pass as single -u target.
    tmp_targets: Optional[str] = None
    if wordlist and url:
        tmp_targets = build_target_list(url, wordlist)
        targets_file = tmp_targets
        print(f"  Built {sum(1 for _ in open(tmp_targets))} target URLs from wordlist + base URL")
    elif wordlist:
        targets_file = wordlist
    else:
        targets_file = None

    tags, matched_rules = map_findings_to_tags(findings, args.min_severity)
    print_mapping_report(findings, matched_rules, tags, url, args.min_severity, wordlist)

    if not tags:
        if tmp_targets:
            os.unlink(tmp_targets)
        sys.exit("\n⚠  No Nuclei tags derived — nothing to run.\n")

    if not shutil.which("nuclei"):
        if tmp_targets:
            os.unlink(tmp_targets)
        sys.exit(
            "\n❌  'nuclei' not found on PATH.\n"
            "    Install from: https://projectdiscovery.io/\n"
        )

    # --output on standalone 'validate'; --nuclei-output on 'run'
    nuclei_output = getattr(args, "output", None) or getattr(args, "nuclei_output", None)
    extra = args.nuclei_args.split() if args.nuclei_args else []
    cmd   = build_nuclei_cmd(url, tags, args.templates_dir, nuclei_output, extra, targets_file,
                             getattr(args, "concurrency", 50))

    no_claude = getattr(args, "no_claude", False)

    if args.dry_run:
        print(f"\n{_color('[dry-run]', _YELLOW)} nuclei command:\n  {' '.join(cmd)}\n")
        if tmp_targets:
            print(f"  Target list ({tmp_targets}):")
            for line in open(tmp_targets):
                print(f"      {line.rstrip()}")
        if tmp_targets:
            os.unlink(tmp_targets)
        return

    # If Claude reporting is enabled and no output file was specified, use a
    # temp file so we can parse nuclei findings for the AI report.
    tmp_nuclei_output: Optional[str] = None
    if not no_claude and not nuclei_output:
        tmp_fd, tmp_nuclei_output = tempfile.mkstemp(suffix=".jsonl")
        os.close(tmp_fd)
        # Rebuild cmd with the temp output file.
        cmd = build_nuclei_cmd(url, tags, args.templates_dir, tmp_nuclei_output, extra,
                               targets_file, getattr(args, "concurrency", 50))

    try:
        rc, live_nuclei_findings = run_nuclei(cmd)
    finally:
        if tmp_targets:
            os.unlink(tmp_targets)

    if rc != 0:
        if tmp_nuclei_output:
            os.unlink(tmp_nuclei_output)
        sys.exit(f"\n❌  nuclei exited with code {rc}\n")

    if nuclei_output:
        print(f"\n✅  Nuclei results saved to {nuclei_output}")

    # Claude Code AI report — prefer the in-memory list captured during the run
    # (already filtered); fall back to parsing the output file if needed.
    if not no_claude:
        if live_nuclei_findings:
            nuclei_findings = live_nuclei_findings
        else:
            report_file = nuclei_output or tmp_nuclei_output
            nuclei_findings = parse_nuclei_jsonl(report_file) if report_file else []
        run_claude_fixes(findings, nuclei_findings)
        if tmp_nuclei_output:
            os.unlink(tmp_nuclei_output)


def cmd_run(args: argparse.Namespace) -> None:
    """scan + validate in sequence, passing findings in memory."""
    findings = cmd_scan(args)
    if findings:
        cmd_validate(args, findings)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _add_scan_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--path",         "-p", metavar="DIR",     required=True,
                   help="Local directory or file to scan.")
    p.add_argument("--url",          "-u", metavar="URL",
                   help="Target URL (stored in findings JSON; required for 'run').")
    p.add_argument("--config",       "-c", metavar="RULESET",  default="auto",
                   help="Semgrep ruleset. Default: auto. E.g. p/owasp-top-ten.")
    p.add_argument("--severity",     "-s", nargs="+",
                   choices=["info", "warning", "error", "critical"], metavar="LEVEL",
                   help="Only include findings at these severity levels.")
    p.add_argument("--output",       "-o", metavar="FILE",
                   help="Save findings JSON. Defaults to findings.json when --url is set.")
    p.add_argument("--package",      "-pkg", metavar="NAME",
                   help="Application name (used as repo label in output).")
    p.add_argument("--semgrep-args", metavar="ARGS", default="",
                   help="Extra args forwarded to semgrep.")


def _add_validate_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--wordlist", "-w", metavar="FILE",
                   help="File of target paths (one per line). Combined with --url to build full targets.")
    p.add_argument("--concurrency", metavar="N", type=int, default=50,
                   help="Number of concurrent nuclei workers (-c and -bs). Default: 50.")
    p.add_argument("--min-severity", metavar="LEVEL", default="info",
                   choices=["critical", "error", "warning", "info"],
                   help="Minimum severity to include when selecting templates. Default: info.")
    p.add_argument("--templates-dir", metavar="DIR",
                   help="nuclei-templates directory (uses nuclei default if omitted).")
    p.add_argument("--nuclei-output", metavar="FILE",
                   help="Write Nuclei results to this file (JSONL).")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the nuclei command without running it.")
    p.add_argument("--nuclei-args", metavar="ARGS", default="",
                   help="Extra args forwarded to nuclei.")
    p.add_argument("--no-claude", action="store_true",
                   help="Skip the Claude Code AI security report after nuclei runs.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dast.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────
    scan_p = sub.add_parser("scan", help="Run Semgrep locally and write findings JSON.")
    _add_scan_args(scan_p)

    # ── validate ──────────────────────────────────────────────────
    val_p = sub.add_parser("validate", help="Map findings JSON to Nuclei tags and run Nuclei.")
    val_p.add_argument("--findings", "-f", metavar="FILE", required=True,
                       help="Findings JSON from 'scan' or semgrep-pull.py.")
    val_p.add_argument("--url", "-u", metavar="URL",
                       help="Override target URL (uses value stored in JSON if omitted).")
    val_p.add_argument("--output", "-o", metavar="FILE",
                       help="Write Nuclei results to this file (JSONL).")
    _add_validate_args(val_p)

    # ── run ───────────────────────────────────────────────────────
    run_p = sub.add_parser("run", help="scan + validate in one step.")
    _add_scan_args(run_p)
    _add_validate_args(run_p)
    # 'run' requires --url (needed for nuclei)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    dispatch = {"scan": cmd_scan, "validate": cmd_validate, "run": cmd_run}
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
