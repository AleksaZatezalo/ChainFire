"""
Maps semgrep rule IDs to nuclei tags.
Logic extracted from dast.py — keeps the original keyword→tag mapping intact.
"""
from __future__ import annotations

import re

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "error":    1,
    "warning":  2,
    "info":     3,
    "unknown":  4,
}

KEYWORD_TO_TAGS: dict[str, list[str]] = {
    "sql":          ["sqli", "time-based-sqli"],
    "sqli":         ["sqli", "time-based-sqli"],
    "nosql":        ["sqli"],
    "xpath":        ["sqli"],
    "injection":    ["sqli", "rce", "xss"],
    "tainted":      ["sqli", "xss"],
    "exec":         ["rce"],
    "command":      ["rce", "cmdi"],
    "rce":          ["rce"],
    "shell":        ["rce"],
    "eval":         ["rce"],
    "ssti":         ["ssti"],
    "template":     ["ssti"],
    "jinja":        ["ssti"],
    "twig":         ["ssti"],
    "freemarker":   ["ssti"],
    "velocity":     ["ssti"],
    "xxe":          ["xxe"],
    "xml":          ["xxe"],
    "xss":          ["xss"],
    "dom":          ["xss"],
    "reflected":    ["xss"],
    "stored":       ["xss"],
    "lfi":          ["lfi"],
    "traversal":    ["lfi"],
    "path":         ["lfi"],
    "directory":    ["lfi"],
    "include":      ["lfi"],
    "ssrf":         ["ssrf"],
    "fetch":        ["ssrf"],
    "url":          ["ssrf", "redirect"],
    "redirect":     ["redirect"],
    "forward":      ["redirect"],
    "auth":         ["auth-bypass"],
    "authorization": ["auth-bypass"],
    "bypass":       ["auth-bypass"],
    "csrf":         ["csrf"],
    "jwt":          ["jwt"],
    "idor":         ["idor"],
    "hardcoded":    ["exposure"],
    "secret":       ["exposure"],
    "password":     ["exposure"],
    "credential":   ["exposure"],
    "key":          ["exposure"],
    "token":        ["exposure"],
    "crypto":       ["exposure"],
    "weak":         ["exposure", "misconfig"],
    "deserializ":   ["deserialization"],
    "pickle":       ["rce"],
    "marshal":      ["rce"],
    "debug":        ["exposure", "misconfig"],
    "cors":         ["misconfig"],
    "csp":          ["misconfig"],
    "hsts":         ["misconfig"],
    "crlf":         ["crlf"],
    "header":       ["misconfig"],
    "tls":          ["misconfig", "exposure"],
    "ssl":          ["misconfig", "exposure"],
    "ldap":         ["ldap"],
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
                    if len(keyword) >= 4 and (
                        token.startswith(keyword) or keyword in token
                    ):
                        rule_tags.update(tags)

        if rule_tags:
            matched_tags.update(rule_tags)
            matched_rules.append(rule_id)

    return matched_tags, matched_rules
