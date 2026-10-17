"""Output formats: console text, JSON, and a Markdown audit report."""
from __future__ import annotations

import json
from collections import Counter
from datetime import date
from typing import List

from .change import ChangeResult
from .checks import Finding

SEVERITIES = ["critical", "high", "medium", "low"]


def summary(findings: List[Finding]) -> dict:
    c = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in SEVERITIES}


def risk_score(findings: List[Finding]) -> int:
    """0 (clean) .. 100 (very risky), weighted by severity."""
    weights = {"critical": 25, "high": 10, "medium": 4, "low": 1}
    return min(100, sum(weights[f.severity] for f in findings))


def as_text(findings: List[Finding], source: str, rule_count: int) -> str:
    lines = [f"Firewall policy review: {source}  ({rule_count} rules)",
             f"Risk score: {risk_score(findings)}/100  " +
             "  ".join(f"{k}={v}" for k, v in summary(findings).items()), ""]
    for f in findings:
        lines.append(f"[{f.severity.upper():8}] {f.check:24} {f.rule}")
        lines.append(f"           {f.message}")
        lines.append(f"           -> {f.recommendation}")
    if not findings:
        lines.append("No findings.")
    return "\n".join(lines)


def as_json(findings: List[Finding], source: str, rule_count: int) -> str:
    return json.dumps({
        "source": source, "rules": rule_count, "risk_score": risk_score(findings),
        "summary": summary(findings), "findings": [f.to_dict() for f in findings],
    }, indent=2)


def as_markdown(findings: List[Finding], source: str, rule_count: int) -> str:
    s = summary(findings)
    out = [
        "# Firewall Policy Audit Report", "",
        f"- **Policy source:** `{source}`",
        f"- **Date:** {date.today().isoformat()}",
        f"- **Rules reviewed:** {rule_count}",
        f"- **Risk score:** {risk_score(findings)}/100", "",
        "## Summary", "", "| Severity | Count |", "|---|---|",
        *[f"| {k.capitalize()} | {v} |" for k, v in s.items()], "",
        "## Findings", "",
        "| # | Severity | Check | Rule | Issue | Recommendation |", "|---|---|---|---|---|---|",
    ]
    for i, f in enumerate(findings, 1):
        out.append(f"| {i} | {f.severity} | {f.check} | {f.rule} | {f.message} | {f.recommendation} |")
    return "\n".join(out) + "\n"


def changes_as_text(results: List[ChangeResult]) -> str:
    lines = []
    for r in results:
        lines.append(f"[{r.verdict:16}] {r.request_id}: {r.traffic}  (currently {r.current})")
        for risk in r.risks:
            lines.append(f"                   ! {risk}")
        lines.append(f"                   {r.notes}")
    return "\n".join(lines)
