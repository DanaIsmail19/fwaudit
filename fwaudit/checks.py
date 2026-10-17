"""Firewall policy review checks (rule hygiene, risk and compliance)."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List

from .model import Rule

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

RISKY_PORTS: Dict[int, str] = {
    21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MS-SQL", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 161: "SNMP",
}


@dataclass
class Finding:
    check: str
    severity: str
    rule: str
    message: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


def risky_ports_in(rule: Rule) -> List[str]:
    if rule.is_any_port():
        return ["ALL ports"]
    return [f"{name}/{p}" for p, name in RISKY_PORTS.items() if any(lo <= p <= hi for lo, hi in rule.ports)]


def check_any_any(rules: List[Rule]) -> List[Finding]:
    return [
        Finding("ANY_ANY_ALLOW", "critical", r.label(),
                "Rule allows any source to any destination on any service.",
                "Replace with explicit source, destination and service objects.")
        for r in rules
        if r.enabled and r.action == "allow" and r.is_any_src() and r.is_any_dst() and r.is_any_port()
    ]


def check_risky_from_any(rules: List[Rule]) -> List[Finding]:
    out = []
    for r in rules:
        if not (r.enabled and r.action == "allow" and r.is_any_src()):
            continue
        if r.is_any_dst() and r.is_any_port():
            continue  # already reported as ANY_ANY_ALLOW
        risky = risky_ports_in(r)
        if risky:
            out.append(Finding("RISKY_SERVICE_FROM_ANY", "high", r.label(),
                               f"Risky service(s) reachable from any source: {', '.join(risky)}.",
                               "Restrict the source to management or trusted networks, or use VPN/ZTNA."))
    return out


def check_shadowed_and_redundant(rules: List[Rule]) -> List[Finding]:
    out = []
    active = [r for r in rules if r.enabled]
    for i, later in enumerate(active):
        for earlier in active[:i]:
            if earlier.covers(later):
                if earlier.action != later.action:
                    out.append(Finding("SHADOWED_RULE", "high", later.label(),
                                       f"Never matches: fully covered by earlier rule {earlier.label()} "
                                       f"with the opposite action ({earlier.action}).",
                                       "Reorder or remove; confirm the intended behaviour with the rule owner."))
                else:
                    out.append(Finding("REDUNDANT_RULE", "low", later.label(),
                                       f"Fully covered by earlier rule {earlier.label()} with the same action.",
                                       "Remove the redundant rule to reduce policy complexity."))
                break
    return out


def check_logging(rules: List[Rule]) -> List[Finding]:
    return [
        Finding("LOGGING_DISABLED", "medium", r.label(),
                "Allow rule does not log traffic, limiting audit and incident investigation.",
                "Enable traffic logging (e.g. FortiOS `set logtraffic all`).")
        for r in rules
        if r.enabled and r.action == "allow" and r.log is False
    ]


def check_broad_source(rules: List[Rule]) -> List[Finding]:
    return [
        Finding("BROAD_SOURCE", "medium", r.label(),
                "Allow rule uses a very broad source network (/8 or larger).",
                "Narrow the source to the networks that actually need access.")
        for r in rules
        if r.enabled and r.action == "allow" and not r.is_any_src()
        and any(n.prefixlen <= 8 for n in r.src)
    ]


def check_disabled(rules: List[Rule]) -> List[Finding]:
    return [
        Finding("DISABLED_RULE", "low", r.label(),
                "Rule is disabled but still present in the policy.",
                "Remove after confirming with the owner, or document why it is kept.")
        for r in rules if not r.enabled
    ]


def check_documentation(rules: List[Rule]) -> List[Finding]:
    return [
        Finding("MISSING_COMMENT", "low", r.label(),
                "Rule has no comment/ticket reference for change traceability.",
                "Add the change ticket ID, owner and business justification.")
        for r in rules
        if r.comment is not None and not r.comment.strip() and r.action == "allow"
    ]


ALL_CHECKS = [
    check_any_any, check_risky_from_any, check_shadowed_and_redundant,
    check_logging, check_broad_source, check_disabled, check_documentation,
]


def run_all(rules: List[Rule]) -> List[Finding]:
    findings = [f for check in ALL_CHECKS for f in check(rules)]
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])
