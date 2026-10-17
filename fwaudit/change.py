"""Traffic simulation and firewall change-request validation."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

from .checks import RISKY_PORTS
from .model import Rule


def first_match(rules: List[Rule], src: str, dst: str, proto: str, port: int) -> Optional[Rule]:
    for r in rules:
        if r.enabled and r.matches(src, dst, proto, port):
            return r
    return None  # implicit deny


@dataclass
class ChangeResult:
    request_id: str
    traffic: str
    current: str
    verdict: str  # NO_CHANGE_NEEDED | IMPLEMENT | BLOCKED_BY_DENY | REJECT_RISK
    risks: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def validate_request(rules: List[Rule], req: dict) -> ChangeResult:
    src, dst = req["src"], req["dst"]
    proto, port = req.get("proto", "tcp"), int(req.get("port", 0))
    traffic = f"{src} -> {dst} {proto}/{port}"
    src_ip = str(ipaddress.ip_network(src, strict=False).network_address)
    dst_ip = str(ipaddress.ip_network(dst, strict=False).network_address)
    hit = first_match(rules, src_ip, dst_ip, proto, port)
    risks: List[str] = []

    if ipaddress.ip_network(src, strict=False).prefixlen == 0:
        risks.append("Source is ANY (0.0.0.0/0)")
    if port in RISKY_PORTS:
        risks.append(f"Risky service {RISKY_PORTS[port]}/{port}")
    if not req.get("ticket"):
        risks.append("No change ticket reference")
    if not req.get("justification"):
        risks.append("No business justification")

    rid = str(req.get("id", "?"))
    if hit and hit.action == "allow" and hit.is_any_src() and hit.is_any_dst():
        risks.append(f"Only permitted by overly broad rule {hit.label()}")
        return ChangeResult(rid, traffic, f"allowed by {hit.label()}", "SCOPE_REQUIRED", risks,
                            "Traffic works today only because of a broad rule; add a scoped, logged rule "
                            "so the broad rule can be removed safely.")
    if hit and hit.action == "allow":
        return ChangeResult(rid, traffic, f"allowed by {hit.label()}", "NO_CHANGE_NEEDED", risks,
                            "Traffic is already permitted; close the request without a policy change.")
    if hit and hit.action == "deny":
        return ChangeResult(rid, traffic, f"denied by {hit.label()}", "BLOCKED_BY_DENY", risks,
                            "An explicit deny matches first; a new allow rule must be placed above it "
                            "and reviewed with the deny rule's owner.")
    verdict = "REJECT_RISK" if any(r.startswith(("Source is ANY", "Risky")) for r in risks) else "IMPLEMENT"
    note = ("High-risk request: requires security approval before implementation."
            if verdict == "REJECT_RISK" else "No existing rule matches; add a scoped allow rule with logging.")
    return ChangeResult(rid, traffic, "implicit deny", verdict, risks, note)


def validate_file(rules: List[Rule], path: str) -> List[ChangeResult]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [validate_request(rules, r) for r in data["requests"]]
