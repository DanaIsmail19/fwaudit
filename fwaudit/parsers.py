"""Parsers that turn vendor configurations into a list of Rule objects.

Supported formats:
  * fortios   - FortiGate `show full-configuration` / backup .conf
  * iptables  - output of `iptables-save`
  * json      - vendor-neutral JSON rule list (see examples/policy.json)
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Dict, List, Tuple

from .model import ALL_PORTS, ANY_NET, PortRange, Rule, net

# FortiOS predefined services (subset of the defaults shipped on FortiGate)
FORTI_PREDEFINED: Dict[str, Tuple[str, List[PortRange]]] = {
    "ALL": ("any", [ALL_PORTS]),
    "ALL_TCP": ("tcp", [ALL_PORTS]),
    "ALL_UDP": ("udp", [ALL_PORTS]),
    "ALL_ICMP": ("icmp", [ALL_PORTS]),
    "PING": ("icmp", [ALL_PORTS]),
    "HTTP": ("tcp", [(80, 80)]),
    "HTTPS": ("tcp", [(443, 443)]),
    "SSH": ("tcp", [(22, 22)]),
    "TELNET": ("tcp", [(23, 23)]),
    "FTP": ("tcp", [(21, 21)]),
    "SMTP": ("tcp", [(25, 25)]),
    "SMTPS": ("tcp", [(465, 465)]),
    "DNS": ("udp", [(53, 53)]),
    "NTP": ("udp", [(123, 123)]),
    "RDP": ("tcp", [(3389, 3389)]),
    "SMB": ("tcp", [(445, 445)]),
    "SNMP": ("udp", [(161, 162)]),
    "MYSQL": ("tcp", [(3306, 3306)]),
    "MS-SQL": ("tcp", [(1433, 1433)]),
    "LDAP": ("tcp", [(389, 389)]),
    "VNC": ("tcp", [(5900, 5900)]),
}


def load(path: str, fmt: str = "auto") -> List[Rule]:
    text = Path(path).read_text(encoding="utf-8")
    if fmt == "auto":
        fmt = detect_format(path, text)
    if fmt == "fortios":
        return parse_fortios(text)
    if fmt == "iptables":
        return parse_iptables(text)
    if fmt == "json":
        return parse_json(text)
    raise ValueError(f"Unsupported format: {fmt}")


def detect_format(path: str, text: str) -> str:
    if path.endswith(".json"):
        return "json"
    if "config firewall policy" in text:
        return "fortios"
    if re.search(r"^\*filter", text, re.M) or re.search(r"^-A ", text, re.M):
        return "iptables"
    raise ValueError("Could not detect configuration format; pass --format")


def _ports(spec: str) -> List[PortRange]:
    out: List[PortRange] = []
    for part in re.split(r"[ ,]+", spec.strip()):
        if not part:
            continue
        part = part.split(":")[0]  # FortiOS dst[:src] port syntax
        lo, _, hi = part.partition("-")
        out.append((int(lo), int(hi or lo)))
    return out


# ---------------------------------------------------------------------------
# FortiOS
# ---------------------------------------------------------------------------
def _fortios_blocks(text: str, section: str) -> Dict[str, Dict[str, List[str]]]:
    """Return {edit_name: {setting: [values]}} for one `config ...` section."""
    m = re.search(rf"^\s*config {re.escape(section)}\s*$(.*?)^\s*end\s*$", text, re.M | re.S)
    blocks: Dict[str, Dict[str, List[str]]] = {}
    if not m:
        return blocks
    current = None
    for line in m.group(1).splitlines():
        line = line.strip()
        if line.startswith("edit "):
            current = shlex.split(line[5:])[0]
            blocks[current] = {}
        elif line.startswith("set ") and current is not None:
            parts = shlex.split(line[4:])
            blocks[current][parts[0]] = parts[1:]
        elif line == "next":
            current = None
    return blocks


def parse_fortios(text: str) -> List[Rule]:
    addresses: Dict[str, List] = {"all": [ANY_NET]}
    for name, s in _fortios_blocks(text, "firewall address").items():
        if "subnet" in s:
            ip, mask = s["subnet"][0], s["subnet"][1] if len(s["subnet"]) > 1 else "32"
            addresses[name] = [net(f"{ip}/{mask}")]
        elif "start-ip" in s:  # iprange -> approximate with the start host
            addresses[name] = [net(s["start-ip"][0])]
        else:
            addresses[name] = [ANY_NET]
    for name, s in _fortios_blocks(text, "firewall addrgrp").items():
        addresses[name] = [n for m in s.get("member", []) for n in addresses.get(m, [])]

    services = dict(FORTI_PREDEFINED)
    for name, s in _fortios_blocks(text, "firewall service custom").items():
        if "tcp-portrange" in s:
            services[name] = ("tcp", _ports(" ".join(s["tcp-portrange"])))
        elif "udp-portrange" in s:
            services[name] = ("udp", _ports(" ".join(s["udp-portrange"])))

    rules: List[Rule] = []
    for pid, s in _fortios_blocks(text, "firewall policy").items():
        svc_names = s.get("service", ["ALL"])
        protos = {services.get(n, ("any", [ALL_PORTS]))[0] for n in svc_names}
        proto = protos.pop() if len(protos) == 1 else "any"
        ports = [p for n in svc_names for p in services.get(n, ("any", [ALL_PORTS]))[1]]
        rules.append(
            Rule(
                id=f"policy-{pid}",
                name=(s.get("name") or [""])[0],
                action="allow" if (s.get("action") or ["deny"])[0] == "accept" else "deny",
                src=[n for a in s.get("srcaddr", ["all"]) for n in addresses.get(a, [ANY_NET])],
                dst=[n for a in s.get("dstaddr", ["all"]) for n in addresses.get(a, [ANY_NET])],
                proto=proto,
                ports=ports or [ALL_PORTS],
                log=(s.get("logtraffic") or ["utm"])[0] != "disable",
                enabled=(s.get("status") or ["enable"])[0] != "disable",
                comment=" ".join(s.get("comments", [])),
            )
        )
    return rules


# ---------------------------------------------------------------------------
# iptables-save
# ---------------------------------------------------------------------------
def parse_iptables(text: str, chain: str = "INPUT") -> List[Rule]:
    rules: List[Rule] = []
    log_next = False
    n = 0
    for line in text.splitlines():
        if not line.startswith(f"-A {chain} "):
            continue
        tok = shlex.split(line)
        opts: Dict[str, str] = {}
        i = 2
        while i < len(tok):
            if tok[i].startswith("-") and i + 1 < len(tok) and not tok[i + 1].startswith("-"):
                opts[tok[i]] = tok[i + 1]
                i += 2
            else:
                i += 1
        target = opts.get("-j", "")
        if target == "LOG":
            log_next = True
            continue
        if target not in ("ACCEPT", "DROP", "REJECT"):
            continue
        # Loopback and established/related return traffic are standard, not policy
        if opts.get("-i") == "lo" or "--state" in opts or "--ctstate" in opts:
            log_next = False
            continue
        n += 1
        port_spec = opts.get("--dport") or opts.get("--dports")
        rules.append(
            Rule(
                id=f"{chain}-{n}",
                action="allow" if target == "ACCEPT" else "deny",
                src=[net(opts.get("-s", "any"))],
                dst=[net(opts.get("-d", "any"))],
                proto=opts.get("-p", "any"),
                ports=_ports(port_spec.replace(":", "-")) if port_spec else [ALL_PORTS],
                log=log_next,
                comment=opts.get("--comment"),
            )
        )
        log_next = False
    return rules


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def parse_json(text: str) -> List[Rule]:
    rules = []
    for i, r in enumerate(json.loads(text)["rules"], 1):
        rules.append(
            Rule(
                id=str(r.get("id", i)),
                name=r.get("name", ""),
                action=r["action"],
                src=[net(x) for x in r.get("src", ["any"])],
                dst=[net(x) for x in r.get("dst", ["any"])],
                proto=r.get("proto", "any"),
                ports=_ports(",".join(map(str, r["ports"]))) if r.get("ports") else [ALL_PORTS],
                log=r.get("log"),
                enabled=r.get("enabled", True),
                comment=r.get("comment"),
            )
        )
    return rules
