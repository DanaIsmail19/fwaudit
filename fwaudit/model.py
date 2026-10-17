"""Vendor-neutral firewall rule model and matching logic."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

Network = ipaddress.IPv4Network
PortRange = Tuple[int, int]

ANY_NET = ipaddress.ip_network("0.0.0.0/0")
ALL_PORTS: PortRange = (0, 65535)


def net(value: str) -> Network:
    value = value.strip()
    if value.lower() in ("any", "all", "0.0.0.0/0"):
        return ANY_NET
    return ipaddress.ip_network(value, strict=False)


@dataclass
class Rule:
    id: str
    action: str  # "allow" | "deny"
    src: List[Network] = field(default_factory=lambda: [ANY_NET])
    dst: List[Network] = field(default_factory=lambda: [ANY_NET])
    proto: str = "any"  # "tcp" | "udp" | "icmp" | "any"
    ports: List[PortRange] = field(default_factory=lambda: [ALL_PORTS])
    name: str = ""
    log: Optional[bool] = None  # None = unknown for this vendor
    enabled: bool = True
    comment: Optional[str] = None  # None = vendor has no comment field

    # -- helpers ---------------------------------------------------------
    def label(self) -> str:
        return f"{self.id}" + (f" ({self.name})" if self.name else "")

    def is_any_src(self) -> bool:
        return any(n == ANY_NET for n in self.src)

    def is_any_dst(self) -> bool:
        return any(n == ANY_NET for n in self.dst)

    def is_any_port(self) -> bool:
        return self.proto == "any" or any(p == ALL_PORTS for p in self.ports)

    def matches(self, src_ip: str, dst_ip: str, proto: str, port: int) -> bool:
        s = ipaddress.ip_address(src_ip)
        d = ipaddress.ip_address(dst_ip)
        if not any(s in n for n in self.src):
            return False
        if not any(d in n for n in self.dst):
            return False
        if self.proto != "any" and self.proto != proto:
            return False
        if self.proto in ("any", "icmp") or proto == "icmp":
            return True
        return any(lo <= port <= hi for lo, hi in self.ports)

    def covers(self, other: "Rule") -> bool:
        """True if every packet matched by `other` is also matched by self."""
        if not _nets_cover(self.src, other.src) or not _nets_cover(self.dst, other.dst):
            return False
        if self.proto != "any" and self.proto != other.proto:
            return False
        if self.proto == "any" or self.is_any_port():
            return True
        if other.proto in ("any", "icmp"):
            return other.proto == "icmp" and self.proto == "icmp"
        return all(any(lo <= olo and ohi <= hi for lo, hi in self.ports) for olo, ohi in other.ports)


def _nets_cover(outer: List[Network], inner: List[Network]) -> bool:
    return all(any(i.subnet_of(o) for o in outer) for i in inner)
