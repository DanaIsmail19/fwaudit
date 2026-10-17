# fwaudit — Firewall Policy Review & Change Validation

![CI](https://github.com/DanaIsmail19/fwaudit/actions/workflows/ci.yml/badge.svg)

`fwaudit` is a lightweight, open-source firewall policy analyzer inspired by the workflows of commercial
policy-management platforms such as AlgoSec and Tufin. It parses **FortiGate (FortiOS)** and **iptables**
configurations into a vendor-neutral model and answers the three questions network security teams ask every day:

1. **Is the policy clean and compliant?** → `fwaudit audit`
2. **Is this traffic allowed, and by which rule?** → `fwaudit query`
3. **Does this change request need a rule change, and is it safe?** → `fwaudit change`

No dependencies beyond the Python standard library.

## Install

```bash
git clone https://github.com/DanaIsmail19/fwaudit && cd fwaudit
pip install -e ".[dev]"
```

## 1. Policy review (`audit`)

```bash
fwaudit audit examples/fortigate.conf                     # console
fwaudit audit examples/fortigate.conf --output markdown   # audit report
fwaudit audit policy.conf --fail-on high                  # CI/CD policy gate (exit 1)
```

| Check | Severity | What it finds |
|---|---|---|
| `ANY_ANY_ALLOW` | critical | Allow rules with any source, destination and service |
| `RISKY_SERVICE_FROM_ANY` | high | RDP, SMB, Telnet, FTP, SQL, VNC, SNMP… exposed to any source |
| `SHADOWED_RULE` | high | Rules that can never match because an earlier rule with the opposite action covers them |
| `REDUNDANT_RULE` | low | Rules fully covered by an earlier rule with the same action |
| `LOGGING_DISABLED` | medium | Allow rules without traffic logging |
| `BROAD_SOURCE` | medium | Sources of /8 or larger |
| `DISABLED_RULE` | low | Stale disabled rules left in the policy |
| `MISSING_COMMENT` | low | Rules without a change-ticket reference |

Each run produces a 0–100 risk score. See [`examples/sample_audit_report.md`](examples/sample_audit_report.md).

## 2. Traffic simulation (`query`)

```bash
$ fwaudit query examples/fortigate.conf --src 10.10.1.1 --dst 172.16.20.5 --port 3306
DENY  matched policy-4 (Block-DB)  10.10.1.1 -> 172.16.20.5 tcp/3306
```

First-match semantics with an implicit deny, as on FortiGate and iptables.

## 3. Change-request validation (`change`)

```bash
fwaudit change examples/fortigate.conf examples/change_requests.json
```

| Verdict | Meaning |
|---|---|
| `NO_CHANGE_NEEDED` | Traffic is already allowed by a scoped rule |
| `SCOPE_REQUIRED` | Works today only because of an any/any rule — add a scoped rule first |
| `BLOCKED_BY_DENY` | An explicit deny matches first; placement must be reviewed |
| `IMPLEMENT` | No rule matches; safe to implement a scoped, logged rule |
| `REJECT_RISK` | Risky service or any-source request; needs security approval |

Requests are also checked for a ticket reference and business justification.

## Supported inputs

| Format | Source |
|---|---|
| `fortios` | FortiGate backup / `show full-configuration` (addresses, address groups, custom services, policies) |
| `iptables` | `iptables-save` output (INPUT chain; loopback and established/related rules ignored) |
| `json` | Vendor-neutral rule list |

## Lab

[`lab/LAB_GUIDE.md`](lab/LAB_GUIDE.md) describes the Proxmox home lab used to test fwaudit against live
firewall, IPS, WAF and proxy configurations.

## Limitations

IPv4 only; FortiOS IP ranges are approximated by their start address; NAT, schedules, users and
interfaces are not modelled. Contributions welcome.

## License

MIT
