# Firewall Policy Audit Report

- **Policy source:** `examples/fortigate.conf`
- **Date:** 2026-10-16
- **Rules reviewed:** 9
- **Risk score:** 58/100

## Summary

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 2 |
| Medium | 2 |
| Low | 5 |

## Findings

| # | Severity | Check | Rule | Issue | Recommendation |
|---|---|---|---|---|---|
| 1 | critical | ANY_ANY_ALLOW | policy-9 (Any-Any-Temp) | Rule allows any source to any destination on any service. | Replace with explicit source, destination and service objects. |
| 2 | high | RISKY_SERVICE_FROM_ANY | policy-3 (Internet-RDP) | Risky service(s) reachable from any source: RDP/3389. | Restrict the source to management or trusted networks, or use VPN/ZTNA. |
| 3 | high | SHADOWED_RULE | policy-5 (Users-to-DB-MySQL) | Never matches: fully covered by earlier rule policy-4 (Block-DB) with the opposite action (deny). | Reorder or remove; confirm the intended behaviour with the rule owner. |
| 4 | medium | LOGGING_DISABLED | policy-3 (Internet-RDP) | Allow rule does not log traffic, limiting audit and incident investigation. | Enable traffic logging (e.g. FortiOS `set logtraffic all`). |
| 5 | medium | BROAD_SOURCE | policy-7 (Corp-wide-web) | Allow rule uses a very broad source network (/8 or larger). | Narrow the source to the networks that actually need access. |
| 6 | low | REDUNDANT_RULE | policy-6 (Web-dup) | Fully covered by earlier rule policy-1 (Users-to-Web) with the same action. | Remove the redundant rule to reduce policy complexity. |
| 7 | low | DISABLED_RULE | policy-8 (Old-temp-rule) | Rule is disabled but still present in the policy. | Remove after confirming with the owner, or document why it is kept. |
| 8 | low | MISSING_COMMENT | policy-3 (Internet-RDP) | Rule has no comment/ticket reference for change traceability. | Add the change ticket ID, owner and business justification. |
| 9 | low | MISSING_COMMENT | policy-7 (Corp-wide-web) | Rule has no comment/ticket reference for change traceability. | Add the change ticket ID, owner and business justification. |
| 10 | low | MISSING_COMMENT | policy-8 (Old-temp-rule) | Rule has no comment/ticket reference for change traceability. | Add the change ticket ID, owner and business justification. |

