# Network Security Lab on Proxmox

A small, reproducible lab for practising network security operations and testing `fwaudit`
against real configurations. Runs on a single Proxmox VE host (≈16 GB RAM recommended).

## Topology

```
            [ Internet / vmbr0 ]
                    |
            +---------------+
            |  FortiGate VM | <- NGFW: policies, IPS, web filter, logging
            +---------------+
              |           |
      vmbr1 (LAN)     vmbr2 (DMZ)
      10.10.0.0/16    172.16.10.0/24
         |                 |
   [Ubuntu client]   [Nginx + ModSecurity WAF] -> [demo web app]
   [Kali attacker]   [Squid forward proxy]
```

## Components and what each practises

| Component | Skills |
|---|---|
| FortiGate VM (Fortinet's evaluation licence — check current terms) | Firewall policy, address/service objects, IPS profiles, logging |
| pfSense + Suricata (alternative to FortiGate) | Open-source NGFW and IDS/IPS in inline mode |
| Nginx + ModSecurity + OWASP Core Rule Set | WAF tuning, blocking SQLi/XSS from Kali |
| Squid | Forward proxy, URL filtering, access logs |
| Kali Linux | Generating test traffic (Nmap, sqlmap, curl) |
| Wireshark / tcpdump | Packet capture and troubleshooting on each bridge |

## Exercises

1. **Baseline policy** – build LAN→DMZ policies on the firewall, export the config, run
   `fwaudit audit` and fix every finding. Keep the before/after reports.
2. **Change management** – write change requests in JSON, validate them with `fwaudit change`,
   implement only approved ones, and record ticket IDs in rule comments.
3. **IPS** – run an Nmap scan and a known exploit attempt from Kali; confirm IPS blocks and logs it.
4. **WAF** – send SQLi/XSS payloads to the web app; confirm ModSecurity blocks them; tune false positives.
5. **Troubleshooting** – break a rule on purpose, then find the cause with `fwaudit query`,
   firewall logs and a packet capture.

Document each exercise (goal, steps, evidence, result) in `lab/notes/` — this becomes your audit-style
evidence trail.
