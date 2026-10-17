"""fwaudit command-line interface."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, report
from .change import first_match, validate_file
from .checks import SEVERITY_ORDER, run_all
from .parsers import load


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="fwaudit", description="Firewall policy review and change validation.")
    p.add_argument("--version", action="version", version=f"fwaudit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="Review a policy for risky, shadowed and undocumented rules")
    a.add_argument("policy")
    a.add_argument("--format", default="auto", choices=["auto", "fortios", "iptables", "json"])
    a.add_argument("--output", default="text", choices=["text", "json", "markdown"])
    a.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="Exit 1 if a finding at/above this severity exists")

    q = sub.add_parser("query", help="Simulate a flow and show which rule matches")
    q.add_argument("policy")
    q.add_argument("--format", default="auto", choices=["auto", "fortios", "iptables", "json"])
    q.add_argument("--src", required=True)
    q.add_argument("--dst", required=True)
    q.add_argument("--proto", default="tcp", choices=["tcp", "udp", "icmp"])
    q.add_argument("--port", type=int, default=0)

    c = sub.add_parser("change", help="Validate firewall change requests against the current policy")
    c.add_argument("policy")
    c.add_argument("requests", help="JSON file with change requests")
    c.add_argument("--format", default="auto", choices=["auto", "fortios", "iptables", "json"])
    c.add_argument("--output", default="text", choices=["text", "json"])

    args = p.parse_args(argv)
    rules = load(args.policy, args.format)

    if args.cmd == "audit":
        findings = run_all(rules)
        render = {"text": report.as_text, "json": report.as_json, "markdown": report.as_markdown}[args.output]
        print(render(findings, args.policy, len(rules)))
        if args.fail_on:
            limit = SEVERITY_ORDER[args.fail_on]
            return 1 if any(SEVERITY_ORDER[f.severity] <= limit for f in findings) else 0
        return 0

    if args.cmd == "query":
        hit = first_match(rules, args.src, args.dst, args.proto, args.port)
        if hit is None:
            print(f"DENY  (implicit deny) {args.src} -> {args.dst} {args.proto}/{args.port}")
        else:
            print(f"{hit.action.upper():5} matched {hit.label()}  {args.src} -> {args.dst} {args.proto}/{args.port}")
        return 0

    results = validate_file(rules, args.requests)
    if args.output == "json":
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        print(report.changes_as_text(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
