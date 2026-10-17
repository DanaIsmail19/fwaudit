from fwaudit.checks import run_all


def by_check(findings, name):
    return {f.rule for f in findings if f.check == name}


def test_forti_findings(forti_rules):
    f = run_all(forti_rules)
    assert by_check(f, "ANY_ANY_ALLOW") == {"policy-9 (Any-Any-Temp)"}
    assert by_check(f, "RISKY_SERVICE_FROM_ANY") == {"policy-3 (Internet-RDP)"}
    assert by_check(f, "SHADOWED_RULE") == {"policy-5 (Users-to-DB-MySQL)"}
    assert by_check(f, "REDUNDANT_RULE") == {"policy-6 (Web-dup)"}
    assert by_check(f, "LOGGING_DISABLED") == {"policy-3 (Internet-RDP)"}
    assert by_check(f, "BROAD_SOURCE") == {"policy-7 (Corp-wide-web)"}
    assert by_check(f, "DISABLED_RULE") == {"policy-8 (Old-temp-rule)"}


def test_findings_sorted_by_severity(forti_rules):
    sev = [f.severity for f in run_all(forti_rules)]
    order = ["critical", "high", "medium", "low"]
    assert sev == sorted(sev, key=order.index)


def test_disabled_rules_not_used_for_shadowing(forti_rules):
    # policy-8 is a disabled any/any rule; it must not shadow policy-9
    assert "policy-9 (Any-Any-Temp)" not in by_check(run_all(forti_rules), "REDUNDANT_RULE")


def test_iptables_findings(ipt_rules):
    f = run_all(ipt_rules)
    assert by_check(f, "RISKY_SERVICE_FROM_ANY") == {"INPUT-2"}
    assert by_check(f, "REDUNDANT_RULE") == {"INPUT-4"}
