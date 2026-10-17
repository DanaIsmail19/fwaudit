import json

from fwaudit.change import first_match, validate_file, validate_request
from fwaudit.cli import main


def test_first_match_and_implicit_deny(ipt_rules):
    assert first_match(ipt_rules, "10.99.0.5", "1.1.1.1", "tcp", 22).id == "INPUT-1"
    assert first_match(ipt_rules, "8.8.8.8", "1.1.1.1", "tcp", 3389) is None


def test_change_verdicts(forti_rules, examples_dir):
    res = {r.request_id: r for r in validate_file(forti_rules, str(examples_dir / "change_requests.json"))}
    assert res["CHG-3001"].verdict == "NO_CHANGE_NEEDED"
    assert res["CHG-3002"].verdict == "BLOCKED_BY_DENY"
    assert res["CHG-3003"].verdict == "SCOPE_REQUIRED"
    assert "No change ticket reference" in res["CHG-3004"].risks


def test_change_implement_vs_reject(ipt_rules):
    ok = validate_request(ipt_rules, {"src": "10.1.1.1", "dst": "10.2.2.2", "port": 8080,
                                      "ticket": "T1", "justification": "app"})
    risky = validate_request(ipt_rules, {"src": "0.0.0.0/0", "dst": "10.2.2.2", "port": 3389,
                                         "ticket": "T2", "justification": "remote"})
    assert ok.verdict == "IMPLEMENT"
    assert risky.verdict == "REJECT_RISK"


def test_cli_json_output(examples_dir, capsys):
    assert main(["audit", str(examples_dir / "fortigate.conf"), "--output", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["rules"] == 9 and data["summary"]["critical"] == 1


def test_cli_fail_on(examples_dir, capsys):
    assert main(["audit", str(examples_dir / "fortigate.conf"), "--fail-on", "critical"]) == 1
    assert main(["audit", str(examples_dir / "iptables.rules"), "--fail-on", "critical"]) == 0


def test_cli_markdown_report(examples_dir, capsys):
    main(["audit", str(examples_dir / "fortigate.conf"), "--output", "markdown"])
    out = capsys.readouterr().out
    assert out.startswith("# Firewall Policy Audit Report") and "| Critical | 1 |" in out


def test_cli_query(examples_dir, capsys):
    main(["query", str(examples_dir / "fortigate.conf"), "--src", "10.10.1.1", "--dst", "172.16.20.5", "--port", "3306"])
    assert "DENY" in capsys.readouterr().out
