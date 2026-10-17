import pytest

from fwaudit.parsers import detect_format, parse_json


def test_fortios_policy_count_and_fields(forti_rules):
    assert len(forti_rules) == 9
    p1 = forti_rules[0]
    assert p1.id == "policy-1" and p1.name == "Users-to-Web"
    assert p1.action == "allow" and p1.proto == "tcp"
    assert (443, 443) in p1.ports and (8443, 8443) in p1.ports
    assert str(p1.src[0]) == "10.10.0.0/16"


def test_fortios_address_group_expands(forti_rules):
    mgmt = forti_rules[1]
    assert {str(n) for n in mgmt.dst} == {"172.16.10.10/32", "172.16.20.5/32"}


def test_fortios_status_and_logging(forti_rules):
    assert forti_rules[2].log is False
    assert forti_rules[7].enabled is False


def test_iptables_skips_loopback_and_state(ipt_rules):
    assert len(ipt_rules) == 4
    assert all(not (r.is_any_src() and r.is_any_dst() and r.is_any_port()) for r in ipt_rules)


def test_iptables_log_target_marks_next_rule(ipt_rules):
    web = ipt_rules[2]
    assert web.log is True and (80, 80) in web.ports and (443, 443) in web.ports


def test_iptables_comment(ipt_rules):
    assert ipt_rules[0].comment == "CHG-2001 mgmt ssh"


def test_json_parser():
    rules = parse_json('{"rules": [{"action": "allow", "src": ["10.0.0.0/8"], "proto": "tcp", "ports": ["22", "1000-2000"]}]}')
    assert rules[0].ports == [(22, 22), (1000, 2000)]


def test_detect_format_unknown():
    with pytest.raises(ValueError):
        detect_format("x.txt", "hello")
