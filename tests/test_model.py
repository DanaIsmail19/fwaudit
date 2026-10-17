from fwaudit.model import Rule, net


def mk(**kw):
    return Rule(id=kw.pop("id", "r"), action=kw.pop("action", "allow"), **kw)


def test_net_any_aliases():
    assert net("all").prefixlen == 0
    assert net("any").prefixlen == 0


def test_matches_port_and_subnet():
    r = mk(src=[net("10.0.0.0/24")], dst=[net("192.168.1.10")], proto="tcp", ports=[(443, 443)])
    assert r.matches("10.0.0.5", "192.168.1.10", "tcp", 443)
    assert not r.matches("10.0.1.5", "192.168.1.10", "tcp", 443)
    assert not r.matches("10.0.0.5", "192.168.1.10", "tcp", 80)
    assert not r.matches("10.0.0.5", "192.168.1.10", "udp", 443)


def test_covers_subnet_and_port_range():
    broad = mk(src=[net("10.0.0.0/8")], proto="tcp", ports=[(1, 1024)])
    narrow = mk(src=[net("10.1.2.0/24")], proto="tcp", ports=[(22, 22), (443, 443)])
    assert broad.covers(narrow)
    assert not narrow.covers(broad)


def test_any_proto_covers_everything():
    assert mk().covers(mk(proto="udp", ports=[(53, 53)]))


def test_different_proto_not_covered():
    assert not mk(proto="tcp", ports=[(53, 53)]).covers(mk(proto="udp", ports=[(53, 53)]))
