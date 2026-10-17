from pathlib import Path

import pytest

from fwaudit.parsers import load

EX = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def forti_rules():
    return load(str(EX / "fortigate.conf"))


@pytest.fixture
def ipt_rules():
    return load(str(EX / "iptables.rules"))


@pytest.fixture
def examples_dir():
    return EX
