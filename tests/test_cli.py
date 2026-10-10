"""Command-line handling: options and where the key is looked for."""

import pytest
from helpers import ORIGIN

from zedit import cli


def test_find_keyfile_order(tmp_path, monkeypatch):
    """Without -k: $ZEDIT_KEYFILE, else the zone's own key, else default.key,
    else no key; each one found takes precedence over the ones after it."""
    monkeypatch.delenv("ZEDIT_KEYFILE", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert cli.find_keyfile(ORIGIN) is None
    default = tmp_path / "zedit" / "default.key"
    default.parent.mkdir()
    default.write_text("x")
    assert cli.find_keyfile(ORIGIN) == str(default)
    zone = tmp_path / "zedit" / "keys" / "example.com.key"
    zone.parent.mkdir()
    zone.write_text("x")
    assert cli.find_keyfile(ORIGIN) == str(zone)
    monkeypatch.setenv("ZEDIT_KEYFILE", "/elsewhere.key")
    assert cli.find_keyfile(ORIGIN) == "/elsewhere.key"


@pytest.mark.parametrize("value", ["0", "65536", "-1", "x"])
def test_port_out_of_range_is_a_usage_error(value, capsys):
    """A port outside 1-65535 is rejected by the parser (exit status 2, as for
    any bad option), instead of failing later with a traceback."""
    with pytest.raises(SystemExit) as e:
        cli.make_parser().parse_args(["-p", value, "example.com"])
    assert e.value.code == 2 and "is not a port number (1-65535)" in capsys.readouterr().err


def test_port_in_range():
    """The highest port is still a port."""
    assert cli.make_parser().parse_args(["-p", "65535", "example.com"]).port == 65535
