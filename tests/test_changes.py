import pytest
from helpers import CDNSKEY_RDATA, CDS_RDATA, ORIGIN, changeset, lines, model, soa_rd

from zedit import changes, rfc2136, zonefile
from zedit.model import ZeditError


def test_serial_max_rfc1982():
    assert changes.serial_max(100, None) == 100
    assert changes.serial_max(100, 105) == 105
    assert changes.serial_max(105, 100) == 105
    assert changes.serial_max(4294967290, 3) == 3  # wrapped, 3 is "greater"


def test_soa_update_uses_live_serial():
    _, old, _ = model("", soa="@ 3600 IN SOA ns1 hm 100 7200 900 1209600 300\n")
    _, new, _ = model("", soa="@ 3600 IN SOA ns1 hm 100 7200 900 1209600 60\n")
    soa, _ = changes.soa_to_send(old, new, soa_rd("117 7200 900 1209600 300"))
    assert soa[0].serial == 118


def test_soa_keeps_concurrent_changes_to_other_fields():
    """Mine: MINIMUM 300 -> 60; on the server meanwhile: REFRESH 7200 -> 3600.
    Both survive, instead of mine overwriting the server's REFRESH."""
    base, mine = soa_rd("100 7200 900 1209600 300"), soa_rd("100 7200 900 1209600 60")
    live = soa_rd("105 3600 900 1209600 300")
    soa, conflicts = changes.soa_to_send(base, mine, live)
    assert (soa[0].serial, soa[0].refresh, soa[0].minimum, conflicts) == (106, 3600, 60, [])


def test_soa_keeps_concurrent_changes_to_locked_fields():
    """Mine: MINIMUM 300 -> 60; on the server meanwhile: MNAME ns1 -> ns2 and the
    SOA TTL 3600 -> 7200. The SOA sent has the server's MNAME and TTL, not the
    transferred ones."""
    base, mine = soa_rd("100 7200 900 1209600 300"), soa_rd("100 7200 900 1209600 60")
    _, live, _ = model("", soa="@ 7200 IN SOA ns2 hm 105 7200 900 1209600 300\n")
    soa, conflicts = changes.soa_to_send(base, mine, live)
    assert (str(soa[0].mname), soa.ttl, soa[0].minimum, conflicts) == ("ns2", 7200, 60, [])
    (line,) = lines(rfc2136.soa_update(soa, ORIGIN))
    assert line == (
        "update add example.com. 7200 IN SOA ns2.example.com. hm.example.com. 106 7200 900 1209600 60"
    )


def test_soa_conflict_on_the_same_field():
    base, mine = soa_rd("100 7200 900 1209600 300"), soa_rd("100 7200 900 1209600 60")
    live = soa_rd("105 7200 900 1209600 120")
    _, conflicts = changes.soa_to_send(base, mine, live)
    assert conflicts == ["MINIMUM"]


def test_soa_not_sent_blind():
    base, mine = soa_rd("100 7200 900 1209600 300"), soa_rd("100 7200 900 1209600 60")
    with pytest.raises(ZeditError, match="current SOA"):
        changes.soa_to_send(base, mine, None)


def test_signal_warnings():
    base, _, _ = model(f"stale CDS {CDS_RDATA}\n")
    new, _, _ = model(
        f"stale CDS {CDS_RDATA}\n"  # unchanged: no warning
        f"_dsboot.a.example CDS {CDS_RDATA}\n"
        f"_DSBOOT.b.example CDNSKEY {CDNSKEY_RDATA}\n"  # DNS names are case-insensitive
        f"_dsbot.c.example CDS {CDS_RDATA}\n"
    )
    (warning,) = changes.signal_warnings(base, new)
    assert warning.startswith("_dsbot.c.example CDS is not at a _dsboot name")


def test_ascii_warnings():
    base, _, _ = model('old TXT "v=spf1 include:r\u00e4ksm\u00f6rg\u00e5s.se -all"\n')
    new, _, _ = model(
        'old TXT "v=spf1 include:r\u00e4ksm\u00f6rg\u00e5s.se -all"\n'  # unchanged: no warning
        '@ TXT "v=spf1 ip4:192.0.2.0/24 \u2013all"\n'  # pasted en dash
        'ok TXT "v=spf1 -all"\n'
        'sel._domainkey TXT "v=DKIM1; k=rsa; " "p=MIGf\u00a0MA0"\n'  # no-break space, split string
        '_dmarc TXT "v=DMARC1; p=none; rua=mailto:d@r\u00e4ksm\u00f6rg\u00e5s.se"\n'
        'note TXT "R\u00e4ksm\u00f6rg\u00e5s"\n'  # free text may be anything
        'v10 TXT "v=spf10 \u00e5"\n'
    )
    warnings = changes.ascii_warnings(base, new)
    assert [w.split(":")[0] for w in warnings] == ["@ TXT", "_dmarc TXT", "sel._domainkey TXT"]
    assert "SPF records must be ASCII" in warnings[0] and "A-labels (xn--...)" in warnings[0]
    assert "DMARC" in warnings[1] and "DKIM" in warnings[2]


def test_change_count_counts_records_as_the_diff_shows_them():
    """The summary before sending counts the records the diff adds and removes."""
    old, _, _ = model(
        "www 300 A 192.0.2.1\nmx 300 A 192.0.2.5\nttl 300 A 192.0.2.7\nttl 300 A 192.0.2.8\n"
        "twenties 60 A 127.0.0.20\ntwenties 60 A 127.0.0.21\ntwenties 60 A 127.0.0.22\n"
    )
    new, _, _ = model(
        "www 300 A 192.0.2.1\nwww 300 A 192.0.2.2\nmx 300 A 192.0.2.6\n"
        "ttl 60 A 192.0.2.7\nttl 60 A 192.0.2.8\n"
        "tens 60 A 127.0.0.10\ntens 60 A 127.0.0.11\ntens 60 A 127.0.0.12\n"
    )
    # deleted: mx, ttl x2 (new TTL), twenties x3; added: www, mx, ttl x2, tens x3
    assert changes.change_count(changeset(old, new)) == (6, 7)
    assert changes.change_count(changeset(old, old)) == (0, 0)
    old_lines, new_lines = zonefile.rr_lines(old, ORIGIN), zonefile.rr_lines(new, ORIGIN)
    assert changes.change_count(changeset(old, new)) == (
        len(set(old_lines) - set(new_lines)),
        len(set(new_lines) - set(old_lines)),
    )
