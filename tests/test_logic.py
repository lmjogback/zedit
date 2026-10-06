import dns.exception
import dns.name
import dns.zone
import pytest

from zedit import cli

ORIGIN = dns.name.from_text("example.com.")
SOA = "@ 3600 IN SOA ns1 hostmaster 100 7200 900 1209600 300\n"


def model(body, soa=SOA):
    z = dns.zone.from_text("$TTL 300\n" + soa + body, origin=ORIGIN, relativize=True, check_origin=False)
    m, s, rejected = cli.to_model(z)
    return m, s, rejected


def key(name, t):
    return (dns.name.from_text(name, None), int(dns.rdatatype.from_text(t)))


def addrs(m, name, t="A"):
    return sorted(r.to_text() for r in m[key(name, t)])


def test_dnssec_types_filtered():
    m, _, rejected = model("@ NS ns1\nns1 A 192.0.2.1\n@ NSEC3PARAM 1 0 0 -\n@ TYPE65534 \\# 5 0D12340001\n")
    assert set(m) == {key("@", "NS"), key("ns1", "A")}
    assert {k[1] for k in rejected} == {51, 65534}


def test_compute_update_minimal_and_ordered():
    old, _, _ = model("www A 192.0.2.1\nwww A 192.0.2.2\nfoo A 192.0.2.9\n")
    new, _, _ = model("www A 192.0.2.1\nwww A 192.0.2.3\nfoo CNAME www\n")
    dels, adds = cli.compute_update(old, new, ORIGIN)
    assert dels == [
        "update delete foo.example.com. IN A",
        "update delete www.example.com. IN A 192.0.2.2",
    ]
    assert sorted(adds) == [
        "update add foo.example.com. 300 IN CNAME www.example.com.",
        "update add www.example.com. 300 IN A 192.0.2.3",
    ]


def test_ttl_change_replaces_rrset():
    old, _, _ = model("www 300 A 192.0.2.1\n")
    new, _, _ = model("www 60 A 192.0.2.1\n")
    dels, adds = cli.compute_update(old, new, ORIGIN)
    assert dels == ["update delete www.example.com. IN A"]
    assert adds == ["update add www.example.com. 60 IN A 192.0.2.1"]


def test_soa_update_bumps_serial_and_wraps():
    _, old, _ = model("", soa="@ 3600 IN SOA ns1 hm 4294967295 7200 900 1209600 300\n")
    _, new, _ = model("", soa="@ 3600 IN SOA ns1 hm 4294967295 7200 900 1209600 60\n")
    (line,) = cli.soa_update(old, new, ORIGIN)
    assert " 0 7200 900 1209600 60" in line
    assert cli.soa_update(old, old, ORIGIN) == []


def test_locked_soa_fields(tmp_path):
    _, base_soa, _ = model("")
    f = tmp_path / "z.zone"
    f.write_text("$TTL 300\n@ 3600 IN SOA ns2 hostmaster 101 7200 900 1209600 300\n")
    with pytest.raises(ValueError, match="MNAME, SERIAL"):
        cli.parse_file(str(f), ORIGIN, base_soa)
    f.write_text("$TTL 300\n@ 60 IN SOA ns1 hostmaster 100 7200 900 1209600 300\n")
    with pytest.raises(ValueError, match="TTL"):
        cli.parse_file(str(f), ORIGIN, base_soa)


def test_cname_conflict_rejected(tmp_path):
    # At parse time (dnspython rejects it itself) ...
    _, base_soa, _ = model("")
    f = tmp_path / "z.zone"
    f.write_text("$TTL 300\n" + SOA + "foo CNAME www\nfoo TXT x\n")
    with pytest.raises(dns.exception.DNSException):
        cli.parse_file(str(f), ORIGIN, base_soa)
    # ... and in the model, e.g. after a merge
    a, _, _ = model("foo CNAME www\n")
    b, _, _ = model("foo TXT x\n")
    with pytest.raises(ValueError, match="CNAME"):
        cli.check_cname({**a, **b})


def test_merge_disjoint_changes():
    base, _, _ = model("a A 192.0.2.1\nb A 192.0.2.2\n")
    mine, _, _ = model("a A 192.0.2.11\nb A 192.0.2.2\n")
    theirs, _, _ = model("a A 192.0.2.1\nb A 192.0.2.22\nc A 192.0.2.3\n")
    merged, notes, dropped, conflicts = cli.merge3(base, mine, theirs)
    assert addrs(merged, "a") == ["192.0.2.11"]
    assert addrs(merged, "b") == ["192.0.2.22"]
    assert addrs(merged, "c") == ["192.0.2.3"]
    assert (notes, dropped, conflicts) == ({}, [], 0)


def test_merge_same_rrset_both_sides_with_ttl_conflict():
    base, _, _ = model("www 300 A 192.0.2.11\n")
    mine, _, _ = model("www 60 A 192.0.2.12\n")
    theirs, _, _ = model("www 900 A 192.0.2.11\nwww 900 A 192.0.2.13\n")
    merged, notes, _, conflicts = cli.merge3(base, mine, theirs)
    assert addrs(merged, "www") == ["192.0.2.12", "192.0.2.13"]
    assert merged[key("www", "A")].ttl == 60
    assert conflicts == 1 and key("www", "A") in notes


def test_merge_already_applied_is_noop():
    base, _, _ = model("a A 192.0.2.1\n")
    mine, _, _ = model("a A 192.0.2.2\n")
    merged, notes, _, conflicts = cli.merge3(base, mine, mine)
    assert addrs(merged, "a") == ["192.0.2.2"] and not notes and not conflicts


def test_merge_soa_fieldwise():
    _, b, _ = model("", soa="@ 3600 IN SOA ns1 hm 100 7200 900 1209600 300\n")
    _, m, _ = model("", soa="@ 3600 IN SOA ns1 admin 100 7200 900 1209600 300\n")
    _, t, _ = model("", soa="@ 3600 IN SOA ns1 hm 105 3600 900 1209600 300\n")
    soa, note, conflicts = cli.merge_soa(b, m, t)
    r = soa[0]
    assert (str(r.rname), r.refresh, r.serial, conflicts) == ("admin", 3600, 105, 0)


def test_prereqs_only_on_touched_rrsets():
    old, _, _ = model("www A 192.0.2.1\nwww A 192.0.2.2\nmail A 192.0.2.9\ngone TXT x\n")
    new, _, _ = model("www A 192.0.2.1\nwww A 192.0.2.3\nmail A 192.0.2.9\nnew A 192.0.2.4\n")
    assert sorted(cli.compute_prereqs(old, new, ORIGIN)) == [
        "prereq nxrrset new.example.com. IN A",
        'prereq yxrrset gone.example.com. IN TXT "x"',
        "prereq yxrrset www.example.com. IN A 192.0.2.1",
        "prereq yxrrset www.example.com. IN A 192.0.2.2",
    ]


def test_serial_max_rfc1982():
    assert cli.serial_max(100, None) == 100
    assert cli.serial_max(100, 105) == 105
    assert cli.serial_max(105, 100) == 105
    assert cli.serial_max(4294967290, 3) == 3  # wrapped, 3 is "greater"


def test_soa_update_uses_live_serial():
    _, old, _ = model("", soa="@ 3600 IN SOA ns1 hm 100 7200 900 1209600 300\n")
    _, new, _ = model("", soa="@ 3600 IN SOA ns1 hm 100 7200 900 1209600 60\n")
    (line,) = cli.soa_update(old, new, ORIGIN, current_serial=117)
    assert " 118 7200 900 1209600 60" in line


SIGNED = (
    "@ NS ns1\n"
    "@ RRSIG NS 13 2 300 20261019040406 20261005123408 34319 @ AAAA\n"
    "@ DNSKEY 257 3 13 AwEAAQ==\n"
    "@ RRSIG DNSKEY 13 2 3600 20261019133408 20261005123408 34319 @ AAAA\n"
    "@ TYPE65534 \\# 5 0d860f0001\n"
    "www A 192.0.2.10\n"
    "www RRSIG A 13 3 300 20261019040406 20261005123408 34319 @ AAAA\n"
    "www NSEC @ A RRSIG NSEC\n"
)


def test_show_all_renders_read_only_and_round_trips():
    m, soa, hidden = model(SIGNED)
    text = cli.render_file(soa, m, ORIGIN, "x", hidden=hidden)
    ro = [line for line in text.splitlines() if line.startswith(";ro ")]
    assert len(ro) == 6  # RRSIG NS, DNSKEY, RRSIG DNSKEY, TYPE65534, RRSIG A, NSEC
    lines = text.splitlines()
    # Each RRSIG set follows the type it covers
    a = next(i for i, x in enumerate(lines) if x.startswith("www") and " A " in x)
    assert " RRSIG  A " in lines[a + 1]
    k = next(i for i, x in enumerate(lines) if " DNSKEY " in x)
    assert " RRSIG  DNSKEY " in lines[k + 1]
    # Read-only lines are comments: parsing the file yields exactly the editable model
    m2, soa2 = cli.parse_text(text, ORIGIN)
    assert set(m2) == set(m) and all(cli.same(m[x], m2[x]) for x in m)


def test_no_rrsig_keeps_keys_drops_noise():
    _, _, hidden = model(SIGNED)
    ctx = cli.SimpleNamespace(show_all=True, no_rrsig=True)
    assert sorted(cli.tname(k[1]) for k in cli.shown(ctx, hidden)) == ["DNSKEY", "TYPE65534"]
    assert cli.shown(cli.SimpleNamespace(show_all=False, no_rrsig=False), hidden) is None


def test_find_keyfile_order(tmp_path, monkeypatch):
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


def test_primary_from_mname(monkeypatch):
    _, soa, _ = model("", soa="@ 3600 IN SOA ns1.example.net. hm 1 2 3 4 5\n")
    monkeypatch.setattr(cli.dns.resolver, "resolve", lambda *a, **kw: soa)
    assert cli.primary_from_mname(ORIGIN) == "ns1.example.net."


@pytest.mark.parametrize(
    "seconds, text",
    [
        (0, "0 seconds"),
        (1, "1 second"),
        (60, "1 minute"),
        (86400, "1 day"),
        (86401, "1 day and 1 second"),
        (90061, "1 day, 1 hour, 1 minute and 1 second"),
        (1209600, "2 weeks"),
    ],
)
def test_human_duration(seconds, text):
    assert cli.human_duration(seconds) == text


def test_rname_to_email():
    assert cli.rname_to_email(dns.name.from_text("hostmaster", None), ORIGIN) == "hostmaster@example.com"
    assert cli.rname_to_email(dns.name.from_text(r"john\.doe.example.net."), ORIGIN) == "john.doe@example.net"


def test_soa_help_is_comment_only():
    m, soa, _ = model("www A 192.0.2.1\n", soa="@ 3600 IN SOA ns1 hostmaster 100 86401 900 1209600 300\n")
    text = cli.render_file(soa, m, ORIGIN, "x")
    assert ";   REFRESH = 86401" in text and "(1 day and 1 second)" in text
    assert ";   EXPIRE  = 1209600" in text and "(2 weeks)" in text
    assert "contact: hostmaster@example.com" in text
    m2, soa2 = cli.parse_text(text, ORIGIN)
    assert soa2[0] == soa[0] and set(m2) == set(m)


def test_file_stem_is_a_safe_file_name():
    assert cli.file_stem(dns.name.from_text("Example.COM.")) == "example.com"
    assert cli.file_stem(dns.name.from_text("16/28.2.0.192.in-addr.arpa.")) == "16_28.2.0.192.in-addr.arpa"


def test_origin_directive_inside_zone():
    o = dns.name.from_text("2.0.192.in-addr.arpa.")
    text = "$TTL 300\n" + SOA + "$ORIGIN 2.0.192.in-addr.arpa.\n10 PTR www.example.com.\n"
    m, _ = cli.parse_text(text, o)
    assert set(m) == {(dns.name.from_text("10", None), int(dns.rdatatype.PTR))}


def test_names_outside_zone_are_rejected_not_dropped():
    # dnspython's reader would silently drop these
    text = "$TTL 300\n" + SOA + "www A 192.0.2.1\n$ORIGIN example.org.\nfoo A 192.0.2.2\n"
    with pytest.raises(ValueError, match="foo.example.org"):
        cli.parse_text(text, ORIGIN)
