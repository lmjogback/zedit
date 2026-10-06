import shutil
import subprocess

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


REV = dns.name.from_text("2.0.192.in-addr.arpa.")


def generated(line):
    text, _ = cli.expand_generate(line)
    return text.split("\n")


@pytest.mark.parametrize(
    "template, i, expected",
    [
        ("host$", 20, "host20"),
        ("dyn-${0,3,d}-${100,0,x}", 30, "dyn-030-82"),  # several modifiers per side
        ("h${0,4,X}", 42, "h002A"),
        ("${-200,3,o}", 250, "062"),
        ("${0,0,n}", 0x1A, "a.1"),
        ("${0,7,n}", 0x1A, "a.1.0.0"),  # width counts characters, dots included
        ("${0,0,N}", 0xFA, "A.F"),
        (r"x\$y$", 3, r"x\$y3"),  # escapes are left to the zone parser
    ],
)
def test_generate_substitute_like_bind(template, i, expected):
    assert cli.generate_substitute(template, i) == expected


def test_generate_range_and_step():
    assert generated("$GENERATE 30-34/2 $ PTR h$.example.com.") == [
        "30 PTR h30.example.com.",
        "32 PTR h32.example.com.",
        "34 PTR h34.example.com.",
    ]


@pytest.mark.parametrize(
    "line, match",
    [
        ("$GENERATE 5-1 $ PTR x.", "bad \\$GENERATE range"),
        ("$GENERATE 1-x $ PTR x.", "bad \\$GENERATE range"),
        ("$GENERATE 1-2 $ PTR ${0,2,q}", "bad \\$GENERATE base"),
        ("$GENERATE 1-2 $ PTR ${-5}", "negative"),
    ],
)
def test_generate_errors(line, match):
    with pytest.raises(ValueError, match=match):
        cli.expand_generate(line)


def test_generate_errors_point_at_the_users_line():
    text = "$TTL 300\n" + SOA + "$GENERATE 1-50 $ PTR h$.example.com.\nbad line here\n"
    with pytest.raises(ValueError, match="^line 4:"):
        cli.parse_text(text, REV)


def test_generate_outside_zone_is_rejected():
    text = "$TTL 300\n" + SOA + "$ORIGIN example.org.\n$GENERATE 1-3 h$ A 192.0.2.$\n"
    with pytest.raises(ValueError, match="h1.example.org.*h2.example.org.*h3.example.org"):
        cli.parse_text(text, REV)


@pytest.mark.skipif(not shutil.which("named-checkzone"), reason="named-checkzone not found")
def test_generate_matches_named_checkzone(tmp_path):
    zone = (
        "$TTL 300\n@ 3600 IN SOA ns1.example.net. hostmaster.example.net. 1 7200 900 1209600 300\n"
        "@ IN NS ns1.example.net.\n"
        "$GENERATE 20-23 $ PTR host$.example.com.\n"
        "$GENERATE 30-34/2 $ PTR dyn-${0,3,d}-${100,0,x}.example.com.\n"
        "$GENERATE 40-42 ${0,0,d} PTR h${0,4,X}-$.example.com.\n"
        "$GENERATE 1-3 w$ CNAME x\\$y$\n"
        "$GENERATE 250-254 n$ TXT ${0,5,n}-${0,0,N}-${-200,3,o}\n"
    )
    f = tmp_path / "z"
    f.write_text(zone)
    out = subprocess.check_output(
        ["named-checkzone", "-q", "-D", "-o", "-", REV.to_text(), str(f)], text=True
    )
    bind = set()
    for line in out.splitlines():
        name, _ttl, cls, rtype, rdata = line.split(None, 4)
        if rtype not in ("SOA", "NS"):
            bind.add(f"{name} {cls} {rtype} {rdata}")
    m, _ = cli.parse_text(zone, REV)
    ours = {
        f"{n.derelativize(REV)} IN {cli.tname(t)} {rd.to_text(origin=REV, relativize=False)}"
        for (n, t), rds in m.items()
        if cli.tname(t) != "NS"
        for rd in rds
    }
    assert len(bind) == 18 and ours == bind


# --- IP addresses as owner names in reverse zones -------------------------

V6 = dns.name.from_text("8.b.d.0.1.0.0.2.ip6.arpa.")
V6_NAME_1 = "1." + "0." * 23 + "8.b.d.0.1.0.0.2.ip6.arpa."


def owners(text, origin):
    m, _ = cli.parse_text("$TTL 300\n" + SOA + text, origin)
    return {k[0].derelativize(origin).to_text() for k in m}


@pytest.mark.parametrize(
    "zone, owner, name",
    [
        ("2.0.192.in-addr.arpa.", "192.0.2.10", "10.2.0.192.in-addr.arpa."),
        ("100.50.100.in-addr.arpa.", "100.50.100.50", "50.100.50.100.in-addr.arpa."),
        ("0.192.in-addr.arpa.", "192.0.2.10", "10.2.0.192.in-addr.arpa."),  # /16 zone
        ("16/28.2.0.192.in-addr.arpa.", "192.0.2.17", "17.16/28.2.0.192.in-addr.arpa."),
        ("16-31.2.0.192.in-addr.arpa.", "192.0.2.31", "31.16-31.2.0.192.in-addr.arpa."),
        ("17.2.0.192.in-addr.arpa.", "192.0.2.17", "17.2.0.192.in-addr.arpa."),  # per address: apex
        ("8.b.d.0.1.0.0.2.ip6.arpa.", "2001:db8::1", V6_NAME_1),
        ("8.b.d.0.1.0.0.2.ip6.arpa.", "2001:0DB8:0000:0:0:0:0:0001", V6_NAME_1),  # any spelling
    ],
)
def test_address_owner_round_trip(zone, owner, name):
    origin = dns.name.from_text(zone)
    assert cli.owner_to_name(owner, origin) == name
    canonical = str(cli.ipaddress.ip_address(owner))
    assert cli.name_to_address(dns.name.from_text(name), origin) == canonical


def test_address_owners_in_a_reverse_zone():
    assert owners("192.0.2.10 PTR www.example.com.\n11 PTR mail.example.com.\n", REV) == {
        "10.2.0.192.in-addr.arpa.",
        "11.2.0.192.in-addr.arpa.",
    }
    assert owners("2001:db8::1 PTR www.example.com.\n", V6) == {V6_NAME_1}


@pytest.mark.parametrize(
    "zone, owner",
    [
        ("2.0.192.in-addr.arpa.", "10.2.0.192"),  # written backwards
        ("100.50.100.in-addr.arpa.", "50.100.50.100"),  # backwards, not a palindrome
        ("2.0.192.in-addr.arpa.", "192.0.3.10"),  # another network
        ("16/28.2.0.192.in-addr.arpa.", "192.0.2.40"),  # outside the RFC 2317 range
        ("8.b.d.0.1.0.0.2.ip6.arpa.", "2001:db9::1"),
        ("8.b.d.0.1.0.0.2.ip6.arpa.", "192.0.2.10"),  # IPv4 in an ip6.arpa zone
        ("2.0.192.in-addr.arpa.", "2001:db8::1"),  # IPv6 in an in-addr.arpa zone
    ],
)
def test_address_outside_the_zone_is_rejected(zone, owner):
    with pytest.raises(ValueError, match="outside the zone"):
        owners(f"{owner} PTR x.example.com.\n", dns.name.from_text(zone))


def test_palindrome_address_is_the_same_either_way():
    origin = dns.name.from_text("20.10.in-addr.arpa.")
    assert owners("10.20.20.10 PTR x.example.com.\n", origin) == {"10.20.20.10.in-addr.arpa."}


@pytest.mark.parametrize("owner", ["192.0.2.010", "192.0.2.256", "2001:db8:::1"])
def test_invalid_address_is_an_error_with_the_users_line(owner):
    # line 1 $TTL, 2 SOA, 3 the 10 PTR record, 4 the invalid one
    with pytest.raises(ValueError, match=r"^line 4: .*not a valid one"):
        owners(f"10 PTR a.example.com.\n{owner} PTR x.example.com.\n", REV)


def test_no_rewriting_outside_reverse_zones_or_for_absolute_names():
    # In a forward zone 192.0.2.10 is an ordinary relative name
    assert owners("192.0.2.10 A 192.0.2.10\n", ORIGIN) == {"192.0.2.10.example.com."}
    # A trailing dot makes it an absolute name, used as written
    assert owners("10.2.0.192.in-addr.arpa. PTR x.example.com.\n", REV) == {"10.2.0.192.in-addr.arpa."}


def test_continuation_lines_are_not_owners():
    m, _ = cli.parse_text("$TTL 300\n" + SOA + '10 TXT ( "first"\n192.0.2.99 )\n', REV)
    ((key, rds),) = m.items()
    assert key[0].to_text() == "10" and rds[0].to_text() == '"first" "192.0.2.99"'


def test_generate_with_address_owners():
    assert owners("$GENERATE 20-22 192.0.2.$ PTR h$.example.com.\n", REV) == {
        "20.2.0.192.in-addr.arpa.",
        "21.2.0.192.in-addr.arpa.",
        "22.2.0.192.in-addr.arpa.",
    }
    v6 = owners("$GENERATE 10-11 2001:db8::${0,0,x} PTR h$.example.com.\n", V6)
    assert v6 == {n.replace("1.0.0.0.", "a.0.0.0.", 1) for n in [V6_NAME_1]} | {
        "b." + "0." * 23 + "8.b.d.0.1.0.0.2.ip6.arpa."
    }


def test_show_addresses_renders_and_round_trips():
    z = dns.zone.from_text(
        "$TTL 300\n" + SOA + "@ NS ns1.example.net.\n100 PTR c.example.com.\n"
        "2 PTR a.example.com.\n10 PTR b.example.com.\n",
        origin=REV,
        relativize=True,
    )
    m, soa, _ = cli.to_model(z)
    text = cli.render_file(soa, m, REV, "x", addresses=True)
    records = [line.split()[0] for line in text.splitlines() if " PTR " in line]
    assert records == ["192.0.2.2", "192.0.2.10", "192.0.2.100"]  # numeric order
    assert any(line.startswith("@ ") and " NS " in line for line in text.splitlines())  # apex stays @
    m2, _ = cli.parse_text(text, REV)
    assert set(m2) == set(m)


def test_show_addresses_ipv6_compressed():
    m = {(dns.name.from_text(V6_NAME_1).relativize(V6), 12): None}
    assert cli.owner_text(next(iter(m))[0], V6, True) == "2001:db8::1"
    assert cli.owner_text(next(iter(m))[0], V6, False) == V6_NAME_1.replace(".8.b.d.0.1.0.0.2.ip6.arpa.", "")


@pytest.mark.parametrize(
    "owner, match",
    [
        ("2001:123:456::2323::1", "not a valid one"),  # two ::
        ("2001:db8:1:2:3:4:5:6:7", "not a valid one"),  # nine groups
        ("2001:db8:1:2:3:4:5::6:7", "not a valid one"),  # :: with eight groups
        ("2001:db8::12345", "not a valid one"),  # five hex digits in a group
        ("2001:db8::g1", "not a valid one"),  # not hex
        ("2001:db8::1:", "not a valid one"),  # trailing single colon
        (":2001:db8::1", "not a valid one"),  # leading single colon
        ("2001:db8:::1", "not a valid one"),  # triple colon
        ("2001:db8::1%eth0", "zone id"),
        ("2001:db8::/64", "prefix"),
        ("192.0.2.0/24", "prefix"),
    ],
)
def test_malformed_address_owners(owner, match):
    with pytest.raises(ValueError, match=match):
        cli.owner_to_name(owner, V6)


@pytest.mark.parametrize("owner", ["16/28", "17.16/28", "0-127", "10", "10.2"])
def test_rfc2317_and_relative_names_are_not_addresses(owner):
    assert cli.owner_to_name(owner, REV) is None


@pytest.mark.parametrize(
    "owner",
    [
        "2001:db8:0:0:0:0:0:1",  # full form
        "2001:0db8:0000:0000:0000:0000:0000:0001",  # with leading zeros
        "2001:DB8::1",  # upper case
        "2001:db8::0:1",  # :: not at the longest run
    ],
)
def test_ipv6_spellings_give_the_same_name(owner):
    assert cli.owner_to_name(owner, V6) == V6_NAME_1


def test_ipv6_with_embedded_ipv4_notation():
    # 2001:db8::192.0.2.1 is 2001:db8::c000:201
    name = cli.owner_to_name("2001:db8::192.0.2.1", V6)
    assert name.startswith("1.0.2.0.0.0.0.c.") and name.endswith(".8.b.d.0.1.0.0.2.ip6.arpa.")
    assert cli.name_to_address(dns.name.from_text(name), V6) == "2001:db8::c000:201"


def test_ipv4_mapped_address_outside_the_zone():
    with pytest.raises(ValueError, match="outside the zone"):
        owners("::ffff:192.0.2.1 PTR x.example.com.\n", V6)
