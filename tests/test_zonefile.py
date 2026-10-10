"""Reading and writing zone files: what is editable and what is read-only,
the checks on an edited file, $GENERATE, error line numbers, internationalized
names, and the session file's layout and comments."""

import os
import shutil
import subprocess

import dns.exception
import dns.name
import dns.zone
import pytest
from helpers import CDNSKEY_RDATA, CDS_RDATA, ORIGIN, REV, SOA, key, model

from zedit import zonefile
from zedit.model import Options, same, tname


def test_dnssec_types_filtered():
    """DNSSEC records and BIND's signing state (TYPE65534) are the server's to
    maintain: they go to the read-only part, not into the editable model."""
    m, _, rejected = model("@ NS ns1\nns1 A 192.0.2.1\n@ NSEC3PARAM 1 0 0 -\n@ TYPE65534 \\# 5 0D12340001\n")
    assert set(m) == {key("@", "NS"), key("ns1", "A")}
    assert {k[1] for k in rejected} == {51, 65534}


def test_locked_soa_fields(tmp_path):
    """MNAME, SERIAL and the SOA's own TTL may not be edited; the error names
    the fields that were."""
    _, base_soa, _ = model("")
    f = tmp_path / "z.zone"
    f.write_text("$TTL 300\n@ 3600 IN SOA ns2 hostmaster 101 7200 900 1209600 300\n")
    with pytest.raises(ValueError, match="MNAME, SERIAL"):
        zonefile.parse_file(str(f), ORIGIN, base_soa)
    f.write_text("$TTL 300\n@ 60 IN SOA ns1 hostmaster 100 7200 900 1209600 300\n")
    with pytest.raises(ValueError, match="TTL"):
        zonefile.parse_file(str(f), ORIGIN, base_soa)


def test_cname_conflict_rejected(tmp_path):
    """A name with a CNAME may hold nothing else (RFC 1034). BIND silently
    ignores an UPDATE that breaks this rule, so zedit must catch it first."""
    # At parse time (dnspython rejects it itself) ...
    _, base_soa, _ = model("")
    f = tmp_path / "z.zone"
    f.write_text("$TTL 300\n" + SOA + "foo CNAME www\nfoo TXT x\n")
    with pytest.raises(dns.exception.DNSException):
        zonefile.parse_file(str(f), ORIGIN, base_soa)
    # ... and in the model, e.g. after a merge
    a, _, _ = model("foo CNAME www\n")
    b, _, _ = model("foo TXT x\n")
    with pytest.raises(ValueError, match="CNAME"):
        zonefile.check_cname({**a, **b})


# Records of a signed zone, as a transfer gives them
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
    """With -a, the read-only records are shown as ';ro' comment lines, each
    RRSIG next to what it signs, and reading the file back ignores them."""
    m, soa, hidden = model(SIGNED)
    text = zonefile.render_file(soa, m, ORIGIN, "x", hidden=hidden)
    ro = [line for line in text.splitlines() if line.startswith(";ro ")]
    assert len(ro) == 6  # RRSIG NS, DNSKEY, RRSIG DNSKEY, TYPE65534, RRSIG A, NSEC
    lines = text.splitlines()
    # Each RRSIG set follows the type it covers
    a = next(i for i, x in enumerate(lines) if x.startswith("www") and " A " in x)
    assert " RRSIG  A " in lines[a + 1]
    k = next(i for i, x in enumerate(lines) if " DNSKEY " in x)
    assert " RRSIG  DNSKEY " in lines[k + 1]
    # Read-only lines are comments: parsing the file yields exactly the editable model
    m2 = zonefile.parse_text(text, ORIGIN).records
    assert set(m2) == set(m) and all(same(m[x], m2[x]) for x in m)


def test_no_rrsig_keeps_keys_drops_noise():
    """--no-rrsig shows the keys and the signing state but not the RRSIG and
    NSEC records, which are many and change with every re-signing; without -a,
    nothing read-only is shown."""
    _, _, hidden = model(SIGNED)
    opts = Options(ORIGIN, show_all=True, no_rrsig=True)
    assert sorted(tname(k[1]) for k in zonefile.shown(opts, hidden)) == ["DNSKEY", "TYPE65534"]
    assert zonefile.shown(Options(ORIGIN), hidden) is None


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
    """SOA timers are explained in words in the session file."""
    assert zonefile.human_duration(seconds) == text


def test_rname_to_email():
    """The SOA RNAME is a mail address with the first dot as the '@'; an escaped
    dot belongs to the local part."""
    assert zonefile.rname_to_email(dns.name.from_text("hostmaster", None), ORIGIN) == "hostmaster@example.com"
    assert (
        zonefile.rname_to_email(dns.name.from_text(r"john\.doe.example.net."), ORIGIN)
        == "john.doe@example.net"
    )


def test_soa_help_is_comment_only():
    """The explanation of the SOA fields is comments only: reading the file
    back gives the same SOA and records."""
    m, soa, _ = model("www A 192.0.2.1\n", soa="@ 3600 IN SOA ns1 hostmaster 100 86401 900 1209600 300\n")
    text = zonefile.render_file(soa, m, ORIGIN, "x")
    assert ";   REFRESH = 86401" in text and "(1 day and 1 second)" in text
    assert ";   EXPIRE  = 1209600" in text and "(2 weeks)" in text
    assert "contact: hostmaster@example.com" in text
    z2 = zonefile.parse_text(text, ORIGIN)
    assert z2.soa[0] == soa[0] and set(z2.records) == set(m)


def test_rname_control_characters_stay_in_the_comment():
    """An RNAME with a line break (\\010) or other unprintable characters is
    escaped in the comment: unescaped, the rest of it would be read as a record."""
    rname = r"x\010evil\032TXT\032\034injected\034\013\226\128\168"
    soa = f"@ 3600 IN SOA ns1 {rname} 100 7200 900 1209600 300\n"
    m, soa_rds, _ = model("www A 192.0.2.1\n", soa=soa)
    text = zonefile.render_file(soa_rds, m, ORIGIN, "x")
    assert 'contact: x\\010evil TXT "injected"\\013\\226\\128\\168@example.com' in text  # U+2028 too
    z2 = zonefile.parse_text(text, ORIGIN)
    assert z2.soa[0] == soa_rds[0] and set(z2.records) == set(m)


def test_origin_directive_inside_zone():
    """$ORIGIN may be used in the file; names are made relative to the zone."""
    o = dns.name.from_text("2.0.192.in-addr.arpa.")
    text = "$TTL 300\n" + SOA + "$ORIGIN 2.0.192.in-addr.arpa.\n10 PTR www.example.com.\n"
    m = zonefile.parse_text(text, o).records
    assert set(m) == {(dns.name.from_text("10", None), int(dns.rdatatype.PTR))}


def test_names_outside_zone_are_rejected_not_dropped():
    """A record outside the zone (here after a wrong $ORIGIN) is an error, not
    silently lost as dnspython would lose it."""
    # dnspython's reader would silently drop these
    text = "$TTL 300\n" + SOA + "www A 192.0.2.1\n$ORIGIN example.org.\nfoo A 192.0.2.2\n"
    with pytest.raises(ValueError, match="foo.example.org"):
        zonefile.parse_text(text, ORIGIN)


def generated(line):
    """The lines a $GENERATE line expands to."""
    text, _ = zonefile.expand_generate(line)
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
    """$ and ${offset,width,base} are substituted as BIND does."""
    assert zonefile.generate_substitute(template, i) == expected


def test_generate_range_and_step():
    """START-STOP/STEP, both ends included."""
    assert generated("$GENERATE 30-34/2 $ PTR h$.example.com.") == [
        "30 PTR h30.example.com.",
        "32 PTR h32.example.com.",
        "34 PTR h34.example.com.",
    ]


def test_generate_leaves_the_comment_alone():
    """A '$' in the comment is no modifier, and the comment isn't repeated."""
    assert generated('$GENERATE 1-2 $ TXT "a;$" ; see ${docs}, $5') == ['1 TXT "a;1"', '2 TXT "a;2"']


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
    """A bad range or modifier is an error, not a guess."""
    with pytest.raises(ValueError, match=match):
        zonefile.expand_generate(line)


def test_generate_errors_point_at_the_users_line():
    """After expanding 50 records, an error on the next line is still reported
    on the user's line 4, not on line 53 of the expanded text."""
    text = "$TTL 300\n" + SOA + "$GENERATE 1-50 $ PTR h$.example.com.\nbad line here\n"
    with pytest.raises(ValueError, match="^line 4:"):
        zonefile.parse_text(text, REV)


def test_generate_outside_zone_is_rejected():
    """Generated records outside the zone are reported, like written ones."""
    text = "$TTL 300\n" + SOA + "$ORIGIN example.org.\n$GENERATE 1-3 h$ A 192.0.2.$\n"
    with pytest.raises(ValueError, match="h1.example.org.*h2.example.org.*h3.example.org"):
        zonefile.parse_text(text, REV)


# BIND's zone checker, often in an sbin directory that isn't on a user's PATH
NAMED_CHECKZONE = shutil.which("named-checkzone") or shutil.which(
    "named-checkzone", path=os.pathsep.join(["/usr/local/sbin", "/usr/sbin", "/sbin"])
)


@pytest.mark.skipif(not NAMED_CHECKZONE, reason="named-checkzone not found")
def test_generate_matches_named_checkzone(tmp_path):
    """zedit's $GENERATE gives exactly the records BIND does, checked with
    named-checkzone where it is installed."""
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
    out = subprocess.check_output([NAMED_CHECKZONE, "-q", "-D", "-o", "-", REV.to_text(), str(f)], text=True)
    bind = set()
    for line in out.splitlines():
        name, _ttl, cls, rtype, rdata = line.split(None, 4)
        if rtype not in ("SOA", "NS"):
            bind.add(f"{name} {cls} {rtype} {rdata}")
    m = zonefile.parse_text(zone, REV).records
    ours = {
        f"{n.derelativize(REV)} IN {tname(t)} {rd.to_text(origin=REV, relativize=False)}"
        for (n, t), rds in m.items()
        if tname(t) != "NS"
        for rd in rds
    }
    assert len(bind) == 18 and ours == bind


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ("www CNAME a\nwww CNAME b\n", "line 5: more than one www CNAME record"),
        ("@ SOA ns1 other 100 7200 900 1209600 300\n", "line 4: more than one @ SOA record"),
        # dnspython would silently give the RRset the lowest TTL
        ("www 300 A 192.0.2.1\nwww 3600 A 192.0.2.2\n", "line 5: www A: TTL 3600 differs from 300"),
        ("www 300 A 192.0.2.1\nmail A 192.0.2.9\nwww A 192.0.2.2\n", "line 6: www A: TTL 3600 differs"),
    ],
)
def test_records_dnspython_would_merge_silently_are_errors(body, match):
    """Lines that dnspython would quietly merge into something else, reported
    on the offending line: a second CNAME or SOA (it keeps only the last), or a
    different TTL within one RRset (it keeps the lowest)."""
    with pytest.raises(ValueError, match=match):
        zonefile.parse_text("$TTL 3600\n" + SOA + "@ NS ns1\n" + body, ORIGIN)


def test_identical_records_are_not_an_error():
    """The same record twice is harmless (it is one record), also when written
    once relative and once absolute."""
    m = zonefile.parse_text(
        "$TTL 300\n"
        + SOA
        + "@ NS ns1\nwww CNAME a\nwww CNAME a.example.com.\nmail A 192.0.2.9\nmail A 192.0.2.9\n",
        ORIGIN,
    ).records
    assert len(m[key("www", "CNAME")]) == 1 and len(m[key("mail", "A")]) == 1


def test_dnspython_reader_hook():
    """zedit relies on private dnspython API: dns.zonefile.Reader calls _eat_line()
    when it drops a record outside the zone, with the owner in last_name (see
    zonefile._Reader). If this fails after a dnspython upgrade, that API has changed
    and records outside the zone would again be silently ignored."""
    text = (
        SOA
        + "www 300 IN A 192.0.2.10\n"
        + "other.example.net. 300 IN A 192.0.2.11\n"
        + "$ORIGIN elsewhere.org.\n"
        + "host 300 IN A 192.0.2.12\n"
        + "$ORIGIN example.com.\n"
        + "mail 300 IN A 192.0.2.20\n"
    )
    zone, outside = zonefile.read_zone(text, ORIGIN)
    assert outside == ["host.elsewhere.org.", "other.example.net."]
    assert {n.to_text() for n in zone.nodes} == {"@", "www", "mail"}
    # zonefile._StrictAdds relies on the reader adding each record with
    # txn.add(name, ttl, rdata); if that changes, it no longer sees the records.
    with pytest.raises(ValueError, match="TTL 600 differs"):
        zonefile.read_zone(SOA + "www 300 IN A 192.0.2.10\nwww 600 IN A 192.0.2.11\n", ORIGIN)


def test_cds_filtered_only_at_the_apex():
    """CDS and CDNSKEY at the apex are maintained by the server; below it they
    are ordinary records, e.g. RFC 9615 signals, and can be edited."""
    m, _, rejected = model(
        f"@ CDS {CDS_RDATA}\n@ CDNSKEY {CDNSKEY_RDATA}\n"
        f"_dsboot.child.example CDS {CDS_RDATA}\n_dsboot.child.example CDNSKEY {CDNSKEY_RDATA}\n"
    )
    assert set(m) == {key("_dsboot.child.example", "CDS"), key("_dsboot.child.example", "CDNSKEY")}
    assert {(k[0].to_text(), k[1]) for k in rejected} == {("@", 59), ("@", 60)}


def test_cds_at_the_apex_cannot_be_added():
    """Adding CDS at the apex in the file is an error, since the server owns it."""
    with pytest.raises(ValueError, match="CDS/CDNSKEY at the apex"):
        zonefile.parse_text("$TTL 300\n" + SOA + f"@ CDS {CDS_RDATA}\n", ORIGIN)
    m = zonefile.parse_text("$TTL 300\n" + SOA + f"_dsboot.child.example CDS {CDS_RDATA}\n", ORIGIN).records
    assert key("_dsboot.child.example", "CDS") in m


def test_apex_ns_cannot_all_be_removed(tmp_path):
    """A zone needs an NS record at its apex; BIND would silently ignore
    deleting the last one, so it is an error here."""
    _, base_soa, _ = model("")
    f = tmp_path / "z.zone"
    f.write_text("$TTL 300\n" + SOA + "www A 192.0.2.10\n")
    with pytest.raises(ValueError, match="apex needs at least one NS"):
        zonefile.parse_file(str(f), ORIGIN, base_soa)


def test_session_files_are_utf8(tmp_path):
    """Read as UTF-8 whatever the locale; a file saved in another encoding is
    reported with its line, rather than read as something else."""
    _, base_soa, _ = model("")
    f = tmp_path / "s.zone"
    body = "$TTL 300\n" + SOA + '@ NS ns1\ntxt TXT "R\u00e4ksm\u00f6rg\u00e5s"\n'
    f.write_bytes(body.encode("utf-8"))
    m = zonefile.parse_file(str(f), ORIGIN, base_soa).records
    assert m[key("txt", "TXT")][0].strings == ("R\u00e4ksm\u00f6rg\u00e5s".encode(),)
    f.write_bytes(body.encode("latin-1"))
    with pytest.raises(ValueError, match="^line 4: not valid UTF-8 \\(byte 0xe4\\)"):
        zonefile.parse_file(str(f), ORIGIN, base_soa)


@pytest.mark.parametrize(
    "records",
    [
        "www A 999.1.1.1\nok A 192.0.2.1",  # the bad field is the line's last
        "www A 999.1.1.1",
        "www MX x\nok A 192.0.2.1",
        "www BOGUS 1\nok A 192.0.2.1",
    ],
)
def test_errors_are_reported_on_their_line(records):
    """A syntax error is reported on its own line, also when it is in the last
    field of a line or the last line of the file."""
    with pytest.raises(ValueError, match="^line 4: "):
        zonefile.parse_text("$TTL 300\n" + SOA + "@ NS ns1\n" + records + "\n", ORIGIN)


def test_non_ascii_names_use_idna_2008():
    """As registries do: under IDNA 2003 (dnspython's default) straße.de would
    become strasse.de, a different domain."""
    text = "$TTL 300\n" + SOA + "@ NS ns1\nr\u00e4ksm\u00f6rg\u00e5s CNAME stra\u00dfe.de.\n"
    m = zonefile.parse_text(text, ORIGIN).records
    assert zonefile.rr_lines(m, ORIGIN)[1] == "xn--rksmrgs-5wao1o\t300\tIN\tCNAME\txn--strae-oqa.de."


@pytest.mark.parametrize("record", ["\u2603 A 192.0.2.1", "x CNAME a\u200db."])
def test_invalid_idn_is_an_error_on_its_line(record):
    """A name that isn't a valid internationalized name (a snowman, a zero-width
    joiner) is an error on its line."""
    with pytest.raises(ValueError, match="^line 4: IDNA"):
        zonefile.parse_text("$TTL 300\n" + SOA + "@ NS ns1\n" + record + "\n", ORIGIN)
