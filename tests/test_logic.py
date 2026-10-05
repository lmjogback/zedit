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
    assert {t for _, t in rejected} == {51, 65534}


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
