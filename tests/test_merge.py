import pytest
from helpers import ORIGIN, SOA, addrs, key, model, zone

from zedit import changes, merge, zonefile
from zedit.model import tname


def test_merge_disjoint_changes():
    base, _, _ = model("a A 192.0.2.1\nb A 192.0.2.2\n")
    mine, _, _ = model("a A 192.0.2.11\nb A 192.0.2.2\n")
    theirs, _, _ = model("a A 192.0.2.1\nb A 192.0.2.22\nc A 192.0.2.3\n")
    r = merge.merge3(base, mine, theirs)
    assert addrs(r.records, "a") == ["192.0.2.11"]
    assert addrs(r.records, "b") == ["192.0.2.22"]
    assert addrs(r.records, "c") == ["192.0.2.3"]
    assert (r.notes, r.dropped, r.conflicts) == ({}, [], 0)


def test_merge_same_rrset_both_sides_with_ttl_conflict():
    base, _, _ = model("www 300 A 192.0.2.11\n")
    mine, _, _ = model("www 60 A 192.0.2.12\n")
    theirs, _, _ = model("www 900 A 192.0.2.11\nwww 900 A 192.0.2.13\n")
    r = merge.merge3(base, mine, theirs)
    assert addrs(r.records, "www") == ["192.0.2.12", "192.0.2.13"]
    assert r.records[key("www", "A")].ttl == 60
    assert r.conflicts == 1 and key("www", "A") in r.notes


def test_merge_already_applied_is_noop():
    base, _, _ = model("a A 192.0.2.1\n")
    mine, _, _ = model("a A 192.0.2.2\n")
    r = merge.merge3(base, mine, mine)
    assert addrs(r.records, "a") == ["192.0.2.2"] and not r.notes and not r.conflicts


def test_merge_soa_fieldwise():
    _, b, _ = model("", soa="@ 3600 IN SOA ns1 hm 100 7200 900 1209600 300\n")
    _, m, _ = model("", soa="@ 3600 IN SOA ns1 admin 100 7200 900 1209600 300\n")
    _, t, _ = model("", soa="@ 3600 IN SOA ns1 hm 105 3600 900 1209600 300\n")
    merged = merge.merge_soa(b, m, t)
    r = merged.soa[0]
    assert (str(r.rname), r.refresh, r.serial, merged.conflicts) == ("admin", 3600, 105, 0)


@pytest.mark.parametrize(
    ("base", "mine", "theirs"),
    [
        ("alias CNAME old\n", "alias CNAME mine\n", "alias CNAME theirs\n"),
        ("", "alias CNAME mine\n", "alias CNAME theirs\n"),  # added on both sides
    ],
)
def test_merge_singleton_type_is_a_conflict(base, mine, theirs):
    """A CNAME holds one record, so mine and the server's can't be merged as a
    union: dnspython would keep one of them depending on hash order. It is a
    conflict, and mine is kept."""
    merged = merge.merge3(model(base)[0], model(mine)[0], model(theirs)[0])
    k = key("alias", "CNAME")
    assert [r.to_text() for r in merged.records[k]] == ["mine"]
    assert merged.conflicts == 1
    assert any(line.startswith("; CONFLICT CNAME:") and "mine kept" in line for line in merged.notes[k])


def test_case_only_changes_are_put_back():
    """DNS names compare case-insensitively: the UPDATE for a case-only change is
    empty, so the diff must not show one either."""
    base = zone("www CNAME target\nmail MX 10 Mx\nmail MX 20 mx2\n")
    new = zone(
        "WWW CNAME Target\nmail MX 10 mx\nmail MX 30 mx3\n", soa=SOA.replace("hostmaster", "HostMaster")
    )
    new, recased = merge.keep_base_case(base, new)
    assert [f"{k[0]} {tname(k[1])}" for k in recased] == ["@ SOA", "www CNAME", "mail MX"]
    assert zonefile.rr_lines(new.records, ORIGIN) == [
        "mail\t300\tIN\tMX\t10 Mx",
        "mail\t300\tIN\tMX\t30 mx3",
        "www\t300\tIN\tCNAME\ttarget",
    ]
    assert str(new.soa[0].rname) == "hostmaster" and not changes.soa_changed(base.soa, new.soa)
    unchanged, none = merge.keep_base_case(base, base)
    assert none == [] and unchanged == base
