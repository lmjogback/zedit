import pytest
from helpers import ORIGIN, SOA, addrs, key, model

from zedit import changes, merge, zonefile
from zedit.model import tname


def test_merge_disjoint_changes():
    base, _, _ = model("a A 192.0.2.1\nb A 192.0.2.2\n")
    mine, _, _ = model("a A 192.0.2.11\nb A 192.0.2.2\n")
    theirs, _, _ = model("a A 192.0.2.1\nb A 192.0.2.22\nc A 192.0.2.3\n")
    merged, notes, dropped, conflicts = merge.merge3(base, mine, theirs)
    assert addrs(merged, "a") == ["192.0.2.11"]
    assert addrs(merged, "b") == ["192.0.2.22"]
    assert addrs(merged, "c") == ["192.0.2.3"]
    assert (notes, dropped, conflicts) == ({}, [], 0)


def test_merge_same_rrset_both_sides_with_ttl_conflict():
    base, _, _ = model("www 300 A 192.0.2.11\n")
    mine, _, _ = model("www 60 A 192.0.2.12\n")
    theirs, _, _ = model("www 900 A 192.0.2.11\nwww 900 A 192.0.2.13\n")
    merged, notes, _, conflicts = merge.merge3(base, mine, theirs)
    assert addrs(merged, "www") == ["192.0.2.12", "192.0.2.13"]
    assert merged[key("www", "A")].ttl == 60
    assert conflicts == 1 and key("www", "A") in notes


def test_merge_already_applied_is_noop():
    base, _, _ = model("a A 192.0.2.1\n")
    mine, _, _ = model("a A 192.0.2.2\n")
    merged, notes, _, conflicts = merge.merge3(base, mine, mine)
    assert addrs(merged, "a") == ["192.0.2.2"] and not notes and not conflicts


def test_merge_soa_fieldwise():
    _, b, _ = model("", soa="@ 3600 IN SOA ns1 hm 100 7200 900 1209600 300\n")
    _, m, _ = model("", soa="@ 3600 IN SOA ns1 admin 100 7200 900 1209600 300\n")
    _, t, _ = model("", soa="@ 3600 IN SOA ns1 hm 105 3600 900 1209600 300\n")
    soa, note, conflicts = merge.merge_soa(b, m, t)
    r = soa[0]
    assert (str(r.rname), r.refresh, r.serial, conflicts) == ("admin", 3600, 105, 0)


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
    merged, notes, dropped, conflicts = merge.merge3(model(base)[0], model(mine)[0], model(theirs)[0])
    k = key("alias", "CNAME")
    assert [r.to_text() for r in merged[k]] == ["mine"]
    assert conflicts == 1
    assert any(line.startswith("; CONFLICT CNAME:") and "mine kept" in line for line in notes[k])


def test_case_only_changes_are_put_back():
    """DNS names compare case-insensitively: the UPDATE for a case-only change is
    empty, so the diff must not show one either."""
    base, base_soa, _ = model("www CNAME target\nmail MX 10 Mx\nmail MX 20 mx2\n")
    new, new_soa, _ = model(
        "WWW CNAME Target\nmail MX 10 mx\nmail MX 30 mx3\n", soa=SOA.replace("hostmaster", "HostMaster")
    )
    new, new_soa, recased = merge.keep_base_case(base, base_soa, new, new_soa)
    assert [f"{k[0]} {tname(k[1])}" for k in recased] == ["@ SOA", "www CNAME", "mail MX"]
    assert zonefile.rr_lines(new, ORIGIN) == [
        "mail\t300\tIN\tMX\t10 Mx",
        "mail\t300\tIN\tMX\t30 mx3",
        "www\t300\tIN\tCNAME\ttarget",
    ]
    assert str(new_soa[0].rname) == "hostmaster" and not changes.soa_changed(base_soa, new_soa)
    unchanged, _, none = merge.keep_base_case(base, base_soa, base, base_soa)
    assert none == [] and unchanged == base
