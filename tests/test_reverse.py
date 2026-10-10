import dns.exception
import dns.name
import dns.zone
import pytest
from helpers import ORIGIN, REV, SOA

from zedit import reverse, zonefile

V6 = dns.name.from_text("8.b.d.0.1.0.0.2.ip6.arpa.")
V6_NAME_1 = "1." + "0." * 23 + "8.b.d.0.1.0.0.2.ip6.arpa."


def owners(text, origin):
    m, _ = zonefile.parse_text("$TTL 300\n" + SOA + text, origin)
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
    assert reverse.owner_to_name(owner, origin) == name
    canonical = str(reverse.ipaddress.ip_address(owner))
    assert reverse.name_to_address(dns.name.from_text(name), origin) == canonical


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


IP6_48 = dns.name.from_text("0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.")  # 2001:db8::/48


@pytest.mark.parametrize("owner", ["0.5.0.0", "0.0.0.0", "1.2.3.4", "a.b.c.d", "f", "0.5"])
def test_nibble_names_in_ip6_zones_are_not_ipv4(owner):
    # In ip6.arpa, 0.5.0.0 is a nibble name (here the /64 2001:db8:0:500::/64)
    assert reverse.owner_to_name(owner, IP6_48) is None
    assert owners(f"{owner} NS ns1.example.net.\n", IP6_48) == {f"{owner}.{IP6_48}"}


def test_ip6_zone_with_delegations_and_ptrs():
    text = (
        "@ NS ns1.example.net.\n"
        "0.5.0.0 NS ns1.example.net.\n"
        "6.4.2.0.0.0.0.0.0.0.0.0.0.0.0.0 NS ns2.example.net.\n"
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0 PTR r1.example.net.\n"
        "2001:db8::1:0:0:0:2 PTR r2.example.net.\n"
    )
    assert owners(text, IP6_48) == {
        f"{IP6_48}",
        f"0.5.0.0.{IP6_48}",
        f"6.4.2.0.0.0.0.0.0.0.0.0.0.0.0.0.{IP6_48}",
        f"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.{IP6_48}",
        f"2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.{IP6_48}",
    }


def test_ipv4_in_an_ip6_zone_is_still_rejected():
    # Not a nibble sequence, so still taken as an IPv4 address: outside the zone
    with pytest.raises(ValueError, match="outside the zone"):
        owners("192.0.2.10 PTR x.example.com.\n", IP6_48)


def test_no_rewriting_in_in_addr_arpa_itself():
    origin = dns.name.from_text("in-addr.arpa.")
    assert reverse.owner_to_name("10.2.0.192", origin) is None


def test_no_addresses_shown_in_in_addr_arpa_itself():
    # Shown as 192.0.2.10, the owner would be read back as the relative name
    # 192.0.2.10.in-addr.arpa., so an unchanged file would move the PTR.
    origin = dns.name.from_text("in-addr.arpa.")
    z = dns.zone.from_text(
        "$TTL 300\n" + SOA + "@ NS ns1.example.net.\n10.2.0.192 PTR b.example.com.\n",
        origin=origin,
        relativize=True,
    )
    m, soa, _ = zonefile.to_model(z)
    text = zonefile.render_file(soa, m, origin, "x", addresses=True)
    assert "192.0.2.10 " not in text and "converted to reverse names" not in text
    m2, _ = zonefile.parse_text(text, origin)
    assert set(m2) == set(m)


def test_continuation_lines_are_not_owners():
    m, _ = zonefile.parse_text("$TTL 300\n" + SOA + '10 TXT ( "first"\n192.0.2.99 )\n', REV)
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
    m, soa, _ = zonefile.to_model(z)
    text = zonefile.render_file(soa, m, REV, "x", addresses=True)
    records = [line.split()[0] for line in text.splitlines() if " PTR " in line]
    assert records == ["192.0.2.2", "192.0.2.10", "192.0.2.100"]  # numeric order
    assert any(line.startswith("@ ") and " NS " in line for line in text.splitlines())  # apex stays @
    m2, _ = zonefile.parse_text(text, REV)
    assert set(m2) == set(m)


def test_show_addresses_ipv6_compressed():
    m = {(dns.name.from_text(V6_NAME_1).relativize(V6), 12): None}
    assert zonefile.owner_text(next(iter(m))[0], V6, True) == "2001:db8::1"
    assert zonefile.owner_text(next(iter(m))[0], V6, False) == V6_NAME_1.replace(
        ".8.b.d.0.1.0.0.2.ip6.arpa.", ""
    )


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
        reverse.owner_to_name(owner, V6)


@pytest.mark.parametrize("owner", ["16/28", "17.16/28", "0-127", "10", "10.2"])
def test_rfc2317_and_relative_names_are_not_addresses(owner):
    assert reverse.owner_to_name(owner, REV) is None


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
    assert reverse.owner_to_name(owner, V6) == V6_NAME_1


def test_ipv6_with_embedded_ipv4_notation():
    # 2001:db8::192.0.2.1 is 2001:db8::c000:201
    name = reverse.owner_to_name("2001:db8::192.0.2.1", V6)
    assert name.startswith("1.0.2.0.0.0.0.c.") and name.endswith(".8.b.d.0.1.0.0.2.ip6.arpa.")
    assert reverse.name_to_address(dns.name.from_text(name), V6) == "2001:db8::c000:201"


def test_ipv4_mapped_address_outside_the_zone():
    with pytest.raises(ValueError, match="outside the zone"):
        owners("::ffff:192.0.2.1 PTR x.example.com.\n", V6)


SWEEP_ZONES = [
    "example.com.",
    "2.0.192.in-addr.arpa.",
    "0.192.in-addr.arpa.",
    "192.in-addr.arpa.",
    "in-addr.arpa.",
    "16/28.2.0.192.in-addr.arpa.",
    "17.2.0.192.in-addr.arpa.",
    "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
    "8.b.d.0.1.0.0.2.ip6.arpa.",
    "ip6.arpa.",
]
SWEEP_LABELS = ["0", "5", "a", "F", "10", "17", "255", "256", "010"]
SWEEP_MIXES = [("0", "10"), ("a", "5"), ("255", "0"), ("256", "1"), ("010", "1"), ("17", "f")]


def sweep_tokens():
    for dots in range(8):
        k = dots + 1
        yield from {".".join([label] * k) for label in SWEEP_LABELS}
        yield from {".".join((mix * k)[:k]) for mix in SWEEP_MIXES}


def sweep_expected(token, origin):
    """The rules, stated independently of the implementation."""
    labels = token.split(".")
    if not reverse.is_reverse(origin) or len(labels) != 4 or not all(x.isdigit() for x in labels):
        return "name"  # only a decimal dotted quad in a reverse zone can be IPv4
    if origin == reverse.IN_ADDR:
        return "name"  # four labels are a valid name directly under in-addr.arpa
    if origin.is_subdomain(reverse.IP6_ARPA) and all(len(x) == 1 for x in labels):
        return "name"  # nibbles
    if all(str(int(x)) == x and int(x) <= 255 for x in labels):
        return "address"
    return "error"  # looks like IPv4 but isn't valid


@pytest.mark.parametrize("zone", SWEEP_ZONES)
def test_owner_sweep(zone):
    origin = dns.name.from_text(zone)
    rtype = "PTR x.example.com." if reverse.is_reverse(origin) else "A 192.0.2.1"
    mismatches = []
    for token in sorted(set(sweep_tokens())):
        expected = sweep_expected(token, origin)
        # The helper ...
        try:
            got = "name" if reverse.owner_to_name(token, origin) is None else "address"
        except ValueError:
            got = "error"
        # ... and end to end, the way an edited file is read
        try:
            m, _ = zonefile.parse_text(f"$TTL 300\n{SOA}{token} {rtype}\n", origin)
            (name,) = [k[0].derelativize(origin) for k in m]
            if expected == "name":
                e2e = name == dns.name.from_text(token, origin)
            else:
                e2e = expected == "address" and name == dns.name.from_text(
                    reverse.owner_to_name(token, origin)
                )
        except ValueError as e:
            e2e = expected == "error" or (expected == "address" and "outside the zone" in str(e))
        if got != expected or not e2e:
            mismatches.append((token, expected, got, e2e))
    assert not mismatches
