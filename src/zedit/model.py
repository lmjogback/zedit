"""Types, constants and helpers shared by the other modules."""

import sys
from dataclasses import dataclass, field
from typing import NamedTuple, NoReturn

import dns.name
import dns.rdataset
import dns.rdatatype

SOA = int(dns.rdatatype.SOA)
CNAME = int(dns.rdatatype.CNAME)
NS = int(dns.rdatatype.NS)
RRSIG = int(dns.rdatatype.RRSIG)
# RRSIG, NSEC, DNSKEY, NSEC3, NSEC3PARAM, ZONEMD, BIND private (signing state)
FILTERED = {46, 47, 48, 50, 51, 63, 65534}
# CDS, CDNSKEY: maintained by the server at the apex. Below it they are ordinary
# records, e.g. RFC 9615 bootstrapping signals at _dsboot.CHILD._signal.NS-HOST.
FILTERED_AT_APEX = {59, 60}
# Names written with non-ASCII letters (räksmörgås) are encoded with IDNA 2008, as
# registries do. dnspython's default is IDNA 2003, which maps e.g. straße to
# strasse, a different domain (IDNA 2008: xn--strae-oqa).
IDNA = dns.name.IDNA_2008
SIGNAL_LABEL = b"_dsboot"
# Omitted from --show-all by --no-rrsig: the bulky, constantly changing ones
NOISY = {46, 47, 50}  # RRSIG, NSEC, NSEC3
SOA_EDITABLE = ("rname", "refresh", "retry", "expire", "minimum")
LOCKED_SOA = ("mname", "serial")  # and the SOA record's own TTL


class ZeditError(Exception):
    pass


class RRKey(NamedTuple):
    """An RRset in the model: owner name relative to the zone, and type."""

    name: dns.name.Name
    rdtype: int


class HiddenKey(NamedTuple):
    """A read-only RRset (DNSSEC, server-maintained): like RRKey, with the type
    an RRSIG set covers, since there is one RRSIG set per type."""

    name: dns.name.Name
    rdtype: int
    covers: int


Records = dict[RRKey, dns.rdataset.Rdataset]
Hidden = dict[HiddenKey, dns.rdataset.Rdataset]
Notes = dict[RRKey, list[str]]  # comment lines to show above an RRset
SOA_KEY = RRKey(dns.name.empty, SOA)
APEX_NS = RRKey(dns.name.empty, NS)


@dataclass(frozen=True)
class Options:
    """The zone and how to show it, as the command line asks."""

    origin: dns.name.Name
    show_all: bool = False  # -a, --no-rrsig
    no_rrsig: bool = False
    addresses: bool = False  # -A


@dataclass(frozen=True)
class Zone:
    """A zone as zedit sees it: the records that can be edited, the apex SOA,
    and the read-only records (none for a zone read from a file)."""

    records: Records
    soa: dns.rdataset.Rdataset
    hidden: Hidden = field(default_factory=dict)


def tname(t: int) -> str:
    return dns.rdatatype.RdataType.to_text(t)


def die(msg: str, code: int = 1) -> NoReturn:
    print(f"zedit: {msg}", file=sys.stderr)
    sys.exit(code)


def sortkey(k: RRKey | HiddenKey) -> tuple[dns.name.Name, int]:
    return (k.name, k.rdtype)  # dns.name gives canonical DNS order, apex first


def display_key(k: RRKey | HiddenKey) -> tuple[dns.name.Name, int, int]:
    """Owner name, then type; an RRSIG set sorts right after the type it covers."""
    name, t = k.name, k.rdtype
    if t == RRSIG and isinstance(k, HiddenKey):  # RRSIG is never editable
        return (name, k.covers, 1)
    return (name, t, 0)


def same(a: dns.rdataset.Rdataset | None, b: dns.rdataset.Rdataset | None) -> bool:
    if a is None or b is None:
        return a is b
    return a.ttl == b.ttl and set(a) == set(b)
