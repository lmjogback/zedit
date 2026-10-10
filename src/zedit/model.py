"""Types, constants and helpers shared by the other modules.

The model of a zone is a dict of RRsets: Records maps an RRKey (owner name
relative to the zone, and type) to a dnspython Rdataset, which holds the TTL and
the records. The apex SOA is kept apart from it, since it is edited and sent
differently from everything else (see changes.soa_to_send()), and so are the
records zedit shows read-only, if at all: DNSSEC records and other ones the
server maintains itself. A Zone holds all three.
"""

from dataclasses import dataclass, field
from typing import NamedTuple

import dns.name
import dns.rdataset
import dns.rdatatype

# Record types as plain ints, as the keys of the model hold them
SOA = int(dns.rdatatype.SOA)
CNAME = int(dns.rdatatype.CNAME)
NS = int(dns.rdatatype.NS)
RRSIG = int(dns.rdatatype.RRSIG)
BIND_PRIVATE = 65534  # BIND's signing state (sig-signing-type); dnspython has no name for it
# DNSSEC records and BIND's signing state, all maintained by the server
FILTERED = {
    int(t)
    for t in (
        dns.rdatatype.RRSIG,
        dns.rdatatype.NSEC,
        dns.rdatatype.DNSKEY,
        dns.rdatatype.NSEC3,
        dns.rdatatype.NSEC3PARAM,
        dns.rdatatype.ZONEMD,
    )
} | {BIND_PRIVATE}
# CDS, CDNSKEY: maintained by the server at the apex. Below it they are ordinary
# records, e.g. RFC 9615 bootstrapping signals at _dsboot.CHILD._signal.NS-HOST.
FILTERED_AT_APEX = {int(dns.rdatatype.CDS), int(dns.rdatatype.CDNSKEY)}
# Names written with non-ASCII letters (räksmörgås) are encoded with IDNA 2008, as
# registries do. dnspython's default is IDNA 2003, which maps e.g. straße to
# strasse, a different domain (IDNA 2008: xn--strae-oqa).
IDNA = dns.name.IDNA_2008
SIGNAL_LABEL = b"_dsboot"  # the first label of an RFC 9615 signal name
# Omitted from --show-all by --no-rrsig: the bulky, constantly changing ones
NOISY = {int(dns.rdatatype.RRSIG), int(dns.rdatatype.NSEC), int(dns.rdatatype.NSEC3)}
# The SOA fields the user may change. The others are locked: MNAME names the
# primary, and the serial is zedit's to set (one more than the server's).
SOA_EDITABLE = ("rname", "refresh", "retry", "expire", "minimum")
LOCKED_SOA = ("mname", "serial")  # and the SOA record's own TTL


class ZeditError(Exception):
    """An error to report to the user as "zedit: MESSAGE", with exit status 1:
    something about the setup or the server, not a bug in zedit."""


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


Records = dict[RRKey, dns.rdataset.Rdataset]  # the RRsets the user edits
Hidden = dict[HiddenKey, dns.rdataset.Rdataset]  # the read-only ones
Notes = dict[RRKey, list[str]]  # comment lines to show above an RRset
# The apex has the empty relative name ("@" in a zone file)
SOA_KEY = RRKey(dns.name.empty, SOA)  # for notes on the SOA, which isn't in Records
APEX_NS = RRKey(dns.name.empty, NS)  # the zone's own NS RRset; see rfc2136.compute_update()


VERIFY_TIMEOUT = 120.0  # seconds, for all of the verification after an update


@dataclass(frozen=True)
class Options:
    """The zone, how to show it and how long to verify, as the command line asks."""

    origin: dns.name.Name
    show_all: bool = False  # -a, --no-rrsig
    no_rrsig: bool = False
    addresses: bool = False  # -A
    verify_timeout: float = VERIFY_TIMEOUT  # --verify-timeout


@dataclass(frozen=True)
class Zone:
    """A zone as zedit sees it: the records that can be edited, the apex SOA,
    and the read-only records (none for a zone read from a file)."""

    records: Records
    soa: dns.rdataset.Rdataset
    hidden: Hidden = field(default_factory=dict)


def tname(t: int) -> str:
    """A type's name, e.g. "A", or "TYPE65534" for one without a name."""
    return dns.rdatatype.RdataType.to_text(t)


def sortkey(k: RRKey | HiddenKey) -> tuple[dns.name.Name, int]:
    """The order in which RRsets are processed and listed in messages."""
    return (k.name, k.rdtype)  # dns.name gives canonical DNS order, apex first


def display_key(k: RRKey | HiddenKey) -> tuple[dns.name.Name, int, int]:
    """Owner name, then type; an RRSIG set sorts right after the type it covers."""
    name, t = k.name, k.rdtype
    if t == RRSIG and isinstance(k, HiddenKey):  # RRSIG is never editable
        return (name, k.covers, 1)
    return (name, t, 0)


def same(a: dns.rdataset.Rdataset | None, b: dns.rdataset.Rdataset | None) -> bool:
    """Whether two RRsets (None: no RRset) hold the same records with the same
    TTL. The order of the records doesn't matter, as it doesn't in DNS."""
    if a is None or b is None:
        return a is b
    return a.ttl == b.ttl and set(a) == set(b)
