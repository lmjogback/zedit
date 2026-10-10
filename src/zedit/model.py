"""Types, constants and helpers shared by the other modules."""

import sys

import dns.name
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


def tname(t):
    return dns.rdatatype.to_text(t)


def die(msg, code=1):
    print(f"zedit: {msg}", file=sys.stderr)
    sys.exit(code)


def sortkey(k):
    return (k[0], k[1])  # dns.name gives canonical DNS order, apex first


def display_key(k):
    """Owner name, then type; an RRSIG set sorts right after the type it covers."""
    name, t = k[0], k[1]
    if t == RRSIG:
        return (name, k[2], 1)
    return (name, t, 0)


def same(a, b):
    if a is None or b is None:
        return a is b
    return a.ttl == b.ttl and set(a) == set(b)
