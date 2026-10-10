"""Helpers shared by the unit tests.

Most tests build zones from zone file text: model("www A 192.0.2.1\n") parses
the records (with $TTL 300 and the SOA below prepended) into zedit's model, as
a transfer would give it, and zone() returns the same as a Zone. Keys and
records are compared with key() and addrs().
"""

import dns.exception
import dns.name
import dns.zone

from zedit import changes, rfc2136, zonefile
from zedit.model import Zone

ORIGIN = dns.name.from_text("example.com.")  # the zone of most tests
SOA = "@ 3600 IN SOA ns1 hostmaster 100 7200 900 1209600 300\n"


def model(body, soa=SOA):
    """Zone file records (relative to ORIGIN) -> (Records, SOA RRset, Hidden),
    as zonefile.to_model() splits a transferred zone."""
    z = dns.zone.from_text("$TTL 300\n" + soa + body, origin=ORIGIN, relativize=True, check_origin=False)
    m, s, rejected = zonefile.to_model(z)
    return m, s, rejected


def zone(body, soa=SOA):
    """model() as a Zone."""
    return Zone(*model(body, soa))


def changeset(old, new):
    """The ChangeSet from records old to records new, with the SOA unchanged."""
    soa = model("")[1]
    return changes.change_set(Zone(old, soa), Zone(new, soa))


def key(name, t):
    """The model's key for an RRset: key("www", "A"). A plain tuple compares
    equal to the RRKey zedit uses."""
    return (dns.name.from_text(name, None), int(dns.rdatatype.from_text(t)))


def addrs(m, name, t="A"):
    """The records of one RRset in m as sorted text, e.g. ["192.0.2.1"]."""
    return sorted(r.to_text() for r in m[key(name, t)])


def lines(ops):
    """Ops as the nsupdate commands zedit shows."""
    return [line for op in ops for line in rfc2136.op_lines(op, ORIGIN)]


def soa_rd(fields):
    """An SOA RRset from its numbers: soa_rd("100 7200 900 1209600 300") for
    SERIAL REFRESH RETRY EXPIRE MINIMUM."""
    _, rds, _ = model("", soa=f"@ 3600 IN SOA ns1 hm {fields}\n")
    return rds


REV = dns.name.from_text("2.0.192.in-addr.arpa.")  # a reverse zone, for 192.0.2.0/24


# A CDS and a CDNSKEY record, for the tests of DNSSEC signals (RFC 9615)
CDS_RDATA = "28889 13 2 5859EF0BDC217560D43AA3133526503E4428B6809CCE400FB0B27D74136B41D8"
CDNSKEY_RDATA = (
    "257 3 13 ZxTaTTbQHRgbrjhjiThNK5sSqDC2Wu+zPitbVcMjo7mW22++S5bioe1/zicKEy4sOy9MJx8BRNUqXuouo6f3QA=="
)
