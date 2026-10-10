"""Helpers shared by the unit tests."""

import dns.exception
import dns.name
import dns.zone

from zedit import rfc2136, zonefile

ORIGIN = dns.name.from_text("example.com.")
SOA = "@ 3600 IN SOA ns1 hostmaster 100 7200 900 1209600 300\n"


def model(body, soa=SOA):
    z = dns.zone.from_text("$TTL 300\n" + soa + body, origin=ORIGIN, relativize=True, check_origin=False)
    m, s, rejected = zonefile.to_model(z)
    return m, s, rejected


def key(name, t):
    return (dns.name.from_text(name, None), int(dns.rdatatype.from_text(t)))


def addrs(m, name, t="A"):
    return sorted(r.to_text() for r in m[key(name, t)])


def lines(ops):
    """Ops as the nsupdate commands zedit shows."""
    return [line for op in ops for line in rfc2136.op_lines(op, ORIGIN)]


def soa_rd(fields):
    _, rds, _ = model("", soa=f"@ 3600 IN SOA ns1 hm {fields}\n")
    return rds


REV = dns.name.from_text("2.0.192.in-addr.arpa.")


CDS_RDATA = "28889 13 2 5859EF0BDC217560D43AA3133526503E4428B6809CCE400FB0B27D74136B41D8"
CDNSKEY_RDATA = (
    "257 3 13 ZxTaTTbQHRgbrjhjiThNK5sSqDC2Wu+zPitbVcMjo7mW22++S5bioe1/zicKEy4sOy9MJx8BRNUqXuouo6f3QA=="
)
