#!/usr/bin/env python3
"""zedit - edit a dynamic DNS zone as if it were a plain zone file.

Flow:
  AXFR (TSIG) -> strip DNSSEC/server-maintained types -> $EDITOR
  -> semantic diff -> confirmation -> nsupdate (one atomic UPDATE with
  value-dependent prerequisites on exactly the RRsets it touches, acting as
  an optimistic lock) -> verification by a fresh AXFR.

  The lock deliberately does not use the SOA: in a DNSSEC-signed zone the
  serial changes on every re-signing, and with inline-signing the transferred
  (signed) serial differs from the serial of the unsigned zone that receives
  the UPDATE.

Error handling:
  The edit is saved in $XDG_STATE_HOME/zedit (default ~/.local/state/zedit)
  together with FILE.base = the zone as transferred. If the server changed
  RRsets you touched (prereq -> NXRRSET/YXRRSET) or nsupdate times out, the edit can be
  rebased: new AXFR + three-way merge (base, mine, theirs).
  Aborted/failed sessions are resumed with --resume FILE.

Requires: python >= 3.10, dnspython >= 2.4, nsupdate (bind9-dnsutils).
"""

import argparse
import asyncio
import contextlib
import difflib
import ipaddress
import itertools
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.resolver
import dns.tokenizer
import dns.tsigkeyring
import dns.zone
import dns.zonefile

from zedit import __version__

SOA = int(dns.rdatatype.SOA)
CNAME = int(dns.rdatatype.CNAME)
NS = int(dns.rdatatype.NS)
RRSIG = int(dns.rdatatype.RRSIG)
# RRSIG, NSEC, DNSKEY, NSEC3, NSEC3PARAM, ZONEMD, BIND private (signing state)
FILTERED = {46, 47, 48, 50, 51, 63, 65534}
# CDS, CDNSKEY: maintained by the server at the apex. Below it they are ordinary
# records, e.g. RFC 9615 bootstrapping signals at _dsboot.CHILD._signal.NS-HOST.
FILTERED_AT_APEX = {59, 60}
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


# ---------------------------------------------------------------- TSIG


KEY_STATEMENT = re.compile(r'key\s+"?([^"\s{]+)"?\s*\{(.*?)\}\s*;', re.S)


def load_bind_key(path):
    """Read a key in tsig-keygen / named.conf format."""
    with open(path) as f:
        text = f.read()
    keys = KEY_STATEMENT.findall(text)
    if not keys:
        die(f"no key statement found in {path}")
    if len(keys) > 1:
        # zedit would use the first for AXFR, but nsupdate -k refuses the file
        names = ", ".join(name for name, _ in keys)
        die(f"{path} has {len(keys)} key statements ({names}); nsupdate accepts only one key per file")
    ((name, body),) = keys
    alg = re.search(r'algorithm\s+"?([\w.-]+)"?\s*;', body)
    sec = re.search(r'secret\s+"([^"]+)"\s*;', body)
    if not (alg and sec):
        die(f"algorithm/secret missing in {path}")
    kr = dns.tsigkeyring.from_text({name: (alg.group(1), sec.group(1))})
    return kr, dns.name.from_text(name)


# ---------------------------------------------------------------- zone <-> model


def is_filtered(name, t):
    return t in FILTERED or (t in FILTERED_AT_APEX and name == dns.name.empty)


def to_model(zone):
    """-> (model, apex SOA, rejected).

    model:    {(relative name, rdtype): Rdataset} without SOA and filtered types
    rejected: {(relative name, rdtype, covers): Rdataset} for filtered types and
              any SOA outside the apex (keyed with covers: one RRSIG set per type)"""
    m, rejected, soa = {}, {}, None
    for name, rds in zone.iterate_rdatasets():
        t = int(rds.rdtype)
        if t == SOA and name == dns.name.empty:
            soa = rds
        elif t == SOA or is_filtered(name, t):
            rejected[(name, t, int(rds.covers))] = rds
        else:
            m[(name, t)] = rds
    return m, soa, rejected


def fetch(ctx):
    try:
        xfr = dns.query.xfr(
            ctx.server, ctx.origin, port=ctx.port, keyring=ctx.keyring, keyname=ctx.keyname, lifetime=120
        )
        zone = dns.zone.from_xfr(xfr, relativize=True)
    except Exception as e:  # dnspython raises a whole zoo of types here
        raise ZeditError(f"AXFR failed: {e}") from e
    model, soa, hidden = to_model(zone)
    if soa is None:
        raise ZeditError("AXFR has no SOA at the apex")
    return model, soa, hidden


class _Reader(dns.zonefile.Reader):
    """dnspython's zone file reader silently drops records whose owner name is
    outside the zone (e.g. after a $ORIGIN pointing elsewhere); _eat_line() is
    called only on that path. Record the names so they can be reported."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outside = []

    def _eat_line(self):
        self.outside.append(self.last_name)
        super()._eat_line()


class _StrictAdds:
    """Wraps the transaction the zone file reader adds records to. dnspython merges
    records into RRsets silently: an RRset gets the lowest TTL of its lines, and
    a single-record type such as CNAME or SOA keeps only the last line. Both are
    reported instead, with the line in the tokenizer's text (which must end with
    a newline: the reader has read a record's end of line when it adds it)."""

    def __init__(self, txn, tok):
        self._txn, self._tok = txn, tok
        self._first = {}  # (name, rdtype, covers) -> (ttl, rdata) of its first line

    def __getattr__(self, attr):
        return getattr(self._txn, attr)

    def add(self, name, ttl, rd):
        k = (name, rd.rdtype, rd.covers())
        if k in self._first:
            first_ttl, first_rd = self._first[k]
            line = self._tok.where()[1] - 1
            what = f"{name} {tname(rd.rdtype)}"
            if dns.rdatatype.is_singleton(rd.rdtype) and rd != first_rd:
                raise ValueError(
                    f"line {line}: more than one {what} record; a {tname(rd.rdtype)} RRset holds only one"
                )
            if ttl != first_ttl:
                raise ValueError(
                    f"line {line}: {what}: TTL {ttl} differs from {first_ttl} earlier in the RRset;"
                    " an RRset has one TTL"
                )
        else:
            self._first[k] = (ttl, rd)
        return self._txn.add(name, ttl, rd)


GENERATE_LINE = re.compile(r"^\$GENERATE[ \t]+(\S+)[ \t]+(\S.*)$", re.IGNORECASE)
GENERATE_RANGE = re.compile(r"^(\d+)-(\d+)(?:/(\d+))?$")
GENERATE_TOKEN = re.compile(r"\\.|\$\{([^}]*)\}|\$")
GENERATE_MAX = 65536


def nibbles(value, width, mode):
    """BIND's ${offset,width,n|N}: hex digits, least significant first, separated
    by dots (for ip6.arpa); width counts output characters including dots."""
    digits = "0123456789abcdef" if mode == "n" else "0123456789ABCDEF"
    out = []
    while True:
        out.append(digits[value & 0xF])
        value >>= 4
        width = max(width - 1, 0)
        if width > 0 or value != 0:
            out.append(".")
            width = max(width - 1, 0)
        if value == 0 and width == 0:
            return "".join(out)


def generate_substitute(template, i):
    """Expand '$', '${offset[,width[,base]]}' in a $GENERATE template, as BIND does.
    Backslash escapes (e.g. '\\$' for a literal '$') are left for the zone parser."""

    def repl(m):
        token = m.group(0)
        if token.startswith("\\"):
            return token
        if token == "$":
            return str(i)
        fields = m.group(1).split(",")
        if len(fields) > 3 or not fields[0].strip().lstrip("-").isdigit():
            raise ValueError(f"bad $GENERATE modifier {token}")
        offset = int(fields[0])
        width = int(fields[1]) if len(fields) > 1 and fields[1].strip() else 0
        base = fields[2].strip() if len(fields) > 2 and fields[2].strip() else "d"
        value = i + offset
        if value < 0:
            raise ValueError(f"$GENERATE modifier {token} gives a negative value")
        if base in ("d", "o", "x", "X"):
            return format(value, f"0{width}{base}")
        if base in ("n", "N"):
            return nibbles(value, width, base)
        raise ValueError(f"bad $GENERATE base {base!r} in {token}")

    return GENERATE_TOKEN.sub(repl, template)


def expand_generate(text):
    """Replace $GENERATE lines with the records they generate, following BIND
    (several '$' and modifiers per side; dnspython's own expansion handles only
    one modifier and silently leaves the rest as text).
    -> (expanded text, original line number for each line of the expanded text)."""
    out, linemap = [], []
    for n, line in enumerate(text.split("\n"), 1):
        # Without its comment, where a '$' is no modifier
        m = GENERATE_LINE.match(line[: scan_line(line)[0]].rstrip())
        if not m:
            out.append(line)
            linemap.append(n)
            continue
        r = GENERATE_RANGE.match(m.group(1))
        if not r:
            raise ValueError(f"line {n}: bad $GENERATE range {m.group(1)!r} (start-stop[/step])")
        start, stop, step = int(r.group(1)), int(r.group(2)), int(r.group(3) or 1)
        if stop < start or step < 1 or (stop - start) // step >= GENERATE_MAX:
            raise ValueError(f"line {n}: bad $GENERATE range {m.group(1)!r}")
        try:
            out += [generate_substitute(m.group(2), i) for i in range(start, stop + 1, step)]
        except ValueError as e:
            raise ValueError(f"line {n}: {e}") from None
        linemap += [n] * len(range(start, stop + 1, step))
    return "\n".join(out), linemap


IN_ADDR = dns.name.from_text("in-addr.arpa.")
IP6_ARPA = dns.name.from_text("ip6.arpa.")
LOOKS_LIKE_IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$")  # with an optional (rejected) prefix


def is_reverse(origin):
    return origin.is_subdomain(IN_ADDR) or origin.is_subdomain(IP6_ARPA)


def classless_range(origin):
    """For an RFC 2317 zone such as 16/28.2.0.192.in-addr.arpa (or 16-31.2...),
    the range of last octets it holds, else None."""
    if not origin.is_subdomain(IN_ADDR) or len(origin) != 7:  # x.c.b.a.in-addr.arpa.
        return None
    first = origin.labels[0].decode(errors="replace")
    m = re.fullmatch(r"(\d+)/(\d+)", first)
    if m and 24 <= int(m.group(2)) <= 32:
        lo = int(m.group(1))
        hi = lo + 2 ** (32 - int(m.group(2))) - 1
    elif m2 := re.fullmatch(r"(\d+)-(\d+)", first):
        lo, hi = int(m2.group(1)), int(m2.group(2))
    else:
        return None
    return (lo, hi) if 0 <= lo <= hi <= 255 else None


def address_to_name(address, origin):
    """Owner name for an IP address in this reverse zone. In an RFC 2317 zone the
    last octet goes under the zone (192.0.2.17 -> 17.16/28.2.0.192.in-addr.arpa.)."""
    name = dns.name.from_text(address.reverse_pointer + ".")
    if address.version == 4 and not name.is_subdomain(origin):
        rng = classless_range(origin)
        if rng and name.parent() == origin.parent() and rng[0] <= int(name.labels[0]) <= rng[1]:
            name = dns.name.Name((name.labels[0], *origin.labels))
    return name


def name_to_address(name, origin):
    """The IP address a reverse-zone owner name stands for, or None."""
    full = name.derelativize(origin)
    labels = [label.decode(errors="replace") for label in full.labels[:-1]]
    if full.is_subdomain(IN_ADDR):
        octets = labels[:-2]
        rng = classless_range(origin)
        if rng and len(octets) == 5 and full.parent() == origin:
            octets = [octets[0], *octets[2:]]
        if len(octets) == 4 and all(o.isdigit() and str(int(o)) == o and int(o) <= 255 for o in octets):
            return ".".join(reversed(octets))
    elif full.is_subdomain(IP6_ARPA):
        nibbles_ = labels[:-2]
        if len(nibbles_) == 32 and all(len(x) == 1 and x in "0123456789abcdefABCDEF" for x in nibbles_):
            return str(ipaddress.IPv6Address(int("".join(reversed(nibbles_)), 16)))
    return None


NIBBLES = re.compile(r"^[0-9a-fA-F](\.[0-9a-fA-F])*$")


def owner_to_name(token, origin):
    """In a reverse zone, an owner written as an IP address -> its absolute owner
    name (text). None if the token isn't an address. Raises ValueError for tokens
    that look like an address but aren't valid (e.g. 192.0.2.010), which would
    otherwise silently become a strange relative name."""
    if not is_reverse(origin):
        return None
    if origin == IN_ADDR or (origin.is_subdomain(IP6_ARPA) and NIBBLES.match(token)):
        # In in-addr.arpa itself four labels are a valid name, and in ip6.arpa a
        # token like 0.5.0.0 is a nibble name (e.g. a /64 under a /48), not an address.
        return None
    if token.endswith(".") or not (LOOKS_LIKE_IPV4.match(token) or ":" in token):
        return None
    # Checked explicitly: whether ipaddress accepts a zone id depends on the
    # Python version, and dropping it silently would be wrong.
    if "%" in token:
        raise ValueError(f"{token!r}: an address with a zone id (%...) cannot be an owner name")
    if "/" in token:
        raise ValueError(f"{token!r}: a prefix is not an address; write one address per record")
    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        raise ValueError(f"{token!r} looks like an IP address but is not a valid one") from None
    return address_to_name(address, origin).to_text()


def scan_line(line):
    """-> (where the comment on a zone file line starts, or len(line); the net
    change in parenthesis depth, to know whether the next line continues a
    record). Quotes and escapes are respected."""
    depth, quoted, escaped = 0, False, False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif not quoted and ch == ";":
            return i, depth
        elif not quoted and ch == "(":
            depth += 1
        elif not quoted and ch == ")":
            depth -= 1
    return len(line), depth


def rewrite_address_owners(text, origin):
    """In a reverse zone, replace owner names written as IP addresses with their
    arpa names. Line count is preserved, so error line numbers stay valid."""
    if not is_reverse(origin):
        return text
    out, depth = [], 0
    for n, line in enumerate(text.split("\n"), 1):
        if depth == 0 and line and not line[0].isspace() and line[0] not in ";$":
            token = line.split(None, 1)[0]
            try:
                name = owner_to_name(token, origin)
            except ValueError as e:
                raise ValueError(f"line {n}: {e}") from None
            if name:
                line = name + line[len(token) :]
        depth = max(depth + scan_line(line)[1], 0)
        out.append(line)
    return "\n".join(out)


def read_zone(text, origin):
    """-> (zone, names outside the zone that the reader dropped)."""
    expanded, linemap = expand_generate(text)

    def users_line(e):
        """The error with the line in the user's file, not in the expanded text."""
        m = re.match(r"line (\d+): (.*)", str(e), re.S)
        if m and int(m.group(1)) <= len(linemap):
            return ValueError(f"line {linemap[int(m.group(1)) - 1]}: {m.group(2)}")
        return e

    try:
        expanded = rewrite_address_owners(expanded, origin) + "\n"
    except ValueError as e:
        raise users_line(e) from None
    zone = dns.zone.Zone(origin, dns.rdataclass.IN, relativize=True)
    tok = dns.tokenizer.Tokenizer(expanded, "<edit>")
    try:
        with zone.writer(True) as txn:
            reader = _Reader(
                tok,
                dns.rdataclass.IN,
                _StrictAdds(txn, tok),
                # $GENERATE is expanded above; never let dnspython's version run
                allow_directives={"$ORIGIN", "$TTL"},
            )
            reader.read()
    except ValueError as e:
        raise users_line(e) from None
    except dns.exception.DNSException as e:
        m = re.match(r"<edit>:(\d+):\s*(.*)", str(e), re.S)
        if m:
            raise users_line(ValueError(f"line {m.group(1)}: {m.group(2)}")) from None
        raise
    return zone, sorted({n.to_text() for n in reader.outside})


def parse_text(text, origin):
    z, outside = read_zone(text, origin)
    if outside:
        raise ValueError(f"names outside the zone {origin} (check $ORIGIN): {', '.join(outside)}")
    m, soa, rejected = to_model(z)
    if rejected:
        bad = ", ".join(sorted({f"{k[0]} {tname(k[1])}" for k in rejected}))
        raise ValueError(f"records not allowed (DNSSEC, CDS/CDNSKEY at the apex, or SOA outside it): {bad}")
    if soa is None:
        raise ValueError("SOA missing - it may be edited but not removed")
    return m, soa


def signal_warnings(base, new):
    """CDS/CDNSKEY added or changed below the apex but not at a _dsboot name, where
    an RFC 9615 signal belongs (e.g. a typo such as _dsbot). Only a warning: zedit
    doesn't check signals against the child zone or its delegation."""
    return [
        f"{k[0]} {tname(k[1])} is not at a _dsboot name; RFC 9615 signals are named "
        "_dsboot.CHILD._signal.NS-HOST"
        for k in sorted(new, key=sortkey)
        if k[1] in FILTERED_AT_APEX
        and k[0].labels[0].lower() != SIGNAL_LABEL
        and not same(base.get(k), new[k])
    ]


def check_cname(m):
    """BIND *silently* ignores adds that violate the CNAME rule (RFC 2136 §3.4.2.2),
    so this must be caught here rather than relying on the server."""
    types = {}
    for n, t in m:
        types.setdefault(n, set()).add(t)
    bad = sorted(
        n.to_text() for n, ts in types.items() if CNAME in ts and (len(ts) > 1 or n == dns.name.empty)
    )
    if bad:
        raise ValueError("CNAME together with other data: " + ", ".join(bad))


def parse_file(path, origin, base_soa):
    with open(path) as f:
        m, soa = parse_text(f.read(), origin)
    o, n = base_soa[0], soa[0]
    locked = [f.upper() for f in LOCKED_SOA if getattr(o, f) != getattr(n, f)]
    if base_soa.ttl != soa.ttl:
        locked.append("SOA record TTL")
    if locked:
        raise ValueError(f"locked SOA fields changed: {', '.join(locked)}")
    check_cname(m)
    if (dns.name.empty, NS) not in m:
        # The server would ignore deleting the last one (RFC 2136 §3.4.2.4)
        raise ValueError("the zone apex needs at least one NS record")
    return m, soa


def sortkey(k):
    return (k[0], k[1])  # dns.name gives canonical DNS order, apex first


def display_key(k):
    """Owner name, then type; an RRSIG set sorts right after the type it covers."""
    name, t = k[0], k[1]
    if t == RRSIG:
        return (name, k[2], 1)
    return (name, t, 0)


def owner_text(name, origin, addresses):
    """The owner as written in the file: the relative name, or with --addresses
    in a reverse zone the IP address (the apex stays '@')."""
    if addresses and name != dns.name.empty:
        address = name_to_address(name, origin)
        if address:
            return address
    return name.to_text()


def sort_key(origin, addresses):
    """display_key, but with --addresses records are ordered by address."""
    if not addresses:
        return display_key

    def key(k):
        name, t, flag = display_key(k)
        address = name_to_address(name, origin) if name != dns.name.empty else None
        if address:
            ip = ipaddress.ip_address(address)
            return (1, ip.version, int(ip), dns.name.empty, t, flag)
        return (0, 0, 0, name, t, flag)

    return key


def rr_lines(m, origin, pad=0, notes=None, hidden=None, addresses=False):
    """Zone file lines for model m. With hidden (a rejected dict from to_model),
    those records are interleaved as ';ro' comment lines: shown, never parsed.
    With addresses, reverse-zone owners are shown as IP addresses."""
    out = []
    hidden = hidden or {}
    for key in sorted([*m, *hidden], key=sort_key(origin, addresses)):
        ro = key in hidden
        name, t = key[0], key[1]
        rds = hidden[key] if ro else m[key]
        if notes and key in notes:
            out += notes[key]
        n = owner_text(name, origin, addresses)
        prefix = ";ro " if ro else ""
        for rd in sorted(rds, key=lambda r: r.to_text(origin=origin, relativize=True)):
            txt = rd.to_text(origin=origin, relativize=True)
            if pad:
                out.append(f"{prefix}{n:<{pad}} {rds.ttl:>7} IN {tname(t):<6} {txt}")
            else:
                out.append(f"{prefix}{n}\t{rds.ttl}\tIN\t{tname(t)}\t{txt}")
    return out


DURATION_UNITS = (("week", 604800), ("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1))


def human_duration(seconds):
    """86401 -> '1 day and 1 second', 1209600 -> '2 weeks'."""
    parts = []
    for unit, size in DURATION_UNITS:
        n, seconds = divmod(seconds, size)
        if n:
            parts.append(f"{n} {unit}{'' if n == 1 else 's'}")
    if not parts:
        return "0 seconds"
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def rname_to_email(rname, origin):
    """SOA RNAME as a mail address: the first label is the local part
    (it may contain escaped dots, e.g. john\\.doe.example.com.)."""
    name = rname.derelativize(origin)
    local = name.labels[0].decode(errors="replace")
    return f"{local}@{dns.name.Name(name.labels[1:]).to_text(omit_final_dot=True)}"


def soa_help(rds, origin):
    """Comment lines explaining the SOA values as transferred."""
    r = rds[0]
    rows = [
        ("MNAME", r.mname.derelativize(origin).to_text(), "primary name server (locked)"),
        ("RNAME", r.rname.derelativize(origin).to_text(), f"contact: {rname_to_email(r.rname, origin)}"),
        ("SERIAL", str(r.serial), "locked; bumped automatically"),
        ("REFRESH", str(r.refresh), f"({human_duration(r.refresh)}) how often secondaries check for changes"),
        ("RETRY", str(r.retry), f"({human_duration(r.retry)}) retry interval after a failed refresh"),
        ("EXPIRE", str(r.expire), f"({human_duration(r.expire)}) secondaries stop answering after this long"),
        ("MINIMUM", str(r.minimum), f"({human_duration(r.minimum)}) TTL of negative answers, RFC 2308"),
        ("TTL", str(rds.ttl), f"({human_duration(rds.ttl)}) TTL of the SOA record itself (locked)"),
    ]
    width = max(len(v) for _, v, _ in rows)
    return [
        "; SOA values as transferred (these comments are not updated when you edit):",
        *(f";   {f:<7} = {v:<{width}}  {t}" for f, v, t in rows),
    ]


def soa_line(rds, origin, pad=0):
    txt = rds[0].to_text(origin=origin, relativize=True)
    if pad:
        return f"{'@':<{pad}} {rds.ttl:>7} IN {'SOA':<6} {txt}"
    return f"@\t{rds.ttl}\tIN\tSOA\t{txt}"


def render_file(soa_rds, model, origin, server, notes=None, extra=(), hidden=None, addresses=False):
    notes = notes or {}
    pad = max([len(owner_text(k[0], origin, addresses)) for k in [*model, *(hidden or {})]] + [1])
    if hidden is None:
        filtered = [
            "; Filtered out: "
            + " ".join(tname(t) for t in sorted(FILTERED))
            + ", and "
            + " ".join(tname(t) for t in sorted(FILTERED_AT_APEX))
            + " at the apex"
        ]
    else:
        filtered = [
            "; Lines starting with ';ro' are read-only (DNSSEC / server-maintained);",
            ";      editing or removing them has no effect.",
        ]
    hdr = [
        f"; Zone: {origin}  Server: {server}  Serial: {soa_rds[0].serial}",
        *filtered,
        "; Records without a TTL get $TTL below (= SOA MINIMUM at transfer time).",
        *(
            ["; Owners may be written as IP addresses; they are converted to reverse names."]
            if is_reverse(origin)
            else []
        ),
        *extra,
        f"$ORIGIN {origin}",
        f"$TTL {soa_rds[0].minimum}",
        "",
        *notes.get("SOA", []),
        soa_line(soa_rds, origin, pad),
        *soa_help(soa_rds, origin),
        "",
    ]
    return "\n".join(hdr + rr_lines(model, origin, pad, notes, hidden, addresses)) + "\n"


def shown(ctx, hidden):
    """The read-only records to display, per --show-all / --no-rrsig, or None."""
    if not ctx.show_all:
        return None
    return {k: v for k, v in hidden.items() if not (ctx.no_rrsig and k[1] in NOISY)}


def write_tmp(path, text):
    """Write text to a new file next to path and fsync it; -> its name. The file
    is created exclusively (a symlink planted under its name isn't followed),
    readable only by the user, since sessions hold zone data."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=os.path.basename(path) + ".")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        os.unlink(tmp)
        raise
    return tmp


def write_pair(files):
    """Replace each (path, text) of files, the session file and its base, which
    must agree. All are written out first, so a failure there (disk full) leaves
    the old ones in place; only a crash between the renames that follow could
    leave one old and one new."""
    tmps = []
    try:
        for path, text in files:
            tmps.append((write_tmp(path, text), path))
        while tmps:
            os.replace(*tmps[0])
            tmps.pop(0)
    finally:
        for tmp, _ in tmps:
            os.unlink(tmp)


# ---------------------------------------------------------------- three-way merge


def same(a, b):
    if a is None or b is None:
        return a is b
    return a.ttl == b.ttl and set(a) == set(b)


def merge_scalar(b, m, t):
    """-> (value, conflict?). On conflict, mine wins."""
    if m == b:
        return t, False
    if t == b or m == t:
        return m, False
    return m, True


def merge3(base, mine, theirs):
    """Per RRset: unchanged by me -> theirs; unchanged on the server -> mine;
    changed on both sides -> rdata set merge: theirs + my additions - my deletions,
    except for single-record types (CNAME etc.), where two values are a conflict."""
    merged, notes, dropped, conflicts = {}, {}, [], 0
    for k in set(base) | set(mine) | set(theirs):
        b, m, t = base.get(k), mine.get(k), theirs.get(k)
        if same(m, b):
            r = t
        elif same(t, b) or same(m, t):
            r = m
        else:
            bs, ms, ts = (set(x) if x else set() for x in (b, m, t))
            rd = (ts | (ms - bs)) - (bs - ms)
            note = ["; MERGED: changed both by you and on the server - please review"]
            if m is None:
                ttl = t.ttl
            elif t is None:
                ttl = m.ttl
            else:
                ttl, c = merge_scalar(b.ttl if b else None, m.ttl, t.ttl)
                if c:
                    conflicts += 1
                    note.append(
                        f"; CONFLICT TTL: base={b.ttl if b else '-'} server={t.ttl} mine={m.ttl} - mine kept"
                    )
            if len(rd) > 1 and dns.rdatatype.is_singleton(k[1]):
                # CNAME, DNAME etc. hold a single record, so two values can't be
                # merged as a union (dnspython would keep one, in hash order)
                conflicts += 1
                note.append(
                    f"; CONFLICT {tname(k[1])}: base={b[0].to_text() if b else '-'} "
                    f"server={t[0].to_text()} mine={m[0].to_text()} - mine kept"
                )
                rd = set(m)
            r = dns.rdataset.from_rdata_list(ttl, list(rd)) if rd else None
            if r is None:
                dropped.append(f"{k[0]} {tname(k[1])}")
            else:
                notes[k] = note
        if r is not None:
            merged[k] = r
    return merged, notes, dropped, conflicts


def merge_soa(b, m, t):
    fields, note, conflicts = {}, [], 0
    for f in SOA_EDITABLE:
        bv, mv, tv = getattr(b[0], f), getattr(m[0], f), getattr(t[0], f)
        fields[f], c = merge_scalar(bv, mv, tv)
        if c:
            conflicts += 1
            note.append(f"; CONFLICT SOA {f.upper()}: base={bv} server={tv} mine={mv} - mine kept")
    # MNAME, SERIAL and the SOA TTL always come from the server
    return dns.rdataset.from_rdata(t.ttl, t[0].replace(**fields)), note, conflicts


def rebase(ctx, base, base_soa, mine, mine_soa):
    theirs, theirs_soa, theirs_hidden = fetch(ctx)
    merged, notes, dropped, conflicts = merge3(base, mine, theirs)
    msoa, snote, sconf = merge_soa(base_soa, mine_soa, theirs_soa)
    if snote:
        notes["SOA"] = snote
    conflicts += sconf
    extra = [f"; Rebased: serial {base_soa[0].serial} -> {theirs_soa[0].serial}."]
    extra += [f"; Removed by merge (empty RRset): {d}" for d in dropped]
    write_pair(
        (
            (
                ctx.path,
                render_file(
                    msoa,
                    merged,
                    ctx.origin,
                    ctx.label,
                    notes,
                    extra,
                    shown(ctx, theirs_hidden),
                    ctx.addresses,
                ),
            ),
            (ctx.basepath, render_file(theirs_soa, theirs, ctx.origin, ctx.label)),
        )
    )
    print(
        f"Rebased onto serial {theirs_soa[0].serial}: {len(notes)} RRset(s) changed on "
        f"both sides, {conflicts} conflict(s), {len(dropped)} removed."
    )
    return theirs, theirs_soa, conflicts


# ---------------------------------------------------------------- diff -> UPDATE


def keep_base_case(base, base_soa, new, new_soa):
    """DNS names compare case-insensitively, so a change of letter case alone
    (www CNAME Target for target) is no change to the server: the UPDATE would
    leave the record as it is. Owner names, records and SOA names equal to ones
    in the base get the base's spelling back, so that the diff shows only what
    is sent. -> (new, new_soa, keys whose case was put back)."""
    out, reverted, base_keys = {}, [], {k: k for k in base}
    for k, rds in new.items():
        bk = base_keys.get(k, k)
        old = {r: r for r in base[bk]} if bk in base else {}
        rds_out = [old.get(r, r) for r in rds]
        texts = [r.to_text() for r in rds]
        if bk[0].to_text() != k[0].to_text() or texts != [r.to_text() for r in rds_out]:
            reverted.append(bk)
            rds = dns.rdataset.from_rdata_list(rds.ttl, rds_out)
        out[bk] = rds
    o, n = base_soa[0], new_soa[0]
    names = {f: getattr(o, f) for f in ("mname", "rname") if getattr(o, f) == getattr(n, f)}
    soa_rd = n.replace(**names)
    if soa_rd.to_text() != n.to_text():
        reverted.insert(0, (dns.name.empty, SOA))
        new_soa = dns.rdataset.from_rdata(new_soa.ttl, soa_rd)
    return out, new_soa, reverted


def compute_update(old, new, origin):
    """-> (deletes, adds, final deletes). Deletes go before adds (handles e.g.
    A -> CNAME), except at the apex NS RRset: RFC 2136 §3.4.2.4 has the server
    ignore deleting the apex NS RRset or its last record, so there the new
    records are added first and the old ones deleted after ("final deletes")."""
    dels, adds, final = [], [], []

    def rd(r):
        return r.to_text(origin=origin, relativize=False)

    for key in sorted(set(old) | set(new), key=sortkey):
        o, n = old.get(key), new.get(key)
        fq = key[0].derelativize(origin).to_text()
        tt = tname(key[1])
        if key == (dns.name.empty, NS) and o is not None and n is not None:
            changed = list(n) if o.ttl != n.ttl else [r for r in n if r not in o]
            adds += [f"update add {fq} {n.ttl} IN {tt} {rd(r)}" for r in changed]
            final += [f"update delete {fq} IN {tt} {rd(r)}" for r in o if r not in n]
        elif o is None:
            adds += [f"update add {fq} {n.ttl} IN {tt} {rd(r)}" for r in n]
        elif n is None:
            dels.append(f"update delete {fq} IN {tt}")
        elif o.ttl != n.ttl:
            # TTL applies to the whole RRset -> replace it entirely
            dels.append(f"update delete {fq} IN {tt}")
            adds += [f"update add {fq} {n.ttl} IN {tt} {rd(r)}" for r in n]
        else:
            dels += [f"update delete {fq} IN {tt} {rd(r)}" for r in o if r not in n]
            adds += [f"update add {fq} {n.ttl} IN {tt} {rd(r)}" for r in n if r not in o]
    return dels, adds, final


def compute_prereqs(old, new, origin):
    """Optimistic lock on exactly the RRsets this update touches (RFC 2136 §2.4):
    value-dependent "RRset exists" with the base content for RRsets that are
    changed or deleted, "RRset does not exist" for RRsets that are created.
    Concurrent changes to other names (e.g. DHCP/DDNS) don't conflict."""
    out = []
    for key in sorted(set(old) | set(new), key=sortkey):
        o, n = old.get(key), new.get(key)
        if same(o, n):
            continue
        fq = key[0].derelativize(origin).to_text()
        tt = tname(key[1])
        if o is None:
            out.append(f"prereq nxrrset {fq} IN {tt}")
        else:
            out += [f"prereq yxrrset {fq} IN {tt} {r.to_text(origin=origin, relativize=False)}" for r in o]
    return out


def serial_max(a, b):
    """The greater of two serials in RFC 1982 serial number arithmetic."""
    if b is None:
        return a
    return b if 0 < (b - a) % 2**32 < 2**31 else a


def live_soa(ctx):
    """The zone's SOA RRset as the server answers it now, or None if the query
    fails. With inline-signing it is the signed zone's SOA: its serial is normally
    >= the unsigned one, and its other fields are the same.

    Names in it are made relative to the zone, as in the transferred zone (an
    RNAME such as hostmaster.example.com. becomes hostmaster), so that its fields
    compare equal to the transferred and edited ones."""
    try:
        q = dns.message.make_query(ctx.origin, dns.rdatatype.SOA)
        if ctx.keyring:
            q.use_tsig(ctx.keyring, keyname=ctx.keyname)
        r = dns.query.tcp(q, ctx.server, port=ctx.port, timeout=10)
        for rrset in r.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                rd = rrset[0]
                return dns.rdataset.from_rdata(
                    rrset.ttl,
                    rd.replace(mname=rd.mname.relativize(ctx.origin), rname=rd.rname.relativize(ctx.origin)),
                )
    except Exception:
        pass
    return None


def soa_changed(old_rds, new_rds):
    return old_rds.ttl != new_rds.ttl or old_rds[0] != new_rds[0]


def soa_to_send(base_rds, new_rds, live):
    """-> (the SOA RRset to send, or None if the edit doesn't change the SOA;
    the editable fields that conflict).

    The SOA can't be locked with a prerequisite: in a signed zone its serial
    changes on every re-signing, and with inline-signing the transferred serial
    belongs to the signed zone, not the one that receives the UPDATE. So the
    editable fields are merged three ways when the UPDATE is built, from the
    SOA as transferred (base), as edited (mine) and as the server has it now
    (live): a field changed only on the server keeps the server's value. The
    locked fields (MNAME, the SOA TTL) are the server's current ones, so a
    concurrent change to them isn't reverted.
    RFC 2136 §3.4.2.2 silently ignores an SOA whose serial isn't greater (RFC
    1982), so the serial is max(base, live) + 1; BIND then doesn't bump it a
    second time."""
    if not soa_changed(base_rds, new_rds):
        return None, []
    if live is None:
        raise ZeditError("cannot read the zone's current SOA from the server, so the SOA change was not sent")
    fields, conflicts = {}, []
    for f in SOA_EDITABLE:
        fields[f], c = merge_scalar(getattr(base_rds[0], f), getattr(new_rds[0], f), getattr(live[0], f))
        if c:
            conflicts.append(f.upper())
    fields["serial"] = (serial_max(base_rds[0].serial, live[0].serial) + 1) % 2**32
    return dns.rdataset.from_rdata(live.ttl, live[0].replace(**fields)), conflicts


def soa_update(soa, origin):
    """The nsupdate line that sets the SOA (an RRset), or none."""
    if soa is None:
        return []
    return [f"update add {origin} {soa.ttl} IN SOA {soa[0].to_text(origin=origin, relativize=False)}"]


def build_script(server, port, origin, prereqs, dels, adds, final=()):
    lines = [f"server {server} {port}", f"zone {origin}"]
    # Deletes before adds, final deletes last; see compute_update()
    return "\n".join(lines + prereqs + dels + adds + list(final) + ["send", ""])


def make_script(ctx, base_soa, new_soa, prereqs, dels, adds, final):
    """-> (nsupdate script, SOA RRset sent or None, conflicting SOA fields).
    The SOA is merged with the live zone at the moment this is called."""
    live = live_soa(ctx) if soa_changed(base_soa, new_soa) else None
    soa, conflicts = soa_to_send(base_soa, new_soa, live)
    script = build_script(
        ctx.server,
        ctx.port,
        ctx.origin,
        prereqs,
        dels,
        adds + soa_update(soa, ctx.origin),
        final,
    )
    return script, soa, conflicts


def soa_conflict_message(conflicts):
    return (
        f"SOA {', '.join(conflicts)} changed both by you and on the server since the transfer; nothing sent."
    )


def verify(ctx, base, new, soa=None, attempts=10):
    """Re-transfer the zone and check that every RRset we changed now matches
    the edit, and the SOA's MNAME and editable fields the SOA RRset sent (soa;
    None if the SOA wasn't sent). BIND silently drops some updates (CNAME rule, SOA with a
    non-greater serial, TTLs above a dnssec-policy max-zone-ttl), and with
    inline-signing the signed zone is updated asynchronously, hence the retries.
    -> list of RRsets that don't match (empty on success)."""
    changed = [k for k in set(base) | set(new) if not same(base.get(k), new.get(k))]
    bad = []
    for i in range(attempts):
        try:
            after, after_soa, _ = fetch(ctx)
        except ZeditError as e:
            # The update was sent, so this is "not verified" (exit 3), not a plain error; retry
            bad = [f"(zone transfer for verification failed: {e})"]
        else:
            bad = [
                f"{k[0]} {tname(k[1])}"
                for k in sorted(changed, key=sortkey)
                if not same(after.get(k), new.get(k))
            ]
            if soa is not None:
                bad += [
                    f"SOA {f.upper()}"
                    for f in ("mname", *SOA_EDITABLE)
                    if getattr(after_soa[0], f) != getattr(soa[0], f)
                ]
            if not bad:
                return []
        time.sleep(min(0.25 * 2**i, 2))
    return bad


def run_nsupdate(script, keyfile):
    """-> (ok, output, rebase_makes_sense)"""
    cmd = ["nsupdate", "-v", "-t", "60"] + (["-k", keyfile] if keyfile else [])
    try:
        p = subprocess.run(cmd, input=script, text=True, capture_output=True, timeout=120)
    except FileNotFoundError:
        return False, "nsupdate not found in PATH (bind9-dnsutils).", False
    except subprocess.TimeoutExpired:
        return (
            False,
            (
                "nsupdate timed out - unknown whether the update was applied. "
                "Rebasing is safe: changes already applied simply drop out."
            ),
            True,
        )
    out = (p.stdout + p.stderr).strip()
    if p.returncode == 0:
        return True, out, False
    if "NXRRSET" in out or "YXRRSET" in out:
        return False, out + "\nRRsets you changed were modified on the server after the transfer.", True
    # REFUSED/NOTAUTH/BADKEY/SERVFAIL etc.: rebasing won't help
    return False, out, False


# ---------------------------------------------------------------- UI


def show_diff(old_lines, new_lines, fromfile, tofile):
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")  # https://no-color.org
    for line in difflib.unified_diff(old_lines, new_lines, fromfile, tofile, lineterm=""):
        if color and line.startswith("+") and not line.startswith("+++"):
            line = f"\033[32m{line}\033[0m"
        elif color and line.startswith("-") and not line.startswith("---"):
            line = f"\033[31m{line}\033[0m"
        elif color and line.startswith("@@"):
            line = f"\033[36m{line}\033[0m"
        print(line)


def run_editor(path):
    """-> the editor's exit status."""
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    try:
        p = subprocess.Popen(shlex.split(editor) + [path])
    except OSError as e:
        raise ZeditError(f"cannot run editor {editor!r}: {e}") from e
    # As git does: Ctrl-C and Ctrl-\ belong to the editor while it runs. Ignored
    # only after it started, so that it doesn't inherit SIG_IGN.
    old = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGQUIT)}
    try:
        return p.wait()
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)


def ask(prompt, choices):
    while True:
        try:
            a = input(prompt).strip().lower()
        except EOFError:
            return ""
        if a in choices or a == "":
            return a


def edit_until_valid(path, origin, base_soa):
    """-> (model, soa), or None if the user aborts."""
    while True:
        status = run_editor(path)
        if status != 0:
            # e.g. vim's :cq, the usual way to abort an edit
            print(f"\nEditor exited with status {status}.")
            if ask("[e]dit again / [a]bort? ", {"e", "a"}) != "e":
                return None
            continue
        try:
            return parse_file(path, origin, base_soa)
        except (dns.exception.DNSException, ValueError) as e:
            print(f"\nError: {e}")
            if ask("[e]dit again / [a]bort? ", {"e", "a"}) != "e":
                return None


def resolve(host, port):
    """The address of host that first accepts a TCP connection on port, using
    Happy Eyeballs (RFC 8305): a server with an AAAA record is still reached
    quickly over IPv4 when IPv6 doesn't work. AXFR and the UPDATE (nsupdate -v)
    use TCP anyway."""

    async def connect():
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, happy_eyeballs_delay=0.25), timeout=10
        )
        address = writer.get_extra_info("peername")[0]
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
        return address

    try:
        return asyncio.run(connect())
    except socket.gaierror as e:
        die(f"cannot resolve {host}: {e}")
    except (OSError, asyncio.TimeoutError) as e:
        die(f"cannot connect to {host} port {port}: {str(e) or 'timed out'}")


def primary_from_mname(origin):
    """The zone's primary according to the SOA MNAME, via the system resolver."""
    try:
        answer = dns.resolver.resolve(origin, "SOA", lifetime=10)
    except dns.exception.DNSException as e:
        die(f"cannot look up the SOA of {origin} to find its primary ({e}); use -s SERVER")
    return answer[0].mname.to_text()


def config_dir():
    return os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "zedit")


def file_stem(origin):
    """The zone name as a safe file name component. RFC 2317 zones such as
    16/28.2.0.192.in-addr.arpa contain '/', which would become a directory;
    anything other than letters, digits, '.', '-' and '_' becomes '_'."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", origin.to_text(omit_final_dot=True)).lower()


def find_keyfile(origin):
    """Default TSIG key: $ZEDIT_KEYFILE, else ~/.config/zedit/keys/ZONE.key,
    else ~/.config/zedit/default.key, else None (no TSIG). ZONE as in file_stem()."""
    env = os.environ.get("ZEDIT_KEYFILE")
    if env:
        return env
    zone = file_stem(origin)
    for p in (os.path.join(config_dir(), "keys", f"{zone}.key"), os.path.join(config_dir(), "default.key")):
        if os.path.isfile(p):
            return p
    return None


def check_keyfile(path):
    if not os.path.isfile(path):
        die(f"key file {path} not found")
    if os.stat(path).st_mode & 0o077:
        print(f"zedit: warning: {path} is readable by group/others (chmod 600)", file=sys.stderr)


def state_dir():
    d = os.path.join(os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"), "zedit")
    os.makedirs(d, mode=0o700, exist_ok=True)  # the mode applies only if it is created
    if os.stat(d).st_mode & 0o077:
        print(
            f"zedit: warning: {d} is accessible by group/others, and saved sessions hold zone data"
            " (chmod 700)",
            file=sys.stderr,
        )
    return d


def resume_command(args, path):
    """The command line that resumes the session in path: the options given on
    this command line, without --dry-run and an earlier --resume."""
    cmd = ["zedit"]
    if args.server:
        cmd += ["-s", args.server]
    if args.port != 53:
        cmd += ["-p", str(args.port)]
    if args.keyfile:
        cmd += ["-k", args.keyfile]
    if args.no_rrsig:
        cmd.append("--no-rrsig")
    elif args.show_all:
        cmd.append("-a")
    if args.addresses:
        cmd.append("-A")
    return shlex.join([*cmd, "--resume", path, args.zone])


def new_session_path(origin):
    """A new session file ZONE-TIMESTAMP.zone in the state directory, created
    empty and exclusively, so that two sessions for the same zone started within
    the same second don't share (and overwrite) one: the second one gets
    ZONE-TIMESTAMP-2.zone, and so on."""
    stem = os.path.join(state_dir(), f"{file_stem(origin)}-{time.strftime('%Y%m%dT%H%M%S')}")
    for n in itertools.count(1):
        path = f"{stem}.zone" if n == 1 else f"{stem}-{n}.zone"
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        except FileExistsError:
            continue
        return path


def hint(ctx, args, dry_run=False):
    if ctx.path and os.path.exists(ctx.path):
        how = "Send them with" if dry_run else "Resume with"
        print(
            f"Your changes are saved in {ctx.path}\n{how}: {resume_command(args, ctx.path)}", file=sys.stderr
        )


def cleanup(ctx):
    for p in (ctx.path, ctx.basepath):
        if p and os.path.exists(p):
            os.unlink(p)


def discard_if_unchanged(ctx, base, base_soa):
    """After an aborted edit, remove the session if its file still parses and
    holds no change from the base: there is nothing to resume. -> removed?"""
    try:
        new, new_soa = parse_file(ctx.path, ctx.origin, base_soa)
    except (dns.exception.DNSException, ValueError, OSError):
        return False
    new, new_soa, _ = keep_base_case(base, base_soa, new, new_soa)
    if (
        soa_changed(base_soa, new_soa)
        or set(new) != set(base)
        or not all(same(base[k], new[k]) for k in base)
    ):
        return False
    cleanup(ctx)
    return True


# ---------------------------------------------------------------- main flow


def session(ctx, args):
    if args.resume:
        ctx.path, ctx.basepath = args.resume, args.resume + ".base"
        if not os.path.exists(ctx.basepath):
            raise ZeditError(f"{ctx.basepath} missing - cannot three-way merge without a base")
        try:
            with open(ctx.basepath) as f:
                base, base_soa = parse_text(f.read(), ctx.origin)
        except (dns.exception.DNSException, ValueError) as e:
            raise ZeditError(f"{ctx.basepath} is invalid: {e}") from e
        try:
            mine, mine_soa = parse_file(ctx.path, ctx.origin, base_soa)
        except (dns.exception.DNSException, ValueError) as e:
            print(f"The saved file is invalid: {e}")
            r = edit_until_valid(ctx.path, ctx.origin, base_soa)
            if r is None:
                return 1
            mine, mine_soa = r
        base, base_soa, conflicts = rebase(ctx, base, base_soa, mine, mine_soa)
        need_edit = conflicts > 0
    else:
        base, base_soa, hidden = fetch(ctx)
        ctx.path = new_session_path(ctx.origin)
        ctx.basepath = ctx.path + ".base"
        write_pair(
            (
                (ctx.basepath, render_file(base_soa, base, ctx.origin, ctx.label)),
                (
                    ctx.path,
                    render_file(
                        base_soa,
                        base,
                        ctx.origin,
                        ctx.label,
                        hidden=shown(ctx, hidden),
                        addresses=ctx.addresses,
                    ),
                ),
            )
        )
        need_edit = True

    while True:
        if need_edit:
            r = edit_until_valid(ctx.path, ctx.origin, base_soa)
            if r is None:
                if discard_if_unchanged(ctx, base, base_soa):
                    print("Aborted without changes.")
                return 1
            new, new_soa = r
        else:
            try:
                new, new_soa = parse_file(ctx.path, ctx.origin, base_soa)
            except (dns.exception.DNSException, ValueError) as e:
                print(f"Error: {e}")
                need_edit = True
                continue
        need_edit = True

        new, new_soa, recased = keep_base_case(base, base_soa, new, new_soa)
        if recased:
            print(
                "Letter case in DNS names is not significant, so case-only changes are not sent: "
                + ", ".join(f"{k[0]} {tname(k[1])}" for k in recased)
            )
        old_lines = [soa_line(base_soa, ctx.origin)] + rr_lines(base, ctx.origin, addresses=ctx.addresses)
        new_lines = [soa_line(new_soa, ctx.origin)] + rr_lines(new, ctx.origin, addresses=ctx.addresses)
        if old_lines == new_lines:
            print("No differences from the server - nothing to send.")
            cleanup(ctx)
            return 0

        dels, adds, final = compute_update(base, new, ctx.origin)
        prereqs = compute_prereqs(base, new, ctx.origin)
        with_soa = soa_changed(base_soa, new_soa)
        plan = (base_soa, new_soa, prereqs, dels, adds, final)

        show_diff(old_lines, new_lines, f"{ctx.origin} (serial {base_soa[0].serial})", "edited")
        print(
            f"\n{len(dels) + len(final)} delete, {len(adds)} add{', SOA changed' if with_soa else ''}"
            " in 1 atomic UPDATE."
        )
        for w in signal_warnings(base, new):
            print(f"Warning: {w}")

        while True:
            a = ask("Send? [y]es / [N]o / [e]dit / [s]cript: ", {"y", "n", "e", "s"})
            if a != "s":
                break
            script, _, conflicts = make_script(ctx, *plan)
            print(script)
            if conflicts:
                print(f"Warning: {soa_conflict_message(conflicts)} Sending would offer a rebase.")
        if a == "e":
            continue
        if a != "y":
            print("Nothing sent.")
            return 2
        if args.dry_run:
            script, _, conflicts = make_script(ctx, *plan)
            print(script)
            if conflicts:
                print(f"Warning: {soa_conflict_message(conflicts)} Sending would offer a rebase.")
            print("Nothing sent (--dry-run).")
            hint(ctx, args, dry_run=True)
            return 0

        script, sent_soa, conflicts = make_script(ctx, *plan)
        if conflicts:
            ok, out, can_rebase = False, soa_conflict_message(conflicts), True
        else:
            ok, out, can_rebase = run_nsupdate(script, ctx.keyfile)
        if ok:
            if out:
                print(out)
            missing = verify(ctx, base, new, sent_soa)
            if missing:
                print(
                    "Update accepted, but could not be verified:\n  "
                    + "\n  ".join(missing)
                    + "\nCheck the server log (e.g. CNAME conflicts, dnssec-policy max-zone-ttl).",
                    file=sys.stderr,
                )
                return 3
            print("Updated and verified.")
            cleanup(ctx)
            return 0
        print(out, file=sys.stderr)
        if not can_rebase:
            return 2
        if ask("[r]ebase onto current zone / [a]bort? ", {"r", "a"}) != "r":
            return 2
        base, base_soa, conflicts = rebase(ctx, base, base_soa, new, new_soa)
        need_edit = conflicts > 0  # conflicts -> straight to the editor, otherwise diff first


def make_parser():
    ap = argparse.ArgumentParser(
        prog="zedit", description="Edit a dynamic DNS zone via AXFR + $EDITOR + nsupdate"
    )
    ap.add_argument("zone")
    ap.add_argument("-s", "--server", help="primary server (default: the zone's SOA MNAME)")
    ap.add_argument("-p", "--port", type=int, default=53)
    ap.add_argument(
        "-k",
        "--keyfile",
        help="TSIG key (tsig-keygen format), used for AXFR and UPDATE (default: $ZEDIT_KEYFILE, "
        "else ~/.config/zedit/keys/ZONE.key, else ~/.config/zedit/default.key)",
    )
    ap.add_argument(
        "-a",
        "--show-all",
        action="store_true",
        help="also show DNSSEC and server-maintained records, as read-only ';ro' comment lines",
    )
    ap.add_argument(
        "--no-rrsig",
        action="store_true",
        help="with --show-all, leave out RRSIG, NSEC and NSEC3 (implies -a)",
    )
    ap.add_argument(
        "-A",
        "--addresses",
        action="store_true",
        help="in reverse zones, show owner names as IP addresses (input in address form always works)",
    )
    ap.add_argument("-n", "--dry-run", action="store_true", help="show the nsupdate script, send nothing")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("-r", "--resume", metavar="FILE", help="resume a saved edit (requires FILE.base)")
    return ap


def main():
    args = make_parser().parse_args()

    try:
        origin = dns.name.from_text(args.zone)
    except dns.exception.DNSException as e:
        die(f"invalid zone name {args.zone!r}: {e}")
    host = args.server or primary_from_mname(origin)
    address = resolve(host, args.port)
    keyfile = args.keyfile or find_keyfile(origin)
    if keyfile:
        check_keyfile(keyfile)
    ctx = SimpleNamespace(
        origin=origin,
        port=args.port,
        server=address,
        label=address if host.rstrip(".") == address else f"{host.rstrip('.')} ({address})",
        keyfile=keyfile,
        keyring=None,
        keyname=None,
        show_all=args.show_all or args.no_rrsig,
        no_rrsig=args.no_rrsig,
        addresses=args.addresses,
        path=None,
        basepath=None,
    )
    if keyfile:
        ctx.keyring, ctx.keyname = load_bind_key(keyfile)
    if not args.server or not args.keyfile:
        print(f"Server: {ctx.label}  Key: {keyfile or 'none'}", file=sys.stderr)

    try:
        rc = session(ctx, args)
    except KeyboardInterrupt:
        print()
        rc = 130
    except (ZeditError, OSError) as e:  # OSError: e.g. state directory not writable, disk full
        print(f"zedit: {e}", file=sys.stderr)
        rc = 1
    if rc:
        hint(ctx, args)
    sys.exit(rc)


if __name__ == "__main__":
    main()
