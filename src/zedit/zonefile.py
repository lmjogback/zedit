"""Zone file text <-> the model: parsing (with $GENERATE) and rendering."""

import ipaddress
import re

import dns.exception
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.tokenizer
import dns.zone
import dns.zonefile

from zedit import reverse
from zedit.model import (
    APEX_NS,
    CNAME,
    FILTERED,
    FILTERED_AT_APEX,
    IDNA,
    LOCKED_SOA,
    NOISY,
    SOA,
    SOA_KEY,
    HiddenKey,
    RRKey,
    Zone,
    display_key,
    tname,
)


def is_filtered(name, t):
    return t in FILTERED or (t in FILTERED_AT_APEX and name == dns.name.empty)


def to_model(zone):
    """-> (model, apex SOA, rejected).

    model:    Records, without SOA and filtered types
    rejected: Hidden, the filtered types and any SOA outside the apex"""
    m, rejected, soa = {}, {}, None
    for name, rds in zone.iterate_rdatasets():
        t = int(rds.rdtype)
        if t == SOA and name == dns.name.empty:
            soa = rds
        elif t == SOA or is_filtered(name, t):
            rejected[HiddenKey(name, t, int(rds.covers))] = rds
        else:
            m[RRKey(name, t)] = rds
    return m, soa, rejected


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


class _Tokenizer(dns.tokenizer.Tokenizer):
    """After the last token on a line, the tokenizer has read the newline and
    counted the next line, then put the newline back without uncounting it, so
    an error in a record's last field (www A 999.1.1.1) was reported on the
    line after it."""

    def where(self):
        filename, line = super().where()
        return filename, line - (self.ungotten_char == "\n")


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
        m = GENERATE_LINE.match(line[: reverse.scan_line(line)[0]].rstrip())
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
        expanded = reverse.rewrite_address_owners(expanded, origin) + "\n"
    except ValueError as e:
        raise users_line(e) from None
    zone = dns.zone.Zone(origin, dns.rdataclass.IN, relativize=True)
    tok = _Tokenizer(expanded, "<edit>", idna_codec=IDNA)
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
    except dns.name.IDNAException as e:
        # Raised for an owner name without the reader's location; the tokenizer
        # is still on its line
        raise users_line(ValueError(f"line {tok.where()[1]}: {e}")) from None
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
        bad = ", ".join(sorted({f"{k.name} {tname(k.rdtype)}" for k in rejected}))
        raise ValueError(f"records not allowed (DNSSEC, CDS/CDNSKEY at the apex, or SOA outside it): {bad}")
    if soa is None:
        raise ValueError("SOA missing - it may be edited but not removed")
    return Zone(m, soa)


def check_cname(m):
    """BIND *silently* ignores adds that violate the CNAME rule (RFC 2136 §3.4.2.2),
    so this must be caught here rather than relying on the server."""
    types: dict[dns.name.Name, set[int]] = {}
    for n, t in m:
        types.setdefault(n, set()).add(t)
    bad = sorted(
        n.to_text() for n, ts in types.items() if CNAME in ts and (len(ts) > 1 or n == dns.name.empty)
    )
    if bad:
        raise ValueError("CNAME together with other data: " + ", ".join(bad))


def read_text(path):
    """A session file's text. Always UTF-8, whatever the locale, so that what
    you type reads the same everywhere."""
    with open(path, "rb") as f:
        data = f.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        line = data.count(b"\n", 0, e.start) + 1
        raise ValueError(
            f"line {line}: not valid UTF-8 (byte 0x{data[e.start]:02x}); save the file as UTF-8"
        ) from None


def parse_file(path, origin, base_soa):
    """The edited zone in path, checked against the SOA as transferred."""
    zone = parse_text(read_text(path), origin)
    m, soa = zone.records, zone.soa
    o, n = base_soa[0], soa[0]
    locked = [f.upper() for f in LOCKED_SOA if getattr(o, f) != getattr(n, f)]
    if base_soa.ttl != soa.ttl:
        locked.append("SOA record TTL")
    if locked:
        raise ValueError(f"locked SOA fields changed: {', '.join(locked)}")
    check_cname(m)
    if APEX_NS not in m:
        # The server would ignore deleting the last one (RFC 2136 §3.4.2.4)
        raise ValueError("the zone apex needs at least one NS record")
    return zone


def owner_text(name, origin, addresses):
    """The owner as written in the file: the relative name, or with --addresses
    in a reverse zone the IP address (the apex stays '@')."""
    if addresses and reverse.address_owners(origin) and name != dns.name.empty:
        address = reverse.name_to_address(name, origin)
        if address:
            return address
    return name.to_text()


def sort_key(origin, addresses):
    """display_key, but with --addresses records are ordered by address."""
    if not (addresses and reverse.address_owners(origin)):
        return display_key

    def key(k):
        name, t, flag = display_key(k)
        address = reverse.name_to_address(name, origin) if name != dns.name.empty else None
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
        name, t = key.name, key.rdtype
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
    (it may contain escaped dots, e.g. john\\.doe.example.com.). Characters
    that aren't printable are shown as \\DDD, as in the zone file: the address
    goes into a comment, and a line break there would end it."""
    name = rname.derelativize(origin)
    local = "".join(
        c if c.isprintable() else "".join(f"\\{b:03d}" for b in c.encode())
        for c in name.labels[0].decode(errors="replace")
    )
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
    pad = max([len(owner_text(k.name, origin, addresses)) for k in [*model, *(hidden or {})]] + [1])
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
            if reverse.address_owners(origin)
            else []
        ),
        *extra,
        f"$ORIGIN {origin}",
        f"$TTL {soa_rds[0].minimum}",
        "",
        *notes.get(SOA_KEY, []),
        soa_line(soa_rds, origin, pad),
        *soa_help(soa_rds, origin),
        "",
    ]
    return "\n".join(hdr + rr_lines(model, origin, pad, notes, hidden, addresses)) + "\n"


def shown(opts, hidden):
    """The read-only records to display, per --show-all / --no-rrsig, or None."""
    if not opts.show_all:
        return None
    return {k: v for k, v in hidden.items() if not (opts.no_rrsig and k.rdtype in NOISY)}
