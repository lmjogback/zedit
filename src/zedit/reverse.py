"""Owner names written as IP addresses in reverse zones."""

import ipaddress
import re

import dns.name

IN_ADDR = dns.name.from_text("in-addr.arpa.")
IP6_ARPA = dns.name.from_text("ip6.arpa.")
LOOKS_LIKE_IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$")  # with an optional (rejected) prefix


def is_reverse(origin):
    return origin.is_subdomain(IN_ADDR) or origin.is_subdomain(IP6_ARPA)


def address_owners(origin):
    """Whether owners in this zone may be written (and shown with -A) as IP
    addresses. Not in in-addr.arpa itself, where four labels are a valid name."""
    return is_reverse(origin) and origin != IN_ADDR


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
    if not address_owners(origin):
        return None
    if origin.is_subdomain(IP6_ARPA) and NIBBLES.match(token):
        # In ip6.arpa a token like 0.5.0.0 is a nibble name (e.g. a /64 under a
        # /48), not an address.
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
    if not address_owners(origin):
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
