"""The RFC 2136 backend: TSIG, AXFR, SOA query and the DNS UPDATE."""

import asyncio
import contextlib
import re
import socket
from typing import NamedTuple

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataset
import dns.rdatatype
import dns.resolver
import dns.tsigkeyring
import dns.update
import dns.zone

from zedit import changes, zonefile
from zedit.model import APEX_NS, SOA, ZeditError, Zone, die, same, sortkey, tname

KEY_STATEMENT = re.compile(r'key\s+"?([^"\s{]+)"?\s*\{(.*?)\}\s*;', re.S)


def load_bind_key(path):
    """Read a key in tsig-keygen / named.conf format."""
    with open(path) as f:
        text = f.read()
    keys = KEY_STATEMENT.findall(text)
    if not keys:
        die(f"no key statement found in {path}")
    if len(keys) > 1:
        names = ", ".join(name for name, _ in keys)
        die(f"{path} has {len(keys)} key statements ({names}); a key file must hold a single key")
    ((name, body),) = keys
    alg = re.search(r'algorithm\s+"?([\w.-]+)"?\s*;', body)
    sec = re.search(r'secret\s+"([^"]+)"\s*;', body)
    if not (alg and sec):
        die(f"algorithm/secret missing in {path}")
    kr = dns.tsigkeyring.from_text({name: (alg.group(1), sec.group(1))})
    return kr, dns.name.from_text(name)


def fetch(ctx):
    try:
        xfr = dns.query.xfr(
            ctx.server, ctx.origin, port=ctx.port, keyring=ctx.keyring, keyname=ctx.keyname, lifetime=120
        )
        zone = dns.zone.from_xfr(xfr, relativize=True)
    except Exception as e:  # dnspython raises a whole zoo of types here
        raise ZeditError(f"AXFR failed: {e}") from e
    model, soa, hidden = zonefile.to_model(zone)
    if soa is None:
        raise ZeditError("AXFR has no SOA at the apex")
    return Zone(model, soa, hidden)


class Op(NamedTuple):
    """One step of an UPDATE (RFC 2136), on an absolute name. The same list of
    steps gives the message that is sent and the nsupdate script that is shown.

    kind "absent":  prerequisite, the RRset does not exist
         "present": prerequisite, the RRset exists with exactly these rdatas
         "delete":  delete these rdatas, or the whole RRset if there are none
         "add":     add these rdatas with this TTL"""

    kind: str
    name: dns.name.Name
    rdtype: int
    ttl: int | None = None
    rdatas: tuple = ()


def compute_update(old, new, origin):
    """-> (deletes, adds, final deletes): only the records that change. Deletes go
    before adds (handles e.g. A -> CNAME), except at the apex NS RRset: RFC 2136
    §3.4.2.4 has the server ignore deleting the apex NS RRset or its last record,
    so there the new records are added first and the old ones deleted after
    ("final deletes"), record by record. Elsewhere a TTL change replaces the
    whole RRset, since the TTL applies to all of it."""
    dels, adds, final = [], [], []
    for key in sorted(set(old) | set(new), key=sortkey):
        o, n = old.get(key), new.get(key)
        name, t = key.name.derelativize(origin), key.rdtype
        if key == APEX_NS and o is not None and n is not None:
            if changed := tuple(n) if o.ttl != n.ttl else tuple(r for r in n if r not in o):
                adds.append(Op("add", name, t, n.ttl, changed))
            if gone := tuple(r for r in o if r not in n):
                final.append(Op("delete", name, t, rdatas=gone))
        elif o is None:
            adds.append(Op("add", name, t, n.ttl, tuple(n)))
        elif n is None:
            dels.append(Op("delete", name, t))
        elif o.ttl != n.ttl:
            dels.append(Op("delete", name, t))
            adds.append(Op("add", name, t, n.ttl, tuple(n)))
        else:
            if gone := tuple(r for r in o if r not in n):
                dels.append(Op("delete", name, t, rdatas=gone))
            if added := tuple(r for r in n if r not in o):
                adds.append(Op("add", name, t, n.ttl, added))
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
        name, t = key.name.derelativize(origin), key.rdtype
        out.append(Op("absent", name, t) if o is None else Op("present", name, t, rdatas=tuple(o)))
    return out


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


def soa_update(soa, origin):
    """The step that sets the SOA (an RRset), or none."""
    if soa is None:
        return []
    return [Op("add", origin, SOA, soa.ttl, (soa[0],))]


def update_ops(ctx, base_soa, new_soa, prereqs, dels, adds, final):
    """-> (all steps of the UPDATE in order, SOA RRset sent or None, conflicting
    SOA fields): prerequisites, deletes, adds, final deletes (see
    compute_update()). The SOA is merged with the live zone at the moment this
    is called."""
    live = live_soa(ctx) if changes.soa_changed(base_soa, new_soa) else None
    soa, conflicts = changes.soa_to_send(base_soa, new_soa, live)
    return prereqs + dels + adds + soa_update(soa, ctx.origin) + final, soa, conflicts


def op_lines(op, origin):
    """An Op as nsupdate commands."""
    name, t = op.name.to_text(), tname(op.rdtype)
    rds = [r.to_text(origin=origin, relativize=False) for r in op.rdatas]
    if op.kind == "absent":
        return [f"prereq nxrrset {name} IN {t}"]
    if op.kind == "present":
        return [f"prereq yxrrset {name} IN {t} {rd}" for rd in rds]
    if op.kind == "delete":
        return [f"update delete {name} IN {t} {rd}" for rd in rds] or [f"update delete {name} IN {t}"]
    return [f"update add {name} {op.ttl} IN {t} {rd}" for rd in rds]


def script_text(server, port, origin, ops):
    """The UPDATE as an nsupdate script, for --dry-run and [s]cript. It can be
    sent by hand with nsupdate -v -k KEYFILE."""
    lines = [f"server {server} {port}", f"zone {origin}"]
    return "\n".join(lines + [line for op in ops for line in op_lines(op, origin)] + ["send", ""])


def make_script(ctx, *plan):
    """-> (nsupdate script, SOA RRset sent or None, conflicting SOA fields)."""
    ops, soa, conflicts = update_ops(ctx, *plan)
    return script_text(ctx.server, ctx.port, ctx.origin, ops), soa, conflicts


def update_message(origin, ops, keyring=None, keyname=None):
    """The UPDATE as a DNS message, signed with TSIG if there is a key."""
    msg = dns.update.UpdateMessage(origin)
    for op in ops:
        if op.kind == "absent":
            msg.absent(op.name, op.rdtype)
        elif op.kind == "present":
            msg.present(op.name, *op.rdatas)
        elif op.kind == "delete":
            msg.delete(op.name, *(op.rdatas or (op.rdtype,)))
        else:
            msg.add(op.name, op.ttl, *op.rdatas)
    if keyring:
        msg.use_tsig(keyring, keyname=keyname)
    return msg


UPDATE_TIMEOUT = 60
UNKNOWN_OUTCOME = (
    "unknown whether the update was applied. Rebasing is safe: changes already applied simply drop out."
)


def send_update(ctx, ops):
    """Send the UPDATE over TCP. -> (ok, message, rebase_makes_sense)"""
    msg = update_message(ctx.origin, ops, ctx.keyring, ctx.keyname)
    try:
        response = dns.query.tcp(msg, ctx.server, port=ctx.port, timeout=UPDATE_TIMEOUT)
    except dns.exception.Timeout:
        return False, f"UPDATE timed out - {UNKNOWN_OUTCOME}", True
    except (EOFError, ConnectionResetError):
        return False, f"connection closed during the UPDATE - {UNKNOWN_OUTCOME}", True
    except (OSError, dns.exception.DNSException) as e:
        # e.g. connection refused, or a TSIG error (bad key, clock skew)
        return False, f"UPDATE failed: {e}", False
    rcode = response.rcode()
    if rcode == dns.rcode.NOERROR:
        return True, "", False
    text = f"update failed: {dns.rcode.to_text(rcode)}"
    if rcode in (dns.rcode.NXRRSET, dns.rcode.YXRRSET):
        return False, text + "\nRRsets you changed were modified on the server after the transfer.", True
    # REFUSED/NOTAUTH/SERVFAIL etc.: rebasing won't help
    return False, text, False


def resolve(host, port):
    """The address of host that first accepts a TCP connection on port, using
    Happy Eyeballs (RFC 8305): a server with an AAAA record is still reached
    quickly over IPv4 when IPv6 doesn't work. AXFR and the UPDATE
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
