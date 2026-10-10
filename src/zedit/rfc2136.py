"""The RFC 2136 backend: TSIG, AXFR, SOA query and the DNS UPDATE."""

import asyncio
import contextlib
import re
import socket
from dataclasses import dataclass, replace
from typing import NamedTuple

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataset
import dns.rdatatype
import dns.resolver
import dns.tsig
import dns.tsigkeyring
import dns.update
import dns.zone

from zedit import changes, zonefile
from zedit.backend import Outcome, Preview, SendResult
from zedit.changes import ChangeSet
from zedit.model import APEX_NS, SOA, ZeditError, Zone, tname

Keyring = dict[dns.name.Name, dns.tsig.Key]
# What a failed query or transfer raises: TSIG errors (bad key or signature),
# a refused or failed transfer (dns.xfr.TransferError), timeouts, connection
# errors, and EOFError when the server closes the connection.
QUERY_ERRORS = (dns.exception.DNSException, OSError, EOFError)
KEY_STATEMENT = re.compile(r'key\s+"?([^"\s{]+)"?\s*\{(.*?)\}\s*;', re.S)


def load_bind_key(path: str) -> tuple[Keyring, dns.name.Name]:
    """Read a key in tsig-keygen / named.conf format."""
    try:
        with open(path) as f:
            text = f.read()
    except (OSError, UnicodeDecodeError) as e:
        raise ZeditError(f"cannot read key file {path}: {e}") from e
    keys = KEY_STATEMENT.findall(text)
    if not keys:
        raise ZeditError(f"no key statement found in {path}")
    if len(keys) > 1:
        names = ", ".join(name for name, _ in keys)
        raise ZeditError(
            f"{path} has {len(keys)} key statements ({names}); a key file must hold a single key"
        )
    ((name, body),) = keys
    alg = re.search(r'algorithm\s+"?([\w.-]+)"?\s*;', body)
    sec = re.search(r'secret\s+"([^"]+)"\s*;', body)
    if not (alg and sec):
        raise ZeditError(f"algorithm/secret missing in {path}")
    try:
        kr = dns.tsigkeyring.from_text({name: (alg.group(1), sec.group(1))})
        keyname = dns.name.from_text(name)
        # dnspython checks the algorithm only when it signs
        q = dns.message.make_query(keyname, dns.rdatatype.SOA)
        q.use_tsig(kr, keyname=keyname)
        q.to_wire()
    except KeyError:
        raise ZeditError(f"invalid key in {path}: unknown algorithm {alg.group(1)}") from None
    except (ValueError, dns.exception.DNSException) as e:  # ValueError: e.g. a secret that isn't base64
        raise ZeditError(f"invalid key in {path}: {e}") from e
    return kr, keyname


@dataclass(frozen=True)
class Rfc2136Backend:
    """The zone's primary server, at address and port, and the TSIG key for it
    (keyring None: no TSIG). label names the server in messages."""

    address: str
    port: int
    label: str
    keyring: Keyring | None = None
    keyname: dns.name.Name | None = None

    def fetch(self, origin: dns.name.Name, timeout: float | None = None) -> Zone:
        return fetch(self, origin, timeout)

    def current_soa(
        self, origin: dns.name.Name, timeout: float | None = None
    ) -> dns.rdataset.Rdataset | None:
        return live_soa(self, origin, timeout)

    def preview(self, origin: dns.name.Name, edit: ChangeSet) -> Preview:
        """The UPDATE as an nsupdate script."""
        ops, _, conflicts = update_ops(self, origin, edit)
        return Preview(script_text(self.address, self.port, origin, ops), conflicts)

    def apply(self, origin: dns.name.Name, edit: ChangeSet) -> SendResult:
        """Send the UPDATE, unless the SOA conflicts."""
        ops, soa, conflicts = update_ops(self, origin, edit)
        if conflicts:
            return SendResult(Outcome.REBASE, changes.soa_conflict_message(conflicts))
        result = send_update(self, origin, ops)
        return replace(result, soa=soa) if result.outcome is Outcome.OK else result


AXFR_TIMEOUT = 120
SOA_QUERY_TIMEOUT = 10


def fetch(server: Rfc2136Backend, origin: dns.name.Name, timeout: float | None = None) -> Zone:
    try:
        xfr = dns.query.xfr(
            server.address,
            origin,
            port=server.port,
            keyring=server.keyring,
            keyname=server.keyname,
            lifetime=AXFR_TIMEOUT if timeout is None else timeout,
        )
        zone = dns.zone.from_xfr(xfr, relativize=True)
    except QUERY_ERRORS as e:
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
    rdatas: tuple[dns.rdata.Rdata, ...] = ()


def compute_update(edit: ChangeSet, origin: dns.name.Name) -> tuple[list[Op], list[Op], list[Op]]:
    """-> (deletes, adds, final deletes): only the records that change. Deletes go
    before adds (handles e.g. A -> CNAME), except at the apex NS RRset: RFC 2136
    §3.4.2.4 has the server ignore deleting the apex NS RRset or its last record,
    so there the new records are added first and the old ones deleted after
    ("final deletes"), record by record. Elsewhere a TTL change replaces the
    whole RRset, since the TTL applies to all of it."""
    dels, adds, final = [], [], []
    for c in edit.rrsets:
        key, o, n = c.key, c.old, c.new
        name, t = key.name.derelativize(origin), key.rdtype
        if key == APEX_NS and o is not None and n is not None:
            if changed := tuple(n) if o.ttl != n.ttl else tuple(r for r in n if r not in o):
                adds.append(Op("add", name, t, n.ttl, changed))
            if gone := tuple(r for r in o if r not in n):
                final.append(Op("delete", name, t, rdatas=gone))
        elif o is None:
            assert n is not None  # a change has at least one side
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


def compute_prereqs(edit: ChangeSet, origin: dns.name.Name) -> list[Op]:
    """Optimistic lock on exactly the RRsets this update touches (RFC 2136 §2.4):
    value-dependent "RRset exists" with the base content for RRsets that are
    changed or deleted, "RRset does not exist" for RRsets that are created.
    Concurrent changes to other names (e.g. DHCP/DDNS) don't conflict."""
    out = []
    for c in edit.rrsets:
        name, t = c.key.name.derelativize(origin), c.key.rdtype
        out.append(Op("absent", name, t) if c.old is None else Op("present", name, t, rdatas=tuple(c.old)))
    return out


def live_soa(
    server: Rfc2136Backend, origin: dns.name.Name, timeout: float | None = None
) -> dns.rdataset.Rdataset | None:
    """The zone's SOA RRset as the server answers it now, or None if the query
    fails. With inline-signing it is the signed zone's SOA: its serial is normally
    >= the unsigned one, and its other fields are the same.

    Names in it are made relative to the zone, as in the transferred zone (an
    RNAME such as hostmaster.example.com. becomes hostmaster), so that its fields
    compare equal to the transferred and edited ones."""
    try:
        q = dns.message.make_query(origin, dns.rdatatype.SOA)
        if server.keyring:
            q.use_tsig(server.keyring, keyname=server.keyname)
        limit = SOA_QUERY_TIMEOUT if timeout is None else min(timeout, SOA_QUERY_TIMEOUT)
        r = dns.query.tcp(q, server.address, port=server.port, timeout=limit)
        for rrset in r.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                rd = rrset[0]
                return dns.rdataset.from_rdata(
                    rrset.ttl,
                    rd.replace(mname=rd.mname.relativize(origin), rname=rd.rname.relativize(origin)),
                )
    except QUERY_ERRORS:
        pass
    return None


def soa_update(soa: dns.rdataset.Rdataset | None, origin: dns.name.Name) -> list[Op]:
    """The step that sets the SOA (an RRset), or none."""
    if soa is None:
        return []
    return [Op("add", origin, SOA, soa.ttl, (soa[0],))]


def update_ops(
    server: Rfc2136Backend, origin: dns.name.Name, edit: ChangeSet
) -> tuple[list[Op], dns.rdataset.Rdataset | None, list[str]]:
    """-> (all steps of the UPDATE for the ChangeSet edit in order, SOA RRset sent
    or None, conflicting SOA fields): prerequisites, deletes, adds, final deletes
    (see compute_update()). The SOA is merged with the live zone at the moment
    this is called."""
    dels, adds, final = compute_update(edit, origin)
    live = live_soa(server, origin) if edit.soa_changed else None
    soa, conflicts = changes.soa_to_send(edit.base_soa, edit.new_soa, live)
    ops = compute_prereqs(edit, origin) + dels + adds + soa_update(soa, origin) + final
    return ops, soa, conflicts


def op_lines(op: Op, origin: dns.name.Name) -> list[str]:
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


def script_text(server: str, port: int, origin: dns.name.Name, ops: list[Op]) -> str:
    """The UPDATE as an nsupdate script, for --dry-run and [s]cript. It can be
    sent by hand with nsupdate -v -k KEYFILE."""
    lines = [f"server {server} {port}", f"zone {origin}"]
    return "\n".join(lines + [line for op in ops for line in op_lines(op, origin)] + ["send", ""])


def update_message(
    origin: dns.name.Name, ops: list[Op], keyring: Keyring | None = None, keyname: dns.name.Name | None = None
) -> dns.update.UpdateMessage:
    """The UPDATE as a DNS message, signed with TSIG if there is a key."""
    msg = dns.update.UpdateMessage(origin)
    for op in ops:
        if op.kind == "absent":
            msg.absent(op.name, dns.rdatatype.RdataType.make(op.rdtype))
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


def send_update(server: Rfc2136Backend, origin: dns.name.Name, ops: list[Op]) -> SendResult:
    """Send the UPDATE over TCP. -> SendResult (without the SOA)."""
    msg = update_message(origin, ops, server.keyring, server.keyname)
    try:
        response = dns.query.tcp(msg, server.address, port=server.port, timeout=UPDATE_TIMEOUT)
    except dns.exception.Timeout:
        return SendResult(Outcome.REBASE, f"UPDATE timed out - {UNKNOWN_OUTCOME}")
    except (EOFError, ConnectionResetError):
        return SendResult(Outcome.REBASE, f"connection closed during the UPDATE - {UNKNOWN_OUTCOME}")
    except (OSError, dns.exception.DNSException) as e:
        # e.g. connection refused, or a TSIG error (bad key, clock skew)
        return SendResult(Outcome.FAILED, f"UPDATE failed: {e}")
    rcode = response.rcode()
    if rcode == dns.rcode.NOERROR:
        return SendResult(Outcome.OK)
    text = f"update failed: {dns.rcode.to_text(rcode)}"
    if rcode in (dns.rcode.NXRRSET, dns.rcode.YXRRSET):
        message = text + "\nRRsets you changed were modified on the server after the transfer."
        return SendResult(Outcome.REBASE, message)
    # REFUSED/NOTAUTH/SERVFAIL etc.: rebasing won't help
    return SendResult(Outcome.FAILED, text)


def resolve(host: str, port: int) -> str:
    """The address of host that first accepts a TCP connection on port, using
    Happy Eyeballs (RFC 8305): a server with an AAAA record is still reached
    quickly over IPv4 when IPv6 doesn't work. AXFR and the UPDATE
    use TCP anyway."""

    async def connect() -> str:
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
        raise ZeditError(f"cannot resolve {host}: {e}") from e
    except (OSError, asyncio.TimeoutError) as e:
        raise ZeditError(f"cannot connect to {host} port {port}: {str(e) or 'timed out'}") from e


def primary_from_mname(origin: dns.name.Name) -> str:
    """The zone's primary according to the SOA MNAME, via the system resolver."""
    try:
        answer = dns.resolver.resolve(origin, "SOA", lifetime=10)
    except dns.exception.DNSException as e:
        raise ZeditError(
            f"cannot look up the SOA of {origin} to find its primary ({e}); use -s SERVER"
        ) from e
    return answer[0].mname.to_text()
