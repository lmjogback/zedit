"""What an edit changes, independent of how it is sent: the ChangeSet a backend
receives, the SOA to send, and warnings."""

import re
from dataclasses import dataclass

import dns.rdataset
import dns.rdatatype

from zedit import merge
from zedit.model import (
    FILTERED_AT_APEX,
    SIGNAL_LABEL,
    SOA_EDITABLE,
    RRKey,
    ZeditError,
    Zone,
    same,
    sortkey,
    tname,
)


@dataclass(frozen=True)
class RRsetChange:
    """One RRset the edit changes: as transferred (None if it is created) and
    as edited (None if it is deleted)."""

    key: RRKey
    old: dns.rdataset.Rdataset | None
    new: dns.rdataset.Rdataset | None


@dataclass(frozen=True)
class ChangeSet:
    """An edit as what it changes, whatever sends it: the changed RRsets in
    canonical order (apex first), and the SOA as transferred and as edited."""

    rrsets: tuple[RRsetChange, ...]
    base_soa: dns.rdataset.Rdataset
    new_soa: dns.rdataset.Rdataset

    @property
    def soa_changed(self):
        return soa_changed(self.base_soa, self.new_soa)


def change_set(base: Zone, new: Zone) -> ChangeSet:
    keys = sorted(set(base.records) | set(new.records), key=sortkey)
    return ChangeSet(
        tuple(
            RRsetChange(k, base.records.get(k), new.records.get(k))
            for k in keys
            if not same(base.records.get(k), new.records.get(k))
        ),
        base.soa,
        new.soa,
    )


def signal_warnings(base, new):
    """CDS/CDNSKEY added or changed below the apex but not at a _dsboot name, where
    an RFC 9615 signal belongs (e.g. a typo such as _dsbot). Only a warning: zedit
    doesn't check signals against the child zone or its delegation."""
    return [
        f"{k.name} {tname(k.rdtype)} is not at a _dsboot name; RFC 9615 signals are named "
        "_dsboot.CHILD._signal.NS-HOST"
        for k in sorted(new, key=sortkey)
        if k.rdtype in FILTERED_AT_APEX
        and k.name.labels[0].lower() != SIGNAL_LABEL
        and not same(base.get(k), new[k])
    ]


TXT = int(dns.rdatatype.TXT)
SPF_RECORD = re.compile(rb"v=spf1(?: |$)", re.IGNORECASE)


def ascii_kind(name, rd):
    """'SPF', 'DKIM' or 'DMARC' for a TXT record of a protocol that is ASCII
    only (RFC 7208, 6376, 7489), else None."""
    text = b"".join(rd.strings)
    labels = [label.lower() for label in name.labels]
    if SPF_RECORD.match(text):
        return "SPF"
    if b"_domainkey" in labels[1:2]:  # SELECTOR._domainkey[.SUB]
        return "DKIM"
    if labels[:1] == [b"_dmarc"]:
        return "DMARC"
    return None


def ascii_warnings(base, new):
    """Non-ASCII bytes in an added SPF, DKIM or DMARC record: typically a
    pasted typographic quote, dash or no-break space, or a domain written in
    Unicode instead of as an A-label. Shown as \\DDD escapes, but easy to miss."""
    out = []
    for k in sorted(new, key=sortkey):
        if k.rdtype != TXT:
            continue
        old = base.get(k) or ()
        for rd in sorted(new[k], key=lambda r: r.to_text()):
            kind = ascii_kind(k.name, rd)
            if kind and rd not in old and any(b < 0x20 or b > 0x7E for s in rd.strings for b in s):
                out.append(
                    f"{k.name} TXT: {kind} records must be ASCII, and this one isn't; "
                    "domain names in it must be A-labels (xn--...)"
                )
    return out


def serial_max(a, b):
    """The greater of two serials in RFC 1982 serial number arithmetic."""
    if b is None:
        return a
    return b if 0 < (b - a) % 2**32 < 2**31 else a


def change_count(edit):
    """-> (records deleted, records added), as the diff shows them: a deleted
    RRset counts each of its records, and so does an RRset whose TTL changes,
    on both sides."""
    dels = adds = 0
    for c in edit.rrsets:
        o, n = c.old, c.new
        if o is not None and n is not None and o.ttl == n.ttl:
            dels += sum(r not in n for r in o)
            adds += sum(r not in o for r in n)
        else:
            dels += len(o or ())
            adds += len(n or ())
    return dels, adds


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
        fields[f], c = merge.merge_scalar(
            getattr(base_rds[0], f), getattr(new_rds[0], f), getattr(live[0], f)
        )
        if c:
            conflicts.append(f.upper())
    fields["serial"] = (serial_max(base_rds[0].serial, live[0].serial) + 1) % 2**32
    return dns.rdataset.from_rdata(live.ttl, live[0].replace(**fields)), conflicts
