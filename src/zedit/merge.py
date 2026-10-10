"""Three-way merge of the zone as transferred, as edited and as on the server.

When the server rejects an UPDATE because an RRset the edit touches has changed
since the transfer, or when a saved session is resumed, the edit is "rebased":
the zone is transferred again, and the user's changes (base -> mine) are
applied to the zone as it is now (theirs), RRset by RRset, as git merges lines.
Where both sides changed the same RRset, the result is marked in the session
file for the user to review before anything is sent.
"""

from dataclasses import dataclass
from typing import TypeVar

import dns.name
import dns.rdataset
import dns.rdatatype

from zedit.model import SOA_EDITABLE, SOA_KEY, Notes, Records, RRKey, Zone, same, tname

T = TypeVar("T")


@dataclass(frozen=True)
class MergeResult:
    """The merged records; the comment lines to show above each RRset changed
    on both sides; the RRsets the merge left empty, as text; the number of
    conflicts (where mine was kept)."""

    records: Records
    notes: Notes
    dropped: list[str]
    conflicts: int


@dataclass(frozen=True)
class SoaMerge:
    """The merged SOA, the comment lines on its conflicts and their number."""

    soa: dns.rdataset.Rdataset
    notes: list[str]
    conflicts: int


def merge_scalar(b: T | None, m: T, t: T) -> tuple[T, bool]:
    """Merge one value, e.g. a TTL or an SOA field, as it was (b, None if it
    didn't exist), as I changed it (m) and as the server has it now (t).
    -> (value, conflict?): the side that changed it wins; if both did, to
    different values, that is a conflict, and mine wins."""
    if m == b:
        return t, False
    if t == b or m == t:
        return m, False
    return m, True


def merge3(base: Records, mine: Records, theirs: Records) -> MergeResult:
    """Per RRset: unchanged by me -> theirs; unchanged on the server -> mine;
    changed on both sides -> rdata set merge: theirs + my additions - my deletions,
    except for single-record types (CNAME etc.), where two values are a conflict."""
    merged, notes, dropped, conflicts = {}, {}, [], 0
    for k in set(base) | set(mine) | set(theirs):
        # None: the RRset doesn't exist on that side
        b, m, t = base.get(k), mine.get(k), theirs.get(k)
        if same(m, b):
            r = t  # I didn't touch it: the server's version, whatever happened there
        elif same(t, b) or same(m, t):
            r = m  # only I changed it, or the server already has my change
        else:
            # Both changed it: start from the server's records, add those I
            # added and remove those I removed, each compared with the base
            bs, ms, ts = (set(x) if x else set() for x in (b, m, t))
            rd = (ts | (ms - bs)) - (bs - ms)
            note = ["; MERGED: changed both by you and on the server - please review"]
            if m is None:
                assert t is not None  # else same(m, t)
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
            if len(rd) > 1 and dns.rdatatype.is_singleton(dns.rdatatype.RdataType.make(k.rdtype)):
                # CNAME, DNAME etc. hold a single record, so two values can't be
                # merged as a union (dnspython would keep one, in hash order).
                # Both sides have one, or rd couldn't hold two.
                assert m is not None and t is not None
                conflicts += 1
                note.append(
                    f"; CONFLICT {tname(k.rdtype)}: base={b[0].to_text() if b else '-'} "
                    f"server={t[0].to_text()} mine={m[0].to_text()} - mine kept"
                )
                rd = set(m)
            r = dns.rdataset.from_rdata_list(ttl, list(rd)) if rd else None
            if r is None:
                # Both sides' changes together leave no records: said in the file
                dropped.append(f"{k.name} {tname(k.rdtype)}")
            else:
                notes[k] = note
        if r is not None:
            merged[k] = r
    return MergeResult(merged, notes, dropped, conflicts)


def merge_soa(b: dns.rdataset.Rdataset, m: dns.rdataset.Rdataset, t: dns.rdataset.Rdataset) -> SoaMerge:
    """Merge the SOA field by field: base (b), mine (m), theirs (t)."""
    fields, note, conflicts = {}, [], 0
    for f in SOA_EDITABLE:
        bv, mv, tv = getattr(b[0], f), getattr(m[0], f), getattr(t[0], f)
        fields[f], c = merge_scalar(bv, mv, tv)
        if c:
            conflicts += 1
            note.append(f"; CONFLICT SOA {f.upper()}: base={bv} server={tv} mine={mv} - mine kept")
    # MNAME, SERIAL and the SOA TTL always come from the server
    return SoaMerge(dns.rdataset.from_rdata(t.ttl, t[0].replace(**fields)), note, conflicts)


def keep_base_case(base: Zone, new: Zone) -> tuple[Zone, list[RRKey]]:
    """DNS names compare case-insensitively, so a change of letter case alone
    (www CNAME Target for target) is no change to the server: the UPDATE would
    leave the record as it is. Owner names, records and SOA names equal to ones
    in the base get the base's spelling back, so that the diff shows only what
    is sent. -> (new Zone, keys whose case was put back)."""
    # Dict lookups compare names case-insensitively, as DNS does, and give back
    # the base's own key or record: its spelling
    out, reverted, base_keys = {}, [], {k: k for k in base.records}
    for k, rds in new.records.items():
        bk = base_keys.get(k, k)
        old = {r: r for r in base.records[bk]} if bk in base.records else {}
        rds_out = [old.get(r, r) for r in rds]
        texts = [r.to_text() for r in rds]
        if bk.name.to_text() != k.name.to_text() or texts != [r.to_text() for r in rds_out]:
            reverted.append(bk)
            rds = dns.rdataset.from_rdata_list(rds.ttl, rds_out)
        out[bk] = rds
    # In the SOA, only MNAME and RNAME are names; the other fields are numbers
    new_soa, o, n = new.soa, base.soa[0], new.soa[0]
    names = {f: getattr(o, f) for f in ("mname", "rname") if getattr(o, f) == getattr(n, f)}
    soa_rd = n.replace(**names)
    if soa_rd.to_text() != n.to_text():
        reverted.insert(0, SOA_KEY)
        new_soa = dns.rdataset.from_rdata(new_soa.ttl, soa_rd)
    return Zone(out, new_soa, new.hidden), reverted
