"""Three-way merge of the zone as transferred, as edited and as on the server."""

import dns.name
import dns.rdataset
import dns.rdatatype

from zedit.model import SOA, SOA_EDITABLE, same, tname


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
