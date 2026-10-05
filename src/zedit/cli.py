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
import difflib
import os
import re
import shlex
import socket
import subprocess
import sys
import time
from types import SimpleNamespace

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdataset
import dns.rdatatype
import dns.tsigkeyring
import dns.zone

from zedit import __version__

SOA = int(dns.rdatatype.SOA)
CNAME = int(dns.rdatatype.CNAME)
# RRSIG, NSEC, DNSKEY, NSEC3, NSEC3PARAM, CDS, CDNSKEY, ZONEMD, BIND private (signing state)
FILTERED = {46, 47, 48, 50, 51, 59, 60, 63, 65534}
SOA_EDITABLE = ("rname", "refresh", "retry", "expire", "minimum")
LOCKED_SOA = ("mname", "serial")
LOCK_SOA_TTL = True


class ZeditError(Exception):
    pass


def tname(t):
    return dns.rdatatype.to_text(t)


def die(msg, code=1):
    print(f"zedit: {msg}", file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------- TSIG


def load_bind_key(path):
    """Read a key in tsig-keygen / named.conf format."""
    with open(path) as f:
        text = f.read()
    m = re.search(r'key\s+"?([^"\s{]+)"?\s*\{(.*?)\}\s*;', text, re.S)
    if not m:
        die(f"no key statement found in {path}")
    name, body = m.groups()
    alg = re.search(r'algorithm\s+"?([\w.-]+)"?\s*;', body)
    sec = re.search(r'secret\s+"([^"]+)"\s*;', body)
    if not (alg and sec):
        die(f"algorithm/secret missing in {path}")
    kr = dns.tsigkeyring.from_text({name: (alg.group(1), sec.group(1))})
    return kr, dns.name.from_text(name)


# ---------------------------------------------------------------- zone <-> model


def to_model(zone):
    """-> ({(relative name, rdtype): Rdataset} without SOA/filtered, apex SOA, rejected)."""
    m, rejected, soa = {}, set(), None
    for name, rds in zone.iterate_rdatasets():
        t = int(rds.rdtype)
        if t == SOA:
            if name == dns.name.empty:
                soa = rds
            else:
                rejected.add((name, t))
            continue
        if t in FILTERED:
            rejected.add((name, t))
            continue
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
    model, soa, _ = to_model(zone)
    if soa is None:
        raise ZeditError("AXFR has no SOA at the apex")
    return model, soa


def parse_text(text, origin):
    z = dns.zone.from_text(text, origin=origin, relativize=True, check_origin=False)
    m, soa, rejected = to_model(z)
    if rejected:
        bad = ", ".join(sorted({f"{n} {tname(t)}" for n, t in rejected}))
        raise ValueError(f"records not allowed (DNSSEC, or SOA outside the apex): {bad}")
    if soa is None:
        raise ValueError("SOA missing - it may be edited but not removed")
    if len(soa) != 1:
        raise ValueError("exactly one SOA is required")
    return m, soa


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
    if LOCK_SOA_TTL and base_soa.ttl != soa.ttl:
        locked.append("SOA record TTL")
    if locked:
        raise ValueError(f"locked SOA fields changed: {', '.join(locked)}")
    check_cname(m)
    return m, soa


def sortkey(k):
    return (k[0], k[1])  # dns.name gives canonical DNS order, apex first


def rr_lines(m, origin, pad=0, notes=None):
    out = []
    for key in sorted(m, key=sortkey):
        name, t = key
        rds = m[key]
        if notes and key in notes:
            out += notes[key]
        n = name.to_text()
        for rd in sorted(rds, key=lambda r: r.to_text(origin=origin, relativize=True)):
            txt = rd.to_text(origin=origin, relativize=True)
            if pad:
                out.append(f"{n:<{pad}} {rds.ttl:>7} IN {tname(t):<6} {txt}")
            else:
                out.append(f"{n}\t{rds.ttl}\tIN\t{tname(t)}\t{txt}")
    return out


def soa_line(rds, origin, pad=0):
    txt = rds[0].to_text(origin=origin, relativize=True)
    if pad:
        return f"{'@':<{pad}} {rds.ttl:>7} IN {'SOA':<6} {txt}"
    return f"@\t{rds.ttl}\tIN\tSOA\t{txt}"


def render_file(soa_rds, model, origin, server, notes=None, extra=()):
    notes = notes or {}
    pad = max([len(k[0].to_text()) for k in model] + [1])
    hdr = [
        f"; Zone: {origin}  Server: {server}  Serial: {soa_rds[0].serial}",
        "; SOA: RNAME, REFRESH, RETRY, EXPIRE and MINIMUM may be edited;",
        ";      MNAME, SERIAL and the SOA record TTL are locked (serial is bumped automatically).",
        "; Filtered out: " + " ".join(tname(t) for t in sorted(FILTERED)),
        "; Records without a TTL get $TTL below (= SOA MINIMUM at transfer time).",
        *extra,
        f"$ORIGIN {origin}",
        f"$TTL {soa_rds[0].minimum}",
        "",
        *notes.get("SOA", []),
        soa_line(soa_rds, origin, pad),
        "",
    ]
    return "\n".join(hdr + rr_lines(model, origin, pad, notes)) + "\n"


def write_atomic(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


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
    changed on both sides -> rdata set merge: theirs + my additions - my deletions."""
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
    ttl = t.ttl
    if not LOCK_SOA_TTL:
        ttl, c = merge_scalar(b.ttl, m.ttl, t.ttl)
        if c:
            conflicts += 1
            note.append(f"; CONFLICT SOA TTL: base={b.ttl} server={t.ttl} mine={m.ttl} - mine kept")
    # MNAME and SERIAL always come from the server
    return dns.rdataset.from_rdata(ttl, t[0].replace(**fields)), note, conflicts


def rebase(ctx, base, base_soa, mine, mine_soa):
    theirs, theirs_soa = fetch(ctx)
    merged, notes, dropped, conflicts = merge3(base, mine, theirs)
    msoa, snote, sconf = merge_soa(base_soa, mine_soa, theirs_soa)
    if snote:
        notes["SOA"] = snote
    conflicts += sconf
    extra = [f"; Rebased: serial {base_soa[0].serial} -> {theirs_soa[0].serial}."]
    extra += [f"; Removed by merge (empty RRset): {d}" for d in dropped]
    # Write the edit first, then the base: if we crash in between, the next
    # rebase is still correct (merged already contains the server's changes).
    write_atomic(ctx.path, render_file(msoa, merged, ctx.origin, ctx.server, notes, extra))
    write_atomic(ctx.basepath, render_file(theirs_soa, theirs, ctx.origin, ctx.server))
    print(
        f"Rebased onto serial {theirs_soa[0].serial}: {len(notes)} RRset(s) changed on "
        f"both sides, {conflicts} conflict(s), {len(dropped)} removed."
    )
    return theirs, theirs_soa, conflicts


# ---------------------------------------------------------------- diff -> UPDATE


def compute_update(old, new, origin):
    dels, adds = [], []

    def rd(r):
        return r.to_text(origin=origin, relativize=False)

    for key in sorted(set(old) | set(new), key=sortkey):
        o, n = old.get(key), new.get(key)
        fq = key[0].derelativize(origin).to_text()
        tt = tname(key[1])
        if o is None:
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
    return dels, adds


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


def live_serial(ctx):
    """Current SOA serial as answered by the server, or None if the query fails.
    With inline-signing this is the signed serial, normally >= the unsigned one."""
    try:
        q = dns.message.make_query(ctx.origin, dns.rdatatype.SOA)
        if ctx.keyring:
            q.use_tsig(ctx.keyring, keyname=ctx.keyname)
        r = dns.query.tcp(q, ctx.server, port=ctx.port, timeout=10)
        for rrset in r.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                return rrset[0].serial
    except Exception:
        pass
    return None


def soa_changed(old_rds, new_rds):
    return old_rds.ttl != new_rds.ttl or old_rds[0] != new_rds[0]


def soa_update(old_rds, new_rds, origin, current_serial=None):
    """RFC 2136 §3.4.2.2: an SOA add replaces the existing SOA only if its serial
    is greater (RFC 1982), otherwise it is silently ignored. The transferred
    serial may be stale (re-signing) or belong to the signed zone (inline-signing),
    so send max(base, live) + 1; BIND then does not bump it a second time.
    No prerequisite is put on the SOA itself, for the same reason."""
    if not soa_changed(old_rds, new_rds):
        return []
    serial = (serial_max(old_rds[0].serial, current_serial) + 1) % 2**32
    soa = new_rds[0].replace(serial=serial)
    return [f"update add {origin} {new_rds.ttl} IN SOA {soa.to_text(origin=origin, relativize=False)}"]


def build_script(server, port, origin, prereqs, dels, adds):
    lines = [f"server {server} {port}", f"zone {origin}"]
    # All deletes before adds: handles e.g. A -> CNAME in the same transaction.
    return "\n".join(lines + prereqs + dels + adds + ["send", ""])


def make_script(ctx, base_soa, new_soa, prereqs, dels, adds):
    # The SOA serial is taken from the live zone at the moment the script is built.
    serial = live_serial(ctx) if soa_changed(base_soa, new_soa) else None
    soa_adds = soa_update(base_soa, new_soa, ctx.origin, serial)
    return build_script(ctx.server, ctx.port, ctx.origin, prereqs, dels, adds + soa_adds)


def verify(ctx, base, new, base_soa, new_soa, attempts=10):
    """Re-transfer the zone and check that every RRset we changed now matches
    the edit. BIND silently drops some updates (CNAME rule, SOA with a non-greater
    serial, TTLs above a dnssec-policy max-zone-ttl), and with inline-signing the
    signed zone is updated asynchronously, hence the retries.
    -> list of RRsets that don't match (empty on success)."""
    changed = [k for k in set(base) | set(new) if not same(base.get(k), new.get(k))]
    bad = []
    for i in range(attempts):
        after, after_soa = fetch(ctx)
        bad = [
            f"{k[0]} {tname(k[1])}"
            for k in sorted(changed, key=sortkey)
            if not same(after.get(k), new.get(k))
        ]
        if soa_changed(base_soa, new_soa):
            bad += [
                f"SOA {f.upper()}" for f in SOA_EDITABLE if getattr(after_soa[0], f) != getattr(new_soa[0], f)
            ]
            if not LOCK_SOA_TTL and after_soa.ttl != new_soa.ttl:
                bad.append("SOA record TTL")
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
    color = sys.stdout.isatty()
    for line in difflib.unified_diff(old_lines, new_lines, fromfile, tofile, lineterm=""):
        if color and line.startswith("+") and not line.startswith("+++"):
            line = f"\033[32m{line}\033[0m"
        elif color and line.startswith("-") and not line.startswith("---"):
            line = f"\033[31m{line}\033[0m"
        elif color and line.startswith("@@"):
            line = f"\033[36m{line}\033[0m"
        print(line)


def run_editor(path):
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    subprocess.call(shlex.split(editor) + [path])


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
        run_editor(path)
        try:
            return parse_file(path, origin, base_soa)
        except (dns.exception.DNSException, ValueError) as e:
            print(f"\nError: {e}")
            if ask("[e]dit again / [a]bort? ", {"e", "a"}) != "e":
                return None


def resolve(host, port):
    try:
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror as e:
        die(f"cannot resolve {host}: {e}")


def state_dir():
    d = os.path.join(os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"), "zedit")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def hint(ctx):
    if ctx.path and os.path.exists(ctx.path):
        print(
            f"Your changes are saved in {ctx.path}\nResume with: zedit [same options] --resume {ctx.path}",
            file=sys.stderr,
        )


def cleanup(ctx):
    for p in (ctx.path, ctx.basepath):
        if p and os.path.exists(p):
            os.unlink(p)


# ---------------------------------------------------------------- main flow


def session(ctx, args):
    if args.resume:
        ctx.path, ctx.basepath = args.resume, args.resume + ".base"
        if not os.path.exists(ctx.basepath):
            raise ZeditError(f"{ctx.basepath} missing - cannot three-way merge without a base")
        with open(ctx.basepath) as f:
            base, base_soa = parse_text(f.read(), ctx.origin)
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
        base, base_soa = fetch(ctx)
        stem = f"{ctx.origin.to_text(omit_final_dot=True)}-{time.strftime('%Y%m%dT%H%M%S')}"
        ctx.path = os.path.join(state_dir(), stem + ".zone")
        ctx.basepath = ctx.path + ".base"
        text = render_file(base_soa, base, ctx.origin, ctx.server)
        write_atomic(ctx.basepath, text)
        write_atomic(ctx.path, text)
        need_edit = True

    while True:
        if need_edit:
            r = edit_until_valid(ctx.path, ctx.origin, base_soa)
            if r is None:
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

        old_lines = [soa_line(base_soa, ctx.origin)] + rr_lines(base, ctx.origin)
        new_lines = [soa_line(new_soa, ctx.origin)] + rr_lines(new, ctx.origin)
        if old_lines == new_lines:
            print("No differences from the server - nothing to send.")
            cleanup(ctx)
            return 0

        dels, adds = compute_update(base, new, ctx.origin)
        prereqs = compute_prereqs(base, new, ctx.origin)
        with_soa = soa_changed(base_soa, new_soa)
        plan = (base_soa, new_soa, prereqs, dels, adds)

        show_diff(old_lines, new_lines, f"{ctx.origin} (serial {base_soa[0].serial})", "edited")
        print(
            f"\n{len(dels)} delete, {len(adds)} add{', SOA changed' if with_soa else ''} in 1 atomic UPDATE."
        )

        while True:
            a = ask("Send? [y]es / [N]o / [e]dit / [s]cript: ", {"y", "n", "e", "s"})
            if a != "s":
                break
            print(make_script(ctx, *plan))
        if a == "e":
            continue
        if a != "y" or args.dry_run:
            if args.dry_run:
                print(make_script(ctx, *plan))
            print("Nothing sent.")
            return 0

        ok, out, can_rebase = run_nsupdate(make_script(ctx, *plan), ctx.keyfile)
        if ok:
            if out:
                print(out)
            missing = verify(ctx, base, new, base_soa, new_soa)
            if missing:
                print(
                    "Update accepted, but the server does not show these changes:\n  "
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


def main():
    ap = argparse.ArgumentParser(
        prog="zedit", description="Edit a dynamic DNS zone via AXFR + $EDITOR + nsupdate"
    )
    ap.add_argument("zone")
    ap.add_argument("-s", "--server", default="127.0.0.1", help="primary server (default 127.0.0.1)")
    ap.add_argument("-p", "--port", type=int, default=53)
    ap.add_argument("-k", "--keyfile", help="TSIG key (tsig-keygen format), used for AXFR and UPDATE")
    ap.add_argument("-n", "--dry-run", action="store_true", help="show the nsupdate script, send nothing")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("-r", "--resume", metavar="FILE", help="resume a saved edit (requires FILE.base)")
    args = ap.parse_args()

    ctx = SimpleNamespace(
        origin=dns.name.from_text(args.zone),
        port=args.port,
        server=resolve(args.server, args.port),
        keyfile=args.keyfile,
        keyring=None,
        keyname=None,
        path=None,
        basepath=None,
    )
    if args.keyfile:
        ctx.keyring, ctx.keyname = load_bind_key(args.keyfile)

    try:
        rc = session(ctx, args)
    except KeyboardInterrupt:
        print()
        rc = 130
    except ZeditError as e:
        print(f"zedit: {e}", file=sys.stderr)
        rc = 1
    if rc:
        hint(ctx)
    sys.exit(rc)


if __name__ == "__main__":
    main()
