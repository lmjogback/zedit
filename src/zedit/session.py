"""An editing session: its files, the editor, the prompts and the main loop."""

import difflib
import itertools
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time

import dns.exception

from zedit import changes, merge, rfc2136, zonefile
from zedit.model import SOA_EDITABLE, SOA_KEY, ZeditError, same, sortkey, tname


def write_tmp(path, text):
    """Write text to a new file next to path and fsync it; -> its name. The file
    is created exclusively (a symlink planted under its name isn't followed),
    readable only by the user, since sessions hold zone data."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=os.path.basename(path) + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
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


def rebase(ctx, base, base_soa, mine, mine_soa):
    theirs, theirs_soa, theirs_hidden = rfc2136.fetch(ctx)
    merged, notes, dropped, conflicts = merge.merge3(base, mine, theirs)
    msoa, snote, sconf = merge.merge_soa(base_soa, mine_soa, theirs_soa)
    if snote:
        notes[SOA_KEY] = snote
    conflicts += sconf
    extra = [f"; Rebased: serial {base_soa[0].serial} -> {theirs_soa[0].serial}."]
    extra += [f"; Removed by merge (empty RRset): {d}" for d in dropped]
    write_pair(
        (
            (
                ctx.path,
                zonefile.render_file(
                    msoa,
                    merged,
                    ctx.origin,
                    ctx.label,
                    notes,
                    extra,
                    zonefile.shown(ctx, theirs_hidden),
                    ctx.addresses,
                ),
            ),
            (ctx.basepath, zonefile.render_file(theirs_soa, theirs, ctx.origin, ctx.label)),
        )
    )
    print(
        f"Rebased onto serial {theirs_soa[0].serial}: {len(notes)} RRset(s) changed on "
        f"both sides, {conflicts} conflict(s), {len(dropped)} removed."
    )
    return theirs, theirs_soa, conflicts


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
    A retry transfers the zone again only if its serial has moved since the last
    transfer, so a lasting mismatch in a large zone costs SOA queries, not AXFRs.
    -> list of RRsets that don't match (empty on success)."""
    changed = [k for k in set(base) | set(new) if not same(base.get(k), new.get(k))]
    bad, serial = [], None
    for i in range(attempts):
        if i:
            time.sleep(min(0.25 * 2 ** (i - 1), 2))
        if serial is not None:
            live = rfc2136.live_soa(ctx)
            if live is not None and live[0].serial == serial:
                continue  # the zone hasn't changed since the last transfer
        try:
            after, after_soa, _ = rfc2136.fetch(ctx)
        except ZeditError as e:
            # The update was sent, so this is "not verified" (exit 3), not a plain error; retry
            bad, serial = [f"(zone transfer for verification failed: {e})"], None
        else:
            serial = after_soa[0].serial
            bad = [
                f"{k.name} {tname(k.rdtype)}"
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
    return bad


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
            return zonefile.parse_file(path, origin, base_soa)
        except (dns.exception.DNSException, ValueError) as e:
            print(f"\nError: {e}")
            if ask("[e]dit again / [a]bort? ", {"e", "a"}) != "e":
                return None


def file_stem(origin):
    """The zone name as a safe file name component. RFC 2317 zones such as
    16/28.2.0.192.in-addr.arpa contain '/', which would become a directory;
    anything other than letters, digits, '.', '-' and '_' becomes '_'."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", origin.to_text(omit_final_dot=True)).lower()


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
        new, new_soa = zonefile.parse_file(ctx.path, ctx.origin, base_soa)
    except (dns.exception.DNSException, ValueError, OSError):
        return False
    new, new_soa, _ = merge.keep_base_case(base, base_soa, new, new_soa)
    if (
        changes.soa_changed(base_soa, new_soa)
        or set(new) != set(base)
        or not all(same(base[k], new[k]) for k in base)
    ):
        return False
    cleanup(ctx)
    return True


def session(ctx, args):
    if args.resume:
        ctx.path, ctx.basepath = args.resume, args.resume + ".base"
        if not os.path.exists(ctx.basepath):
            raise ZeditError(f"{ctx.basepath} missing - cannot three-way merge without a base")
        try:
            base, base_soa = zonefile.parse_text(zonefile.read_text(ctx.basepath), ctx.origin)
        except (dns.exception.DNSException, ValueError) as e:
            raise ZeditError(f"{ctx.basepath} is invalid: {e}") from e
        try:
            mine, mine_soa = zonefile.parse_file(ctx.path, ctx.origin, base_soa)
        except (dns.exception.DNSException, ValueError) as e:
            print(f"The saved file is invalid: {e}")
            r = edit_until_valid(ctx.path, ctx.origin, base_soa)
            if r is None:
                return 1
            mine, mine_soa = r
        base, base_soa, conflicts = rebase(ctx, base, base_soa, mine, mine_soa)
        need_edit = conflicts > 0
    else:
        base, base_soa, hidden = rfc2136.fetch(ctx)
        ctx.path = new_session_path(ctx.origin)
        ctx.basepath = ctx.path + ".base"
        write_pair(
            (
                (ctx.basepath, zonefile.render_file(base_soa, base, ctx.origin, ctx.label)),
                (
                    ctx.path,
                    zonefile.render_file(
                        base_soa,
                        base,
                        ctx.origin,
                        ctx.label,
                        hidden=zonefile.shown(ctx, hidden),
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
                new, new_soa = zonefile.parse_file(ctx.path, ctx.origin, base_soa)
            except (dns.exception.DNSException, ValueError) as e:
                print(f"Error: {e}")
                need_edit = True
                continue
        need_edit = True

        new, new_soa, recased = merge.keep_base_case(base, base_soa, new, new_soa)
        if recased:
            print(
                "Letter case in DNS names is not significant, so case-only changes are not sent: "
                + ", ".join(f"{k.name} {tname(k.rdtype)}" for k in recased)
            )
        old_lines = [zonefile.soa_line(base_soa, ctx.origin)] + zonefile.rr_lines(
            base, ctx.origin, addresses=ctx.addresses
        )
        new_lines = [zonefile.soa_line(new_soa, ctx.origin)] + zonefile.rr_lines(
            new, ctx.origin, addresses=ctx.addresses
        )
        if old_lines == new_lines:
            print("No differences from the server - nothing to send.")
            cleanup(ctx)
            return 0

        dels, adds, final = rfc2136.compute_update(base, new, ctx.origin)
        n_dels, n_adds = changes.change_count(base, new)
        prereqs = rfc2136.compute_prereqs(base, new, ctx.origin)
        with_soa = changes.soa_changed(base_soa, new_soa)
        plan = (base_soa, new_soa, prereqs, dels, adds, final)

        show_diff(old_lines, new_lines, f"{ctx.origin} (serial {base_soa[0].serial})", "edited")
        print(f"\n{n_dels} delete, {n_adds} add{', SOA changed' if with_soa else ''} in 1 atomic UPDATE.")
        for w in changes.signal_warnings(base, new) + changes.ascii_warnings(base, new):
            print(f"Warning: {w}")

        while True:
            a = ask("Send? [y]es / [N]o / [e]dit / [s]cript: ", {"y", "n", "e", "s"})
            if a != "s":
                break
            script, _, conflicts = rfc2136.make_script(ctx, *plan)
            print(script)
            if conflicts:
                print(f"Warning: {soa_conflict_message(conflicts)} Sending would offer a rebase.")
        if a == "e":
            continue
        if a != "y":
            print("Nothing sent.")
            return 2
        if args.dry_run:
            script, _, conflicts = rfc2136.make_script(ctx, *plan)
            print(script)
            if conflicts:
                print(f"Warning: {soa_conflict_message(conflicts)} Sending would offer a rebase.")
            print("Nothing sent (--dry-run).")
            hint(ctx, args, dry_run=True)
            return 0

        ops, sent_soa, conflicts = rfc2136.update_ops(ctx, *plan)
        if conflicts:
            ok, out, can_rebase = False, soa_conflict_message(conflicts), True
        else:
            ok, out, can_rebase = rfc2136.send_update(ctx, ops)
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
