"""An editing session: its files, the editor, the prompts and the main loop.

run() is the whole session. A new one transfers the zone and writes two files:
the session file, which the user edits, and FILE.base, the zone as transferred,
which the edit is compared with and which a rebase merges against. A resumed one
(--resume FILE) reads both and first rebases the edit onto the zone as it is now.
Then edit_loop() repeats until done:

  next_edit()        open $EDITOR and parse the file, until it is valid
  review()           show the diff and ask: send, edit again, show the script, or no
  send_and_verify()  apply the ChangeSet and check the result with a new transfer
  rebase()           if the server changed what the edit touches: merge, repeat

The files stay until the update is verified, so an interrupted or failed session
can always be resumed; zedit prints the command for it.
"""

import argparse
import difflib
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass

import dns.exception
import dns.name
import dns.rdataset

from zedit import changes, merge, zonefile
from zedit.backend import Backend, Outcome, Preview
from zedit.changes import ChangeSet
from zedit.model import SOA_EDITABLE, SOA_KEY, VERIFY_TIMEOUT, Options, ZeditError, Zone, same, tname


@dataclass(frozen=True)
class SessionFiles:
    """A saved session: the edited zone file, and next to it FILE.base, the zone
    as transferred, for the three-way merge."""

    path: str

    @property
    def basepath(self) -> str:
        """FILE.base, the zone as transferred."""
        return self.path + ".base"


def write_tmp(path: str, text: str) -> str:
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


def sync_dir(path: str) -> None:
    """fsync the directory holding path, so that renames in it are on disk."""
    fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def check_ours(path: str) -> None:
    """A file zedit left behind is used only if it is a regular file of the
    user's, not one planted in a shared directory."""
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
        raise ZeditError(f"{path} is not a file of yours; remove it to resume")


def write_session(files: SessionFiles, text: str, base_text: str) -> None:
    """Replace the session file with text and its base with base_text. The two
    must agree (the base's serial is the one the edit is locked to), so the new
    pair is written out completely first, as FILE.base.new and then FILE.new,
    before either old file is replaced. FILE.new is the commit point: once it
    exists, the new pair is complete, and recover() finishes the switch after a
    failure or crash; before, the old pair is untouched."""
    recover(files)  # finish an earlier switch first, so that its .new files aren't lost
    new, base_new = files.path + ".new", files.basepath + ".new"
    try:
        # Each file is written to a temporary name and renamed when complete,
        # so FILE.base.new and FILE.new are never seen half written
        os.replace(write_tmp(files.basepath, base_text), base_new)
        os.replace(write_tmp(files.path, text), new)  # the commit point
        sync_dir(files.path)
    except BaseException:
        # Not committed (or not durably): back to the old pair
        for p in (new, base_new):
            if os.path.lexists(p):
                os.unlink(p)
        raise
    finish_switch(files)


def finish_switch(files: SessionFiles) -> None:
    """Replace the old pair with FILE.new and FILE.base.new, or with what is
    left of them. Each step can be repeated."""
    new, base_new = files.path + ".new", files.basepath + ".new"
    if os.path.lexists(base_new):  # absent if this step was done before an interruption
        os.replace(base_new, files.basepath)
    os.replace(new, files.path)
    sync_dir(files.path)


def recover(files: SessionFiles) -> None:
    """Finish a switch to a new pair that a failure or crash interrupted after
    FILE.new was written, or remove a FILE.base.new from one interrupted before."""
    new, base_new = files.path + ".new", files.basepath + ".new"
    if os.path.lexists(new):
        for p in (new, base_new):
            if os.path.lexists(p):
                check_ours(p)
        finish_switch(files)
    elif os.path.lexists(base_new):
        check_ours(base_new)
        os.unlink(base_new)


def rebase(opts: Options, backend: Backend, files: SessionFiles, base: Zone, mine: Zone) -> tuple[Zone, int]:
    """Transfer the zone again and merge mine into it, writing the session files.
    -> (the new base, number of conflicts)."""
    theirs = backend.fetch(opts.origin)  # the zone as it is now: the new base
    merged = merge.merge3(base.records, mine.records, theirs.records)
    soa = merge.merge_soa(base.soa, mine.soa, theirs.soa)
    notes = {**merged.notes, SOA_KEY: soa.notes} if soa.notes else merged.notes
    conflicts = merged.conflicts + soa.conflicts
    # Said in the file's header, for the user who opens it next
    extra = [f"; Rebased: serial {base.soa[0].serial} -> {theirs.soa[0].serial}."]
    extra += [f"; Removed by merge (empty RRset): {d}" for d in merged.dropped]
    write_session(
        files,
        zonefile.render_file(
            soa.soa,
            merged.records,
            opts.origin,
            backend.label,
            notes,
            extra,
            zonefile.shown(opts, theirs.hidden),
            opts.addresses,
        ),
        zonefile.render_file(theirs.soa, theirs.records, opts.origin, backend.label),
    )
    print(
        f"Rebased onto serial {theirs.soa[0].serial}: {len(notes)} RRset(s) changed on "
        f"both sides, {conflicts} conflict(s), {len(merged.dropped)} removed."
    )
    return theirs, conflicts


def verify(
    backend: Backend,
    origin: dns.name.Name,
    edit: ChangeSet,
    soa: dns.rdataset.Rdataset | None = None,
    attempts: int = 10,
    timeout: float = VERIFY_TIMEOUT,
) -> list[str]:
    """Re-transfer the zone and check that every RRset the ChangeSet edit changes
    now matches it, and the SOA's MNAME and editable fields the SOA RRset sent (soa;
    None if the SOA wasn't sent). BIND silently drops some updates (CNAME rule, SOA with a
    non-greater serial, TTLs above a dnssec-policy max-zone-ttl), and with
    inline-signing the signed zone is updated asynchronously, hence the retries.
    A retry transfers the zone again only if its serial has moved since the last
    transfer, so a lasting mismatch in a large zone costs SOA queries, not AXFRs.
    All of it, transfers included, takes at most timeout seconds.
    -> list of RRsets that don't match (empty on success)."""
    deadline = time.monotonic() + timeout
    bad: list[str] = []
    serial = None  # of the last transfer, if it succeeded
    for i in range(attempts):
        if i:
            # 0.25, 0.5, 1, 2, 2, ... seconds between attempts, but not past the deadline
            time.sleep(max(min(0.25 * 2 ** (i - 1), 2, deadline - time.monotonic()), 0))
        if time.monotonic() >= deadline:
            return [*bad, f"(verification stopped after {timeout:g} seconds)"]
        if serial is not None:
            live = backend.current_soa(origin, timeout=deadline - time.monotonic())
            if live is not None and live[0].serial == serial:
                continue  # the zone hasn't changed since the last transfer
        try:
            after = backend.fetch(origin, timeout=deadline - time.monotonic())
        except ZeditError as e:
            # The update was sent, so this is "not verified" (exit 3), not a plain error; retry
            bad, serial = [f"(zone transfer for verification failed: {e})"], None
        else:
            serial = after.soa[0].serial
            # Each changed RRset must now be as edited (c.new None: gone)
            bad = [
                f"{c.key.name} {tname(c.key.rdtype)}"
                for c in edit.rrsets
                if not same(after.records.get(c.key), c.new)
            ]
            if soa is not None:
                # Not the serial: the server may have bumped it again since (signing)
                bad += [
                    f"SOA {f.upper()}"
                    for f in ("mname", *SOA_EDITABLE)
                    if getattr(after.soa[0], f) != getattr(soa[0], f)
                ]
            if not bad:
                return []
    return bad


def show_diff(old_lines: list[str], new_lines: list[str], fromfile: str, tofile: str) -> None:
    """Print a unified diff of the zone lines, coloured like git's on a terminal."""
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")  # https://no-color.org
    for line in difflib.unified_diff(old_lines, new_lines, fromfile, tofile, lineterm=""):
        if color and line.startswith("+") and not line.startswith("+++"):
            line = f"\033[32m{line}\033[0m"
        elif color and line.startswith("-") and not line.startswith("---"):
            line = f"\033[31m{line}\033[0m"
        elif color and line.startswith("@@"):
            line = f"\033[36m{line}\033[0m"
        print(line)


def run_editor(path: str) -> int:
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


def ask(prompt: str, choices: set[str]) -> str:
    """Ask until the answer is one of choices or empty (the default, which the
    prompt shows in capitals). End of input (Ctrl-D, or no terminal) answers
    with the default."""
    while True:
        try:
            a = input(prompt).strip().lower()
        except EOFError:
            return ""
        if a in choices or a == "":
            return a


def edit_until_valid(path: str, origin: dns.name.Name, base_soa: dns.rdataset.Rdataset) -> Zone | None:
    """Run the editor on path until the file parses and passes the checks, or the
    user gives up. -> the edited Zone, or None if the user aborts."""
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


def file_stem(origin: dns.name.Name) -> str:
    """The zone name as a safe file name component. RFC 2317 zones such as
    16/28.2.0.192.in-addr.arpa contain '/', which would become a directory;
    anything other than letters, digits, '.', '-' and '_' becomes '_'."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", origin.to_text(omit_final_dot=True)).lower()


def state_dir() -> str:
    """$XDG_STATE_HOME/zedit (default ~/.local/state/zedit), created if needed.
    Only warned about if others can read it: changing a directory's mode is
    the user's decision, it may be shared on purpose."""
    d = os.path.join(os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"), "zedit")
    os.makedirs(d, mode=0o700, exist_ok=True)  # the mode applies only if it is created
    if os.stat(d).st_mode & 0o077:
        print(
            f"zedit: warning: {d} is accessible by group/others, and saved sessions hold zone data"
            " (chmod 700)",
            file=sys.stderr,
        )
    return d


def resume_command(args: argparse.Namespace, path: str) -> str:
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
    if args.verify_timeout != VERIFY_TIMEOUT:
        cmd += ["--verify-timeout", f"{args.verify_timeout:g}"]
    return shlex.join([*cmd, "--resume", path, args.zone])


def new_session_path(origin: dns.name.Name) -> str:
    """A new session file ZONE-TIMESTAMP.zone in the state directory, created
    empty and exclusively, so that two sessions for the same zone started within
    the same second don't share (and overwrite) one: the second one gets
    ZONE-TIMESTAMP-2.zone, and so on."""
    stem = os.path.join(state_dir(), f"{file_stem(origin)}-{time.strftime('%Y%m%dT%H%M%S')}")
    n = 1
    while True:
        path = f"{stem}.zone" if n == 1 else f"{stem}-{n}.zone"
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        except FileExistsError:
            n += 1
            continue
        return path


def hint(files: SessionFiles | None, args: argparse.Namespace, dry_run: bool = False) -> None:
    """Tell the user where the session is and the command that resumes it (or,
    after --dry-run, sends it), if there is a session to resume."""
    if files and os.path.exists(files.path):
        how = "Send them with" if dry_run else "Resume with"
        print(
            f"Your changes are saved in {files.path}\n{how}: {resume_command(args, files.path)}",
            file=sys.stderr,
        )


def cleanup(files: SessionFiles) -> None:
    """Remove the session's files: it is done, or there was nothing in it."""
    for p in (files.path, files.basepath, files.path + ".new", files.basepath + ".new"):
        if os.path.lexists(p):
            os.unlink(p)


def discard_if_unchanged(files: SessionFiles, origin: dns.name.Name, base: Zone) -> bool:
    """After an aborted edit, remove the session if its file still parses and
    holds no change from the base: there is nothing to resume. -> removed?"""
    try:
        new = zonefile.parse_file(files.path, origin, base.soa)
    except (dns.exception.DNSException, ValueError, OSError):
        return False
    new, _ = merge.keep_base_case(base, new)  # a change of letter case is no change
    if (
        changes.soa_changed(base.soa, new.soa)
        or set(new.records) != set(base.records)
        or not all(same(base.records[k], new.records[k]) for k in base.records)
    ):
        return False
    cleanup(files)
    return True


def start(opts: Options, backend: Backend, files: SessionFiles, base: Zone) -> None:
    """Write a new session for the zone as transferred (base): the file to edit
    shows the read-only records (-a) and address owners (-A) if asked; the base
    is the plain zone."""
    write_session(
        files,
        zonefile.render_file(
            base.soa,
            base.records,
            opts.origin,
            backend.label,
            hidden=zonefile.shown(opts, base.hidden),
            addresses=opts.addresses,
        ),
        zonefile.render_file(base.soa, base.records, opts.origin, backend.label),
    )


def resume(opts: Options, backend: Backend, files: SessionFiles) -> tuple[Zone, bool] | None:
    """Rebase a saved session onto the zone as it is now. -> (the new base,
    whether to open the editor first), or None if the user aborts."""
    recover(files)  # a switch to a new pair may have been interrupted
    if not os.path.exists(files.basepath):
        raise ZeditError(f"{files.basepath} missing - cannot three-way merge without a base")
    try:
        base = zonefile.parse_text(zonefile.read_text(files.basepath), opts.origin)
    except (dns.exception.DNSException, ValueError) as e:
        raise ZeditError(f"{files.basepath} is invalid: {e}") from e
    mine: Zone | None
    try:
        mine = zonefile.parse_file(files.path, opts.origin, base.soa)
    except (dns.exception.DNSException, ValueError) as e:
        # Saved after a failed parse, say: fix it before merging
        print(f"The saved file is invalid: {e}")
        mine = edit_until_valid(files.path, opts.origin, base.soa)
        if mine is None:
            return None
    base, conflicts = rebase(opts, backend, files, base, mine)
    return base, conflicts > 0


def run(opts: Options, backend: Backend, args: argparse.Namespace) -> int:
    """A whole session, new or resumed (args.resume). -> exit status. Errors are
    reported here, and so is how to resume a session that is left."""
    files = None  # set once there are files the user could resume
    try:
        if args.resume:
            files = SessionFiles(args.resume)
            started = resume(opts, backend, files)
        else:
            base = backend.fetch(opts.origin)  # before creating files: a failure leaves none
            files = SessionFiles(new_session_path(opts.origin))
            start(opts, backend, files, base)
            started = base, True
        rc = 1 if started is None else edit_loop(opts, backend, args, files, *started)
    except KeyboardInterrupt:  # Ctrl-C outside the editor
        print()
        rc = 130
    except (ZeditError, OSError) as e:  # OSError: e.g. state directory not writable, disk full
        print(f"zedit: {e}", file=sys.stderr)
        rc = 1
    except Exception:
        # A bug: the traceback follows, but the edit may be worth keeping, and
        # the UPDATE may have been sent already
        hint(files, args)
        raise
    if rc:
        hint(files, args)
    return rc


def show_preview(preview: Preview) -> None:
    """Print what would be sent, and warn if the SOA conflicts."""
    print(preview.text)
    if preview.soa_conflicts:
        print(f"Warning: {changes.soa_conflict_message(preview.soa_conflicts)} Sending would offer a rebase.")


def next_edit(opts: Options, files: SessionFiles, base: Zone, need_edit: bool) -> Zone | None:
    """The edited zone, from the editor; with need_edit False first from the
    session file as it is (after a rebase without conflicts). None if the user
    aborts."""
    if not need_edit:
        try:
            return zonefile.parse_file(files.path, opts.origin, base.soa)
        except (dns.exception.DNSException, ValueError) as e:
            print(f"Error: {e}")
    return edit_until_valid(files.path, opts.origin, base.soa)


def put_back_case(base: Zone, new: Zone) -> Zone:
    """new with case-only changes put back (see merge.keep_base_case()), saying so."""
    new, recased = merge.keep_base_case(base, new)
    if recased:
        print(
            "Letter case in DNS names is not significant, so case-only changes are not sent: "
            + ", ".join(f"{k.name} {tname(k.rdtype)}" for k in recased)
        )
    return new


def review(opts: Options, backend: Backend, base: Zone, new: Zone, edit: ChangeSet) -> str | None:
    """Show the diff, a summary and warnings, and ask what to do; [s]cript shows
    what would be sent. -> the answer ("y", "e", "n" or "" for no), or None if
    the edit makes no difference."""
    old_lines = [zonefile.soa_line(base.soa, opts.origin)] + zonefile.rr_lines(
        base.records, opts.origin, addresses=opts.addresses
    )
    new_lines = [zonefile.soa_line(new.soa, opts.origin)] + zonefile.rr_lines(
        new.records, opts.origin, addresses=opts.addresses
    )
    if old_lines == new_lines:
        return None
    n_dels, n_adds = changes.change_count(edit)
    show_diff(old_lines, new_lines, f"{opts.origin} (serial {base.soa[0].serial})", "edited")
    soa_note = ", SOA changed" if edit.soa_changed else ""
    print(f"\n{n_dels} delete, {n_adds} add{soa_note} in 1 atomic UPDATE.")
    warnings = changes.signal_warnings(base.records, new.records)
    warnings += changes.ascii_warnings(base.records, new.records)
    for w in warnings:
        print(f"Warning: {w}")
    while True:
        a = ask("Send? [y]es / [N]o / [e]dit / [s]cript: ", {"y", "n", "e", "s"})
        if a != "s":
            return a
        show_preview(backend.preview(opts.origin, edit))


def send_and_verify(opts: Options, backend: Backend, files: SessionFiles, edit: ChangeSet) -> int | None:
    """Apply the edit and verify it. -> exit status, or None to rebase (the
    user's choice when the backend says a rebase may help)."""
    result = backend.apply(opts.origin, edit)
    if result.outcome is Outcome.OK:
        if result.message:
            print(result.message)
        print(f"Update accepted; verifying (up to {opts.verify_timeout:g} seconds)...", flush=True)
        missing = verify(backend, opts.origin, edit, result.soa, timeout=opts.verify_timeout)
        if missing:
            print(
                "Update accepted, but could not be verified:\n  "
                + "\n  ".join(missing)
                + "\nCheck the server log (e.g. CNAME conflicts, dnssec-policy max-zone-ttl).",
                file=sys.stderr,
            )
            return 3
        print("Updated and verified.")
        cleanup(files)
        return 0
    print(result.message, file=sys.stderr)
    if result.outcome is not Outcome.REBASE:
        return 2
    if ask("[r]ebase onto current zone / [a]bort? ", {"r", "a"}) != "r":
        return 2
    return None


def edit_loop(
    opts: Options,
    backend: Backend,
    args: argparse.Namespace,
    files: SessionFiles,
    base: Zone,
    need_edit: bool,
) -> int:
    """Edit, review and send until done. -> exit status (see README): 0 sent and
    verified, or nothing to send; 1 aborted; 2 not sent; 3 sent, not verified.
    base is the zone the edit is compared with; need_edit False shows the diff
    of the session file as it is before opening the editor."""
    while True:
        new = next_edit(opts, files, base, need_edit)
        if new is None:  # the user aborted the editor
            if discard_if_unchanged(files, opts.origin, base):
                print("Aborted without changes.")
            return 1
        need_edit = True  # from now on, every round starts in the editor
        new = put_back_case(base, new)
        edit = changes.change_set(base, new)
        answer = review(opts, backend, base, new, edit)
        if answer is None:
            print("No differences from the server - nothing to send.")
            cleanup(files)
            return 0
        if answer == "e":
            continue  # back to the editor, the file as the user left it
        if answer != "y":
            print("Nothing sent.")
            return 2
        if args.dry_run:
            show_preview(backend.preview(opts.origin, edit))
            print("Nothing sent (--dry-run).")
            hint(files, args, dry_run=True)
            return 0
        rc = send_and_verify(opts, backend, files, edit)
        if rc is not None:
            return rc
        # The server changed what the edit touches, and the user chose to rebase
        base, conflicts = rebase(opts, backend, files, base, new)
        need_edit = conflicts > 0  # conflicts -> straight to the editor, otherwise diff first
