import os
import shlex
import subprocess
import sys
from types import SimpleNamespace

import dns.exception
import dns.name
import dns.zone
import pytest
from helpers import ORIGIN, SOA, addrs, model, soa_rd, zone

from zedit import changes, cli, session, zonefile
from zedit.model import Options, ZeditError


def test_file_stem_is_a_safe_file_name():
    assert session.file_stem(dns.name.from_text("Example.COM.")) == "example.com"
    assert (
        session.file_stem(dns.name.from_text("16/28.2.0.192.in-addr.arpa.")) == "16_28.2.0.192.in-addr.arpa"
    )


def verify_with(monkeypatch, results, serials=(), attempts=None):
    """Run session.verify() with a backend whose fetch() returns (or raises) each
    of results in turn, and whose current_soa() answers with each of serials
    (then None: no answer)."""
    calls, live = iter(results), iter(serials)

    def fetch(origin, timeout=None):
        r = next(calls)
        if isinstance(r, Exception):
            raise r
        return r

    backend = SimpleNamespace(
        fetch=fetch,
        current_soa=lambda origin, timeout=None: next((soa_rd(f"{n} 1 2 3 4") for n in live), None),
    )
    monkeypatch.setattr(session.time, "sleep", lambda s: None)
    base = zone("www A 192.0.2.10\n")
    new = zone("www A 192.0.2.11\n")
    return session.verify(backend, ORIGIN, changes.change_set(base, new), attempts=attempts or len(results))


def test_verify_transfers_again_only_when_the_serial_moved(monkeypatch):
    """A lasting mismatch (the zone has serial 100): the SOA query shows the zone
    unchanged, so no further transfer, until the serial moves to 101."""
    unchanged = zone("www A 192.0.2.10\n")
    edited = zone("www A 192.0.2.11\n", soa=SOA.replace(" 100 ", " 101 "))
    assert verify_with(monkeypatch, [unchanged, edited], serials=[100, 100, 100, 101], attempts=5) == []
    bad = verify_with(monkeypatch, [unchanged], serials=[100] * 9, attempts=10)
    assert bad == ["www A"]  # one transfer for ten attempts


def test_verify_reports_failed_transfer(monkeypatch):
    bad = verify_with(monkeypatch, [ZeditError("AXFR failed: refused")] * 3)
    assert len(bad) == 1 and "transfer for verification failed" in bad[0] and "refused" in bad[0]


def test_verify_retries_after_failed_transfer(monkeypatch):
    edited = zone("www A 192.0.2.11\n")
    assert verify_with(monkeypatch, [ZeditError("AXFR failed: timed out"), edited]) == []


@pytest.mark.parametrize(("cost", "transfers"), [(None, 1), (25, 3)])
def test_verify_stops_at_its_deadline(monkeypatch, cost, transfers):
    """Every transfer fails after cost seconds (None: when its timeout runs
    out). verify() gives each one only the time that is left, and stops at the
    deadline instead of after ten full timeouts."""
    now = [0.0]
    timeouts = []

    def fetch(origin, timeout=None):
        timeouts.append(timeout)
        now[0] += timeout if cost is None else min(cost, timeout)
        raise ZeditError("AXFR failed: timed out")

    monkeypatch.setattr(session.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(session.time, "sleep", lambda s: now.__setitem__(0, now[0] + s))
    backend = SimpleNamespace(fetch=fetch, current_soa=lambda origin, timeout=None: None)
    edit = changes.change_set(zone("www A 192.0.2.10\n"), zone("www A 192.0.2.11\n"))
    bad = session.verify(backend, ORIGIN, edit, timeout=60)
    assert now[0] == 60 and len(timeouts) == transfers and timeouts[0] == 60
    assert bad[-1] == "(verification stopped after 60 seconds)"
    assert "transfer for verification failed" in bad[0]


def editor_session(monkeypatch, tmp_path, editor, answers):
    """Run session.edit_until_valid() on a valid zone file with the given $EDITOR and prompt answers."""
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setenv("EDITOR", editor)
    replies = iter(answers)
    monkeypatch.setattr(session, "ask", lambda prompt, choices: next(replies))
    _, base_soa, _ = model("")
    f = tmp_path / "z.zone"
    f.write_text("$TTL 300\n" + SOA + "@ NS ns1\nwww A 192.0.2.10\n")
    return session.edit_until_valid(str(f), ORIGIN, base_soa)


def test_missing_editor_is_an_error(monkeypatch, tmp_path):
    with pytest.raises(ZeditError, match="cannot run editor"):
        editor_session(monkeypatch, tmp_path, str(tmp_path / "no-such-editor"), [])


def test_failing_editor_aborts_or_edits_again(monkeypatch, tmp_path):
    assert editor_session(monkeypatch, tmp_path, "false", ["a"]) is None
    # "e" runs the editor again; once it succeeds, the file is parsed
    script = tmp_path / "ed.sh"
    script.write_text(f"#!/bin/sh\n[ -e {tmp_path}/ran ] && exit 0\ntouch {tmp_path}/ran\nexit 1\n")
    script.chmod(0o755)
    m = editor_session(monkeypatch, tmp_path, str(script), ["e"]).records
    assert addrs(m, "www") == ["192.0.2.10"]


# Options resume_command() carries over, and those it deliberately doesn't (a
# new session file replaces --resume; --dry-run is dropped)
CARRIED = {"zone", "server", "port", "keyfile", "show_all", "no_rrsig", "addresses", "verify_timeout"}
NOT_CARRIED = {"resume", "dry_run", "help", "version"}
RESUME_ARGVS = [
    ["example.com"],
    ["-s", "ns1.example.net", "-p", "5353", "-k", "/keys/my admin.key", "-a", "-A", "-n", "example.com"],
    ["--no-rrsig", "-r", "/old/session.zone", "--verify-timeout", "30", "2.0.192.in-addr.arpa"],
]


def test_every_option_is_carried_over_or_not_on_purpose():
    """A new option must go into resume_command() and CARRIED, or into NOT_CARRIED."""
    assert {a.dest for a in cli.make_parser()._actions} == CARRIED | NOT_CARRIED


def test_resume_round_trip_covers_every_carried_option():
    """Each carried option is set (not left at its default) in some argv of
    test_resume_command_keeps_the_options, so leaving it out fails there."""
    parser = cli.make_parser()
    defaults = vars(parser.parse_args(["x"]))
    set_somewhere = {
        k for argv in RESUME_ARGVS for k, v in vars(parser.parse_args(argv)).items() if v != defaults[k]
    }
    assert CARRIED - {"zone"} <= set_somewhere


@pytest.mark.parametrize("argv", RESUME_ARGVS)
def test_resume_command_keeps_the_options(argv):
    """The printed command parses to the same options, with --dry-run dropped
    and --resume pointing at the session."""
    parser = cli.make_parser()
    args = parser.parse_args(argv)
    cmd = shlex.split(session.resume_command(args, "/state/ex ample.zone"))
    assert cmd[0] == "zedit"
    again = parser.parse_args(cmd[1:])
    expected = {**vars(args), "dry_run": False, "resume": "/state/ex ample.zone"}
    if args.no_rrsig:
        expected["show_all"] = False  # implied by --no-rrsig, not repeated
    assert vars(again) == expected


@pytest.mark.parametrize(("no_color", "colored"), [(None, True), ("", True), ("1", False)])
def test_diff_color_honours_no_color(monkeypatch, capsys, no_color, colored):
    monkeypatch.setattr(session.sys.stdout, "isatty", lambda: True)
    if no_color is None:
        monkeypatch.delenv("NO_COLOR", raising=False)
    else:
        monkeypatch.setenv("NO_COLOR", no_color)
    session.show_diff(["a"], ["b"], "old", "new")
    assert ("\033[" in capsys.readouterr().out) == colored


def test_sessions_in_the_same_second_get_their_own_files(tmp_path, monkeypatch):
    """Two sessions for the same zone started within one second must not share
    (and overwrite) the saved .zone and .base files."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr(session.time, "strftime", lambda fmt, *a: "20261007T120000")
    first, second = session.new_session_path(ORIGIN), session.new_session_path(ORIGIN)
    assert first != second
    assert os.path.basename(first) == "example.com-20261007T120000.zone"
    assert os.path.basename(second) == "example.com-20261007T120000-2.zone"
    assert os.path.exists(first) and os.path.exists(second)  # created, so reserved


def test_state_dir_warns_if_others_can_access_it(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    d = session.state_dir()
    assert oct(os.stat(d).st_mode & 0o777) == "0o700" and capsys.readouterr().err == ""
    os.chmod(d, 0o755)  # zedit doesn't change it back, but says so
    assert session.state_dir() == d and oct(os.stat(d).st_mode & 0o777) == "0o755"
    assert "is accessible by group/others" in capsys.readouterr().err


def session_pair(serial):
    """A session file and its base that agree, with the given serial."""
    soa = SOA.replace(" 100 ", f" {serial} ")
    base = "$TTL 300\n" + soa + "@ NS ns1\n"
    return base + f"www A 192.0.2.{serial % 256}\n", base


def test_session_files_are_private(tmp_path):
    files = session.SessionFiles(str(tmp_path / "s.zone"))
    session.write_session(files, "edit\n", "base\n")
    for p in (files.path, files.basepath):
        assert oct(os.stat(p).st_mode & 0o777) == "0o600"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["s.zone", "s.zone.base"]


@pytest.mark.parametrize("name", ["s.zone.new", "s.zone.base.new"])
def test_planted_files_are_not_used(tmp_path, name):
    """In a shared directory, someone else could leave FILE.new for recover() to
    take as the user's session; a symlink (or another user's file) is refused."""
    target = tmp_path / "elsewhere"
    target.write_text("planted\n")
    (tmp_path / name).symlink_to(target)
    files = session.SessionFiles(str(tmp_path / "s.zone"))
    with pytest.raises(ZeditError, match="is not a file of yours"):
        session.write_session(files, "edit\n", "base\n")
    assert target.read_text() == "planted\n"


# The steps of write_session() that can fail, in order
STEPS = [
    "write base",
    "rename base",
    "write edit",
    "rename edit",
    "sync",
    "replace base",
    "replace edit",
    "sync 2",
]


@pytest.mark.parametrize("crash", [False, True], ids=["error", "crash"])
@pytest.mark.parametrize("step", STEPS)
def test_interrupted_switch_leaves_a_whole_pair(tmp_path, monkeypatch, step, crash):
    """Whatever step fails, by an exception (cleanup runs) or a crash (nothing
    more runs), the session file and its base are afterwards, once recover()
    has run as --resume does, either both old or both new, and they agree."""
    files = session.SessionFiles(str(tmp_path / "s.zone"))
    old, new = session_pair(100), session_pair(101)
    with open(files.path, "w") as f:
        f.write(old[0])
    with open(files.basepath, "w") as f:
        f.write(old[1])

    calls = {"write": 0, "rename": 0, "sync": 0}
    write_tmp, replace, sync_dir = session.write_tmp, os.replace, session.sync_dir

    def counted(kind, fn, names):
        def wrapper(*args):
            calls[kind] += 1
            if names[calls[kind] - 1] == step:
                raise OSError(5, f"injected at {step}")
            return fn(*args)

        return wrapper

    with monkeypatch.context() as m:
        m.setattr(session, "write_tmp", counted("write", write_tmp, ["write base", "write edit"]))
        m.setattr(
            session.os,
            "replace",
            counted("rename", replace, ["rename base", "rename edit", "replace base", "replace edit"]),
        )
        m.setattr(session, "sync_dir", counted("sync", sync_dir, ["sync", "sync 2"]))
        if crash:
            m.setattr(session.os, "unlink", lambda p: None)  # nothing is cleaned up
        with pytest.raises(OSError, match="injected"):
            session.write_session(files, *new)

    session.recover(files)
    pair = (open(files.path).read(), open(files.basepath).read())
    assert pair in (old, new)
    committed = STEPS.index(step) >= STEPS.index("replace base") or (crash and step == "sync")
    assert pair == (new if committed else old)
    assert not any(p.name.endswith(".new") for p in tmp_path.iterdir())
    base = zonefile.parse_text(pair[1], ORIGIN)
    zonefile.parse_file(files.path, ORIGIN, base.soa)  # agrees with its base: resumable


def test_ctrl_c_in_the_editor_doesnt_stop_zedit(tmp_path):
    """The terminal sends SIGINT to the whole foreground process group. The
    editor gets it, with its default handling; zedit ignores it while waiting.
    Run in a session of its own, so that the signal doesn't reach pytest."""
    editor = tmp_path / "ed.sh"
    editor.write_text("#!/bin/sh\nkill -INT 0\nsleep 1\n")
    editor.chmod(0o755)
    code = "import sys; from zedit import session; print(session.run_editor(sys.argv[1]))"
    env = {k: v for k, v in os.environ.items() if k != "VISUAL"} | {"EDITOR": str(editor)}
    r = subprocess.run(
        [sys.executable, "-c", code, "f"], env=env, capture_output=True, text=True, start_new_session=True
    )
    # The editor died of SIGINT (status -2, default handling); zedit carried on
    assert (r.returncode, r.stdout, r.stderr) == (0, "-2\n", "")


def test_unexpected_error_still_says_where_the_session_is(tmp_path, monkeypatch, capsys):
    """A bug after the session was written: the exception is not swallowed,
    and the user still learns how to resume."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    base = zone("www A 192.0.2.10\n")
    backend = SimpleNamespace(label="ns", fetch=lambda origin: base)

    def bug(*args):
        raise RuntimeError("bug")

    monkeypatch.setattr(session, "edit_loop", bug)
    args = cli.make_parser().parse_args(["example.com"])
    with pytest.raises(RuntimeError, match="bug"):
        session.run(Options(ORIGIN), backend, args)
    err = capsys.readouterr().err
    assert "Your changes are saved in" in err and "Resume with: zedit --resume" in err
