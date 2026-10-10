import os
import shlex
import subprocess
import sys

import dns.exception
import dns.name
import dns.zone
import pytest
from helpers import ORIGIN, SOA, addrs, model, soa_rd, zone

from zedit import changes, cli, rfc2136, session
from zedit.model import ZeditError


def test_file_stem_is_a_safe_file_name():
    assert session.file_stem(dns.name.from_text("Example.COM.")) == "example.com"
    assert (
        session.file_stem(dns.name.from_text("16/28.2.0.192.in-addr.arpa.")) == "16_28.2.0.192.in-addr.arpa"
    )


def verify_with(monkeypatch, results, serials=(), attempts=None):
    """Run session.verify() with fetch() returning (or raising) each of results in
    turn, and live_soa() answering with each of serials (then None: no answer)."""
    calls, live = iter(results), iter(serials)

    def fetch(server, origin):
        r = next(calls)
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(rfc2136, "fetch", fetch)
    monkeypatch.setattr(
        rfc2136, "live_soa", lambda server, origin: next((soa_rd(f"{n} 1 2 3 4") for n in live), None)
    )
    monkeypatch.setattr(session.time, "sleep", lambda s: None)
    base = zone("www A 192.0.2.10\n")
    new = zone("www A 192.0.2.11\n")
    return session.verify(None, ORIGIN, changes.change_set(base, new), attempts=attempts or len(results))


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


@pytest.mark.parametrize(
    "argv",
    [
        ["example.com"],
        ["-s", "ns1.example.net", "-p", "5353", "-k", "/keys/my admin.key", "-a", "-A", "-n", "example.com"],
        ["--no-rrsig", "-r", "/old/session.zone", "2.0.192.in-addr.arpa"],
    ],
)
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


def test_writes_are_private_and_ignores_planted_symlinks(tmp_path):
    path = tmp_path / "s.zone"
    target = tmp_path / "elsewhere"
    (tmp_path / "s.zone.tmp").symlink_to(target)  # the name the old code wrote to
    session.write_pair(((str(path), "x\n"),))
    assert path.read_text() == "x\n" and oct(path.stat().st_mode & 0o777) == "0o600"
    assert not target.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["s.zone", "s.zone.tmp"]


def test_failed_write_leaves_the_session_pair_alone(tmp_path, monkeypatch):
    """If writing the second file fails (say the disk is full), neither file is
    replaced: an edit with the new serial next to the old base couldn't be resumed."""
    edit, base = tmp_path / "s.zone", tmp_path / "s.zone.base"
    edit.write_text("old edit\n")
    base.write_text("old base\n")
    write_tmp = session.write_tmp

    def full_disk(path, text):
        if path == str(base):
            raise OSError(28, "No space left on device")
        return write_tmp(path, text)

    monkeypatch.setattr(session, "write_tmp", full_disk)
    with pytest.raises(OSError):
        session.write_pair(((str(edit), "new edit\n"), (str(base), "new base\n")))
    assert (edit.read_text(), base.read_text()) == ("old edit\n", "old base\n")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["s.zone", "s.zone.base"]


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
