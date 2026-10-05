"""Run zedit against a real named. Skipped if BIND is not installed."""

import contextlib
import datetime
import os
import shutil
import socket
import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.integration

for tool in ("named", "nsupdate", "tsig-keygen", "dig"):
    if not shutil.which(tool):
        pytest.skip(f"{tool} not found", allow_module_level=True)

ZONE = "example.com"
SIGNING = {
    "unsigned": "",
    "inline": "dnssec-policy default; inline-signing yes;",
    "inplace": "dnssec-policy default; inline-signing no;",
}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def dig(port, key, *args):
    out = subprocess.check_output(
        ["dig", "+noall", "+answer", "-p", str(port), "@127.0.0.1", "-k", str(key), *args], text=True
    )
    return {" ".join(line.split()) for line in out.splitlines()}


def axfr(port, key):
    return dig(port, key, ZONE, "AXFR")


@contextlib.contextmanager
def run_named(tmp_path, signing, serial_update_method=None):
    """Start named with ZONE configured as requested; yield (port, key, tmp_path)."""
    port = free_port()
    key = tmp_path / "admin.key"
    key.write_text(subprocess.check_output(["tsig-keygen", "-a", "hmac-sha256", "admin"], text=True))
    (tmp_path / "keys").mkdir()
    (tmp_path / "db.example").write_text(
        "$TTL 300\n@ 3600 IN SOA ns1 hostmaster 100 7200 900 1209600 300\n"
        "@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\nmail IN A 192.0.2.20\n"
    )
    method = f"serial-update-method {serial_update_method};" if serial_update_method else ""
    (tmp_path / "named.conf").write_text(f"""
include "{key}";
options {{ directory "{tmp_path}"; key-directory "{tmp_path}/keys";
  listen-on port {port} {{ 127.0.0.1; }}; listen-on-v6 {{ none; }};
  pid-file "{tmp_path}/named.pid"; recursion no; dnssec-validation no; }};
zone "{ZONE}" {{ type primary; file "{tmp_path}/db.example"; {SIGNING[signing]} {method}
  allow-transfer {{ key admin; }}; update-policy {{ grant admin zonesub ANY; }}; }};
""")
    for p in (tmp_path, tmp_path / "keys"):
        os.chmod(p, 0o777)
    proc = subprocess.Popen(
        ["named", "-g", "-c", str(tmp_path / "named.conf")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    try:
        for _ in range(100):
            try:
                zone = axfr(port, key)
                if signing == "unsigned" or any(" DNSKEY " in rr for rr in zone):
                    break
            except subprocess.CalledProcessError:
                pass
            time.sleep(0.1)
        else:
            pytest.skip("named did not start or did not sign the zone")
        yield port, key, tmp_path
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture(params=list(SIGNING))
def server(request, tmp_path):
    with run_named(tmp_path, request.param) as s:
        yield s


def run_zedit(port, key, tmp_path, editor, answers, *extra):
    """Run zedit; key=None means no -k (the default key lookup applies)."""
    env = dict(
        os.environ,
        EDITOR=str(editor),
        XDG_STATE_HOME=str(tmp_path / "state"),
        XDG_CONFIG_HOME=str(tmp_path / "config"),
    )
    env.pop("ZEDIT_KEYFILE", None)
    keyarg = ["-k", str(key)] if key else []
    args = [sys.executable, "-m", "zedit", "-s", "127.0.0.1", "-p", str(port), *keyarg, *extra]
    return subprocess.run(args + [ZONE], input=answers, text=True, capture_output=True, env=env)


def write_editor(tmp_path, body):
    p = tmp_path / "ed.sh"
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(0o755)
    return p


def nsupdate(key, port, *updates):
    """Shell snippet that applies a concurrent change while the editor is open."""
    body = "\n".join(updates)
    return f"nsupdate -k {key} <<N\nserver 127.0.0.1 {port}\nzone {ZONE}\n{body}\nsend\nN\n"


def saved_files(tmp):
    d = tmp / "state" / "zedit"
    return os.listdir(d) if d.exists() else []


def test_unrelated_concurrent_change_does_not_conflict(server):
    port, key, tmp = server
    ed = write_editor(
        tmp,
        "sed -i -e 's/192.0.2.10/192.0.2.11/' -e 's/1209600 300/1209600 60/' \"$1\"\n"
        "echo 'new IN A 192.0.2.30' >> \"$1\"\n"
        + nsupdate(
            key,
            port,
            "update add dhcp1.example.com. 300 IN A 192.0.2.100",
            "update delete mail.example.com. A",
            "update add mail.example.com. 300 IN A 192.0.2.21",
        ),
    )
    r = run_zedit(port, key, tmp, ed, "y\n")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Updated and verified." in r.stdout
    zone = axfr(port, key)
    for rr in (
        "www.example.com. 300 IN A 192.0.2.11",
        "new.example.com. 300 IN A 192.0.2.30",
        "dhcp1.example.com. 300 IN A 192.0.2.100",
        "mail.example.com. 300 IN A 192.0.2.21",
    ):
        assert rr in zone
    (soa,) = dig(port, key, ZONE, "SOA")
    assert soa.endswith(" 7200 900 1209600 60")
    assert not saved_files(tmp)


def test_overlapping_concurrent_change_rebases(server):
    port, key, tmp = server
    ed = write_editor(
        tmp,
        "sed -i 's/192.0.2.10/192.0.2.11/' \"$1\"\n"
        + nsupdate(key, port, "update add www.example.com. 300 IN A 192.0.2.99"),
    )
    r = run_zedit(port, key, tmp, ed, "y\nr\ny\n")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "NXRRSET" in r.stderr
    www = dig(port, key, "www." + ZONE, "A")
    assert www == {"www.example.com. 300 IN A 192.0.2.11", "www.example.com. 300 IN A 192.0.2.99"}


def test_abort_then_resume(server):
    port, key, tmp = server
    ed = write_editor(
        tmp,
        "sed -i 's/192.0.2.10/192.0.2.12/' \"$1\"\n"
        + nsupdate(key, port, "update add www.example.com. 300 IN A 192.0.2.99"),
    )
    r = run_zedit(port, key, tmp, ed, "y\na\n")
    assert r.returncode == 2 and "--resume" in r.stderr
    (saved,) = [f for f in saved_files(tmp) if f.endswith(".zone")]
    r = run_zedit(port, key, tmp, "true", "y\n", "--resume", str(tmp / "state" / "zedit" / saved))
    assert r.returncode == 0, r.stdout + r.stderr
    www = dig(port, key, "www." + ZONE, "A")
    assert www == {"www.example.com. 300 IN A 192.0.2.12", "www.example.com. 300 IN A 192.0.2.99"}


def test_silently_ignored_update_is_reported(server):
    # A concurrent CNAME makes BIND silently drop our add (RFC 2136 §3.4.2.2).
    # The prerequisite (no A RRset at foo) still holds, so only verification catches it.
    port, key, tmp = server
    ed = write_editor(
        tmp,
        "echo 'foo IN A 192.0.2.50' >> \"$1\"\n"
        + nsupdate(key, port, "update add foo.example.com. 300 IN CNAME www.example.com."),
    )
    r = run_zedit(port, key, tmp, ed, "y\n")
    assert r.returncode == 3, r.stdout + r.stderr
    assert "foo A" in r.stderr


def soa(port, key):
    (rr,) = dig(port, key, ZONE, "SOA")
    serial, refresh = rr.split()[6:8]
    return int(serial), int(refresh)


def serial_greater(new, old):
    """RFC 1982: new is greater than old."""
    return 0 < (new - old) % 2**32 < 2**31


@pytest.mark.parametrize("signing", ["unsigned", "inline"])
@pytest.mark.parametrize("method", ["increment", "unixtime", "date"])
def test_serial_update_methods(tmp_path, method, signing):
    """Record and SOA edits work regardless of serial-update-method: record edits
    leave the serial to BIND, SOA edits carry max(transferred, live) + 1."""
    with run_named(tmp_path, signing, method) as (port, key, tmp):
        s0, _ = soa(port, key)

        r = run_zedit(port, key, tmp, write_editor(tmp, "sed -i 's/192.0.2.10/192.0.2.11/' \"$1\"\n"), "y\n")
        assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
        s1, _ = soa(port, key)
        assert serial_greater(s1, s0)
        # Record edits don't touch the SOA: the serial follows BIND's method.
        if method == "unixtime":
            assert abs(s1 - time.time()) < 3600
        elif method == "date":
            days = {datetime.date.today(), datetime.datetime.now(datetime.timezone.utc).date()}
            assert s1 // 100 in {int(d.strftime("%Y%m%d")) for d in days}

        r = run_zedit(port, key, tmp, write_editor(tmp, "sed -i 's/ 7200 900 / 3600 900 /' \"$1\"\n"), "y\n")
        assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
        s2, refresh = soa(port, key)
        assert refresh == 3600
        assert serial_greater(s2, s1)


def test_show_all_is_read_only(server):
    port, key, tmp = server
    signed = any(" DNSKEY " in rr for rr in axfr(port, key))
    # Save what the editor sees, change www, and tamper with every read-only line
    ed = write_editor(
        tmp,
        'cp "$1" "$1.seen"\n'
        "sed -i -e 's/192.0.2.10/192.0.2.11/' -e '/^;ro /d' \"$1\"\n"
        'cp "$1.seen" ' + str(tmp / "seen.zone") + "\n",
    )
    before = {rr for rr in axfr(port, key) if " DNSKEY " in rr}
    r = run_zedit(port, key, tmp, ed, "y\n", "-a")
    assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
    seen = (tmp / "seen.zone").read_text()
    assert ("\n;ro @" in seen and " DNSKEY " in seen and " RRSIG " in seen) == signed
    assert "1 delete, 1 add" in r.stdout  # only www; the deleted ;ro lines had no effect
    assert {rr for rr in axfr(port, key) if " DNSKEY " in rr} == before


def test_default_keyfile_from_config(server):
    port, key, tmp = server
    keys = tmp / "config" / "zedit" / "keys"
    keys.mkdir(parents=True)
    (keys / "example.com.key").write_text(key.read_text())
    (keys / "example.com.key").chmod(0o600)
    ed = write_editor(tmp, "sed -i 's/192.0.2.10/192.0.2.12/' \"$1\"\n")
    r = run_zedit(port, None, tmp, ed, "y\n")
    assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
    assert f"Key: {keys / 'example.com.key'}" in r.stderr
