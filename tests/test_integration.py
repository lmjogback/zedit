"""Run zedit against a real named. Skipped if BIND is not installed."""

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


@pytest.fixture(params=list(SIGNING))
def server(request, tmp_path):
    port = free_port()
    key = tmp_path / "admin.key"
    key.write_text(subprocess.check_output(["tsig-keygen", "-a", "hmac-sha256", "admin"], text=True))
    (tmp_path / "keys").mkdir()
    (tmp_path / "db.example").write_text(
        "$TTL 300\n@ 3600 IN SOA ns1 hostmaster 100 7200 900 1209600 300\n"
        "@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\nmail IN A 192.0.2.20\n"
    )
    (tmp_path / "named.conf").write_text(f"""
include "{key}";
options {{ directory "{tmp_path}"; key-directory "{tmp_path}/keys";
  listen-on port {port} {{ 127.0.0.1; }}; listen-on-v6 {{ none; }};
  pid-file "{tmp_path}/named.pid"; recursion no; dnssec-validation no; }};
zone "{ZONE}" {{ type primary; file "{tmp_path}/db.example"; {SIGNING[request.param]}
  allow-transfer {{ key admin; }}; update-policy {{ grant admin zonesub ANY; }}; }};
""")
    for p in (tmp_path, tmp_path / "keys"):
        os.chmod(p, 0o777)
    proc = subprocess.Popen(
        ["named", "-g", "-c", str(tmp_path / "named.conf")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    for _ in range(100):
        try:
            zone = axfr(port, key)
            if request.param == "unsigned" or any(" DNSKEY " in rr for rr in zone):
                break
        except subprocess.CalledProcessError:
            pass
        time.sleep(0.1)
    else:
        proc.kill()
        pytest.skip("named did not start or did not sign the zone")
    yield port, key, tmp_path
    proc.terminate()
    proc.wait(timeout=10)


def run_zedit(port, key, tmp_path, editor, answers, *extra):
    env = dict(os.environ, EDITOR=str(editor), XDG_STATE_HOME=str(tmp_path / "state"))
    args = [sys.executable, "-m", "zedit", "-s", "127.0.0.1", "-p", str(port), "-k", str(key), *extra]
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
