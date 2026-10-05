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


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path):
    port = free_port()
    key = tmp_path / "admin.key"
    key.write_text(subprocess.check_output(["tsig-keygen", "-a", "hmac-sha256", "admin"], text=True))
    (tmp_path / "db.example").write_text(
        "$TTL 300\n@ 3600 IN SOA ns1 hostmaster 100 7200 900 1209600 300\n"
        "@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\nmail IN A 192.0.2.20\n"
    )
    (tmp_path / "named.conf").write_text(f"""
include "{key}";
options {{ directory "{tmp_path}"; listen-on port {port} {{ 127.0.0.1; }}; listen-on-v6 {{ none; }};
  pid-file "{tmp_path}/named.pid"; recursion no; dnssec-validation no; }};
zone "example.com" {{ type primary; file "{tmp_path}/db.example";
  allow-transfer {{ key admin; }}; update-policy {{ grant admin zonesub ANY; }}; }};
""")
    os.chmod(tmp_path, 0o777)
    proc = subprocess.Popen(
        ["named", "-g", "-c", str(tmp_path / "named.conf")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.skip("named did not start")
    yield port, key, tmp_path
    proc.terminate()
    proc.wait(timeout=10)


def axfr(port, key):
    out = subprocess.check_output(
        ["dig", "+noall", "+answer", "-p", str(port), "@127.0.0.1", "-k", str(key), "example.com", "AXFR"],
        text=True,
    )
    return {" ".join(line.split()) for line in out.splitlines()}


def run_zedit(port, key, tmp_path, editor, answers, *extra):
    env = dict(os.environ, EDITOR=str(editor), XDG_STATE_HOME=str(tmp_path / "state"))
    args = [sys.executable, "-m", "zedit", "-s", "127.0.0.1", "-p", str(port), "-k", str(key), *extra]
    return subprocess.run(args + ["example.com"], input=answers, text=True, capture_output=True, env=env)


def write_editor(tmp_path, name, body):
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(0o755)
    return p


CONCURRENT = """nsupdate -k {key} <<N
server 127.0.0.1 {port}
zone example.com
update add dhcp1.example.com. 300 IN A 192.0.2.100
update delete mail.example.com. A
update add mail.example.com. 300 IN A 192.0.2.21
send
N
"""


def test_concurrent_change_rebase(server):
    port, key, tmp = server
    ed = write_editor(
        tmp,
        "ed.sh",
        "sed -i -e 's/192.0.2.10/192.0.2.11/' -e 's/1209600 300/1209600 60/' \"$1\"\n"
        "echo 'new IN A 192.0.2.30' >> \"$1\"\n" + CONCURRENT.format(key=key, port=port),
    )
    r = run_zedit(port, key, tmp, ed, "y\nr\ny\n")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "NXRRSET" in r.stderr
    zone = axfr(port, key)
    for rr in (
        "www.example.com. 300 IN A 192.0.2.11",
        "new.example.com. 300 IN A 192.0.2.30",
        "dhcp1.example.com. 300 IN A 192.0.2.100",
        "mail.example.com. 300 IN A 192.0.2.21",
        "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 102 7200 900 1209600 60",
    ):
        assert rr in zone
    assert not os.listdir(tmp / "state" / "zedit")


def test_abort_then_resume(server):
    port, key, tmp = server
    ed = write_editor(
        tmp, "ed.sh", "sed -i 's/192.0.2.10/192.0.2.12/' \"$1\"\n" + CONCURRENT.format(key=key, port=port)
    )
    r = run_zedit(port, key, tmp, ed, "y\na\n")
    assert r.returncode == 2 and "--resume" in r.stderr
    (saved,) = [f for f in os.listdir(tmp / "state" / "zedit") if f.endswith(".zone")]
    r = run_zedit(port, key, tmp, "true", "y\n", "--resume", str(tmp / "state" / "zedit" / saved))
    assert r.returncode == 0, r.stdout + r.stderr
    zone = axfr(port, key)
    assert "www.example.com. 300 IN A 192.0.2.12" in zone
    assert "dhcp1.example.com. 300 IN A 192.0.2.100" in zone
