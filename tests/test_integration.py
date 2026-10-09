"""Run zedit against a real named. Skipped if BIND is not installed, or if named
doesn't start; with ZEDIT_REQUIRE_INTEGRATION set (as in CI), that fails instead."""

import contextlib
import datetime
import os
import re
import shutil
import socket
import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.integration

# named and tsig-keygen live in /usr/sbin, which isn't in an ordinary user's
# PATH on Debian, so look there too.
SBIN = os.pathsep.join(["/usr/local/sbin", "/usr/sbin", "/sbin"])


def find_tool(name):
    return shutil.which(name) or shutil.which(name, path=SBIN)


# In CI, BIND is installed for these tests, so a skip would hide a broken setup
REQUIRED = bool(os.environ.get("ZEDIT_REQUIRE_INTEGRATION"))


def skip(reason, **kwargs):
    if REQUIRED:
        pytest.fail(f"{reason} (ZEDIT_REQUIRE_INTEGRATION is set)", pytrace=False)
    pytest.skip(reason, **kwargs)


TOOLS = {name: find_tool(name) for name in ("named", "nsupdate", "tsig-keygen", "dig")}
if missing := [name for name, path in TOOLS.items() if not path]:
    skip(f"not found: {', '.join(missing)}", allow_module_level=True)

ZONE = "example.com"
SIGNING = {
    "unsigned": "",
    "inline": "dnssec-policy default; inline-signing yes;",
    "inplace": "dnssec-policy default; inline-signing no;",
}


def free_port():
    """A port free for both TCP and UDP on 127.0.0.1, since named listens on both."""
    for _ in range(100):
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            try:
                udp.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no port free for both TCP and UDP")


class DigError(Exception):
    pass


def dig_tsig(key):
    """The key file as dig's -y ALG:NAME:SECRET. dig -k can't read key files
    outside $HOME on Ubuntu 26.04, whose AppArmor profile for dig allows only
    those, and the tests keep their keys in tmp_path."""
    text = key.read_text()
    name = re.search(r'key\s+"([^"]+)"', text).group(1)
    alg = re.search(r"algorithm\s+([\w.-]+);", text).group(1)
    secret = re.search(r'secret\s+"([^"]+)";', text).group(1)
    return f"{alg}:{name}:{secret}"


def dig(port, key, *args):
    """Answer records, over TCP like zedit itself. Anything dig reports instead
    (';' lines, e.g. a failed transfer or a malformed response) raises DigError."""
    out = subprocess.check_output(
        [
            TOOLS["dig"],
            "+tcp",
            "+noall",
            "+answer",
            "-p",
            str(port),
            "@127.0.0.1",
            "-y",
            dig_tsig(key),
            *args,
        ],
        text=True,
    )
    lines = out.splitlines()
    if any(line.startswith(";") for line in lines):
        raise DigError(out)
    return {" ".join(line.split()) for line in lines}


def axfr(port, key):
    return dig(port, key, ZONE, "AXFR")


FORWARD = "@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\nmail IN A 192.0.2.20\n"


@contextlib.contextmanager
def run_named(
    tmp_path, signing, serial_update_method=None, zone=ZONE, records=FORWARD, rname="hostmaster.example.net."
):
    """Start named with ZONE configured as requested; yield (port, key, tmp_path)."""
    port = free_port()
    key = tmp_path / "admin.key"
    key.write_text(subprocess.check_output([TOOLS["tsig-keygen"], "-a", "hmac-sha256", "admin"], text=True))
    (tmp_path / "keys").mkdir()
    (tmp_path / "db.example").write_text(
        f"$TTL 300\n@ 3600 IN SOA ns1.example.net. {rname} 100 7200 900 1209600 300\n" + records
    )
    method = f"serial-update-method {serial_update_method};" if serial_update_method else ""
    (tmp_path / "named.conf").write_text(f"""
include "{key}";
options {{ directory "{tmp_path}"; key-directory "{tmp_path}/keys";
  listen-on port {port} {{ 127.0.0.1; }}; listen-on-v6 {{ none; }};
  pid-file "{tmp_path}/named.pid"; recursion no; dnssec-validation no; }};
zone "{zone}" {{ type primary; file "{tmp_path}/db.example"; {SIGNING[signing]} {method}
  allow-transfer {{ key admin; }}; update-policy {{ grant admin zonesub ANY; }}; }};
""")
    for p in (tmp_path, tmp_path / "keys"):
        os.chmod(p, 0o777)
    log = tmp_path / "named.log"
    with open(log, "w") as out:
        proc = subprocess.Popen(
            [TOOLS["named"], "-g", "-c", str(tmp_path / "named.conf")], stdout=out, stderr=subprocess.STDOUT
        )
    try:
        ready = False
        for _ in range(100):
            if proc.poll() is not None:
                break  # named exited; no point in waiting
            try:
                rrs = dig(port, key, zone, "AXFR")
                loaded = any(" SOA " in rr for rr in rrs)  # dig exits 0 on SERVFAIL too
                ready = loaded and (signing == "unsigned" or any(" DNSKEY " in rr for rr in rrs))
            except (subprocess.CalledProcessError, DigError):
                pass
            if ready:
                break
            time.sleep(0.1)
        if not ready:
            tail = "\n".join(log.read_text(errors="replace").splitlines()[-25:])
            skip(f"named did not start or did not load/sign the zone; end of its log:\n{tail}")
        yield port, key, tmp_path
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture(params=list(SIGNING))
def server(request, tmp_path):
    with run_named(tmp_path, request.param) as s:
        yield s


def run_zedit(port, key, tmp_path, editor, answers, *extra, zone=ZONE):
    """Run zedit; key=None means no -k (the default key lookup applies)."""
    env = dict(
        os.environ,
        PATH=os.pathsep.join([os.path.dirname(TOOLS["nsupdate"]), os.environ.get("PATH", "")]),
        EDITOR=str(editor),
        XDG_STATE_HOME=str(tmp_path / "state"),
        XDG_CONFIG_HOME=str(tmp_path / "config"),
    )
    # zedit prefers $VISUAL over $EDITOR; a developer's VISUAL (e.g. nvim) would
    # otherwise be started instead of the test editor and hang without a terminal.
    env.pop("VISUAL", None)
    env.pop("ZEDIT_KEYFILE", None)
    keyarg = ["-k", str(key)] if key else []
    args = [sys.executable, "-m", "zedit", "-s", "127.0.0.1", "-p", str(port), *keyarg, *extra]
    # A timeout turns anything waiting for a terminal into a failure instead of a hang
    return subprocess.run(args + [zone], input=answers, text=True, capture_output=True, env=env, timeout=120)


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


def test_declined_update_keeps_session(server):
    port, key, tmp = server
    ed = write_editor(tmp, "sed -i 's/192.0.2.10/192.0.2.12/' \"$1\"\n")
    r = run_zedit(port, key, tmp, ed, "n\n")
    assert r.returncode == 2 and "--resume" in r.stderr, r.stdout + r.stderr
    assert sorted(f.rsplit(".zone", 1)[1] for f in saved_files(tmp)) == ["", ".base"]
    assert dig(port, key, "www." + ZONE, "A") == {"www.example.com. 300 IN A 192.0.2.10"}


def test_dry_run_keeps_session_for_resume(server):
    port, key, tmp = server
    ed = write_editor(tmp, "sed -i 's/192.0.2.10/192.0.2.12/' \"$1\"\n")
    r = run_zedit(port, key, tmp, ed, "y\n", "--dry-run")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "update add www.example.com. 300 IN A 192.0.2.12" in r.stdout
    (saved,) = [f for f in saved_files(tmp) if f.endswith(".zone")]
    path = tmp / "state" / "zedit" / saved
    assert f"Send them with: zedit -s 127.0.0.1 -p {port} -k {key} --resume {path} {ZONE}\n" in r.stderr
    assert dig(port, key, "www." + ZONE, "A") == {"www.example.com. 300 IN A 192.0.2.10"}
    r = run_zedit(port, key, tmp, "true", "y\n", "--resume", str(path))
    assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
    assert dig(port, key, "www." + ZONE, "A") == {"www.example.com. 300 IN A 192.0.2.12"}
    assert not saved_files(tmp)


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


def test_rfc2317_zone_with_slash(tmp_path):
    """Classless reverse zones (RFC 2317) have '/' in their name, which must not
    end up as a directory in the saved-state or key file paths."""
    zone = "16/28.2.0.192.in-addr.arpa"
    records = "@ IN NS ns1.example.net.\n18 IN PTR host18.example.com.\n"
    with run_named(tmp_path, "unsigned", zone=zone, records=records) as (port, key, tmp):
        keys = tmp / "config" / "zedit" / "keys"
        keys.mkdir(parents=True)
        (keys / "16_28.2.0.192.in-addr.arpa.key").write_text(key.read_text())
        (keys / "16_28.2.0.192.in-addr.arpa.key").chmod(0o600)
        ed = write_editor(tmp, "printf '17 PTR host17.example.com.\\n' >> \"$1\"\n")
        r = run_zedit(port, None, tmp, ed, "y\n", zone=zone)
        assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
        assert "16_28.2.0.192.in-addr.arpa.key" in r.stderr
        assert dig(port, key, "17." + zone, "PTR") == {f"17.{zone}. 300 IN PTR host17.example.com."}


def test_generate_in_reverse_zone(tmp_path):
    zone = "2.0.192.in-addr.arpa"
    with run_named(tmp_path, "unsigned", zone=zone, records="@ IN NS ns1.example.net.\n") as (port, key, tmp):
        add = tmp / "add.txt"
        add.write_text("$GENERATE 30-34/2 $ PTR dyn-${0,3,d}-${100,0,x}.example.com.\n")
        ed = write_editor(tmp, f'cat "{add}" >> "$1"\n')
        r = run_zedit(port, key, tmp, ed, "y\n", zone=zone)
        assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
        assert "0 delete, 3 add" in r.stdout
        assert dig(port, key, "32." + zone, "PTR") == {f"32.{zone}. 300 IN PTR dyn-032-84.example.com."}


@pytest.mark.parametrize(
    "zone, existing, shown_as, added, expected",
    [
        (
            "2.0.192.in-addr.arpa",
            "10 IN PTR old.example.com.\n",
            "192.0.2.10",
            "192.0.2.11 PTR new.example.com.\n",
            {"10.2.0.192.in-addr.arpa.", "11.2.0.192.in-addr.arpa."},
        ),
        (
            "8.b.d.0.1.0.0.2.ip6.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 IN PTR old.example.com.\n",
            "2001:db8::1",
            "2001:db8::2 PTR new.example.com.\n",
            {
                "1." + "0." * 23 + "8.b.d.0.1.0.0.2.ip6.arpa.",
                "2." + "0." * 23 + "8.b.d.0.1.0.0.2.ip6.arpa.",
            },
        ),
        (
            "16/28.2.0.192.in-addr.arpa",
            "17 IN PTR old.example.com.\n",
            "192.0.2.17",
            "192.0.2.18 PTR new.example.com.\n",
            {"17.16/28.2.0.192.in-addr.arpa.", "18.16/28.2.0.192.in-addr.arpa."},
        ),
    ],
)
def test_reverse_zone_in_address_form(tmp_path, zone, existing, shown_as, added, expected):
    records = "@ IN NS ns1.example.net.\n" + existing
    with run_named(tmp_path, "unsigned", zone=zone, records=records) as (port, key, tmp):
        add = tmp / "add.txt"
        add.write_text(added)
        seen = tmp / "seen.zone"
        ed = write_editor(tmp, f'cp "$1" "{seen}"\ncat "{add}" >> "$1"\n')
        r = run_zedit(port, key, tmp, ed, "y\n", "-A", zone=zone)
        assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
        # The existing record was shown in address form...
        shown = [line.split()[0] for line in seen.read_text().splitlines() if " PTR " in line]
        assert shown == [shown_as]
        # ...and the record added in address form landed on the right reverse name
        names = {rr.split()[0] for rr in dig(port, key, zone, "AXFR") if " PTR " in rr}
        assert names == expected


def test_ip6_zone_with_four_nibble_delegation(tmp_path):
    """A /48 reverse zone with a /64 delegation (0.5.0.0 NS) must stay editable:
    0.5.0.0 is a nibble name, not the IPv4 address 0.5.0.0."""
    zone = "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    records = (
        "@ IN NS ns1.example.net.\n"
        "0.5.0.0 IN NS ns1.example.net.\n"
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0 IN PTR r1.example.net.\n"
    )
    with run_named(tmp_path, "unsigned", zone=zone, records=records) as (port, key, tmp):
        add = tmp / "add.txt"
        add.write_text("2001:db8::1:0:0:0:2 PTR r2.example.net.\n")
        ed = write_editor(tmp, f'cat "{add}" >> "$1"\n')
        for extra in ([], ["-A"]):
            r = run_zedit(port, key, tmp, ed if not extra else "true", "y\n", *extra, zone=zone)
            assert r.returncode == 0, r.stdout + r.stderr
        # A delegation is answered with a referral, so check the zone content
        rrs = dig(port, key, zone, "AXFR")
        assert f"0.5.0.0.{zone}. 300 IN NS ns1.example.net." in rrs
        assert f"2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.{zone}. 300 IN PTR r2.example.net." in rrs


@pytest.mark.parametrize("signing", list(SIGNING))
def test_bootstrapping_signals(tmp_path, signing):
    """RFC 9615 signals (CDS/CDNSKEY below the apex of a signaling zone) can be
    added and removed; the server accepts them in every signing mode."""
    zone = "_signal.ns1.example.net"
    signal = f"_dsboot.child.example.{zone}."
    cds = "28889 13 2 5859EF0BDC217560D43AA3133526503E4428B6809CCE400FB0B27D74136B41D8"
    cdnskey = (
        "257 3 13 ZxTaTTbQHRgbrjhjiThNK5sSqDC2Wu+zPitbVcMjo7mW22++S5bioe1/zicKEy4sOy9MJx8BRNUqXuouo6f3QA=="
    )
    with run_named(tmp_path, signing, zone=zone, records="@ IN NS ns1.example.net.\n") as (port, key, tmp):
        ed = write_editor(
            tmp,
            f"printf '_dsboot.child.example 3600 IN CDS {cds}\\n' >> \"$1\"\n"
            f"printf '_dsboot.child.example 3600 IN CDNSKEY {cdnskey}\\n' >> \"$1\"\n"
            f"printf '_dsbot.typo.example 3600 IN CDS {cds}\\n' >> \"$1\"\n",
        )
        r = run_zedit(port, key, tmp, ed, "y\n", zone=zone)
        assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
        assert "Warning: _dsbot.typo.example CDS is not at a _dsboot name" in r.stdout
        assert dig(port, key, signal, "CDS") == {f"{signal} 3600 IN CDS {cds[:-8]} {cds[-8:]}"}
        assert len(dig(port, key, signal, "CDNSKEY")) == 1

        ed = write_editor(tmp, "sed -i -e '/^_dsboot/d' -e '/^_dsbot/d' \"$1\"\n")
        r = run_zedit(port, key, tmp, ed, "y\n", zone=zone)
        assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
        assert not dig(port, key, signal, "CDS") and not dig(port, key, signal, "CDNSKEY")


def concurrent_soa(key, port, fields, mname="ns1.example.net.", ttl=3600):
    """Shell snippet: the server's SOA changed by someone else while editing.
    It waits until the server answers with the change: with inline-signing the
    signed zone, which answers queries, follows the unsigned one a moment later,
    and zedit can only see the change once it is there (see README, "SOA")."""
    timers = " ".join(fields.split()[1:])  # REFRESH RETRY EXPIRE MINIMUM; the signed serial differs
    return nsupdate(
        key, port, f"update add example.com. {ttl} IN SOA {mname} hostmaster.example.net. {fields}"
    ) + (
        f"for i in $(seq 100); do {TOOLS['dig']} +short -p {port} @127.0.0.1 {ZONE} SOA"
        f' | grep -q "^{mname} .* {timers}$" && break; sleep 0.1; done\n'
    )


def soa_fields(port, key):
    (rr,) = dig(port, key, ZONE, "SOA")
    return rr.split()[7:]  # REFRESH RETRY EXPIRE MINIMUM


def test_soa_change_keeps_concurrent_change_to_another_field(server):
    """Mine: MINIMUM 300 -> 60. Meanwhile on the server: REFRESH 7200 -> 3600.
    Both survive; the SOA isn't sent as edited from the old transfer."""
    port, key, tmp = server
    ed = write_editor(
        tmp,
        "sed -i 's/1209600 300/1209600 60/' \"$1\"\n" + concurrent_soa(key, port, "150 3600 900 1209600 300"),
    )
    r = run_zedit(port, key, tmp, ed, "y\n")
    assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
    assert soa_fields(port, key) == ["3600", "900", "1209600", "60"]


def test_soa_change_keeps_concurrent_change_to_locked_fields(server):
    """Mine: MINIMUM 300 -> 60. Meanwhile on the server: MNAME ns1 -> ns2 and the
    SOA TTL 3600 -> 7200. Sending the SOA doesn't put the old MNAME and TTL back."""
    port, key, tmp = server
    ed = write_editor(
        tmp,
        "sed -i 's/1209600 300/1209600 60/' \"$1\"\n"
        + concurrent_soa(key, port, "150 7200 900 1209600 300", mname="ns2.example.net.", ttl=7200),
    )
    r = run_zedit(port, key, tmp, ed, "y\n")
    assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
    (rr,) = dig(port, key, ZONE, "SOA")
    assert rr.split()[1] == "7200" and rr.split()[4] == "ns2.example.net." and rr.split()[-1] == "60"


def test_soa_conflict_on_the_same_field_rebases(server):
    """Mine: MINIMUM 300 -> 60. Meanwhile on the server: MINIMUM 300 -> 120.
    Nothing is sent; the rebase marks the conflict, keeps mine and opens the editor."""
    port, key, tmp = server
    ed = write_editor(
        tmp,
        # Only the first time: the editor opens again after the rebase
        f'[ -e "{tmp}/edited" ] && exit 0\ntouch "{tmp}/edited"\n'
        "sed -i 's/1209600 300/1209600 60/' \"$1\"\n" + concurrent_soa(key, port, "150 7200 900 1209600 120"),
    )
    r = run_zedit(port, key, tmp, ed, "y\nr\ny\n")
    assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
    assert "SOA MINIMUM changed both by you and on the server" in r.stderr
    assert "1 conflict(s)" in r.stdout
    assert soa_fields(port, key) == ["7200", "900", "1209600", "60"]


@pytest.mark.parametrize(
    ("sed", "expected"),
    [
        # Replace the only apex NS: deleting the last one first would be ignored
        (r"s/(IN +NS +)ns1\./\1ns2./", {"300 IN NS ns2.example.net."}),
        # Change its TTL: deleting the apex NS RRset would be ignored
        (r"s/^(@ +)300( +IN +NS )/\1600\2/", {"600 IN NS ns1.example.net."}),
        # Both at once
        (r"s/^(@ +)300( +IN +NS +)ns1\./\1600\2ns2./", {"600 IN NS ns2.example.net."}),
    ],
)
def test_apex_ns_change(tmp_path, sed, expected):
    """RFC 2136 §3.4.2.4: a server ignores deleting the last apex NS record or the
    apex NS RRset, so zedit adds before it deletes there."""
    records = "@ IN NS ns1.example.net.\nwww IN A 192.0.2.10\n"
    with run_named(tmp_path, "unsigned", records=records) as (port, key, tmp):
        ed = write_editor(tmp, f"sed -i -E '{sed}' \"$1\"\n")
        r = run_zedit(port, key, tmp, ed, "y\n")
        assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
        assert {rr.split(" ", 1)[1] for rr in dig(port, key, ZONE, "NS")} == expected


@pytest.mark.parametrize("signing", list(SIGNING))
@pytest.mark.parametrize(
    ("sed", "rname", "refresh"),
    [
        ("s/ 7200 900 1209600 300$/ 3600 900 1209600 300/", "hostmaster.example.com.", "3600"),  # a timer
        ("s/ hostmaster / admin /", "admin.example.com.", "7200"),  # RNAME itself
    ],
)
def test_soa_change_with_rname_inside_the_zone(tmp_path, signing, sed, rname, refresh):
    """An RNAME inside the zone comes relative from the transfer (hostmaster) but
    absolute from the SOA query (hostmaster.example.com.). They are the same name:
    no false conflict, no false verification failure."""
    with run_named(tmp_path, signing, rname="hostmaster.example.com.") as (port, key, tmp):
        ed = write_editor(tmp, f"sed -i '/ IN SOA / {sed}' \"$1\"\n")
        r = run_zedit(port, key, tmp, ed, "y\n")
        assert r.returncode == 0 and "Updated and verified." in r.stdout, r.stdout + r.stderr
        (rr,) = dig(port, key, ZONE, "SOA")
        assert rr.split()[5] == rname and rr.split()[7] == refresh
