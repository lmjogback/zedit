"""The RFC 2136 backend: the steps of the UPDATE and their order, the
prerequisites that lock what the edit touches, the message and the nsupdate
script made from the steps, the outcomes of sending, TSIG key files, and
finding and reaching the server. The steps are compared as nsupdate commands
(helpers.lines()), which read like the script --dry-run shows."""

import socket

import pytest
from helpers import ORIGIN, changeset, lines, model

from zedit import changes, rfc2136
from zedit.backend import Outcome
from zedit.model import ZeditError


def test_compute_update_minimal_and_ordered():
    """Only the records that change are sent: www keeps .1, loses .2 and gains
    .3. foo's A RRset is deleted before its CNAME is added: the server applies
    the steps in order, and ignores a CNAME added where other data still is
    (RFC 2136 §3.4.2.2)."""
    old, _, _ = model("www A 192.0.2.1\nwww A 192.0.2.2\nfoo A 192.0.2.9\n")
    new, _, _ = model("www A 192.0.2.1\nwww A 192.0.2.3\nfoo CNAME www\n")
    dels, adds, final = rfc2136.compute_update(changeset(old, new), ORIGIN)
    assert lines(dels) == [
        "update delete foo.example.com. IN A",
        "update delete www.example.com. IN A 192.0.2.2",
    ]
    assert sorted(lines(adds)) == [
        "update add foo.example.com. 300 IN CNAME www.example.com.",
        "update add www.example.com. 300 IN A 192.0.2.3",
    ]


def test_ttl_change_replaces_rrset():
    """A TTL belongs to the whole RRset, so changing it deletes the RRset and
    adds it again with the new TTL."""
    old, _, _ = model("www 300 A 192.0.2.1\n")
    new, _, _ = model("www 60 A 192.0.2.1\n")
    dels, adds, final = rfc2136.compute_update(changeset(old, new), ORIGIN)
    assert lines(dels) == ["update delete www.example.com. IN A"]
    assert lines(adds) == ["update add www.example.com. 60 IN A 192.0.2.1"]
    assert final == []


@pytest.mark.parametrize(
    ("old_ns", "new_ns", "adds", "final"),
    [
        ("@ NS ns1\n", "@ NS ns2\n", ["300 IN NS ns2.example.com."], ["IN NS ns1.example.com."]),
        ("@ 300 NS ns1\n", "@ 600 NS ns1\n", ["600 IN NS ns1.example.com."], []),
        ("@ NS ns1\n@ NS ns2\n", "@ NS ns1\n", [], ["IN NS ns2.example.com."]),
    ],
)
def test_apex_ns_added_before_deleted(old_ns, new_ns, adds, final):
    """RFC 2136 §3.4.2.4: deleting the apex NS RRset or its last record is
    ignored, so at the apex NS zedit adds first and deletes the old records last,
    one by one, never the whole RRset."""
    old, _, _ = model(old_ns)
    new, _, _ = model(new_ns)
    d, a, f = rfc2136.compute_update(changeset(old, new), ORIGIN)
    assert d == []
    assert [x.removeprefix("update add example.com. ") for x in lines(a)] == adds
    assert [x.removeprefix("update delete example.com. ") for x in lines(f)] == final
    # update_ops() puts the final deletes last
    server = rfc2136.Rfc2136Backend("192.0.2.53", 53, "ns")
    ops, _, _ = rfc2136.update_ops(server, ORIGIN, changeset(old, new))
    script = rfc2136.script_text(server.address, server.port, ORIGIN, ops)
    assert all(script.index(x) < script.index(y) for x in lines(a) for y in lines(f))


def test_soa_update_bumps_serial_and_wraps():
    """The serial after 4294967295 is 0 (RFC 1982); an SOA that isn't changed
    isn't sent, and doesn't need the server's current one (None)."""
    _, old, _ = model("", soa="@ 3600 IN SOA ns1 hm 4294967295 7200 900 1209600 300\n")
    _, new, _ = model("", soa="@ 3600 IN SOA ns1 hm 4294967295 7200 900 1209600 60\n")
    soa, conflicts = changes.soa_to_send(old, new, old)
    (line,) = lines(rfc2136.soa_update(soa, ORIGIN))
    assert " 0 7200 900 1209600 60" in line and conflicts == []
    assert changes.soa_to_send(old, old, None) == (None, [])
    assert rfc2136.soa_update(None, ORIGIN) == []


def test_prereqs_only_on_touched_rrsets():
    """Each RRset the UPDATE changes must still be exactly as transferred (www,
    gone) or still absent (new); mail isn't touched, so it isn't checked, and a
    concurrent change to it doesn't make the UPDATE fail."""
    old, _, _ = model("www A 192.0.2.1\nwww A 192.0.2.2\nmail A 192.0.2.9\ngone TXT x\n")
    new, _, _ = model("www A 192.0.2.1\nwww A 192.0.2.3\nmail A 192.0.2.9\nnew A 192.0.2.4\n")
    assert sorted(lines(rfc2136.compute_prereqs(changeset(old, new), ORIGIN))) == [
        "prereq nxrrset new.example.com. IN A",
        'prereq yxrrset gone.example.com. IN TXT "x"',
        "prereq yxrrset www.example.com. IN A 192.0.2.1",
        "prereq yxrrset www.example.com. IN A 192.0.2.2",
    ]


def test_primary_from_mname(monkeypatch):
    """Without -s, the server is the SOA MNAME, looked up with the system resolver."""
    _, soa, _ = model("", soa="@ 3600 IN SOA ns1.example.net. hm 1 2 3 4 5\n")
    monkeypatch.setattr(rfc2136.dns.resolver, "resolve", lambda *a, **kw: soa)
    assert rfc2136.primary_from_mname(ORIGIN) == "ns1.example.net."


@pytest.fixture
def listener():
    """A TCP listener on 127.0.0.1 only -> its port."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        yield s.getsockname()[1]


def test_resolve_falls_back_to_a_reachable_address(monkeypatch, listener):
    """A server whose first address doesn't answer is still reached on the next
    one (Happy Eyeballs), and that address is used for the whole session."""

    # IPv6 first, as for a server with an AAAA record, but nothing answers there
    def getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]

    monkeypatch.setattr(rfc2136.socket, "getaddrinfo", getaddrinfo)
    assert rfc2136.resolve("ns1.example.net", listener) == "127.0.0.1"


def test_resolve_fails_when_nothing_answers():
    """An unreachable server is a plain error, before anything else happens."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]  # bound but not listening: refused
        with pytest.raises(ZeditError, match="cannot connect to 127.0.0.1 port"):
            rfc2136.resolve("127.0.0.1", closed)


# A key file as tsig-keygen writes it
KEY = 'key "{name}" {{\n\talgorithm hmac-sha256;\n\tsecret "c2VjcmV0c2VjcmV0c2VjcmV0";\n}};\n'


def test_key_file_with_one_key(tmp_path):
    """The key's name in the file is the name it signs with."""
    f = tmp_path / "admin.key"
    f.write_text(KEY.format(name="admin"))
    keyring, keyname = rfc2136.load_bind_key(str(f))
    assert keyname == rfc2136.dns.name.from_text("admin") and keyname in keyring


def test_key_file_with_several_keys_is_an_error(tmp_path):
    """One key per file, as in 1.2.1, where nsupdate -k refused such a file;
    kept so that the switch to dnspython changes no behaviour."""
    f = tmp_path / "two.key"
    f.write_text(KEY.format(name="admin") + KEY.format(name="other"))
    with pytest.raises(
        ZeditError, match=r"has 2 key statements \(admin, other\); a key file must hold a single key"
    ):
        rfc2136.load_bind_key(str(f))


def test_live_soa_names_are_relative_like_the_transfer(monkeypatch):
    """The SOA query answers with absolute names; the transferred zone has them
    relative. live_soa() makes them relative, so an RNAME inside the zone compares
    equal (no false conflict or verification failure), and one outside stays."""
    answer = "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 105 7200 900 1209600 300"

    def tcp(q, server, port, timeout):
        return rfc2136.dns.message.from_text(
            f"id {q.id}\nopcode QUERY\nrcode NOERROR\nflags QR AA\n;ANSWER\n{answer}\n"
        )

    monkeypatch.setattr(rfc2136.dns.query, "tcp", tcp)
    server = rfc2136.Rfc2136Backend("192.0.2.53", 53, "ns")
    live = rfc2136.live_soa(server, ORIGIN)
    _, base, _ = model("", soa="@ 3600 IN SOA ns1 hostmaster 100 7200 900 1209600 300\n")
    assert (live[0].mname, live[0].rname, live[0].serial) == (base[0].mname, base[0].rname, 105)
    assert live.ttl == 3600
    answer = answer.replace("hostmaster.example.com.", "hostmaster.example.net.")
    assert rfc2136.live_soa(server, ORIGIN)[0].rname.to_text() == "hostmaster.example.net."


def plan_ops():
    """Prerequisites, deletes and adds for a typical edit."""
    old, _, _ = model("www A 192.0.2.1\nwww A 192.0.2.2\ngone TXT x\n")
    new, _, _ = model("www A 192.0.2.1\nwww A 192.0.2.3\nnew A 192.0.2.4\n")
    dels, adds, final = rfc2136.compute_update(changeset(old, new), ORIGIN)
    return rfc2136.compute_prereqs(changeset(old, new), ORIGIN) + dels + adds + final


def test_update_message_sections():
    """RFC 2136 encoding: value-dependent prerequisites in class IN with TTL 0,
    "RRset does not exist" in class NONE, deleting an RRset in class ANY,
    deleting one RR in class NONE with TTL 0."""
    msg = rfc2136.update_message(ORIGIN, plan_ops())
    sections = {
        name: sorted(" ".join(line.split()) for rrset in rrsets for line in rrset.to_text().splitlines())
        for name, rrsets in (("prereq", msg.prerequisite), ("update", msg.update))
    }
    assert sections == {
        "prereq": [
            'gone.example.com. 0 IN TXT "x"',
            "new.example.com. NONE A",
            "www.example.com. 0 IN A 192.0.2.1",
            "www.example.com. 0 IN A 192.0.2.2",
        ],
        "update": [
            "gone.example.com. ANY TXT",
            "new.example.com. 300 IN A 192.0.2.4",
            "www.example.com. 0 NONE A 192.0.2.2",
            "www.example.com. 300 IN A 192.0.2.3",
        ],
    }
    assert msg.zone[0].name == ORIGIN and not msg.had_tsig


def test_update_message_is_signed_with_the_key():
    """The UPDATE is signed with the same key as the transfer."""
    keyring = rfc2136.dns.tsigkeyring.from_text({"admin": ("hmac-sha256", "c2VjcmV0c2VjcmV0c2VjcmV0")})
    msg = rfc2136.update_message(ORIGIN, plan_ops(), keyring, rfc2136.dns.name.from_text("admin"))
    msg.to_wire()  # signs
    assert msg.keyname == rfc2136.dns.name.from_text("admin") and msg.had_tsig


def test_script_text_matches_the_ops():
    """The script --dry-run shows is a complete nsupdate script: server, zone,
    the steps, send. It can be sent by hand with nsupdate -k."""
    script = rfc2136.script_text("192.0.2.53", 53, ORIGIN, plan_ops())
    assert script.splitlines()[:2] == ["server 192.0.2.53 53", "zone example.com."]
    assert script.splitlines()[-1] == "send"
    assert "prereq nxrrset new.example.com. IN A" in script
    assert "update delete www.example.com. IN A 192.0.2.2" in script


def send_with(monkeypatch, outcome):
    """Run rfc2136.send_update() with dns.query.tcp answering with rcode outcome, or
    raising it."""

    def tcp(msg, server, port, timeout):
        if isinstance(outcome, BaseException):
            raise outcome
        response = rfc2136.dns.message.make_response(msg)
        response.set_rcode(outcome)
        return response

    monkeypatch.setattr(rfc2136.dns.query, "tcp", tcp)
    server = rfc2136.Rfc2136Backend("192.0.2.53", 53, "ns")
    return rfc2136.send_update(server, ORIGIN, plan_ops())


@pytest.mark.parametrize(
    ("outcome", "expected", "text"),
    [
        (rfc2136.dns.rcode.NOERROR, Outcome.OK, ""),
        (rfc2136.dns.rcode.NXRRSET, Outcome.REBASE, "NXRRSET"),
        (rfc2136.dns.rcode.YXRRSET, Outcome.REBASE, "YXRRSET"),
        (rfc2136.dns.rcode.REFUSED, Outcome.FAILED, "REFUSED"),
        (rfc2136.dns.rcode.NOTAUTH, Outcome.FAILED, "NOTAUTH"),
        (rfc2136.dns.exception.Timeout(), Outcome.REBASE, "unknown whether"),
        (EOFError(), Outcome.REBASE, "unknown whether"),
        (ConnectionRefusedError(111, "Connection refused"), Outcome.FAILED, "Connection refused"),
    ],
)
def test_send_update_outcomes(monkeypatch, outcome, expected, text):
    """How each answer, or failure to get one, is reported. NXRRSET/YXRRSET (a
    prerequisite failed) and a lost answer (it may or may not have been applied)
    offer a rebase; a refusal or a TSIG error doesn't, as rebasing won't help."""
    result = send_with(monkeypatch, outcome)
    assert result.outcome is expected and text in result.message


def test_backend_soa_conflict_is_previewed_and_offers_a_rebase(monkeypatch):
    """The same SOA field changed by the edit and on the server: preview() names
    it, and apply() sends nothing and offers a rebase."""
    _, base, _ = model("", soa="@ 3600 IN SOA ns1 hm 100 7200 900 1209600 300\n")
    _, mine, _ = model("", soa="@ 3600 IN SOA ns1 hm 100 7200 900 1209600 60\n")
    _, live, _ = model("", soa="@ 3600 IN SOA ns1 hm 101 7200 900 1209600 120\n")
    monkeypatch.setattr(rfc2136, "live_soa", lambda server, origin: live)
    monkeypatch.setattr(rfc2136, "send_update", lambda *a: pytest.fail("sent despite the conflict"))
    server = rfc2136.Rfc2136Backend("192.0.2.53", 53, "ns")
    edit = changes.ChangeSet((), base, mine)
    assert server.preview(ORIGIN, edit).soa_conflicts == ["MINIMUM"]
    result = server.apply(ORIGIN, edit)
    assert result.outcome is Outcome.REBASE and "SOA MINIMUM changed both by you" in result.message


@pytest.mark.parametrize(
    ("algorithm", "secret", "match"),
    [
        ("hmac-sha256", "not*base64", "invalid key in .*: Invalid base64"),
        ("hmac-foo", "c2VjcmV0c2VjcmV0c2VjcmV0", "invalid key in .*: unknown algorithm hmac-foo"),
    ],
)
def test_invalid_key_is_an_error(tmp_path, algorithm, secret, match):
    """dnspython raises binascii.Error for a bad secret, and KeyError for an
    unknown algorithm only when it signs; both are errors when the key is read."""
    f = tmp_path / "bad.key"
    f.write_text(f'key "admin" {{ algorithm {algorithm}; secret "{secret}"; }};\n')
    with pytest.raises(ZeditError, match=match):
        rfc2136.load_bind_key(str(f))


def test_unreadable_key_file_is_an_error(tmp_path):
    """A key file that can't be read is a plain error, not a traceback."""
    with pytest.raises(ZeditError, match="cannot read key file"):
        rfc2136.load_bind_key(str(tmp_path))  # a directory
