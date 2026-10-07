# zedit

Edit a dynamic DNS zone as if it were a plain zone file.

`zedit` transfers the zone with AXFR, strips DNSSEC and other server-maintained
records, opens it in `$EDITOR`, shows a semantic diff of your changes, and on
confirmation applies them with **one atomic `nsupdate`** guarded by
prerequisites on exactly the RRsets you touched, then **verifies** the result.
Concurrent changes elsewhere in the zone (DHCP/DDNS, another admin) don't
conflict; if someone changed the same RRsets, your edits are **rebased** onto
the current zone with a three-way merge instead of overwriting their change.
Works with unsigned and DNSSEC-signed zones (in-place and inline-signing).

```
$ zedit -s ns1.example.net -k /etc/bind/admin.key example.com
--- example.com. (serial 2026100412)
+++ edited
@@ -3,4 +3,5 @@
 mail    300  IN  A  192.0.2.20
+new     300  IN  A  192.0.2.30
-www     300  IN  A  192.0.2.10
+www     300  IN  A  192.0.2.11

1 delete, 2 add in 1 atomic UPDATE.
Send? [y]es / [N]o / [e]dit / [s]cript:
```

## Install

Requires Python ≥ 3.10 and `nsupdate` from BIND (not installable via pip):

```sh
sudo apt install bind9-dnsutils     # Debian/Ubuntu
brew install bind                   # macOS
```

Then install `zedit` as an isolated tool with [uv](https://docs.astral.sh/uv/):

```sh
uv tool install git+https://github.com/lmjogback/zedit
# or run once without installing
uvx --from git+https://github.com/lmjogback/zedit zedit --help
```

`pipx install git+https://github.com/lmjogback/zedit` works too.

## Usage

```
zedit [-s SERVER] [-p PORT] [-k KEYFILE] [-a] [--no-rrsig] [-A] [-n] [-r FILE] zone
```

| Option | |
|---|---|
| `-s`, `--server` | Primary to transfer from and update (default: the zone's SOA MNAME, looked up with the system resolver) |
| `-p`, `--port` | Port (default 53) |
| `-k`, `--keyfile` | TSIG key in `tsig-keygen` / `named.conf` format, used for both AXFR and UPDATE (default: see below) |
| `-a`, `--show-all` | Also show DNSSEC and server-maintained records, as read-only `;ro` comment lines |
| `--no-rrsig` | With `--show-all`, leave out RRSIG, NSEC and NSEC3 (implies `-a`) |
| `-A`, `--addresses` | In reverse zones, show owner names as IP addresses |
| `-n`, `--dry-run` | Show the `nsupdate` script, send nothing; the session is kept for `--resume` |
| `-r`, `--resume FILE` | Resume a saved session (rebases onto the current zone) |

When the server or key comes from a default, zedit prints which ones it uses.
If the server name has several addresses, zedit connects with Happy Eyeballs
(RFC 8305) and uses the first address that accepts a TCP connection, so a
broken IPv6 path quickly falls back to IPv4.

### Default key

Without `-k`, the first of these that exists is used:

1. `$ZEDIT_KEYFILE`
2. `~/.config/zedit/keys/ZONE.key` (e.g. `keys/example.com.key`; honours `$XDG_CONFIG_HOME`).
   ZONE is lower-cased, and characters other than letters, digits, `.`, `-` and `_`
   become `_`, so the RFC 2317 zone `16/28.2.0.192.in-addr.arpa` uses
   `keys/16_28.2.0.192.in-addr.arpa.key`.
3. `~/.config/zedit/default.key`

If none exists, zedit runs without TSIG. zedit warns if the key file is readable by
group or others. A key file must hold a single key, since `nsupdate` refuses
files with more than one.

```sh
mkdir -p ~/.config/zedit/keys && chmod 700 ~/.config/zedit
tsig-keygen -a hmac-sha256 admin > ~/.config/zedit/default.key
chmod 600 ~/.config/zedit/default.key
```

### Server requirements

zedit uses only standard protocols: AXFR (RFC 5936) and UPDATE (RFC 2136), both
with TSIG. It should work with any server that supports them, but it is tested
with BIND 9.20 only, and the examples here are for BIND. Reports on other servers
are welcome.

The key needs transfer rights and an update policy covering every type you
intend to edit, including SOA. With BIND:

```
zone "example.com" {
    allow-transfer { key admin; };
    update-policy { grant admin zonesub ANY; };
};
```

Use a dedicated admin key, not the one your DHCP server uses for DDNS.

## Behaviour

**Filtered types.** RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY, ZONEMD and BIND's
private TYPE65534 are removed from both sides of the diff and never touched, and
so are CDS and CDNSKEY at the zone's apex, where BIND maintains them. (Deleting
NSEC3PARAM or TYPE65534 through UPDATE would change signing.)

**Bootstrapping signals.** Below the apex, CDS and CDNSKEY are ordinary records,
so a DNS operator can publish RFC 9615 signals (`_dsboot.CHILD._signal.NS-HOST`)
that let a registry turn on DNSSEC for a child zone. zedit warns if such a record
is not at a `_dsboot` name. See [docs/signaling.md](docs/signaling.md) for how
signals work and how to set them up with BIND.

**`$ORIGIN`.** You can use `$ORIGIN` lines in the file, e.g. to add a block of
PTR records. Every owner name must stay inside the zone; names that fall outside
it are reported as an error rather than silently ignored.

**`$GENERATE`.** You can add ranges of records with `$GENERATE`, with BIND's
syntax and semantics: `start-stop[/step]`, several `$` and
`${offset[,width[,base]]}` modifiers per line (bases `d`, `o`, `x`, `X`, and `n`/`N`
for `ip6.arpa` nibbles) and `\$` for a literal `$`:

```
$GENERATE 20-29 $ PTR host$.example.com.
$GENERATE 30-38/2 $ PTR dyn-${0,3,d}.example.com.
```

The expansion is done by zedit, not dnspython, whose own `$GENERATE` handles only
one modifier per side. A dynamic zone stores the generated records, not the
`$GENERATE` line, so the next edit shows the individual records.

**Reverse zones in address form.** In a zone under `in-addr.arpa` or `ip6.arpa`
you can write owners as IP addresses, in normal order; zedit converts them to the
reverse names:

```
192.0.2.10    PTR www.example.com.     ; -> 10.2.0.192.in-addr.arpa.
2001:db8::1   PTR www.example.com.     ; -> 1.0.0.0.…8.b.d.0.1.0.0.2.ip6.arpa.
$GENERATE 20-29 192.0.2.$ PTR host$.example.com.
```

An owner counts as an address when it is a dotted quad or contains `:`, with no
trailing dot. As a relative name a dotted quad would have more than four octets
under `in-addr.arpa`, which no IPv4 address has, so this is unambiguous in
practice; an absolute name (trailing dot) is always used as written, and other
zones are never rewritten. An address must belong to the zone, which also catches
an address typed backwards. Something that looks like an address but isn't valid
(`192.0.2.010`) is an error. In an RFC 2317 zone such as
`16/28.2.0.192.in-addr.arpa`, `192.0.2.17` becomes `17.16/28.2.0.192.in-addr.arpa.`;
in a zone for a single address it is the apex.

With `-A` the file also *shows* owners as addresses (IPv6 compressed), ordered by
address; the apex stays `@`. The update always uses the real reverse names.

**Seeing everything.** With `-a` the filtered records are shown in place, as
comment lines marked `;ro`, each RRSIG right after the type it covers:

```
@        300 IN NS     ns1
;ro @    300 IN RRSIG  NS 13 2 300 20261019040406 20261005123408 34319 @ y0Ov…
;ro @   3600 IN DNSKEY 257 3 13 et91FeNyNspnfPc6wD0cXkDc1N92g8Eg…
www      300 IN A      192.0.2.10
;ro www  300 IN RRSIG  A 13 3 300 20261019040406 20261005123408 34319 @ eiIq…
```

Being comments, they never reach the diff, the update or the merge, so editing or
deleting them has no effect. `--no-rrsig` keeps the interesting ones (DNSKEY, CDS,
CDNSKEY, NSEC3PARAM, TYPE65534) and drops the bulky ones.

**SOA.** RNAME, REFRESH, RETRY, EXPIRE and MINIMUM are editable. MNAME, SERIAL and
the SOA record's own TTL are locked. Below the SOA record, comment lines explain
each value as transferred:

```
@      60 IN SOA    ns1.example.net. hostmaster.example.net. 2026100526 300 120 21600 60
; SOA values as transferred (these comments are not updated when you edit):
;   MNAME   = ns1.example.net.         primary name server (locked)
;   RNAME   = hostmaster.example.net.  contact: hostmaster@example.net
;   SERIAL  = 2026100526               locked; bumped automatically
;   REFRESH = 300                      (5 minutes) how often secondaries check for changes
;   RETRY   = 120                      (2 minutes) retry interval after a failed refresh
;   EXPIRE  = 21600                    (6 hours) secondaries stop answering after this long
;   MINIMUM = 60                       (1 minute) TTL of negative answers, RFC 2308
;   TTL     = 60                       (1 minute) TTL of the SOA record itself (locked)
```

When you change the SOA, zedit reads the server's current SOA at the moment of
sending and merges the editable fields three ways: a field changed only on the
server since the transfer keeps the server's value, so a concurrent change to
another field isn't overwritten. If you and the server changed the same field to
different values, nothing is sent and you can rebase, which marks the conflict.
The serial sent is `max(transferred, live) + 1` in RFC 1982 arithmetic, since RFC
2136 §3.4.2.2 silently ignores an SOA whose serial isn't greater. The SOA can't be
locked with a prerequisite (see below), so a change made in the milliseconds
between reading it and sending is still overwritten.

**Semantic diff.** Both sides are parsed and re-rendered canonically before
diffing, so whitespace, alignment, comments, ordering and equivalent rdata
spellings (`www` vs `www.example.com.`) don't show up as changes. On a terminal
the diff is coloured, unless `NO_COLOR` is set.

**Minimal atomic update.** Only changed RRs are sent, deletes before adds,
in a single UPDATE. A TTL change replaces the whole RRset. The apex NS RRset is
the exception: a server ignores deleting it or its last record (RFC 2136
§3.4.2.4), so there the new records are added first and the old ones deleted
after. The apex must keep at least one NS record.

**Optimistic lock per RRset.** Every RRset the update changes or deletes gets a
value-dependent `prereq yxrrset` with its content as transferred; every RRset it
creates gets `prereq nxrrset`. The update fails (NXRRSET/YXRRSET) only if one of
*those* RRsets changed in the meantime. The SOA is deliberately not used as the
lock: in a signed zone the serial changes on every re-signing, and with
inline-signing the transferred (signed) serial never matches the unsigned zone
that receives the UPDATE.

One narrow case gets through: RFC 2136 prerequisites ignore TTLs. If someone
else changes only the TTL of an RRset while you change its records (keeping its
TTL), the prerequisite still holds and the server gives the whole RRset your
TTL, undoing theirs. Verification doesn't notice, since the result matches your
edit.

**Verification.** After a successful `nsupdate`, zedit transfers the zone again
(with retries, since inline-signing updates the signed zone asynchronously) and
checks that every changed RRset matches your edit. BIND silently drops some
updates, e.g. an add that violates the CNAME rule, an SOA with a non-greater
serial, or TTLs above a `dnssec-policy` `max-zone-ttl`. Mismatches are listed
and zedit exits with status 3, as it does if the zone can't be transferred again.

**Rebase.** On NXRRSET/YXRRSET (or an `nsupdate` timeout) you can rebase. zedit does a
new AXFR and merges per RRset:

- changed only by you → yours
- changed only on the server → theirs
- changed on both sides → server RRs + your additions − your deletions,
  marked `; MERGED` in the file
- conflicting TTL or SOA field, or two different values of a single-record
  type such as CNAME → yours wins, marked `; CONFLICT`, and the
  editor opens for review

Rebasing after a timeout is safe: changes that did get applied simply drop out.

**Saved state.** Each session is stored in `$XDG_STATE_HOME/zedit/`
(default `~/.local/state/zedit/`) as `ZONE-TIMESTAMP.zone` plus
`ZONE-TIMESTAMP.zone.base` (the zone as transferred); a session started in the
same second as another one for the zone gets `ZONE-TIMESTAMP-2.zone`, and so on.
Both are removed after a successful, verified update. On abort or failure,
including answering no to `Send?`, zedit prints a `--resume` command. So does
`--dry-run`: resume without `--dry-run` to send the same edit, rebased onto the
zone as it is then.

**Exit status.** 0 success (or nothing to do), 1 error or aborted edit,
2 update rejected or aborted, 3 update accepted but not verified, 130 interrupted.

## Development

```sh
uv sync
uv run zedit --help
uv run pytest                 # integration tests run if named/nsupdate/dig are installed
uv run ruff check . && uv run ruff format .
```

## License

MIT
