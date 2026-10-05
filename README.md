# zedit

Edit a dynamic DNS zone as if it were a plain zone file.

`zedit` transfers the zone with AXFR, strips DNSSEC and other server-maintained
records, opens it in `$EDITOR`, shows a semantic diff of your changes, and on
confirmation applies them with **one atomic `nsupdate`** guarded by an SOA
prerequisite. If the zone changed while you were editing (DHCP/DDNS, another
admin), your edits are **rebased** onto the current zone with a three-way merge
instead of overwriting the concurrent change.

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
zedit [-s SERVER] [-p PORT] [-k KEYFILE] [-n] [-r FILE] zone
```

| Option | |
|---|---|
| `-s`, `--server` | Primary to transfer from and update (default `127.0.0.1`) |
| `-p`, `--port` | Port (default 53) |
| `-k`, `--keyfile` | TSIG key in `tsig-keygen` / `named.conf` format, used for both AXFR and UPDATE |
| `-n`, `--dry-run` | Show the `nsupdate` script, send nothing |
| `-r`, `--resume FILE` | Resume a saved session (rebases onto the current zone) |

### Server requirements

The key needs transfer rights and an update policy covering every type you
intend to edit, including SOA:

```
zone "example.com" {
    allow-transfer { key admin; };
    update-policy { grant admin zonesub ANY; };
};
```

Use a dedicated admin key, not the one your DHCP server uses for DDNS.

## Behaviour

**Filtered types.** RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY, CDS, CDNSKEY, ZONEMD and
BIND's private TYPE65534 are removed from both sides of the diff and never
touched. (Deleting NSEC3PARAM or TYPE65534 through UPDATE would change signing.)

**SOA.** RNAME, REFRESH, RETRY, EXPIRE and MINIMUM are editable. MNAME, SERIAL and
the SOA record's own TTL are locked. When the SOA changes, the update carries
`serial + 1`, since RFC 2136 §3.4.2.2 silently ignores an SOA whose serial isn't
greater.

**Semantic diff.** Both sides are parsed and re-rendered canonically before
diffing, so whitespace, alignment, comments, ordering and equivalent rdata
spellings (`www` vs `www.example.com.`) don't show up as changes.

**Minimal atomic update.** Only changed RRs are sent, deletes before adds,
in a single UPDATE. A TTL change replaces the whole RRset. The prerequisite
`prereq yxrrset <zone> SOA <exact rdata>` makes the update fail with NXRRSET if
anything changed since the transfer.

**Rebase.** On NXRRSET (or an `nsupdate` timeout) you can rebase. zedit does a
new AXFR and merges per RRset:

- changed only by you → yours
- changed only on the server → theirs
- changed on both sides → server RRs + your additions − your deletions,
  marked `; MERGED` in the file
- conflicting TTL or SOA field → yours wins, marked `; CONFLICT`, and the
  editor opens for review

Rebasing after a timeout is safe: changes that did get applied simply drop out.

**Saved state.** Each session is stored in `$XDG_STATE_HOME/zedit/`
(default `~/.local/state/zedit/`) as `ZONE-TIMESTAMP.zone` plus
`ZONE-TIMESTAMP.zone.base` (the zone as transferred). Both are removed after a
successful update. On abort or failure zedit prints a `--resume` command.

## Development

```sh
uv sync
uv run zedit --help
uv run pytest                 # integration tests run if named/nsupdate/dig are installed
uv run ruff check . && uv run ruff format .
```

## License

MIT
