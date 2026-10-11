# zedit

Edit a dynamic DNS zone as if it were a plain zone file.

`zedit` transfers the zone with AXFR, strips DNSSEC and other server-maintained
records, opens it in `$EDITOR`, shows a semantic diff of your changes, and on
confirmation applies them with **one atomic DNS UPDATE** guarded by
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

Requires Python ≥ 3.10. zedit talks DNS itself (AXFR and UPDATE, with
[dnspython](https://www.dnspython.org/)), so no BIND tools are needed.

Install `zedit` as an isolated tool with [uv](https://docs.astral.sh/uv/):

```sh
uv tool install git+https://github.com/lmjogback/zedit
# or run once without installing
uvx --from git+https://github.com/lmjogback/zedit zedit --help
```

`pipx install git+https://github.com/lmjogback/zedit` works too.

To try a change before it is released, add `@BRANCH` (or a tag or commit) to
the URL. `--refresh` makes uv fetch the branch again instead of using a cached
copy, and `--force` replaces an installed zedit:

```sh
uvx --refresh --from git+https://github.com/lmjogback/zedit@BRANCH zedit --help
uv tool install --force git+https://github.com/lmjogback/zedit@BRANCH
# back to main
uv tool install --force git+https://github.com/lmjogback/zedit
```

Until the release, `zedit --version` shows the previous version number.

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
| `--verify-timeout SECONDS` | After an update, give up verifying it after this long, transfers included (default 120) |
| `-n`, `--dry-run` | Show the update as an `nsupdate` script, send nothing; the session is kept for `--resume` |
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
group or others. A key file must hold a single key.

```sh
mkdir -p ~/.config/zedit/keys && chmod 700 ~/.config/zedit
tsig-keygen -a hmac-sha256 admin > ~/.config/zedit/default.key
chmod 600 ~/.config/zedit/default.key
```

## Exit status

0 success (or nothing to do), 1 error or aborted edit,
2 update rejected or aborted, 3 update accepted but not verified, 130 interrupted.


## Documentation

- [docs/editing.md](docs/editing.md): what you can write in the file
- [docs/how-it-works.md](docs/how-it-works.md): what zedit sends, and how it verifies and rebases
- [docs/server.md](docs/server.md): setting up the server
- [docs/signaling.md](docs/signaling.md): DNSSEC bootstrapping signals (RFC 9615)
- [CONTRIBUTING.md](CONTRIBUTING.md): development

## License

MIT
