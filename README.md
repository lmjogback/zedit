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

## Getting started

1. Create a TSIG key where zedit finds it by default:

   ```sh
   mkdir -p ~/.config/zedit && chmod 700 ~/.config/zedit
   tsig-keygen -a hmac-sha256 admin > ~/.config/zedit/default.key
   chmod 600 ~/.config/zedit/default.key
   ```

   Use a dedicated admin key, not the one your DHCP server uses for DDNS.

2. Give the key the right to transfer and update the zone. With BIND, add the
   key file's contents to `named.conf` and:

   ```
   zone "example.com" {
       allow-transfer { key admin; };
       update-policy { grant admin zonesub ANY; };
   };
   ```

   [docs/server.md](docs/server.md) has the details, also for DNSSEC-signed
   zones.

3. Run `zedit example.com`. The zone opens in `$VISUAL` or `$EDITOR` as a zone
   file. Edit it, save and quit, and zedit shows what you changed and asks:

   - `y` sends the changes as one UPDATE and then checks that the server has
     them.
   - `N` sends nothing.
   - `e` opens the file again.
   - `s` shows the update as an `nsupdate` script.

   If the server is not the zone's SOA MNAME, give it with `-s`.

If you stop before the update is sent and verified, zedit keeps your edit and
prints a `zedit --resume FILE` command to pick it up again. If someone else
changed the same records meanwhile, zedit offers to rebase your edit onto the
zone as it is now and shows you the result before sending anything; where your
change and theirs conflict, it opens the editor with the conflicts marked.

[docs/editing.md](docs/editing.md) describes what you can write in the file
(`$GENERATE`, IP addresses as names in reverse zones, internationalized names,
the SOA), and [docs/how-it-works.md](docs/how-it-works.md) what zedit sends
and how it verifies and rebases.

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

## Exit status

| Status | |
|---|---|
| 0 | Sent and verified, or nothing to do |
| 1 | Error, or the edit was aborted |
| 2 | The update was rejected, or you didn't send it |
| 3 | The server accepted the update, but it could not be verified |
| 130 | Interrupted |

## Documentation

- [docs/editing.md](docs/editing.md): what you can write in the file
- [docs/how-it-works.md](docs/how-it-works.md): what zedit sends, and how it verifies and rebases
- [docs/server.md](docs/server.md): setting up the server
- [docs/signaling.md](docs/signaling.md): DNSSEC bootstrapping signals (RFC 9615)
- [CONTRIBUTING.md](CONTRIBUTING.md): development, tests, and trying an unreleased branch
- [CHANGELOG.md](CHANGELOG.md)

## License

MIT
