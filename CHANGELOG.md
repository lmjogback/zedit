# Changelog

## Unreleased

- Fix: if the zone transfer used to verify an update failed, zedit exited
  with status 1 as if nothing had been sent, although the update was applied.
  A failed transfer is now retried like a mismatch, and if it keeps failing
  zedit reports the update as not verified (exit status 3).

## 1.0.4 - 2026-10-06

- Fix: in ip6.arpa zones, owners made of four single-digit nibbles (such as
  `0.5.0.0` for a /64 delegated under a /48) were taken for IPv4 addresses and
  rejected as outside the zone, which made such zones impossible to edit.
- Tests: the integration tests now find BIND's tools in `/usr/sbin`, ignore a
  developer's `$VISUAL`, and can no longer hang waiting for a terminal.

## 1.0.3 - 2026-10-06

- Fix: `$GENERATE` with more than one `${offset,width,base}` modifier per side
  produced wrong records (dnspython expands only one). zedit now expands
  `$GENERATE` itself, following BIND, including `n`/`N` nibbles for `ip6.arpa`.
- In reverse zones, owners can be written as IP addresses (`192.0.2.10`,
  `2001:db8::1`), also in `$GENERATE`; RFC 2317 zones are handled.
- New `-A`/`--addresses` shows reverse-zone owners as IP addresses.

## 1.0.2 - 2026-10-06

- Fix: zones with '/' in their name (RFC 2317 classless reverse zones) crashed
  when saving the session. The default key for such a zone is
  `keys/16_28.2.0.192.in-addr.arpa.key` ('/' becomes '_').
- Fix: records placed outside the zone, e.g. after a `$ORIGIN` pointing
  elsewhere, were silently ignored. They are now reported as an error.

## 1.0.1 - 2026-10-06

- Package metadata only: copyright holder in `LICENSE` is now "LM Jogbäck",
  and `pyproject.toml` lists the author. No code changes.

## 1.0.0 - 2026-10-05

First stable release.

- Edit a dynamic zone as a zone file: AXFR with TSIG, `$EDITOR`, semantic diff,
  one atomic `nsupdate`.
- DNSSEC and server-maintained records (RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY,
  CDS, CDNSKEY, ZONEMD, TYPE65534) are filtered out and never touched;
  `-a`/`--show-all` shows them as read-only `;ro` comment lines, `--no-rrsig`
  leaves out RRSIG, NSEC and NSEC3.
- Editable SOA fields (RNAME, REFRESH, RETRY, EXPIRE, MINIMUM), explained in
  comments below the SOA record; the serial is bumped automatically.
- Optimistic locking with value-dependent prerequisites on exactly the RRsets
  an update touches, so concurrent DHCP/DDNS updates elsewhere don't conflict.
- Verification by a fresh AXFR after every update, reporting changes the
  server silently dropped (exit status 3).
- Three-way rebase onto the current zone on conflicts or timeouts; sessions
  are saved and can be resumed with `--resume`.
- Works with unsigned zones and DNSSEC-signed zones (in-place and
  inline-signing), with every `serial-update-method`.
- Defaults: server from the zone's SOA MNAME; key from `$ZEDIT_KEYFILE`,
  `~/.config/zedit/keys/ZONE.key` or `~/.config/zedit/default.key`.
