# Changelog

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
