# Changelog

## Unreleased

- zedit no longer needs `nsupdate` (BIND's `bind9-dnsutils`): it sends the
  UPDATE itself with dnspython, signed with the same TSIG key it uses for the
  transfer. `--dry-run` and `[s]cript` still show the update as an `nsupdate`
  script, which can be sent by hand.
- Fix: changing the SOA put back the MNAME and SOA TTL from the transfer, so a
  change to either made on the server while you were editing was reverted, and
  the update was still reported as verified. They are now taken from the
  server's current SOA, and verification checks the MNAME too.
- Fix: records with different TTLs in one RRset silently got the lowest of
  them (raising the TTL on one line of a multi-record RRset gave "No
  differences"), and a second CNAME, SOA or other single-record type at a name
  silently replaced the first. Both are now errors on the offending line.
- Fix: a change of letter case alone (`www CNAME Target` for `target`, or an
  owner name) showed in the diff, but the UPDATE was empty, since DNS names
  compare case-insensitively; zedit still reported "Updated and verified".
  The original spelling is now kept, with a note, and only real changes are
  shown and sent.
- Fix: `$GENERATE` substituted `$` inside a comment at the end of the line too,
  so `; see ${docs}` failed with "bad $GENERATE modifier".
- Fix: saved session files lost their owner-only permissions on the first
  write (they got the umask's, usually 0644), and the write went through a
  fixed `FILE.tmp` name, following a symlink planted there (relevant when
  `--resume FILE` is in a shared directory). They are now written through a
  new, exclusively created file readable only by you.
- Fix: if writing the rebased session failed halfway (say the disk was full),
  the edit could be left with the server's new serial next to the old base, and
  `--resume` then failed with "locked SOA fields changed: SERIAL". Both files
  are now written out before either is replaced.
- Fix: Ctrl-C or Ctrl-\ while the editor ran also interrupted zedit, if the
  editor doesn't take the terminal's signal keys for itself (vim and nano do).
  As git does, zedit now ignores them until the editor exits.
- Aborting the editor (e.g. vim's `:cq`) without changing anything now removes
  the session instead of leaving it in the state directory with a `--resume`
  hint.
- Verification retries transfer the zone again only when its serial has moved
  since the last transfer (checked with an SOA query), instead of up to ten
  full transfers when a change doesn't show up, which was heavy for large
  zones. The last retry no longer ends with a needless wait.
- README: zedit is tested with BIND 9.18 and 9.20, not 9.20 only.
- The file you edit is always read and written as UTF-8, whatever the locale.
  Before, non-ASCII text (say in a TXT record) was read with the locale's
  encoding. A file saved in another encoding is now reported with its line.
- Fix: an error in the last field of a record (say `www A 999.1.1.1`) was
  reported on the line after it.
- Fix: names written with non-ASCII letters were encoded with IDNA 2003, which
  maps some letters differently from IDNA 2008, the standard registries use:
  `straße.de` became `strasse.de`, a different domain, instead of
  `xn--strae-oqa.de`. zedit now uses IDNA 2008, and depends on the `idna`
  package for it.
- A warning when an added SPF, DKIM or DMARC record contains non-ASCII bytes,
  such as a pasted typographic dash or a domain not written as an A-label
  (`xn--`). These records must be ASCII, and the `\DDD` escapes they are
  shown with are easy to miss.
- README: sign a dynamic zone in place (`inline-signing no`); with
  inline-signing, BIND's `serial-update-method` doesn't apply to updates.
- Fix: a line break in the SOA RNAME (`\010` in its first label) went
  unescaped into the "contact:" comment, so the rest of the label became a line
  of zone data, and zedit offered to add a record nobody wrote. Characters that
  aren't printable are now shown there as `\DDD`.
- Fix: in the zone `in-addr.arpa.` itself, `-A` showed `10.2.0.192` as
  `192.0.2.10`, which is read back as a name, so saving the file unchanged moved
  every PTR record. `-A` now leaves that zone's owners as they are, as input
  already did. Ordinary reverse zones are not affected.

## 1.2.2 - 2026-10-07

- Fix: in a zone whose SOA RNAME is inside the zone (say
  `hostmaster.example.com.` in `example.com`), changing the RNAME gave a false
  conflict, and changing an SOA timer ended in a false "not verified" (exit
  status 3) although the update was applied. The server's current SOA, read
  when sending since 1.2.1, had its names absolute while the transferred zone
  has them relative.
- README: with inline-signing, a concurrent SOA change can be missed for as
  long as the server takes to sign it; mostly the server then ignores zedit's
  SOA and zedit reports exit status 3. The tests for concurrent SOA changes
  now wait until the server answers with the change.

## 1.2.1 - 2026-10-07

- Fix: when a rebase met a CNAME (or another single-record type) changed to
  different values by you and on the server, it kept one of them at random and
  reported no conflict. It is now a conflict: yours is kept, marked
  `; CONFLICT`, and the editor opens.
- Fix: changing the SOA overwrote a concurrent change to another SOA field
  (say REFRESH changed on the server while you changed MINIMUM), and zedit
  still reported "Updated and verified." The editable fields are now merged
  with the server's current SOA when sending; if both sides changed the same
  field, nothing is sent and you can rebase.
- Fix: replacing the zone's only apex NS record left the old one in place
  (the server ignores deleting the last apex NS, RFC 2136 §3.4.2.4); zedit
  reported it as not verified, but the zone had changed. At the apex NS, new
  records are now added before old ones are deleted. Removing every apex NS
  record is an error in the editor.
- Fix: two sessions for the same zone started within the same second shared
  their saved files, so one overwrote the other's edit. Session files are now
  created exclusively, numbered `-2`, `-3` … if the name is taken.
- A key file with more than one key statement is now an error at start.
  `nsupdate` refuses such a file, so the update used to fail only after editing.
- zedit warns if the directory with the saved sessions is accessible by group
  or others. It doesn't change the permissions.

## 1.2.0 - 2026-10-07

- CDS and CDNSKEY records can now be edited below the zone's apex, so DNS
  operators can publish RFC 9615 DNSSEC bootstrapping signals. At the apex they
  stay read-only. zedit warns if such a record is not at a `_dsboot` name.
  New guide: `docs/signaling.md`.
- Fix: a server with an AAAA record couldn't be reached when IPv6 doesn't
  work, since zedit used only the first address. It now connects with Happy
  Eyeballs (RFC 8305) and uses the first address that answers.
- The diff is no longer coloured when `NO_COLOR` is set (https://no-color.org).
- README: zedit uses only AXFR and UPDATE with TSIG and should work with any
  server that supports them; it is tested with BIND 9.20.
- Development: the CI actions run on Node 24, are pinned by commit SHA and
  are kept up to date by Dependabot. CI also tests on Ubuntu 26.04, treats a
  skipped integration test as a failure, and can be started by hand on any
  branch. The integration tests are more robust (dig over TCP, ports free for
  both TCP and UDP, TSIG keys that Ubuntu 26.04's AppArmor profile for dig
  allows). uv_build 0.12 is allowed as build backend.

## 1.1.0 - 2026-10-07

- Fix: if the zone transfer used to verify an update failed, zedit exited
  with status 1 as if nothing had been sent, although the update was applied.
  A failed transfer is now retried like a mismatch, and if it keeps failing
  zedit reports the update as not verified (exit status 3).
- Fix: answering no to `Send?` exited with status 0 and left the saved
  session behind without saying so. It now exits with status 2, as
  documented, and prints the `--resume` command.
- `--dry-run` keeps the session and prints a `--resume` command, so the edit
  can be sent later without editing it again.
- The `--resume` command zedit prints is now complete, with the options you
  gave (except `--dry-run`), ready to copy and paste.
- If the editor exits with a non-zero status (such as vim's `:cq`), zedit
  asks whether to edit again or abort instead of carrying on.
- An editor that can't be started, an invalid zone name, a damaged `.base`
  file or an unwritable state directory now give an error message instead of
  a Python traceback.
- Fix: `zedit --version` in release 1.0.4 reported 1.0.3.
- README: describes the one narrow case the per-RRset lock can't detect, a
  concurrent change of only an RRset's TTL.
- dnspython must now be below 3: zedit relies on internals of its zone file
  reader, which a new major version may change.
- Development: CI checks that the version, the changelog and the release tag
  agree, and runs the unit tests with the oldest allowed dependency versions.
  `AGENTS.md` has notes for coding agents.

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
