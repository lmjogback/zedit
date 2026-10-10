"""zedit - edit a dynamic DNS zone as if it were a plain zone file.

Flow:
  AXFR (TSIG) -> strip DNSSEC/server-maintained types -> $EDITOR
  -> semantic diff -> confirmation -> one atomic UPDATE (RFC 2136, with
  value-dependent prerequisites on exactly the RRsets it touches, acting as
  an optimistic lock) -> verification by a fresh AXFR.

  The lock deliberately does not use the SOA: in a DNSSEC-signed zone the
  serial changes on every re-signing, and with inline-signing the transferred
  (signed) serial differs from the serial of the unsigned zone that receives
  the UPDATE.

Error handling:
  The edit is saved in $XDG_STATE_HOME/zedit (default ~/.local/state/zedit)
  together with FILE.base = the zone as transferred. If the server changed
  RRsets you touched (prereq -> NXRRSET/YXRRSET) or the UPDATE times out, the edit can be
  rebased: new AXFR + three-way merge (base, mine, theirs).
  Aborted/failed sessions are resumed with --resume FILE.

Modules:
  cli (command line) -> session (files, editor, prompts, main loop) ->
  rfc2136 (the server: AXFR, SOA query, UPDATE), changes (SOA and warnings),
  merge (three-way merge), zonefile (parse and render) -> reverse (address
  owners) and model (shared constants and helpers).

Requires: python >= 3.10, dnspython >= 2.4.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("zedit")
except PackageNotFoundError:  # running from a source tree without installation
    __version__ = "0+unknown"
