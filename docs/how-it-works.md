# How zedit updates a zone

What zedit sends to the server, why, and what it does when the zone changed
under you. For what you can write in the file, see [editing.md](editing.md).

## Connecting

zedit talks to one server, the zone's primary: the SOA MNAME, looked up with
the system resolver, or the server given with `-s`. If the name has several
addresses, zedit connects with Happy Eyeballs (RFC 8305) and uses the first
address that accepts a TCP connection, so a broken IPv6 path quickly falls back
to IPv4. The transfer, the SOA query and the UPDATE all use TCP and are signed
with the TSIG key, and the server's answers must be signed with it too: an
unsigned answer, which could be forged, or one whose signature doesn't verify,
is not used.

## Semantic diff

Both sides are parsed and re-rendered canonically before diffing, so
whitespace, alignment, comments, ordering and equivalent rdata spellings (`www`
vs `www.example.com.`) don't show up as changes. Nor does a change of letter
case alone (`Target` for `target`): DNS names compare case-insensitively, so
the server would keep the record as it is. zedit puts the original spelling
back and says so. On a terminal the diff is coloured, unless `NO_COLOR` is set.

## Minimal atomic update

Only changed RRs are sent, deletes before adds, in a single UPDATE. A TTL
change replaces the whole RRset. The apex NS RRset is the exception: a server
ignores deleting it or its last record (RFC 2136 §3.4.2.4), so there the new
records are added first and the old ones deleted after. The apex must keep at
least one NS record.

## Optimistic lock per RRset

Every RRset the update changes or deletes gets a value-dependent
`prereq yxrrset` with its content as transferred; every RRset it creates gets
`prereq nxrrset`. The update fails (NXRRSET/YXRRSET) only if one of *those*
RRsets changed in the meantime. The SOA is deliberately not used as the lock:
in a signed zone the serial changes on every re-signing, and with
inline-signing the transferred (signed) serial never matches the unsigned zone
that receives the UPDATE.

One narrow case gets through: RFC 2136 prerequisites ignore TTLs. If someone
else changes only the TTL of an RRset while you change its records (keeping its
TTL), the prerequisite still holds and the server gives the whole RRset your
TTL, undoing theirs. Verification doesn't notice, since the result matches your
edit.

## SOA changes

When you change the SOA, zedit reads the server's current SOA at the moment of
sending and merges the editable fields three ways: a field changed only on the
server since the transfer keeps the server's value, so a concurrent change to
another field isn't overwritten. The locked MNAME and SOA TTL are sent as the
server has them then, so a concurrent change to them isn't reverted either. If
you and the server changed the same field to different values, nothing is sent
and you can rebase, which marks the conflict. The serial sent is
`max(transferred, live) + 1` in RFC 1982 arithmetic, since RFC 2136 §3.4.2.2
silently ignores an SOA whose serial isn't greater.

The SOA can't be locked with a prerequisite (see above), so a change made in
the milliseconds between reading it and sending is still overwritten. With
inline-signing that window is as long as the server takes to sign a change,
usually under a second: the SOA zedit reads comes from the signed zone, which
follows the unsigned one. Mostly the server then ignores zedit's SOA, because
the unsigned zone's serial has already moved past it, and zedit reports the
update as not verified (exit status 3); resume to try again.

## Verification

After a successful UPDATE, zedit transfers the zone again and checks that every
changed RRset matches your edit. It retries for about 15 seconds, since
inline-signing updates the signed zone asynchronously; a retry queries the SOA
first and transfers again only if the serial has moved. BIND silently drops
some updates, e.g. an add that violates the CNAME rule, an SOA with a
non-greater serial, or TTLs above a `dnssec-policy` `max-zone-ttl`. Mismatches
are listed and zedit exits with status 3, as it does if the zone can't be
transferred again. All of it, transfers included, takes at most
`--verify-timeout` seconds (default 120), so a server that stops answering
right after accepting the update doesn't keep zedit waiting; it says that the
update was accepted before it starts verifying.

## Rebase

On NXRRSET/YXRRSET, or when it is unknown whether the update was applied (a
timeout, a lost connection, an answer that is unsigned or fails its checks),
you can rebase. zedit does a new AXFR and
merges per RRset:

- changed only by you → yours
- changed only on the server → theirs
- changed on both sides → server RRs + your additions − your deletions,
  marked `; MERGED` in the file
- conflicting TTL or SOA field, or two different values of a single-record
  type such as CNAME → yours wins, marked `; CONFLICT`, and the
  editor opens for review

Without conflicts, zedit shows the diff against the new zone and asks again
before sending. Rebasing after a timeout is safe: changes that did get applied
simply drop out.
