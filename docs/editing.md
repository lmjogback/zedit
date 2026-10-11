# Editing a zone

What zedit shows you in the editor and what you can write there. For what it
then sends to the server, see [how-it-works.md](how-it-works.md).

The file is an ordinary zone file, with one record per line and names relative
to the zone. Records the server maintains for DNSSEC are left out (see
[server.md](server.md#dnssec-signed-zones)); `-a` shows them as read-only
comments.

## SOA

RNAME, REFRESH, RETRY, EXPIRE and MINIMUM are editable. MNAME, SERIAL and the
SOA record's own TTL are locked. Below the SOA record, comment lines explain
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

How a changed SOA is merged with changes made on the server meanwhile is in
[how-it-works.md](how-it-works.md#soa-changes).

## Seeing everything

With `-a` the filtered records are shown in place, as comment lines marked
`;ro`, each RRSIG right after the type it covers:

```
@        300 IN NS     ns1
;ro @    300 IN RRSIG  NS 13 2 300 20261019040406 20261005123408 34319 @ y0Ov…
;ro @   3600 IN DNSKEY 257 3 13 et91FeNyNspnfPc6wD0cXkDc1N92g8Eg…
www      300 IN A      192.0.2.10
;ro www  300 IN RRSIG  A 13 3 300 20261019040406 20261005123408 34319 @ eiIq…
```

Being comments, they never reach the diff, the update or the merge, so editing
or deleting them has no effect. `--no-rrsig` keeps the interesting ones
(DNSKEY, CDS, CDNSKEY, NSEC3PARAM, TYPE65534) and drops the bulky ones.

## RRsets

All records of an RRset must have the same TTL, and a single-record type such
as CNAME or SOA may appear only once per name. Either is reported as an error
on the offending line, where the zone file parser would silently give the
RRset its lowest TTL or keep only the last record.

## `$ORIGIN`

You can use `$ORIGIN` lines in the file, e.g. to add a block of PTR records.
Every owner name must stay inside the zone; names that fall outside it are
reported as an error rather than silently ignored.

## `$GENERATE`

You can add ranges of records with `$GENERATE`, with BIND's syntax and
semantics: `start-stop[/step]`, several `$` and `${offset[,width[,base]]}`
modifiers per line (bases `d`, `o`, `x`, `X`, and `n`/`N` for `ip6.arpa`
nibbles) and `\$` for a literal `$`. A comment at the end of the line is left
alone:

```
$GENERATE 20-29 $ PTR host$.example.com.
$GENERATE 30-38/2 $ PTR dyn-${0,3,d}.example.com.
```

The expansion is done by zedit, not dnspython, whose own `$GENERATE` handles
only one modifier per side. A dynamic zone stores the generated records, not
the `$GENERATE` line, so the next edit shows the individual records.

## Reverse zones in address form

In a zone under `in-addr.arpa` or `ip6.arpa` you can write owners as IP
addresses, in normal order; zedit converts them to the reverse names:

```
192.0.2.10    PTR www.example.com.     ; -> 10.2.0.192.in-addr.arpa.
2001:db8::1   PTR www.example.com.     ; -> 1.0.0.0.…8.b.d.0.1.0.0.2.ip6.arpa.
$GENERATE 20-29 192.0.2.$ PTR host$.example.com.
```

An owner counts as an address when it is a dotted quad or contains `:`, with no
trailing dot. As a relative name a dotted quad would have more than four octets
under `in-addr.arpa`, which no IPv4 address has, so this is unambiguous in
practice; an absolute name (trailing dot) is always used as written, and other
zones are never rewritten. An address must belong to the zone, which also
catches an address typed backwards. Something that looks like an address but
isn't valid (`192.0.2.010`) is an error. In an RFC 2317 zone such as
`16/28.2.0.192.in-addr.arpa`, `192.0.2.17` becomes
`17.16/28.2.0.192.in-addr.arpa.`; in a zone for a single address it is the
apex.

With `-A` the file also *shows* owners as addresses (IPv6 compressed), ordered
by address; the apex stays `@`. The update always uses the real reverse names.
In the zone `in-addr.arpa.` itself, where `10.2.0.192` is a valid relative
name, owners are neither read nor shown as addresses.

## Internationalized names

Names may be written with non-ASCII letters, as owners or in record data
(`räksmörgås CNAME straße.de.`). zedit encodes them with IDNA 2008, as
registries do, and shows them as A-labels (`xn--rksmrgs-5wao1o`). Before that,
names are mapped as in Unicode UTS #46 (non-transitional), as browsers do:
upper case and full-width forms are folded, so `RÄKA`, `ＲÄＫＡ` and `räka` are
all `xn--rka-qla`, while `ß` stays `ß`. The zone file parser's default, IDNA
2003, would turn `straße.de` into `strasse.de`, a different domain.

Text in TXT records is not a name and is never converted: zedit shows its
non-ASCII bytes as `\DDD` escapes, as BIND does. SPF, DKIM and DMARC records
must be ASCII, with any domain in them written as an A-label, so zedit warns
when you add one with non-ASCII bytes. That is usually a typographic quote,
dash or no-break space pasted along with the record.

## Sessions and `--resume`

Each session is stored in `$XDG_STATE_HOME/zedit/` (default
`~/.local/state/zedit/`) as `ZONE-TIMESTAMP.zone` plus
`ZONE-TIMESTAMP.zone.base` (the zone as transferred); a session started in the
same second as another one for the zone gets `ZONE-TIMESTAMP-2.zone`, and so
on. Both are removed after a successful, verified update, and when you abort
the editor without having changed anything. On any other abort or failure,
including answering no to `Send?`, zedit prints a `--resume` command. So does
`--dry-run`: resume without `--dry-run` to send the same edit, rebased onto the
zone as it is then.

The files are UTF-8 and readable only by you, and the directory is created
accessible only to you; zedit warns, but changes nothing, if its permissions
have since been opened to others. The two files are replaced together: zedit
writes the new pair as `FILE.new` and `FILE.base.new` first, so if writing is
interrupted (disk full, a crash), `--resume` finds either the old pair or the
new one and finishes the switch.
