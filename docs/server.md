# Server setup

What a DNS server needs for zedit to edit its zones, and what zedit leaves to
the server.

zedit uses only standard protocols: AXFR (RFC 5936) and UPDATE (RFC 2136), both
with TSIG. It should work with any server that supports them, but it is tested
with BIND only (9.18 and 9.20), and the examples here are for BIND. Reports on
other servers are welcome.

## Key and permissions

The key needs transfer rights and an update policy covering every type you
intend to edit, including SOA. With BIND:

```
zone "example.com" {
    allow-transfer { key admin; };
    update-policy { grant admin zonesub ANY; };
};
```

Use a dedicated admin key, not the one your DHCP server uses for DDNS.

zedit sends the UPDATE to the server it transferred the zone from: the zone's
SOA MNAME, or the server given with `-s`. That must be the primary.

## Serial numbers

An edit that doesn't change the SOA doesn't send it: the server bumps the serial
by its own rules, with BIND those of `serial-update-method`. When you do change
the SOA, zedit sends a serial one greater than the server's; see
[how-it-works.md](how-it-works.md#soa-changes).

## DNSSEC-signed zones

zedit works with unsigned zones and with zones signed in place or with
inline-signing. Sign a dynamic zone in place, with `dnssec-policy` and
`inline-signing no`: with inline-signing, `serial-update-method` doesn't apply
to the serials updates produce, and a change appears in the signed zone, which
zedit transfers, only once the server has signed it.

RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY, ZONEMD and BIND's private TYPE65534
are removed from both sides of the diff and never touched, and so are CDS and
CDNSKEY at the zone's apex, where BIND maintains them. (Deleting NSEC3PARAM or
TYPE65534 through UPDATE would change signing.) `zedit -a` shows them as
read-only comments; see [editing.md](editing.md#seeing-everything).

## Bootstrapping signals

Below the apex, CDS and CDNSKEY are ordinary records, so a DNS operator can
publish RFC 9615 signals (`_dsboot.CHILD._signal.NS-HOST`) that let a registry
turn on DNSSEC for a child zone. zedit warns if such a record is not at a
`_dsboot` name. See [signaling.md](signaling.md) for how signals work and how
to set them up with BIND.
