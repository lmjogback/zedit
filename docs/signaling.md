# DNSSEC bootstrapping signals (RFC 9615) with zedit

This guide is for **DNS operators** who run BIND name servers for other people's
zones and want the parent registry to turn on DNSSEC for those zones
automatically. It explains how bootstrapping signals work and how to publish
them with zedit.

## Why signals are needed

A signed zone tells its parent which DS records it wants by publishing CDS and
CDNSKEY records at its apex (RFC 7344, RFC 8078). BIND with `dnssec-policy` does
this by itself. For a zone that already has DS records, the parent can validate
the CDS/CDNSKEY with DNSSEC and update the DS records.

For a zone that is **not yet securely delegated** that doesn't work: nothing
proves that the CDS records at the apex are genuine. Some registries accept them
after watching them for a few days over TCP ("bootstrap from insecure"); RFC 9615
offers a cryptographic alternative. The DNS operator publishes a copy of the
child's CDS/CDNSKEY records under its own name server host names, in zones that
**are** signed and securely delegated. The parent validates that copy, compares
it with the records at the child's apex, and adds the DS records.

## How signals work

For a child zone `example.com` with the name servers `ns1.example.net` and
`ns2.example.net`:

- Each name server host name has a **signaling domain**, `_signal.` followed by
  the host name: `_signal.ns1.example.net` and `_signal.ns2.example.net`.
- The **signal** for the child is at `_dsboot.` + the child's name + the
  signaling domain:

  ```
  _dsboot.example.com._signal.ns1.example.net.  CDS      ...
  _dsboot.example.com._signal.ns1.example.net.  CDNSKEY  ...
  _dsboot.example.com._signal.ns2.example.net.  CDS      ...
  _dsboot.example.com._signal.ns2.example.net.  CDNSKEY  ...
  ```

- The contents must be **identical** to the CDS and CDNSKEY RRsets at the
  child's apex. The parent compares each type separately, so publish both types
  if the apex has both. TTLs don't have to match.
- The signal must be published under **every** name server of the child's
  delegation, except name servers inside the child zone itself (such as
  `ns1.example.com` for `example.com`). At least one name server must be outside
  the child zone; a zone served only by its own name servers can't be
  bootstrapped this way.
- Each signaling zone **must be signed and securely delegated**: the parent
  validates the signal through the normal DNSSEC chain of trust, so
  `example.net` needs DS records at `.net`, and each signaling zone needs DS
  records in `example.net`. RFC 9615 recommends that each signaling domain is a
  zone of its own.
- After the parent has added the DS records, the signal has done its job and
  should be **removed**.
- Very long child or name server names can't be used, since the signal's name
  must fit within DNS name length limits.

Which parents act on signals changes over time. In October 2026 the registries
for `.ch` and `.li` documented support, as does the registrar Glauca. The
[cds-updates list](https://github.com/oskar456/cds-updates) tracks registries,
registrars and DNS providers.

zedit lets you add, change and remove CDS and CDNSKEY records **below** a zone's
apex, which is where signals live. At the apex they remain read-only, since BIND
maintains them there. zedit warns if a CDS or CDNSKEY record you add is not at a
`_dsboot` name, which catches typos. It doesn't check a signal against the child
zone or its delegation; see [Checking a signal](#checking-a-signal) for how to do
that.

## Setting up a signaling zone with BIND

Repeat this for each name server host name. In `named.conf`, on the primary:

```
zone "_signal.ns1.example.net" {
    type primary;
    file "/var/lib/bind/_signal.ns1.example.net.db";
    dnssec-policy default;
    inline-signing yes;
    allow-transfer { key admin; };
    update-policy { grant admin zonesub CDS CDNSKEY; };
};
```

The `update-policy` only allows CDS and CDNSKEY records, which is all a
signaling zone needs. Add `SOA` to the list if you want to edit the SOA timers
with zedit.

A minimal zone file to start from:

```
$TTL 3600
@  IN SOA  ns1.example.net. hostmaster.example.net. 1 7200 900 1209600 300
@  IN NS   ns1.example.net.
@  IN NS   ns2.example.net.
```

Once BIND has signed the zone, delegate it from `example.net` with NS and DS
records. Get the DS record from the signaling zone's DNSKEY:

```sh
dig @ns1.example.net +noall +answer _signal.ns1.example.net DNSKEY |
    dnssec-dsfromkey -2 -f - _signal.ns1.example.net
```

If `example.net` is a dynamic zone, you can add the delegation with zedit
(`zedit example.net`):

```
_signal.ns1  3600 IN NS  ns1.example.net.
_signal.ns1  3600 IN NS  ns2.example.net.
_signal.ns1  3600 IN DS  26092 13 2 60AD3A78C458C2433F082CB277C025D1DCC7AEE2C80D4DC0A2EB769F6EEBB088
```

As for any zone with `dnssec-policy`, tell BIND when the DS is published
(`rndc dnssec -checkds published _signal.ns1.example.net`) or configure
`parental-agents`, so that later key rollovers can proceed.

Check that the signaling zone validates from the outside before you rely on it:

```sh
delv _signal.ns1.example.net SOA
```

`delv` should print `; fully validated`.

## Publishing a signal with zedit

1. Fetch the child's CDS and CDNSKEY records directly from one of its name
   servers, written with the signal's owner name relative to the signaling zone.
   Put dig's options before the queries; options after a query apply to that
   query only.

   ```sh
   dig @ns1.example.net +noall +answer example.com CDS example.com CDNSKEY |
       sed 's/^example\.com\./_dsboot.example.com/'
   ```

   ```
   _dsboot.example.com  3600  IN  CDS      25894 13 2 4742E7F5E98C2158B7B15AD701453DD69D6AE862D1FE50C7F8AE49E3 FBBB0F72
   _dsboot.example.com  3600  IN  CDNSKEY  257 3 13 C1pGjyYqEw1g5qyqCbt3dbN8VDvMV4dwPLN/VNuj9ycmF1c8ozLPsJrL jmjOdBE7VekPQOs9d0WAQbkS0N6R5w==
   ```

   If the child has no CDS records yet, BIND hasn't published them: with
   `dnssec-policy` that happens once the key is ready to be referred to by a DS
   record, which takes a while after signing starts.

2. Open the signaling zone and paste the lines at the end:

   ```sh
   zedit _signal.ns1.example.net
   ```

   zedit shows the two added records and sends them in one UPDATE.

3. Repeat for `_signal.ns2.example.net` and any other name server of the child.

To change a signal, for example after a key rollover in the child before the
parent has acted, replace the lines the same way. To remove it, delete them.

### Many zones

For more than a handful of zones, generate the updates with a script instead and
use zedit to look at the result. This replaces the signal for one child in every
signaling zone with the child's current records:

```sh
child=example.com
for ns in ns1.example.net ns2.example.net; do
    sig="_dsboot.$child._signal.$ns."
    {
        echo "server ns1.example.net"     # the primary for the signaling zones
        echo "zone _signal.$ns"
        echo "update delete $sig CDS"
        echo "update delete $sig CDNSKEY"
        dig @"$ns" +noall +answer "$child" CDS "$child" CDNSKEY |
            sed "s/^[^[:space:]]*/update add $sig/"
        echo send
    } | nsupdate -k /etc/bind/admin.key
done
```

If the child has no CDS records, this removes the signal, which is what you
want: a signal must match the child's apex.

## Checking a signal

A parent checks roughly this:

1. The child has no DS records yet:

   ```sh
   dig +short example.com DS
   ```

2. Each of the child's name servers returns the same CDS and CDNSKEY records,
   asked directly:

   ```sh
   for ns in $(dig +short example.com NS); do
       dig @"$ns" +norec +noall +answer example.com CDS example.com CDNSKEY
   done
   ```

3. The signal under each name server validates and has the same contents:

   ```sh
   for ns in $(dig +short example.com NS); do
       delv "_dsboot.example.com._signal.${ns%.}" CDS
       delv "_dsboot.example.com._signal.${ns%.}" CDNSKEY
   done
   ```

   Each answer should be `; fully validated` and contain the same records as in
   step 2.

## When the child's name servers change

The parent looks for the signal under the name servers in the delegation at the
time it checks. If you add a name server to the child before the parent has
bootstrapped it, publish the signal in that name server's signaling zone too;
until you do, the check fails and the parent tries again later. A signal under a
name server you have removed from the delegation is simply ignored, and can be
removed.

## After bootstrapping

Once the parent has added the DS records (`dig +short example.com DS` shows
them), remove the signal from every signaling zone. From then on the parent can
validate the CDS records at the child's apex directly, and BIND's `dnssec-policy`
handles key rollovers with them as usual.
