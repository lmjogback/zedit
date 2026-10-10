#!/usr/bin/env python3
"""Command line: options, server and key lookup, and main()."""

import argparse
import os
import sys
from types import SimpleNamespace

import dns.exception
import dns.name

from zedit import __version__, rfc2136, session
from zedit.model import IDNA, ZeditError, die


def config_dir():
    return os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "zedit")


def find_keyfile(origin):
    """Default TSIG key: $ZEDIT_KEYFILE, else ~/.config/zedit/keys/ZONE.key,
    else ~/.config/zedit/default.key, else None (no TSIG). ZONE as in session.file_stem()."""
    env = os.environ.get("ZEDIT_KEYFILE")
    if env:
        return env
    zone = session.file_stem(origin)
    for p in (os.path.join(config_dir(), "keys", f"{zone}.key"), os.path.join(config_dir(), "default.key")):
        if os.path.isfile(p):
            return p
    return None


def check_keyfile(path):
    if not os.path.isfile(path):
        die(f"key file {path} not found")
    if os.stat(path).st_mode & 0o077:
        print(f"zedit: warning: {path} is readable by group/others (chmod 600)", file=sys.stderr)


def make_parser():
    ap = argparse.ArgumentParser(
        prog="zedit", description="Edit a dynamic DNS zone via AXFR + $EDITOR + DNS UPDATE"
    )
    ap.add_argument("zone")
    ap.add_argument("-s", "--server", help="primary server (default: the zone's SOA MNAME)")
    ap.add_argument("-p", "--port", type=int, default=53)
    ap.add_argument(
        "-k",
        "--keyfile",
        help="TSIG key (tsig-keygen format), used for AXFR and UPDATE (default: $ZEDIT_KEYFILE, "
        "else ~/.config/zedit/keys/ZONE.key, else ~/.config/zedit/default.key)",
    )
    ap.add_argument(
        "-a",
        "--show-all",
        action="store_true",
        help="also show DNSSEC and server-maintained records, as read-only ';ro' comment lines",
    )
    ap.add_argument(
        "--no-rrsig",
        action="store_true",
        help="with --show-all, leave out RRSIG, NSEC and NSEC3 (implies -a)",
    )
    ap.add_argument(
        "-A",
        "--addresses",
        action="store_true",
        help="in reverse zones, show owner names as IP addresses (input in address form always works)",
    )
    ap.add_argument(
        "-n", "--dry-run", action="store_true", help="show the update as an nsupdate script, send nothing"
    )
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("-r", "--resume", metavar="FILE", help="resume a saved edit (requires FILE.base)")
    return ap


def main():
    args = make_parser().parse_args()

    try:
        origin = dns.name.from_text(args.zone, idna_codec=IDNA)
    except dns.exception.DNSException as e:
        die(f"invalid zone name {args.zone!r}: {e}")
    host = args.server or rfc2136.primary_from_mname(origin)
    address = rfc2136.resolve(host, args.port)
    keyfile = args.keyfile or find_keyfile(origin)
    if keyfile:
        check_keyfile(keyfile)
    ctx = SimpleNamespace(
        origin=origin,
        port=args.port,
        server=address,
        label=address if host.rstrip(".") == address else f"{host.rstrip('.')} ({address})",
        keyfile=keyfile,
        keyring=None,
        keyname=None,
        show_all=args.show_all or args.no_rrsig,
        no_rrsig=args.no_rrsig,
        addresses=args.addresses,
        path=None,
        basepath=None,
    )
    if keyfile:
        ctx.keyring, ctx.keyname = rfc2136.load_bind_key(keyfile)
    if not args.server or not args.keyfile:
        print(f"Server: {ctx.label}  Key: {keyfile or 'none'}", file=sys.stderr)

    try:
        rc = session.session(ctx, args)
    except KeyboardInterrupt:
        print()
        rc = 130
    except (ZeditError, OSError) as e:  # OSError: e.g. state directory not writable, disk full
        print(f"zedit: {e}", file=sys.stderr)
        rc = 1
    if rc:
        session.hint(ctx, args)
    sys.exit(rc)


if __name__ == "__main__":
    main()
