"""What zedit needs from whatever holds the zone: the Backend protocol and the
results it returns. rfc2136.Rfc2136Backend is the one implementation.

The session (session.py) uses only this interface: it fetches the zone, lets
the user edit it, and hands the backend a ChangeSet to show (preview) or to
apply. How the changes travel, here as an RFC 2136 UPDATE, is the backend's
business, and so is how it guards against changes made on the server since
the transfer; it reports such a conflict as Outcome.REBASE, and the session
then merges the edit into the zone as it is now and asks again.
"""

import enum
from dataclasses import dataclass
from typing import Protocol

import dns.name
import dns.rdataset

from zedit.changes import ChangeSet
from zedit.model import Zone


class Outcome(enum.Enum):
    """How applying a ChangeSet went, as far as the session needs to know."""

    OK = "ok"  # applied
    REBASE = "rebase"  # not applied, or unknown whether: rebase onto the zone as it is now
    FAILED = "failed"  # not applied, and rebasing won't help


@dataclass(frozen=True)
class SendResult:
    """outcome, a message for the user (may be empty when OK), and with OK the
    SOA RRset that was sent, or None if the edit didn't change the SOA."""

    outcome: Outcome
    message: str = ""
    soa: dns.rdataset.Rdataset | None = None


@dataclass(frozen=True)
class Preview:
    """What would be sent, as text, and the SOA fields that conflict with the
    zone as it is now (sending would then offer a rebase)."""

    text: str
    soa_conflicts: list[str]


class Backend(Protocol):
    """A server or service that holds zones. Names are absolute (origin); the
    records in a Zone and a ChangeSet are relative to it."""

    @property
    def label(self) -> str:
        """Names the server in messages and in the session file."""
        ...

    def fetch(self, origin: dns.name.Name, timeout: float | None = None) -> Zone:
        """The whole zone as it is now; raises ZeditError if it can't be read,
        within timeout seconds if given."""
        ...

    def current_soa(
        self, origin: dns.name.Name, timeout: float | None = None
    ) -> dns.rdataset.Rdataset | None:
        """The zone's SOA as it is now, cheaply, or None if it can't be read
        (within timeout seconds if given)."""
        ...

    def preview(self, origin: dns.name.Name, edit: ChangeSet) -> Preview:
        """What apply() would send now, for the user to read: --dry-run and
        [s]cript."""
        ...

    def apply(self, origin: dns.name.Name, edit: ChangeSet) -> SendResult:
        """Make the changes in edit, at once and only if the RRsets they touch
        are still as in the transfer the edit started from."""
        ...
