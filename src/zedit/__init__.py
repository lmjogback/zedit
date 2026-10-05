"""zedit - edit a dynamic DNS zone via AXFR, $EDITOR and nsupdate."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("zedit")
except PackageNotFoundError:  # running from a source tree without installation
    __version__ = "0+unknown"
