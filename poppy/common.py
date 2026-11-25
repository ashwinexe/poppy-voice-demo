"""Shared settings for both sides of the demo."""

from __future__ import annotations

import ipaddress
import os
import pathlib
import ssl
import urllib.parse

import certifi
import httpx

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / ".poppy"
CERT_DIR = STATE_DIR / "certs"
CA_FILE = CERT_DIR / "ca.pem"

PROTOCOL_VERSION = "1.0"
OPERATIONS_VERSION = "3"

# Both sides run on this machine. Poppy forbids connecting to loopback addresses
# a counterpart hands you unless you're configured to on purpose (spec 3), and
# this flag is that purpose. Leave it off anywhere but a local demo.
ALLOW_LOOPBACK = os.environ.get("POPPY_ALLOW_LOOPBACK") == "1"

SKYLINE_URL = os.environ.get("SKYLINE_URL", "https://skyline.localhost:8443").rstrip("/")
CONCIERGE_URL = os.environ.get("CONCIERGE_URL", "https://wren.localhost:8444").rstrip("/")


def ssl_context() -> ssl.SSLContext:
    """Public roots plus the demo's local CA, when it exists."""
    ctx = ssl.create_default_context(cafile=certifi.where())
    if CA_FILE.exists():
        ctx.load_verify_locations(cafile=str(CA_FILE))
    return ctx


def http_client(**kwargs) -> httpx.AsyncClient:
    # Never follow redirects automatically: Poppy has rules about where secrets may
    # go after a redirect (spec 3), and client metadata must not redirect at all.
    return httpx.AsyncClient(
        verify=ssl_context(), follow_redirects=False, timeout=15.0, **kwargs
    )


def check_url(url: str) -> str:
    """Enforce HTTPS and the loopback rule for URLs the other party gave us."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise ValueError(f"not an HTTPS URL: {url}")
    host = parts.hostname or ""
    loopback = host == "localhost" or host.endswith(".localhost")
    try:
        ip = ipaddress.ip_address(host)
        loopback = loopback or ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        pass
    if loopback and not ALLOW_LOOPBACK:
        raise ValueError(f"refusing loopback/private address {host} (set POPPY_ALLOW_LOOPBACK=1 for the local demo)")
    return url


def host_of(url: str) -> str:
    """Host with port when it isn't 443, as `organization.domain` is written."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    return f"{host}:{parts.port}" if parts.port and parts.port != 443 else host


def same_domain(a: str, b: str) -> bool:
    return host_of(a) == host_of(b)
