from __future__ import annotations

import ipaddress


def is_loopback_host(hostname: str | None) -> bool:
    """Report whether a URL or Host-header hostname stays on this machine.

    A loopback IP literal, or `localhost`: the one name that cannot be
    repointed by DNS. Everything else is treated as remote.
    """
    if not hostname:
        return False
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False
