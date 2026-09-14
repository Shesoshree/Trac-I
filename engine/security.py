"""Security utilities for Trac-I: SSRF protection, input validation, and rate limiting.

Prevents Server-Side Request Forgery (SSRF) when fetching or resolving external
URLs, hostnames, and IP addresses during triage and sandboxed analysis.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from typing import Dict, Optional, Set, Tuple
from urllib.parse import urlparse

# Restricted / Non-routable CIDR networks that MUST NOT be fetched server-side
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # Private RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local & Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # Private RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # Private RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved / Future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 ranges
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("fc00::/7"),           # Unique local address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

# Blocked hostnames
BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",
    "instance-data",
    "kubernetes.default",
}


def is_ip_blocked(ip_str: str) -> Tuple[bool, str]:
    """Check whether an IP address belongs to any forbidden/private CIDR block."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    if ip.is_loopback:
        return True, "Loopback IP addresses are forbidden (SSRF protection)"
    if ip.is_link_local or str(ip) == "169.254.169.254":
        return True, "Link-local / cloud metadata IP addresses are forbidden (SSRF protection)"
    if ip.is_private:
        return True, "Private/internal RFC 1918 IP addresses are forbidden (SSRF protection)"
    if ip.is_multicast or ip.is_reserved:
        return True, "Multicast/reserved IP addresses are forbidden"

    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True, f"Target IP belongs to forbidden subnet {net}"

    return False, ""


def validate_safe_url(target_url: str, resolve_dns: bool = True) -> Tuple[bool, str, str]:
    """Validate a URL against SSRF vulnerabilities.

    Returns:
        Tuple of (is_safe: bool, canonical_url_or_error: str, resolved_ip: str)
    """
    if not target_url or not isinstance(target_url, str):
        return False, "Target URL must be a non-empty string", ""

    target_url = target_url.strip()
    if len(target_url) > 2048:
        return False, "Target URL exceeds maximum length limit (2048 characters)", ""

    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted", ""

    hostname = parsed.hostname
    if not hostname:
        return False, "URL does not contain a valid hostname", ""

    hostname_lower = hostname.lower().strip(".")

    if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower.endswith(".local") or hostname_lower.endswith(".internal"):
        return False, f"Access to internal host '{hostname}' is blocked", ""

    # Check if host is direct IP
    resolved_ip = ""
    try:
        ip = ipaddress.ip_address(hostname_lower)
        blocked, reason = is_ip_blocked(str(ip))
        if blocked:
            return False, reason, str(ip)
        resolved_ip = str(ip)
    except ValueError:
        # Hostname is a domain name, resolve via DNS
        if resolve_dns:
            try:
                addr_info = socket.getaddrinfo(hostname_lower, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                resolved_ips = set(item[4][0] for item in addr_info)
                if not resolved_ips:
                    return False, f"Could not resolve host '{hostname_lower}'", ""

                for ip_candidate in resolved_ips:
                    blocked, reason = is_ip_blocked(ip_candidate)
                    if blocked:
                        return False, f"Hostname '{hostname_lower}' resolves to forbidden IP {ip_candidate}: {reason}", ip_candidate
                resolved_ip = next(iter(resolved_ips))
            except socket.gaierror:
                # Host does not resolve in DNS; not targeting an internal SSRF IP.
                # Allow inspection to continue in offline/simulated mode.
                resolved_ip = ""
            except Exception:
                resolved_ip = ""

    port = parsed.port
    if port and port not in (80, 443, 8080, 8443):
        # We permit standard web ports only for safe sandbox inspection
        return False, f"Port {port} is not permitted for remote inspection", resolved_ip

    canonical_url = parsed.geturl()
    return True, canonical_url, resolved_ip


class SlidingWindowRateLimiter:
    """In-memory sliding window rate limiter for public API endpoints."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clients: Dict[str, list[float]] = {}

    def is_allowed(self, client_id: str) -> Tuple[bool, int, int]:
        """Check if request from client_id is allowed.

        Returns:
            (allowed: bool, remaining_requests: int, retry_after_seconds: int)
        """
        now = time.time()
        window_start = now - self.window_seconds

        timestamps = self._clients.get(client_id, [])
        # Filter out timestamps older than the window
        valid_timestamps = [t for t in timestamps if t > window_start]

        if len(valid_timestamps) >= self.max_requests:
            oldest = valid_timestamps[0]
            retry_after = int(max(1.0, (oldest + self.window_seconds) - now))
            self._clients[client_id] = valid_timestamps
            return False, 0, retry_after

        valid_timestamps.append(now)
        self._clients[client_id] = valid_timestamps
        remaining = self.max_requests - len(valid_timestamps)
        return True, remaining, 0

    def cleanup(self) -> None:
        """Evict stale client buckets."""
        now = time.time()
        window_start = now - self.window_seconds
        stale_keys = [k for k, v in self._clients.items() if not v or v[-1] < window_start]
        for k in stale_keys:
            del self._clients[k]
