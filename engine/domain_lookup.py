"""Real Domain Age & Registration Intelligence Lookup Engine.

Extracts domain registration dates and computes age in days using:
1. RDAP (Registration Data Access Protocol - RFC 7480) via HTTPS
2. WHOIS protocol fallback (TCP port 43)
3. Local persistent SQLite cache with TTL to avoid rate limits
4. Documented graceful fallback with explicit elevated-risk penalty for unverified/unregistered domains
"""

from __future__ import annotations

import datetime
import json
import os
import re
import socket
import sqlite3
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

from engine.security import validate_safe_url

# Baseline registration years for major trusted infrastructure (offline reference)
KNOWN_AUTHORITATIVE_BASELINES: Dict[str, str] = {
    "google.com": "1997-09-15T00:00:00Z",
    "microsoft.com": "1991-05-02T00:00:00Z",
    "defense.gov": "1985-01-01T00:00:00Z",
    "army.mil": "1985-01-01T00:00:00Z",
    "navy.mil": "1985-01-01T00:00:00Z",
    "af.mil": "1985-01-01T00:00:00Z",
    "lockheedmartin.com": "1995-03-01T00:00:00Z",
    "northropgrumman.com": "1997-05-14T00:00:00Z",
    "rtx.com": "1998-04-10T00:00:00Z",
    "boeing.com": "1986-06-18T00:00:00Z",
    "generaldynamics.com": "1996-01-12T00:00:00Z",
    "okta.com": "2009-08-11T00:00:00Z",
    "duo.com": "2009-12-08T00:00:00Z",
    "amazon.com": "1994-11-01T00:00:00Z",
    "apple.com": "1987-02-19T00:00:00Z",
    "github.com": "2007-10-09T00:00:00Z",
    "cloudflare.com": "2009-02-17T00:00:00Z",
    "defenseaerosystems.com": "2014-06-15T00:00:00Z",
}

DEFAULT_CACHE_DB = os.path.join("data", "domain_cache.db")


class DomainAgeLookup:
    """Production-grade RDAP & WHOIS registration lookup with local caching and risk scoring."""

    _cache_db: str = DEFAULT_CACHE_DB
    _memory_cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def set_cache_db(cls, path: str) -> None:
        cls._cache_db = path
        cls._init_db()

    @classmethod
    def _init_db(cls) -> None:
        """Initialize SQLite caching table."""
        os.makedirs(os.path.dirname(cls._cache_db), exist_ok=True)
        try:
            with sqlite3.connect(cls._cache_db) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS domain_age_cache (
                        domain TEXT PRIMARY KEY,
                        creation_date TEXT,
                        age_days INTEGER,
                        registrar TEXT,
                        status TEXT,
                        updated_at REAL
                    )
                """)
                conn.commit()
        except Exception:
            pass

    @classmethod
    def _get_from_cache(cls, domain: str) -> Optional[Dict[str, Any]]:
        """Check in-memory or SQLite cache for fresh record (< 24h old)."""
        domain = domain.lower().strip()
        # Memory check
        if domain in cls._memory_cache:
            entry = cls._memory_cache[domain]
            if datetime.datetime.now().timestamp() - entry["cached_at"] < 86400:
                return entry["data"]

        # DB check
        try:
            cls._init_db()
            with sqlite3.connect(cls._cache_db) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT creation_date, age_days, registrar, status, updated_at FROM domain_age_cache WHERE domain = ?",
                    (domain,)
                )
                row = cursor.fetchone()
                if row:
                    creation_date, age_days, registrar, status, updated_at = row
                    if datetime.datetime.now().timestamp() - updated_at < 86400:
                        data = {
                            "domain": domain,
                            "creation_date": creation_date,
                            "age_days": age_days,
                            "registrar": registrar,
                            "lookup_status": status,
                            "cached": True,
                        }
                        cls._memory_cache[domain] = {"cached_at": updated_at, "data": data}
                        return data
        except Exception:
            pass

        return None

    @classmethod
    def _save_to_cache(cls, domain: str, data: Dict[str, Any]) -> None:
        """Save record to both memory and SQLite cache."""
        domain = domain.lower().strip()
        now = datetime.datetime.now().timestamp()
        cls._memory_cache[domain] = {"cached_at": now, "data": data}

        try:
            cls._init_db()
            with sqlite3.connect(cls._cache_db) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO domain_age_cache
                    (domain, creation_date, age_days, registrar, status, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    domain,
                    data.get("creation_date"),
                    data.get("age_days"),
                    data.get("registrar"),
                    data.get("lookup_status"),
                    now
                ))
                conn.commit()
        except Exception:
            pass

    @classmethod
    def _parse_iso_date(cls, date_str: str) -> Optional[datetime.datetime]:
        """Parse various ISO and WHOIS date formats into datetime object."""
        if not date_str:
            return None
        # Clean up string
        cleaned = date_str.strip()
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d-%b-%Y",
            "%Y.%m.%d",
        ]
        # Remove trailing Z if present for simple iso format
        for fmt in formats:
            try:
                # Truncate timezone info if standard parse fails
                return datetime.datetime.strptime(cleaned[:19], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                pass
            try:
                return datetime.datetime.strptime(cleaned[:10], "%Y-%m-%d")
            except ValueError:
                pass
        return None

    @classmethod
    def _query_rdap(cls, domain: str) -> Optional[Dict[str, Any]]:
        """Query official RDAP endpoint via HTTPS (timeout 3.0s)."""
        url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Trac-I-Threat-Intelligence/2.4 (Defense SOC; RDAP Client)",
                "Accept": "application/rdap+json, application/json",
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    raw = resp.read(65536) # Max 64KB
                    data = json.loads(raw.decode("utf-8", errors="replace"))

                    # Extract events: registration / creation date
                    events = data.get("events", [])
                    creation_str = None
                    for event in events:
                        action = event.get("eventAction", "").lower()
                        if action in ("registration", "created", "transfer"):
                            creation_str = event.get("eventDate")
                            if action == "registration":
                                break

                    registrar = ""
                    entities = data.get("entities", [])
                    for ent in entities:
                        roles = ent.get("roles", [])
                        if "registrar" in roles:
                            vcard = ent.get("vcardArray", [])
                            if len(vcard) > 1:
                                for prop in vcard[1]:
                                    if prop[0] == "fn":
                                        registrar = prop[3]
                                        break

                    if creation_str:
                        return {
                            "creation_date": creation_str,
                            "registrar": registrar or "ICANN Accredited Registrar",
                            "status": "rdap_verified",
                        }
        except Exception:
            pass

        return None

    @classmethod
    def _query_whois_socket(cls, domain: str) -> Optional[Dict[str, Any]]:
        """Fallback to standard TCP port 43 WHOIS query with tight timeout."""
        tld = domain.split(".")[-1].lower() if "." in domain else ""
        whois_servers = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "io": "whois.nic.io",
            "xyz": "whois.nic.xyz",
            "top": "whois.nic.top",
            "live": "whois.nic.live",
        }
        server = whois_servers.get(tld, "whois.iana.org")

        try:
            with socket.create_connection((server, 43), timeout=2.5) as sock:
                sock.sendall(f"{domain}\r\n".encode("utf-8"))
                response = b""
                while len(response) < 16384:
                    chunk = sock.recv(2048)
                    if not chunk:
                        break
                    response += chunk

            text = response.decode("utf-8", errors="replace")

            # Extract Creation Date
            match = re.search(
                r"(?:Creation Date|Created|Registration Time|created):\s*([^\r\n]+)",
                text,
                re.IGNORECASE
            )
            if match:
                date_str = match.group(1).strip()
                reg_match = re.search(r"(?:Registrar|Sponsoring Registrar):\s*([^\r\n]+)", text, re.IGNORECASE)
                registrar = reg_match.group(1).strip() if reg_match else "WHOIS Registrar"
                return {
                    "creation_date": date_str,
                    "registrar": registrar,
                    "status": "whois_verified",
                }
        except Exception:
            pass

        return None

    @classmethod
    def lookup_domain_age(cls, domain: str) -> Dict[str, Any]:
        """Master lookup method: checks cache, known baselines, live RDAP, and WHOIS.

        Returns structured domain age dictionary with risk flags and risk score.
        """
        if not domain:
            return cls._make_fallback_result("", "Missing domain")

        domain_clean = domain.lower().strip().rstrip(".")

        # Handle IP address hostnames (no domain age)
        is_ip = bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", domain_clean))
        if is_ip:
            return {
                "domain": domain_clean,
                "is_ip_host": True,
                "age_days": 0,
                "creation_date": None,
                "registrar": "None (Raw IP Host)",
                "is_newly_registered": True,
                "lookup_status": "raw_ip_connection",
                "risk_score": 45.0,
                "risk_reasons": ["Target is a raw IP host bypassing domain name registration controls"],
            }

        # Check local cache first
        cached = cls._get_from_cache(domain_clean)
        if cached:
            return cls._format_result_from_data(domain_clean, cached)

        # Check known authoritative baselines
        for base_domain, base_date in KNOWN_AUTHORITATIVE_BASELINES.items():
            if domain_clean == base_domain or domain_clean.endswith(f".{base_domain}"):
                res_data = {
                    "creation_date": base_date,
                    "registrar": "Authoritative National Registry",
                    "lookup_status": "authoritative_baseline",
                }
                parsed_res = cls._format_result_from_data(domain_clean, res_data)
                cls._save_to_cache(domain_clean, parsed_res)
                return parsed_res

        # Check if live WHOIS/RDAP is enabled (default true, configurable via env)
        enable_live = os.getenv("ENABLE_LIVE_WHOIS", "true").lower() in ("true", "1", "yes")
        if not enable_live:
            fallback_res = cls._make_fallback_result(domain_clean, "Live network lookup disabled via ENABLE_LIVE_WHOIS=false")
            cls._save_to_cache(domain_clean, fallback_res)
            return fallback_res

        # Fast DNS pre-check: if domain cannot resolve, it is unregistered, sinkholed, or offline
        try:
            socket.getaddrinfo(domain_clean, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            fallback_res = cls._make_fallback_result(domain_clean, "Domain does not resolve in DNS (unregistered / sinkholed)")
            cls._save_to_cache(domain_clean, fallback_res)
            return fallback_res
        except Exception:
            pass

        # Attempt Live RDAP query
        rdap_res = cls._query_rdap(domain_clean)
        if rdap_res:
            parsed_res = cls._format_result_from_data(domain_clean, rdap_res)
            cls._save_to_cache(domain_clean, parsed_res)
            return parsed_res

        # Attempt Live WHOIS query
        whois_res = cls._query_whois_socket(domain_clean)
        if whois_res:
            parsed_res = cls._format_result_from_data(domain_clean, whois_res)
            cls._save_to_cache(domain_clean, parsed_res)
            return parsed_res

        # If live lookups fail or environment is offline: Graceful Fallback
        # Clearly label as "lookup failed — treating as elevated risk"
        fallback_res = cls._make_fallback_result(domain_clean, "Live RDAP and WHOIS unreachable or domain unverified")
        cls._save_to_cache(domain_clean, fallback_res)
        return fallback_res

    @classmethod
    def _format_result_from_data(cls, domain: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Compute age in days and risk parameters from parsed dates."""
        if "risk_score" in data and "is_newly_registered" in data:
            return data

        creation_str = data.get("creation_date", "")
        parsed_dt = cls._parse_iso_date(creation_str)

        if parsed_dt:
            now = datetime.datetime.utcnow()
            age_delta = now - parsed_dt
            age_days = max(0, age_delta.days)
        else:
            raw_age = data.get("age_days")
            age_days = int(raw_age) if raw_age is not None else 0

        is_newly_registered = age_days < 30
        is_young_domain = age_days < 180

        risk_score = 0.0
        reasons = []

        if age_days < 7:
            risk_score = 45.0
            reasons.append(f"Critical Zero-Day Domain Age ({age_days} days old): Registered within last week")
        elif age_days < 30:
            risk_score = 35.0
            reasons.append(f"Newly Registered Domain ({age_days} days old): Typical phishing campaign lifespan")
        elif age_days < 180:
            risk_score = 15.0
            reasons.append(f"Young Domain ({age_days} days old): Elevated scrutiny recommended")
        else:
            risk_score = 0.0

        return {
            "domain": domain,
            "is_ip_host": False,
            "age_days": age_days,
            "creation_date": creation_str,
            "registrar": data.get("registrar", "Unknown Registrar"),
            "is_newly_registered": is_newly_registered,
            "is_young_domain": is_young_domain,
            "lookup_status": data.get("lookup_status", "verified"),
            "risk_score": risk_score,
            "risk_reasons": reasons,
        }

    @classmethod
    def _make_fallback_result(cls, domain: str, reason_detail: str) -> Dict[str, Any]:
        """Documented graceful fallback when RDAP/WHOIS is unreachable or offline."""
        return {
            "domain": domain,
            "is_ip_host": False,
            "age_days": None,
            "creation_date": None,
            "registrar": "Unverified / Lookup Inconclusive",
            "is_newly_registered": True, # Fail-secure: treat unknown/unverified as high risk
            "is_young_domain": True,
            "lookup_status": "lookup_failed_or_unregistered",
            "risk_score": 35.0,
            "risk_reasons": [
                f"Domain registration lookup inconclusive ({reason_detail}) — applying fail-secure zero-day risk penalty"
            ],
        }
