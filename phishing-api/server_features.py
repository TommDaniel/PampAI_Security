"""
Server-side feature extraction: WHOIS, DNS, HTTP redirects.

All lookups are parallelized with asyncio.gather and individually
fault-tolerant — a failure in any single lookup returns defaults
without blocking the response.
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Timeouts
WHOIS_TIMEOUT = 3  # seconds
DNS_TIMEOUT = 2  # seconds
REDIRECT_TIMEOUT = 5  # seconds

# WHOIS cache path (local JSON file shipped with the model)
WHOIS_CACHE_PATH = os.environ.get(
    "WHOIS_CACHE_PATH",
    str(Path(__file__).parent / "model" / "whois_cache.json"),
)

# In-memory WHOIS cache loaded once at startup
_whois_cache: Optional[dict] = None


def _load_whois_cache() -> dict:
    """Load WHOIS cache from JSON file (once)."""
    global _whois_cache
    if _whois_cache is not None:
        return _whois_cache
    try:
        with open(WHOIS_CACHE_PATH, "r") as f:
            _whois_cache = json.load(f)
        logger.info(f"WHOIS cache loaded: {len(_whois_cache)} entries")
    except Exception as e:
        logger.warning(f"Failed to load WHOIS cache: {e}")
        _whois_cache = {}
    return _whois_cache


def _extract_domain(url: str) -> str:
    """Extract the registrable domain from a URL."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        hostname = parsed.hostname or ""
        # Remove www. prefix
        if hostname.startswith("www."):
            hostname = hostname[4:]
        return hostname.lower()
    except Exception:
        return ""


@dataclass
class ServerFeatures:
    """Server-side extracted features with defaults of -1 (unknown)."""
    redirects: int = -1
    dom_age: int = -1
    dom_expire: int = -1
    mx_servers: int = -1
    nameservers: int = -1
    dom_spf: int = -1
    dom_in_ip: int = -1
    srv_client: int = -1
    domain_google_index: int = -1  # always -1 (feature removed)

    # WHOIS text tokens for create_feature_text
    whois_text: str = "[WHOIS] unknown"


async def _lookup_whois_cached(domain: str) -> dict:
    """Look up domain in local WHOIS cache."""
    cache = _load_whois_cache()
    return cache.get(domain, {})


async def _lookup_whois_live(domain: str) -> dict:
    """Live WHOIS lookup with timeout. Falls back to empty dict on failure."""
    try:
        import whois

        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, whois.whois, domain),
            timeout=WHOIS_TIMEOUT,
        )
        if result and result.domain_name:
            from datetime import datetime, timezone

            data = {"status": "found"}
            now = datetime.now(timezone.utc)

            # Domain age
            creation = result.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                age_days = (now - creation).days
                data["domain_age_days"] = age_days

            # Expiration
            expiration = result.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]
            if expiration:
                if expiration.tzinfo is None:
                    expiration = expiration.replace(tzinfo=timezone.utc)
                expire_days = (expiration - now).days
                data["days_to_expire"] = expire_days

            # Registrar
            if result.registrar:
                data["registrar"] = str(result.registrar)[:25]

            return data
        return {}
    except Exception as e:
        logger.debug(f"Live WHOIS failed for {domain}: {e}")
        return {}


async def _lookup_whois(domain: str) -> dict:
    """WHOIS lookup: cache first, then live fallback."""
    # Try cache first
    cached = await _lookup_whois_cached(domain)
    if cached and cached.get("status") == "found":
        return cached

    # Live fallback
    live = await _lookup_whois_live(domain)
    if live:
        return live

    return cached  # may be {"status": "not_found"} or {}


async def _lookup_dns(domain: str) -> dict:
    """DNS lookups: MX, NS, SPF (TXT), A records. Returns counts."""
    result = {
        "mx_servers": -1,
        "nameservers": -1,
        "dom_spf": -1,
        "dom_in_ip": -1,
        "srv_client": -1,
    }
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT

        async def query_mx():
            try:
                loop = asyncio.get_event_loop()
                answers = await asyncio.wait_for(
                    loop.run_in_executor(None, resolver.resolve, domain, "MX"),
                    timeout=DNS_TIMEOUT,
                )
                return len(list(answers))
            except Exception:
                return -1

        async def query_ns():
            try:
                loop = asyncio.get_event_loop()
                answers = await asyncio.wait_for(
                    loop.run_in_executor(None, resolver.resolve, domain, "NS"),
                    timeout=DNS_TIMEOUT,
                )
                return len(list(answers))
            except Exception:
                return -1

        async def query_spf():
            try:
                loop = asyncio.get_event_loop()
                answers = await asyncio.wait_for(
                    loop.run_in_executor(None, resolver.resolve, domain, "TXT"),
                    timeout=DNS_TIMEOUT,
                )
                for rdata in answers:
                    txt = rdata.to_text().lower()
                    if "v=spf1" in txt:
                        return 1
                return 0
            except Exception:
                return -1

        async def query_a():
            """Check if domain resolves to an IP (dom_in_ip) and srv_client."""
            try:
                loop = asyncio.get_event_loop()
                answers = await asyncio.wait_for(
                    loop.run_in_executor(None, resolver.resolve, domain, "A"),
                    timeout=DNS_TIMEOUT,
                )
                ips = [r.to_text() for r in answers]
                # dom_in_ip: 1 if the domain itself looks like an IP
                import re
                dom_in_ip = 1 if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain) else 0
                # srv_client: 1 if A record exists (server responds)
                srv_client = 1 if ips else 0
                return dom_in_ip, srv_client
            except Exception:
                return -1, -1

        mx, ns, spf, a_result = await asyncio.gather(
            query_mx(), query_ns(), query_spf(), query_a()
        )

        result["mx_servers"] = mx
        result["nameservers"] = ns
        result["dom_spf"] = spf
        result["dom_in_ip"] = a_result[0]
        result["srv_client"] = a_result[1]

    except ImportError:
        logger.warning("dnspython not installed, skipping DNS lookups")
    except Exception as e:
        logger.debug(f"DNS lookup failed for {domain}: {e}")

    return result


async def _count_redirects(url: str) -> int:
    """Count HTTP redirect chain length."""
    try:
        import httpx

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=REDIRECT_TIMEOUT,
            verify=False,
        ) as client:
            count = 0
            current_url = url
            max_redirects = 10
            while count < max_redirects:
                try:
                    resp = await client.head(current_url)
                    if resp.is_redirect and resp.headers.get("location"):
                        count += 1
                        current_url = resp.headers["location"]
                        # Handle relative redirects
                        if not current_url.startswith("http"):
                            from urllib.parse import urljoin
                            current_url = urljoin(url, current_url)
                    else:
                        break
                except Exception:
                    break
            return count
    except ImportError:
        logger.warning("httpx not installed, skipping redirect counting")
        return -1
    except Exception as e:
        logger.debug(f"Redirect counting failed for {url}: {e}")
        return -1


def _build_whois_text(whois_data: dict) -> str:
    """Build WHOIS tokens matching training format."""
    if not whois_data or whois_data.get("status") != "found":
        return "[WHOIS] unknown"

    age = whois_data.get("domain_age_days")
    age_str = f"{age}d" if age is not None else "?d"

    registrar = whois_data.get("registrar", "unk")
    if not registrar:
        registrar = "unk"
    registrar = str(registrar)[:25]

    expire = whois_data.get("days_to_expire")
    expire_str = f"{expire}d" if expire is not None else "?d"

    return f"[AGE] {age_str} [REG] {registrar} [EXPIRE] {expire_str} [WHOIS] found"


async def extract_server_features(url: str) -> ServerFeatures:
    """
    Extract all server-side features for a URL.
    Uses asyncio.gather to parallelize WHOIS, DNS, and redirect lookups.
    Individual failures return defaults (-1) without blocking.
    """
    domain = _extract_domain(url)
    features = ServerFeatures()

    if not domain:
        return features

    # Parallelize all lookups
    whois_result, dns_result, redirect_count = await asyncio.gather(
        _lookup_whois(domain),
        _lookup_dns(domain),
        _count_redirects(url),
    )

    # WHOIS features
    features.whois_text = _build_whois_text(whois_result)
    if whois_result.get("status") == "found":
        age = whois_result.get("domain_age_days")
        if age is not None:
            features.dom_age = age
        expire = whois_result.get("days_to_expire")
        if expire is not None:
            features.dom_expire = expire

    # DNS features
    features.mx_servers = dns_result.get("mx_servers", -1)
    features.nameservers = dns_result.get("nameservers", -1)
    features.dom_spf = dns_result.get("dom_spf", -1)
    features.dom_in_ip = dns_result.get("dom_in_ip", -1)
    features.srv_client = dns_result.get("srv_client", -1)

    # Redirects
    features.redirects = redirect_count

    # domain_google_index is always -1 (feature removed)
    features.domain_google_index = -1

    return features
