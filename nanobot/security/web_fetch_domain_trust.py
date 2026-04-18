"""Hostname trust tiers for web_fetch (static lists).

TODO(supabase): Merge runtime blocked hostnames from a FireClaw-style community_blocklist
fetched via Supabase REST (see fireclaw-example/dashboard/server.mjs community_blocklist query),
with a TTL cache, into the blocked set used below. Not implemented yet.

Domain lists are vendored from fireclaw-example (AGPL); see nanobot/data/ATTRIBUTION.txt.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Literal
from urllib.parse import urlparse

TrustTier = Literal["trusted", "neutral", "suspicious", "blocked"]


@lru_cache(maxsize=1)
def _load_tier_domains() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    raw = resources.files("nanobot.data").joinpath("web_fetch_domain_tiers.json").read_bytes()
    data = json.loads(raw.decode("utf-8"))
    trusted = frozenset(x.lower() for x in data.get("trusted", []) if isinstance(x, str))
    suspicious = frozenset(x.lower() for x in data.get("suspicious", []) if isinstance(x, str))
    blocked = frozenset(x.lower() for x in data.get("blocked", []) if isinstance(x, str))
    return trusted, suspicious, blocked


def hostname_for_url(url: str) -> str | None:
    try:
        host = urlparse(url).hostname
        return host.lower() if host else None
    except Exception:
        return None


def trust_tier_for_hostname(hostname: str | None) -> TrustTier:
    """Resolve tier: blocked and suspicious before trusted (matches Fireclaw getTier order)."""
    if not hostname:
        return "neutral"
    trusted, suspicious, blocked = _load_tier_domains()
    for domain in blocked:
        if hostname == domain or hostname.endswith("." + domain):
            return "blocked"
    for domain in suspicious:
        if hostname == domain or hostname.endswith("." + domain):
            return "suspicious"
    for domain in trusted:
        if hostname == domain or hostname.endswith("." + domain):
            return "trusted"
    return "neutral"


def trust_tier_for_url(url: str) -> TrustTier:
    return trust_tier_for_hostname(hostname_for_url(url))
