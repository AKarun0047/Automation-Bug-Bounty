"""Fail-closed scope enforcement for multi-program bug bounty runs."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from recon.config import ReconConfig

# Strip scheme/path from URLs before host matching.
_URLISH = re.compile(r"^https?://", re.I)


class ScopeViolation(Exception):
    """Raised when a host is not provably in scope."""


def normalize_host(value: str) -> str:
    """Extract lowercase hostname from URL or bare host."""
    v = value.strip().lower()
    if not v:
        return v
    if _URLISH.match(v) or v.startswith("//"):
        parsed = urlparse(v if v.startswith("http") else f"http://{v}")
        return (parsed.hostname or "").lower()
    # host:port
    return v.split(":")[0].strip().lower()


def host_matches_scope_root(host: str, roots: list[str]) -> bool:
    host = normalize_host(host)
    if not host:
        return False
    for root in roots:
        root = root.strip().lower()
        if not root:
            continue
        if host == root or host.endswith(f".{root}"):
            return True
    return False


def is_explicitly_out_of_scope(host: str, config: ReconConfig) -> bool:
    host = normalize_host(host)
    if not host:
        return True

    for pattern in config.out_of_scope_regex:
        if pattern.search(host):
            return True

    for excluded in config.out_of_scope_hosts:
        ex = excluded.strip().lower()
        if not ex:
            continue
        if host == ex or host.endswith(f".{ex}"):
            return True
    return False


def is_in_scope(url_or_host: str, config: ReconConfig) -> bool:
    """Return True only when host is provably allowed to be probed."""
    host = normalize_host(url_or_host)
    if not host:
        return False

    if is_explicitly_out_of_scope(host, config):
        return False

    if config.in_scope_regex:
        return any(p.search(host) for p in config.in_scope_regex)

    # Fail-closed: require match against scope.txt roots when strict or roots defined.
    roots = config.scope_roots or config.targets
    if config.strict_scope or config.scope_roots:
        return host_matches_scope_root(host, roots)

    # Legacy single-target recon.config.yaml without strict_scope.
    return True


def assert_in_scope(host: str, config: ReconConfig) -> None:
    """Fail-closed: if not provably in-scope, REFUSE."""
    normalized = normalize_host(host)
    if is_explicitly_out_of_scope(normalized, config):
        raise ScopeViolation(f"OUT OF SCOPE: {host}")
    if not is_in_scope(host, config):
        raise ScopeViolation(f"NOT PROVEN IN-SCOPE: {host}")


def filter_in_scope(hosts: list[str], config: ReconConfig) -> tuple[list[str], list[str]]:
    """Partition hosts into (in_scope, rejected)."""
    kept: list[str] = []
    rejected: list[str] = []
    for h in hosts:
        if is_in_scope(h, config):
            kept.append(h)
        else:
            rejected.append(h)
    return kept, rejected
