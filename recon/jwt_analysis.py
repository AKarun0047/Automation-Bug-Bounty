"""JWT extraction, decoding, and tamper analysis."""

from __future__ import annotations

import base64
import json
import logging
import re
from typing import Any

LOG = logging.getLogger("recon.jwt")

JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
)
BEARER_PATTERN = re.compile(
    r"Bearer\s+(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)",
    re.IGNORECASE,
)


def _b64_decode(segment: str) -> dict[str, Any]:
    padding = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(segment + padding)
        return json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, json.JSONDecodeError):
        return {}


def extract_jwts(text: str) -> list[str]:
    found = list(JWT_PATTERN.findall(text))
    found.extend(BEARER_PATTERN.findall(text))
    return list(dict.fromkeys(found))


def _flag_issues(header: dict[str, Any], payload: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    alg = str(header.get("alg", "")).lower()

    if alg in ("none", ""):
        issues.append("CRITICAL: alg:none — try unsigned token")
    if alg == "hs256" and header.get("kid"):
        issues.append("HS256 + kid — RS256→HS256 confusion candidate if public key in kid")
    if alg == "hs256":
        issues.append("HS256 — test weak/brute-forced secrets")

    if payload.get("exp") is None:
        issues.append("exp missing — token may not expire")

    for claim in ("sub", "user_id", "uid", "account_id"):
        if claim in payload:
            issues.append(f"IDOR surface: {claim}={payload.get(claim)}")

    for claim in ("admin", "role", "is_admin", "permissions"):
        if claim in payload:
            issues.append(f"sensitive claim: {claim}={payload.get(claim)}")

    if header.get("kid"):
        issues.append(f"kid header: {header.get('kid')}")

    return issues


def build_jwt_record(token: str, url: str = "", source: str = "") -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        return {"url": url, "source": source, "valid": False, "raw": token[:60]}

    header = _b64_decode(parts[0])
    payload = _b64_decode(parts[1])
    issues = _flag_issues(header, payload)

    return {
        "url": url or source,
        "source": source or url,
        "alg": header.get("alg"),
        "kid": header.get("kid"),
        "typ": header.get("typ"),
        "claims": payload,
        "header": header,
        "raw": f"{token[:24]}...{token[-12:]}",
        "token": token,
        "issues": issues,
        "tamper_candidates": [
            "Set alg:none and strip signature",
            "Change role/admin/sub claims (re-sign if secret known)",
            "kid path traversal: ../../../../dev/null",
        ],
    }


def analyze_jwt(token: str, source: str = "") -> dict[str, Any]:
    return build_jwt_record(token, source=source)


def analyze_text(text: str, source: str, url: str = "") -> list[dict[str, Any]]:
    return [build_jwt_record(token, url=url or source, source=source) for token in extract_jwts(text)]
