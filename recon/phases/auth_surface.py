"""Phase 7 — Auth + API Surface."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import requests

from recon.config import is_intrusive
from recon.context import ReconContext
from recon.utils import (
    classify_id_type,
    curl_status,
    extract_params,
    is_interesting_url,
    md5_short,
    phase_banner,
    read_jsonl,
    read_lines,
    run_cmd,
    tool_path,
    write_lines,
)

LOG = logging.getLogger("recon.phase7")

API_PATTERN = re.compile(r"/api/|/graphql|/v[0-9]+/|/rest/|/rpc", re.IGNORECASE)
AUTH_PATTERN = re.compile(
    r"login|signin|oauth|token|auth|sso|saml|callback|authorize|logout|register|signup|reset|forgot",
    re.IGNORECASE,
)
SWAGGER_PATHS = (
    "/swagger.json",
    "/swagger-ui.html",
    "/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/api/swagger",
    "/v2/api-docs",
)
CORS_ORIGINS = (
    "https://evil.com",
    "null",
    None,  # subdomain takeover style
)
RESET_PATTERN = re.compile(r"reset|forgot|password", re.IGNORECASE)
POISON_HEADERS = (
    "Host: attacker.com",
    "X-Forwarded-Host: attacker.com",
    "X-Forwarded-Server: attacker.com",
    "X-Host: attacker.com",
    "X-Original-Host: attacker.com",
)
ATTACKER_HOST = "attacker.com"


def _extract_api_endpoints(ctx: ReconContext) -> Path:
    out = ctx.phase7 / "api_endpoints.txt"
    endpoints: set[str] = set()

    for record in read_jsonl(ctx.phase3 / "katana_crawl.jsonl"):
        url = record.get("request", {}).get("endpoint") or record.get("url") or ""
        if API_PATTERN.search(url):
            endpoints.add(url)

    for record in read_jsonl(ctx.phase3 / "urls_with_status.jsonl"):
        url = record.get("url", "")
        if API_PATTERN.search(url):
            endpoints.add(url)

    for record in read_jsonl(ctx.phase4 / "js_endpoints.jsonl"):
        url = record.get("url") or record.get("endpoint") or ""
        if url.startswith("http"):
            endpoints.add(url)
        elif url.startswith("/"):
            for asset in read_jsonl(ctx.phase2 / "assets.jsonl"):
                base = asset.get("url", "").rstrip("/")
                if base:
                    endpoints.add(f"{base}{url}")

    write_lines(out, sorted(endpoints))
    return out


def _probe_v1(ctx: ReconContext, api_path: Path) -> Path:
    out = ctx.phase7 / "api_v1_probe.jsonl"
    httpx = tool_path("httpx", ctx.config)
    v1_candidates = ctx.phase7 / "api_v1_candidates.txt"

    v1_urls = list(dict.fromkeys(
        re.sub(r"/v2/", "/v1/", u) for u in read_lines(api_path) if "/v2/" in u
    ))
    write_lines(v1_candidates, v1_urls)

    if httpx and v1_urls:
        run_cmd(
            [httpx, "-l", str(v1_candidates), "-status-code", "-json", "-o", str(out)],
            timeout=600,
        )
    return out


def _graphql_introspection(ctx: ReconContext, api_path: Path) -> Path:
    out = ctx.phase7 / "graphql_introspection.jsonl"
    records: list[dict] = []
    query = '{"query":"{__schema{types{name fields{name}}}}"}'

    for url in read_lines(api_path):
        if "graphql" not in url.lower():
            continue
        try:
            ctx.rate_limiter.wait()
            resp = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                data=query,
                timeout=15,
            )
            records.append({"url": url, "status": resp.status_code, "body": resp.text[:2000]})
        except requests.RequestException as exc:
            records.append({"url": url, "error": str(exc)})

    out.write_text(
        "\n".join(json.dumps(r) for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    return out


def _swagger_discovery(ctx: ReconContext, assets_path: Path) -> Path:
    out = ctx.phase7 / "swagger_endpoints.txt"
    found: list[str] = []
    swagger_dir = ctx.phase7 / "swagger_found"

    for record in read_jsonl(assets_path):
        base = record.get("url", "").rstrip("/")
        if not base:
            continue
        for path in SWAGGER_PATHS:
            full = f"{base}{path}"
            status = curl_status(full, rate_limiter=ctx.rate_limiter)
            if status == 200:
                found.append(full)
                try:
                    ctx.rate_limiter.wait()
                    resp = requests.get(full, timeout=15)
                    (swagger_dir / f"{md5_short(full)}.json").write_text(resp.text[:50000], encoding="utf-8")
                except requests.RequestException:
                    pass

    write_lines(out, found)
    return out


def _auth_endpoints(ctx: ReconContext) -> Path:
    out = ctx.phase7 / "auth_endpoints.txt"
    urls = [u for u in read_lines(ctx.phase3 / "urls_clean.txt") if AUTH_PATTERN.search(u)]
    write_lines(out, urls)
    return out


def _cors_check(ctx: ReconContext, api_path: Path) -> Path:
    out = ctx.phase7 / "cors_check.txt"
    lines: list[str] = []

    for url in read_lines(api_path)[:100]:
        for origin in CORS_ORIGINS:
            if origin is None:
                header_origin = f"https://{ctx.target}.evil.com"
            elif origin == "null":
                header_origin = "null"
            else:
                header_origin = origin
            try:
                ctx.rate_limiter.wait()
                resp = requests.get(url, headers={"Origin": header_origin}, timeout=15)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                lines.append(f"{url} | origin={header_origin} | status={resp.status_code} | ACAO={acao}")
            except requests.RequestException:
                continue

    write_lines(out, lines)
    return out


def _host_header_poison(ctx: ReconContext, auth_path: Path) -> Path:
    out = ctx.phase7 / "host_header_injection.txt"
    lines: list[str] = []

    for url in read_lines(auth_path):
        if not RESET_PATTERN.search(url):
            continue
        for header in POISON_HEADERS:
            name, _, value = header.partition(": ")
            try:
                ctx.rate_limiter.wait()
                resp = requests.post(
                    url,
                    headers={name: value},
                    data={"email": "test@example.com", "username": "test"},
                    timeout=15,
                    allow_redirects=True,
                )
                if ATTACKER_HOST in resp.text or ATTACKER_HOST in str(resp.headers):
                    lines.append(f"POISON: {url} via {header} → reflected in response")
            except requests.RequestException:
                continue

    write_lines(out, lines)
    return out


def _build_api_surface(ctx: ReconContext, api_path: Path, v1_probe_path: Path) -> Path:
    out = ctx.phase7 / "api_surface.jsonl"
    v1_status = {
        r.get("url", ""): r.get("status_code") or r.get("status-code")
        for r in read_jsonl(v1_probe_path)
    }
    swagger_set = set(read_lines(ctx.phase7 / "swagger_endpoints.txt"))
    cors_lines = read_lines(ctx.phase7 / "cors_check.txt")
    cors_wildcard_urls = {line.split(" | ")[0] for line in cors_lines if "*" in line}

    records: list[dict] = []
    for url in read_lines(api_path):
        version_match = re.search(r"/v(\d+)/", url)
        version = f"v{version_match.group(1)}" if version_match else None
        v2_equiv = url.replace("/v1/", "/v2/") if "/v1/" in url else None
        v1_equiv = url.replace("/v2/", "/v1/") if "/v2/" in url else None

        params = extract_params(url)
        id_values = []
        for p in params:
            if p.lower() in {"id", "user_id", "account_id", "order_id", "uid"}:
                from urllib.parse import parse_qs, urlparse
                id_values.extend(parse_qs(urlparse(url).query).get(p, []))

        records.append(
            {
                "url": url,
                "method": "GET",
                "auth_required": False,
                "status": None,
                "content_type": None,
                "params": params,
                "response_sample": "",
                "id_type": classify_id_type(id_values),
                "version": version,
                "v2_exists": v2_equiv is not None,
                "v1_exists": v1_equiv in v1_status if v1_equiv else False,
                "v1_auth_required": v1_status.get(v1_equiv or "") in (401, 403),
                "cors_wildcard": url in cors_wildcard_urls,
                "swagger_available": any(url in s for s in swagger_set),
                "interesting": is_interesting_url(url),
            }
        )

    out.write_text(
        "\n".join(json.dumps(r) for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    return out


def run(ctx: ReconContext) -> None:
    phase_banner("Auth + API Surface", 7)
    assets_path = ctx.phase2 / "assets.jsonl"

    api_path = _extract_api_endpoints(ctx)
    v1_probe = _probe_v1(ctx, api_path)
    _graphql_introspection(ctx, api_path)
    _swagger_discovery(ctx, assets_path)
    _auth_endpoints(ctx)
    auth_path = ctx.phase7 / "auth_endpoints.txt"
    _cors_check(ctx, api_path)
    if is_intrusive(ctx.config):
        _host_header_poison(ctx, auth_path)
    else:
        LOG.info("Host-header poison skipped (needs mode:active + allow_intrusive:true)")
    surface = _build_api_surface(ctx, api_path, v1_probe)

    LOG.info("Phase 7 complete: %d API endpoints", len(read_jsonl(surface)))
