"""JWT analysis phase — extract and decode tokens from auth, JS, and crawl data."""

from __future__ import annotations

import json
import logging

import requests

from recon.context import ReconContext
from recon.jwt_analysis import analyze_text, extract_jwts
from recon.utils import (
    phase_banner,
    read_jsonl,
    read_lines,
    run_cmd,
    tool_path,
)

LOG = logging.getLogger("recon.phase_jwt")


def _jwt_tool_tamper(ctx: ReconContext, token: str) -> str | None:
    jwt_tool = tool_path("jwt_tool", ctx.config)
    if not jwt_tool:
        return None
    ctx.rate_limiter.wait()
    result = run_cmd([jwt_tool, token, "-T"], timeout=60)
    return result.stdout.strip()[:2000] if result.stdout else None


def _fetch_url(ctx: ReconContext, url: str, source: str) -> list[dict]:
    try:
        ctx.rate_limiter.wait()
        resp = requests.get(url, timeout=15, allow_redirects=True)
        auth_header = resp.headers.get("Authorization", "")
        cookie_text = " ".join(f"{k}={v}" for k, v in resp.cookies.items())
        combined = f"{auth_header}\n{resp.text[:80000]}\n{cookie_text}"
        return analyze_text(combined, source=source, url=url)
    except requests.RequestException as exc:
        LOG.debug("JWT fetch %s: %s", url, exc)
        return []


def _from_downloaded_js(ctx: ReconContext, url: str) -> list[dict]:
    records: list[dict] = []
    suffix = url.split("/")[-1][:60]
    download_dir = ctx.phase4 / "downloaded_js"
    for js_path in download_dir.glob(f"*{suffix}"):
        try:
            text = js_path.read_text(encoding="utf-8", errors="replace")
            records.extend(analyze_text(text, source="js_file", url=url))
        except OSError:
            continue
    return records


def _from_katana(ctx: ReconContext) -> list[dict]:
    records: list[dict] = []
    for path in (ctx.phase3 / "katana_crawl.jsonl", ctx.phase3 / "katana_auth_crawl.jsonl"):
        for record in read_jsonl(path):
            endpoint = record.get("request", {}).get("endpoint") or record.get("url") or ""
            resp = record.get("response", {}) or {}
            body = str(resp.get("body", "") or resp.get("raw", "") or "")
            if body and extract_jwts(body):
                records.extend(analyze_text(body, source="katana_response", url=endpoint))
    return records


def run(ctx: ReconContext) -> None:
    phase_banner("JWT Analysis", 9)
    out = ctx.phase7 / "jwt_found.jsonl"
    seen: set[str] = set()
    records: list[dict] = []

    def _add(batch: list[dict]) -> None:
        for rec in batch:
            key = rec.get("token") or rec.get("raw", "")
            if key in seen:
                continue
            seen.add(key)
            records.append(rec)

    for url in read_lines(ctx.phase7 / "auth_endpoints.txt")[:60]:
        _add(_fetch_url(ctx, url, "auth_endpoint"))

    for url in read_lines(ctx.phase4 / "js_files.txt")[:80]:
        _add(_from_downloaded_js(ctx, url))
        if not any((ctx.phase4 / "downloaded_js").iterdir()):
            _add(_fetch_url(ctx, url, "js_file"))

    _add(_from_katana(ctx))

    for rec in records:
        token = rec.get("token", "")
        if rec.get("issues") and token:
            tamper = _jwt_tool_tamper(ctx, token)
            if tamper:
                rec["jwt_tool_tamper"] = tamper
        rec.pop("token", None)

    out.write_text(
        "\n".join(json.dumps(r) for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    LOG.info("JWT analysis complete: %d tokens", len(records))
