"""Phase 5 — Parameter Discovery."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests

from recon.config import is_active
from recon.context import ReconContext
from recon.ssrf_probe import run_ssrf_probes
from recon.utils import (
    classify_id_type,
    extract_params,
    md5_short,
    phase_banner,
    read_jsonl,
    read_lines,
    run_cmd,
    tool_path,
    write_lines,
)

LOG = logging.getLogger("recon.phase5")

GF_PATTERNS = ("sqli", "ssrf", "idor", "xss", "lfi", "rce", "ssti", "redirect")
ID_PARAM_NAMES = {"id", "user_id", "account_id", "order_id", "doc_id", "uid"}


def _gf_classify(ctx: ReconContext, clean_path: Path) -> None:
    gf = tool_path("gf", ctx.config)
    if not gf or not clean_path.exists():
        LOG.warning("gf not found — using built-in param extraction")
        _builtin_classify(ctx, clean_path)
        return

    for pattern in GF_PATTERNS:
        out = ctx.phase5 / f"{pattern}.txt"
        run_cmd(["sh", "-c", f"cat '{clean_path}' | gf {pattern} | sort -u > '{out}'"])


def _builtin_classify(ctx: ReconContext, clean_path: Path) -> None:
    """Fallback when gf is not installed."""
    buckets: dict[str, list[str]] = defaultdict(list)
    ssrf_params = {"url", "uri", "path", "redirect", "src", "dest", "target", "callback"}
    idor_params = {"id", "user_id", "account_id", "order_id", "uid", "doc_id"}
    sqli_params = {"q", "search", "query", "filter", "sort", "order", "column"}
    xss_params = {"msg", "message", "error", "callback", "jsonp", "name", "text"}
    lfi_params = {"file", "page", "template", "include", "path", "doc"}
    redirect_params = {"redirect", "next", "return", "returnUrl", "url", "goto", "dest"}

    for url in read_lines(clean_path):
        params = extract_params(url)
        for p in params:
            pl = p.lower()
            if pl in ssrf_params:
                buckets["ssrf"].append(url)
            if pl in idor_params:
                buckets["idor"].append(url)
            if pl in sqli_params:
                buckets["sqli"].append(url)
            if pl in xss_params:
                buckets["xss"].append(url)
            if pl in lfi_params:
                buckets["lfi"].append(url)
            if pl in redirect_params:
                buckets["redirect"].append(url)

    for pattern, urls in buckets.items():
        write_lines(ctx.phase5 / f"{pattern}.txt", urls)


def _arjun_discovery(ctx: ReconContext, assets_path: Path) -> None:
    arjun = tool_path("arjun", ctx.config)
    if not arjun:
        LOG.warning("arjun not found — skipping hidden param discovery")
        return

    endpoints = [
        r.get("url", "")
        for r in read_jsonl(assets_path)
        if r.get("interesting") and r.get("url")
    ][:20]

    for url in endpoints:
        ctx.rate_limiter.wait()
        out = ctx.phase5 / f"arjun_{md5_short(url)}.json"
        run_cmd([arjun, "-u", url, "-oJ", str(out), "-t", "20", "-d", "2"], timeout=300)


def _wayback_params(ctx: ReconContext) -> Path:
    out = ctx.phase5 / "wayback_params.txt"
    ctx.rate_limiter.wait()
    try:
        resp = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{ctx.target}/*",
                "output": "text",
                "fl": "original",
                "collapse": "urlkey",
                "filter": "statuscode:200",
            },
            timeout=120,
        )
        if resp.ok:
            urls = [line for line in resp.text.splitlines() if "?" in line]
            write_lines(out, urls)
    except requests.RequestException as exc:
        LOG.warning("Wayback CDX fetch failed: %s", exc)
    return out


def _build_params_classified(ctx: ReconContext) -> Path:
    out = ctx.phase5 / "params_classified.jsonl"
    clean_urls = read_lines(ctx.phase3 / "urls_clean.txt")
    status_map = {
        r.get("url", ""): r.get("status_code") or r.get("status-code")
        for r in read_jsonl(ctx.phase3 / "urls_with_status.jsonl")
    }

    param_vuln: dict[str, str] = {}
    for pattern in GF_PATTERNS:
        for url in read_lines(ctx.phase5 / f"{pattern}.txt"):
            for p in extract_params(url):
                param_vuln[p] = pattern

    records: list[dict] = []
    for url in clean_urls:
        if "?" not in url:
            continue
        params = extract_params(url)
        if not params:
            continue

        param_entries = []
        id_type = None
        for name in params:
            values = parse_qs(urlparse(url).query).get(name, [])
            vuln_class = param_vuln.get(name, "unknown")
            param_entries.append(
                {"name": name, "vuln_class": vuln_class, "value_sample": values[0] if values else ""}
            )
            if name.lower() in ID_PARAM_NAMES:
                id_type = classify_id_type(values)

        records.append(
            {
                "url": url,
                "params": param_entries,
                "source": "harvest",
                "status": status_map.get(url),
                "id_type": id_type,
                "auth_required": status_map.get(url) in (401, 403),
            }
        )

    out.write_text(
        "\n".join(json.dumps(r) for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    return out


def run(ctx: ReconContext) -> None:
    phase_banner("Parameter Discovery", 5)
    clean_path = ctx.phase3 / "urls_clean.txt"
    assets_path = ctx.phase2 / "assets.jsonl"

    _gf_classify(ctx, clean_path)
    _arjun_discovery(ctx, assets_path)
    _wayback_params(ctx)
    classified = _build_params_classified(ctx)

    if is_active(ctx.config):
        ssrf_confirmed = ctx.phase5 / "ssrf_confirmed.jsonl"
        confirmed = run_ssrf_probes(ctx, ctx.phase5 / "ssrf.txt", ssrf_confirmed)
    else:
        confirmed = 0
        LOG.info("Passive mode — skipping SSRF active probes")

    LOG.info(
        "Phase 5 complete: %d classified URLs, %d SSRF confirmed",
        len(read_jsonl(classified)),
        confirmed,
    )
