"""Phase 3 — URL Harvesting."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from recon.config import is_in_scope
from recon.context import ReconContext
from recon.utils import (
    STATIC_EXTENSIONS,
    extract_params,
    is_interesting_url,
    phase_banner,
    read_jsonl,
    read_lines,
    run_cmd,
    run_parallel,
    tool_path,
    write_lines,
)

LOG = logging.getLogger("recon.phase3")


def _expand_from_shodan(ctx: ReconContext) -> None:
    """Feed Shodan-discovered hostnames back into subdomains.txt for later phases."""
    shodan_path = ctx.phase2 / "shodan_favicon.jsonl"
    subs_path = ctx.phase1 / "subdomains.txt"
    if not shodan_path.exists():
        return

    existing = set(read_lines(subs_path))
    added: list[str] = []
    suffix = f".{ctx.target.lower()}"

    for record in read_jsonl(shodan_path):
        for host in record.get("shodan_hosts", []):
            host = host.lower().strip()
            if not host or host in existing:
                continue
            if host == ctx.target.lower() or host.endswith(suffix):
                if is_in_scope(host, ctx.config):
                    existing.add(host)
                    added.append(host)
        for match in record.get("matches", []):
            for host in match.get("hostnames") or []:
                host = host.lower().strip()
                if not host or host in existing:
                    continue
                if host == ctx.target.lower() or host.endswith(suffix):
                    if is_in_scope(host, ctx.config):
                        existing.add(host)
                        added.append(host)

    if added:
        write_lines(subs_path, sorted(existing))
        LOG.info("Shodan enrichment: added %d subdomains", len(added))


def _gau(ctx: ReconContext) -> Path:
    out = ctx.phase3 / "urls_gau.txt"
    # Prefer gauplus from tools_path — avoid shell aliases (e.g. gau → git add --update)
    gau = tool_path("gauplus", ctx.config)
    if not gau:
        LOG.warning("gauplus not found in tools_path — skipping archive harvest (install: go install github.com/bp0lr/gauplus@latest)")
        return out
    run_cmd(
        [
            gau,
            "--threads",
            "10",
            "--subs",
            "--blacklist",
            "ttf,woff,woff2,svg,png,jpg,jpeg,gif,ico,css",
            "--o",
            str(out),
            "--",
            ctx.target,
        ],
        timeout=1200,
    )
    return out


def _waymore(ctx: ReconContext) -> Path:
    out = ctx.phase3 / "urls_waymore.txt"
    waymore = tool_path("waymore", ctx.config)
    if not waymore:
        LOG.warning("waymore not found — skipping")
        return out
    run_cmd([waymore, "-i", ctx.target, "-mode", "U", "-oU", str(out)], timeout=1200)
    return out


def _katana_crawl(ctx: ReconContext, assets_path: Path, auth: bool = False) -> Path:
    out = ctx.phase3 / ("katana_auth_crawl.jsonl" if auth else "katana_crawl.jsonl")
    katana = tool_path("katana", ctx.config)
    if not katana or not assets_path.exists():
        return out

    seeds = ctx.phase3 / ("katana_seeds_auth.txt" if auth else "katana_seeds.txt")
    urls = [r.get("url", "") for r in read_jsonl(assets_path) if r.get("url")]
    write_lines(seeds, urls)

    cmd = [
        katana,
        "-list",
        str(seeds),
        "-jc",
        "-jsl",
        "-kf",
        "all",
        "-d",
        "5",
        "-c",
        str(min(ctx.config.threads, 50)),
        "-xhr",
        "-ef",
        "css,png,jpg,gif,ico,svg,woff,ttf",
        "-json",
        "-o",
        str(out),
    ]
    if auth and ctx.config.auth_cookies:
        cmd.extend(["-H", f"Cookie: {ctx.config.auth_cookies}"])

    run_cmd(cmd, timeout=3600)
    return out


def _merge_urls(ctx: ReconContext) -> tuple[Path, Path]:
    raw_path = ctx.phase3 / "urls_raw.txt"
    clean_path = ctx.phase3 / "urls_clean.txt"

    sources = [
        ctx.phase3 / "urls_gau.txt",
        ctx.phase3 / "urls_waymore.txt",
    ]
    katana_paths = [ctx.phase3 / "katana_crawl.jsonl", ctx.phase3 / "katana_auth_crawl.jsonl"]

    merged: list[str] = []
    for path in sources:
        merged.extend(read_lines(path))

    for katana_path in katana_paths:
        for record in read_jsonl(katana_path):
            endpoint = (
                record.get("request", {}).get("endpoint")
                or record.get("url")
                or ""
            )
            if endpoint:
                merged.append(endpoint)

    merged = list(dict.fromkeys(merged))
    write_lines(raw_path, merged)

    http_urls = [u for u in merged if u.startswith("http")]
    filtered = [u for u in http_urls if not STATIC_EXTENSIONS.search(u)]

    uro = tool_path("uro", ctx.config)
    if uro and filtered:
        seeds = ctx.phase3 / "urls_pre_uro.txt"
        write_lines(seeds, filtered)
        run_cmd([uro, "-i", str(seeds), "-o", str(clean_path)], timeout=600)
    else:
        write_lines(clean_path, filtered)

    return raw_path, clean_path


def _alive_check(ctx: ReconContext, clean_path: Path) -> Path:
    out = ctx.phase3 / "urls_with_status.jsonl"
    httpx = tool_path("httpx", ctx.config)
    if not httpx or not clean_path.exists():
        return out

    # Sample if too large
    urls = read_lines(clean_path)
    if len(urls) > 5000:
        LOG.info("Sampling 5000 URLs for alive check (of %d)", len(urls))
        urls = urls[:5000]
        sample_path = ctx.phase3 / "urls_clean_sample.txt"
        write_lines(sample_path, urls)
        clean_path = sample_path

    run_cmd(
        [httpx, "-l", str(clean_path), "-status-code", "-silent", "-json", "-o", str(out)],
        timeout=3600,
    )
    return out


def run(ctx: ReconContext) -> None:
    phase_banner("URL Harvesting", 3)
    _expand_from_shodan(ctx)
    assets_path = ctx.phase2 / "assets.jsonl"

    run_parallel(
        [
            ("gau", lambda: _gau(ctx)),
            ("waymore", lambda: _waymore(ctx)),
        ],
        max_workers=2,
    )

    _katana_crawl(ctx, assets_path, auth=False)
    if ctx.config.auth_cookies:
        LOG.info("Running authenticated katana crawl")
        _katana_crawl(ctx, assets_path, auth=True)

    raw_path, clean_path = _merge_urls(ctx)
    _alive_check(ctx, clean_path)

    LOG.info(
        "Phase 3 complete: %d raw URLs, %d clean URLs",
        len(read_lines(raw_path)),
        len(read_lines(clean_path)),
    )
