"""Phase 2 — HTTP Probe + Fingerprint."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from recon.context import ReconContext
from recon.utils import (
    is_interesting_url,
    phase_banner,
    read_jsonl,
    read_lines,
    run_cmd,
    tool_path,
    write_lines,
)

LOG = logging.getLogger("recon.phase2")

WAF_PATTERN = re.compile(r"(?i)(cloudflare|akamai|incapsula|sucuri|aws|imperva|f5)")


def _port_scan(ctx: ReconContext, subdomains_path: Path) -> Path:
    ports_path = ctx.phase2 / "ports.jsonl"
    naabu = tool_path("naabu", ctx.config)
    if not naabu or not subdomains_path.exists():
        LOG.warning("naabu not found or no subdomains — skipping port scan")
        return ports_path

    ports = "80,443,8080,8443,3000,3001,4000,4443,5000,8000,8008,8888,9000,9090,9200,9443"
    run_cmd(
        [naabu, "-l", str(subdomains_path), "-p", ports, "-silent", "-json", "-o", str(ports_path)],
        timeout=1800,
    )
    return ports_path


def _build_urls_to_probe(ctx: ReconContext, subdomains_path: Path, ports_path: Path) -> Path:
    urls_path = ctx.phase2 / "urls_to_probe.txt"
    urls: list[str] = []

    for record in read_jsonl(ports_path):
        host = record.get("host") or record.get("ip") or ""
        port = record.get("port")
        if host and port:
            scheme = "https" if int(port) == 443 else "http"
            if int(port) in (80, 443):
                urls.append(f"{scheme}://{host}")
            else:
                urls.append(f"http://{host}:{port}")

    httpx = tool_path("httpx", ctx.config)
    probe_out = ctx.phase2 / "httpx_probe.txt"
    if httpx and subdomains_path.exists():
        run_cmd(
            [httpx, "-l", str(subdomains_path), "-probe", "-silent", "-o", str(probe_out)],
            timeout=1200,
        )
        _ansi = re.compile(r"\x1b\[[0-9;]*m")
        for line in read_lines(probe_out):
            clean = _ansi.sub("", line).strip()
            if "SUCCESS" in clean and clean.startswith("http"):
                urls.append(clean.split()[0])

    if not urls:
        for sub in read_lines(subdomains_path):
            urls.append(f"https://{sub}")
            urls.append(f"http://{sub}")

    write_lines(urls_path, urls)
    return urls_path


def _fingerprint(ctx: ReconContext, urls_path: Path) -> Path:
    assets_path = ctx.phase2 / "assets.jsonl"
    httpx = tool_path("httpx", ctx.config)
    if not httpx or not urls_path.exists():
        return assets_path

    run_cmd(
        [
            httpx,
            "-l",
            str(urls_path),
            "-title",
            "-status-code",
            "-tech-detect",
            "-ip",
            "-cdn",
            "-location",
            "-server",
            "-favicon",
            "-hash",
            "sha256",
            "-ports",
            "80,443,8080,8443,3000,8000",
            "-follow-redirects",
            "-max-redirects",
            "5",
            "-rstr",
            "2097152",
            "-json",
            "-o",
            str(assets_path),
        ],
        timeout=3600,
    )
    _enrich_assets(assets_path)
    return assets_path


def _enrich_assets(assets_path: Path) -> None:
    if not assets_path.exists():
        return

    enriched: list[str] = []
    for record in read_jsonl(assets_path):
        url = record.get("url", "")
        status = record.get("status_code") or record.get("status-code") or 0
        server = str(record.get("webserver") or record.get("server") or "")
        cdn = bool(record.get("cdn", False))

        interesting = is_interesting_url(url)
        if status == 403:
            interesting = True
        if server and re.search(r"/\d", server):
            interesting = True

        record["direct_ip"] = not cdn
        record["interesting"] = interesting
        record["notes"] = record.get("notes", "")
        enriched.append(json.dumps(record))

    assets_path.write_text("\n".join(enriched) + ("\n" if enriched else ""), encoding="utf-8")


def _screenshots(ctx: ReconContext, urls_path: Path) -> None:
    if not ctx.config.phases.screenshots:
        return
    gowitness = tool_path("gowitness", ctx.config)
    if not gowitness or not urls_path.exists():
        LOG.warning("gowitness not found — skipping screenshots")
        return
    run_cmd(
        [
            gowitness,
            "file",
            "-f",
            str(urls_path),
            "-P",
            str(ctx.phase2 / "screenshots"),
            "--timeout",
            "10",
        ],
        timeout=3600,
    )


def _waf_detection(ctx: ReconContext, subdomains_path: Path) -> Path:
    waf_path = ctx.phase2 / "waf_detection.txt"
    wafw00f = tool_path("wafw00f", ctx.config)
    lines: list[str] = []

    hosts = read_lines(subdomains_path)[:50]  # cap for speed
    if wafw00f:
        for host in hosts:
            result = run_cmd([wafw00f, f"https://{host}"], timeout=60)
            if result.stdout:
                lines.append(result.stdout.strip())
    else:
        LOG.warning("wafw00f not found — using httpx CDN hints only")
        for record in read_jsonl(ctx.phase2 / "assets.jsonl"):
            url = record.get("url", "")
            cdn_name = record.get("cdn_name") or record.get("cdn-name") or ""
            if cdn_name:
                lines.append(f"{url}: {cdn_name}")

    waf_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return waf_path


def _shodan_favicon_lookup(ctx: ReconContext, assets_path: Path) -> Path:
    out = ctx.phase2 / "shodan_favicon.jsonl"
    if not ctx.config.shodan_api_key or not assets_path.exists():
        if not ctx.config.shodan_api_key:
            LOG.debug("No shodan_api_key — skipping favicon → Shodan lookup")
        return out

    import requests

    hashes: set[str] = set()
    hash_to_url: dict[str, str] = {}
    for record in read_jsonl(assets_path):
        url = record.get("url", "")
        fav_hash = (
            record.get("favicon_hash")
            or record.get("favicon-hash")
            or record.get("favicon_mmh3")
            or record.get("favicon-mmh3")
        )
        if fav_hash is not None and str(fav_hash).strip():
            h = str(fav_hash).strip()
            hashes.add(h)
            hash_to_url.setdefault(h, url)

    records: list[dict] = []
    for h in sorted(hashes)[:20]:
        ctx.rate_limiter.wait()
        try:
            resp = requests.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": ctx.config.shodan_api_key, "query": f"http.favicon.hash:{h}"},
                timeout=30,
            )
            if resp.ok:
                data = resp.json()
                records.append(
                    {
                        "favicon_hash": h,
                        "source_url": hash_to_url.get(h),
                        "shodan_total": data.get("total", 0),
                        "shodan_hosts": list(
                            dict.fromkeys(
                                host
                                for m in (data.get("matches") or [])
                                for host in (m.get("hostnames") or [])
                                if host
                            )
                        ),
                        "matches": [
                            {"ip": m.get("ip_str"), "hostnames": m.get("hostnames"), "org": m.get("org")}
                            for m in (data.get("matches") or [])[:10]
                        ],
                    }
                )
        except requests.RequestException as exc:
            LOG.debug("Shodan lookup failed for hash %s: %s", h, exc)

    out.write_text(
        "\n".join(json.dumps(r) for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    if records:
        LOG.info("Shodan favicon lookup: %d hashes queried", len(records))
    return out


def run(ctx: ReconContext) -> None:
    phase_banner("HTTP Probe + Fingerprint", 2)
    subdomains_path = ctx.phase1 / "subdomains.txt"

    ports_path = _port_scan(ctx, subdomains_path)
    urls_path = _build_urls_to_probe(ctx, subdomains_path, ports_path)
    _fingerprint(ctx, urls_path)
    assets_path = ctx.phase2 / "assets.jsonl"
    _shodan_favicon_lookup(ctx, assets_path)
    _screenshots(ctx, urls_path)
    _waf_detection(ctx, subdomains_path)

    assets = read_jsonl(ctx.phase2 / "assets.jsonl")
    LOG.info("Phase 2 complete: %d live assets", len(assets))
