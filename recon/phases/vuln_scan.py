"""Phase 6 — Vulnerability Scan."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from recon.config import is_active
from recon.context import ReconContext
from recon.utils import (
    curl_status,
    http_get,
    phase_banner,
    read_jsonl,
    read_lines,
    run_cmd,
    tool_path,
    write_lines,
)

LOG = logging.getLogger("recon.phase6")

ACTUATOR_PATHS = (
    "/actuator",
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/trace",
    "/actuator/mappings",
)

BYPASS_HEADERS = (
    "X-Original-URL: /",
    "X-Forwarded-For: 127.0.0.1",
    "X-Custom-IP-Authorization: 127.0.0.1",
    "X-Rewrite-URL: /",
    "X-Host: localhost",
)


def _nuclei_broad(ctx: ReconContext, urls_path: Path) -> Path:
    out = ctx.phase6 / "nuclei_broad.jsonl"
    nuclei = tool_path("nuclei", ctx.config)
    if not nuclei or not urls_path.exists():
        return out

    templates = [
        "cves/",
        "exposures/",
        "misconfigurations/",
        "takeovers/",
        "technologies/",
        "default-logins/",
        "network/",
        "http/request-smuggling/",
        "http/cache-poisoning/",
        "http/vulnerabilities/generic/cors-misconfig.yaml",
    ]
    cmd = [
        nuclei,
        "-l",
        str(urls_path),
        "-severity",
        "critical,high,medium",
        "-rate-limit",
        str(min(ctx.config.rate_limit, 100)),
        "-bulk-size",
        "25",
        "-c",
        "25",
        "-json",
        "-o",
        str(out),
    ]
    for t in templates:
        cmd.extend(["-t", t])

    run_cmd(cmd, timeout=7200)
    return out


def _nuclei_fuzz(ctx: ReconContext) -> list[Path]:
    nuclei = tool_path("nuclei", ctx.config)
    if not nuclei:
        return []

    fuzz_map = {
        "xss": "fuzzing/xss-reflected.yaml",
        "sqli": "fuzzing/sqli.yaml",
        "ssrf": "fuzzing/ssrf.yaml",
    }
    fuzz_outputs: list[Path] = []
    for param_type, template in fuzz_map.items():
        param_file = ctx.phase5 / f"{param_type}.txt"
        if not param_file.exists() or param_file.stat().st_size == 0:
            continue
        fuzz_out = ctx.phase6 / f"nuclei_fuzz_{param_type}.jsonl"
        cmd = [nuclei, "-l", str(param_file), "-t", template, "-json", "-o", str(fuzz_out)]
        if param_type == "ssrf" and ctx.config.burp_collab:
            cmd.extend(["-interactsh-server", ctx.config.burp_collab])
        run_cmd(cmd, timeout=1800)
        fuzz_outputs.append(fuzz_out)
    return fuzz_outputs


def _merge_nuclei_findings(ctx: ReconContext) -> Path:
    out = ctx.phase6 / "nuclei_findings.jsonl"
    seen: set[str] = set()
    lines: list[str] = []

    for path in sorted(ctx.phase6.glob("nuclei_*.jsonl")):
        for record in read_jsonl(path):
            key = json.dumps(
                {
                    "template": record.get("template-id") or record.get("templateID"),
                    "host": record.get("host"),
                    "matched": record.get("matched-at") or record.get("matched"),
                },
                sort_keys=True,
            )
            if key in seen:
                continue
            seen.add(key)
            lines.append(json.dumps(record))

    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return out


def _subzy_takeover(ctx: ReconContext, subdomains_path: Path) -> Path:
    out = ctx.phase6 / "takeovers.txt"
    subzy = tool_path("subzy", ctx.config)
    if not subzy or not subdomains_path.exists():
        return out
    run_cmd(
        [subzy, "run", "--targets", str(subdomains_path), "--concurrency", "50", "--output", str(out)],
        timeout=1200,
    )
    return out


def _cve_intel(ctx: ReconContext, assets_path: Path) -> Path:
    out = ctx.phase6 / "cve_intel.jsonl"
    import requests

    techs: set[str] = set()
    for record in read_jsonl(assets_path):
        for tech in record.get("tech") or []:
            techs.add(str(tech))

    lines: list[str] = []
    for tech in sorted(techs)[:20]:
        ctx.rate_limiter.wait()
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": tech, "resultsPerPage": 5},
                timeout=30,
            )
            if resp.ok:
                lines.append(json.dumps({"tech": tech, "nvd": resp.json()}))
        except requests.RequestException:
            continue

    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return out


def _cache_poison_probe(ctx: ReconContext, assets_path: Path) -> Path:
    out = ctx.phase6 / "cache_poison.txt"
    lines: list[str] = []

    for record in read_jsonl(assets_path)[:40]:
        url = record.get("url", "")
        if not url:
            continue
        ctx.rate_limiter.wait()
        status, _body, headers = http_get(url, rate_limiter=None)
        if status == 0:
            continue
        cache_control = headers.get("Cache-Control", headers.get("cache-control", ""))
        if cache_control and "no-store" in cache_control.lower() and "private" in cache_control.lower():
            continue

        ctx.rate_limiter.wait()
        http_get(url, headers={"X-Forwarded-Host": "evil.com"}, rate_limiter=None)
        ctx.rate_limiter.wait()
        _status2, body2, _h2 = http_get(url, rate_limiter=None)
        if "evil.com" in body2:
            lines.append(f"CACHE POISON: {url} — evil.com reflected on re-fetch")

    write_lines(out, lines)
    return out


def _actuator_check(ctx: ReconContext, assets_path: Path) -> Path:
    out = ctx.phase6 / "actuator_exposed.txt"
    lines: list[str] = []
    for record in read_jsonl(assets_path):
        base = record.get("url", "").rstrip("/")
        if not base:
            continue
        for ep in ACTUATOR_PATHS:
            status = curl_status(f"{base}{ep}", rate_limiter=ctx.rate_limiter)
            if status and status != 404:
                lines.append(f"{base}{ep} → {status}")
    write_lines(out, lines)
    return out


def _header_bypass(ctx: ReconContext, assets_path: Path) -> Path:
    out = ctx.phase6 / "bypass_found.txt"
    lines: list[str] = []
    for record in read_jsonl(assets_path):
        if record.get("status_code") != 403 and record.get("status-code") != 403:
            continue
        url = record.get("url", "")
        for header in BYPASS_HEADERS:
            status = curl_status(url, extra_headers=[header], rate_limiter=ctx.rate_limiter)
            if status and status != 403:
                lines.append(f"BYPASS: {url} via {header} → {status}")
    write_lines(out, lines)
    return out


def run(ctx: ReconContext) -> None:
    phase_banner("Vulnerability Scan", 6)
    urls_path = ctx.phase2 / "urls_to_probe.txt"
    subdomains_path = ctx.phase1 / "subdomains.txt"
    assets_path = ctx.phase2 / "assets.jsonl"

    _nuclei_broad(ctx, urls_path)
    if is_active(ctx.config):
        _nuclei_fuzz(ctx)
        _header_bypass(ctx, assets_path)
        _cache_poison_probe(ctx, assets_path)
    else:
        LOG.info("Passive mode — skipping nuclei fuzz, header bypass, cache poison probes")
    findings_path = _merge_nuclei_findings(ctx)
    _subzy_takeover(ctx, subdomains_path)
    _cve_intel(ctx, assets_path)
    _actuator_check(ctx, assets_path)

    LOG.info("Phase 6 complete: %d nuclei findings", len(read_jsonl(findings_path)))
