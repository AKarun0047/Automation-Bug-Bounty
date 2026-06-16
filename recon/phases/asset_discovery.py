"""Phase 1 — Asset Discovery."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import requests

from recon.context import ReconContext
from recon.scope import filter_in_scope
from recon.utils import (
    ensure_dir,
    filter_target_subdomains,
    phase_banner,
    read_lines,
    run_cmd,
    run_parallel,
    tool_path,
    write_lines,
)

LOG = logging.getLogger("recon.phase1")


def _passive_subfinder(ctx: ReconContext, passive_dir: Path) -> Path:
    out = passive_dir / "subfinder.txt"
    binary = tool_path("subfinder", ctx.config)
    if not binary:
        LOG.warning("subfinder not found — skipping")
        return out
    run_cmd([binary, "-d", ctx.target, "-all", "-recursive", "-silent", "-o", str(out)])
    return out


def _passive_amass(ctx: ReconContext, passive_dir: Path) -> Path:
    out = passive_dir / "amass.txt"
    binary = tool_path("amass", ctx.config)
    if not binary:
        LOG.warning("amass not found — skipping")
        return out
    run_cmd([binary, "enum", "-passive", "-d", ctx.target, "-o", str(out)], timeout=600)
    return out


def _passive_crtsh(ctx: ReconContext, passive_dir: Path) -> Path:
    out = passive_dir / "crtsh.txt"
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{ctx.target}&output=json",
            timeout=60,
        )
        if resp.ok:
            names: set[str] = set()
            for entry in resp.json():
                for name in str(entry.get("name_value", "")).split("\n"):
                    name = name.strip().replace("*.", "")
                    if name:
                        names.add(name.lower())
            write_lines(out, sorted(names))
    except (requests.RequestException, json.JSONDecodeError) as exc:
        LOG.warning("crt.sh fetch failed: %s", exc)
    return out


def _passive_hackertarget(ctx: ReconContext, passive_dir: Path) -> Path:
    out = passive_dir / "hackertarget.txt"
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={ctx.target}",
            timeout=30,
        )
        if resp.ok:
            hosts = [line.split(",")[0].strip() for line in resp.text.splitlines() if line.strip()]
            write_lines(out, hosts)
    except requests.RequestException as exc:
        LOG.warning("hackertarget fetch failed: %s", exc)
    return out


def _passive_otx(ctx: ReconContext, passive_dir: Path) -> Path:
    out = passive_dir / "otx.txt"
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{ctx.target}/passive_dns",
            timeout=30,
        )
        if resp.ok:
            hosts = [
                str(e.get("hostname", "")).lower()
                for e in resp.json().get("passive_dns", [])
                if e.get("hostname")
            ]
            write_lines(out, hosts)
    except (requests.RequestException, json.JSONDecodeError, KeyError) as exc:
        LOG.warning("OTX fetch failed: %s", exc)
    return out


def _resolve_permutations(ctx: ReconContext, raw_path: Path) -> tuple[Path, Path]:
    resolved = ctx.phase1 / "subdomains_resolved.txt"
    wildcards = ctx.phase1 / "wildcards.txt"
    alterx = tool_path("alterx", ctx.config)
    puredns = tool_path("puredns", ctx.config)

    permutations = ctx.phase1 / "permutations.txt"
    if alterx and raw_path.exists() and raw_path.stat().st_size > 0:
        run_cmd([alterx, "-enrich", "-i", str(raw_path), "-o", str(permutations)])
    else:
        if not alterx:
            LOG.warning("alterx not found — skipping permutation expansion")
        permutations = raw_path

    if puredns and permutations.exists() and ctx.config.resolvers.exists():
        run_cmd(
            [
                puredns,
                "resolve",
                str(permutations),
                "-r",
                str(ctx.config.resolvers),
                "--wildcard-tests",
                "5",
                "-o",
                str(resolved),
                "-w",
                str(wildcards),
            ],
            timeout=1800,
        )
    else:
        LOG.warning("puredns or resolvers missing — skipping DNS resolution")
    return resolved, wildcards


def _extract_ips(ctx: ReconContext, subdomains_path: Path) -> Path:
    ips_path = ctx.phase1 / "ips.txt"
    dnsx = tool_path("dnsx", ctx.config)
    if dnsx and subdomains_path.exists():
        run_cmd(
            [dnsx, "-l", str(subdomains_path), "-a", "-resp-only", "-silent", "-o", str(ips_path)],
            timeout=600,
        )
    return ips_path


def _lookup_asns(ctx: ReconContext, ips_path: Path) -> Path:
    asns_path = ctx.phase1 / "asns.txt"
    lines: list[str] = []
    for ip in read_lines(ips_path)[:100]:  # cap to avoid rate limits
        ctx.rate_limiter.wait()
        try:
            resp = requests.get(f"https://ipinfo.io/{ip}/org", timeout=10)
            if resp.ok:
                lines.append(f"{ip} | {resp.text.strip()}")
        except requests.RequestException:
            continue
    write_lines(asns_path, lines)
    return asns_path


def run(ctx: ReconContext) -> None:
    phase_banner("Asset Discovery", 1)
    passive_dir = ensure_dir(ctx.phase1 / "passive")

    run_parallel(
        [
            ("subfinder", lambda: _passive_subfinder(ctx, passive_dir)),
            ("amass", lambda: _passive_amass(ctx, passive_dir)),
            ("crtsh", lambda: _passive_crtsh(ctx, passive_dir)),
            ("hackertarget", lambda: _passive_hackertarget(ctx, passive_dir)),
            ("otx", lambda: _passive_otx(ctx, passive_dir)),
        ],
        max_workers=5,
    )

    merged: list[str] = []
    for path in passive_dir.glob("*.txt"):
        merged.extend(read_lines(path))

    merged = filter_target_subdomains(merged, ctx.config.scope_roots or ctx.config.targets)
    kept, rejected = filter_in_scope(merged, ctx.config)
    if rejected:
        LOG.warning("Scope gate rejected %d subdomains (fail-closed)", len(rejected))
        write_lines(ctx.phase1 / "scope_rejected.txt", rejected)
    merged = kept
    raw_path = ctx.phase1 / "subdomains_raw.txt"
    write_lines(raw_path, merged)

    if not merged:
        LOG.warning("No subdomains found passively — seeding with apex domain")
        write_lines(raw_path, [ctx.target, f"www.{ctx.target}"])

    resolved_path, _ = _resolve_permutations(ctx, raw_path)
    final = list(dict.fromkeys(read_lines(raw_path) + read_lines(resolved_path)))
    kept_final, rejected_final = filter_in_scope(final, ctx.config)
    if rejected_final:
        LOG.warning("Scope gate rejected %d resolved subdomains", len(rejected_final))
        write_lines(ctx.phase1 / "scope_rejected.txt", read_lines(ctx.phase1 / "scope_rejected.txt") + rejected_final)
    subdomains_path = ctx.phase1 / "subdomains.txt"
    write_lines(subdomains_path, kept_final)

    ips_path = _extract_ips(ctx, subdomains_path)
    _lookup_asns(ctx, ips_path)

    LOG.info("Phase 1 complete: %d subdomains", len(read_lines(subdomains_path)))
