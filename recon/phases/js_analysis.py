"""Phase 4 — JS Analysis + Secret Scanning."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import requests

from recon.config import github_org_for_target, is_intrusive
from recon.context import ReconContext
from recon.utils import (
    curl_status,
    http_get,
    md5_short,
    phase_banner,
    read_jsonl,
    read_lines,
    run_cmd,
    tool_path,
    write_lines,
)

LOG = logging.getLogger("recon.phase4")


def _collect_js_files(ctx: ReconContext) -> Path:
    js_path = ctx.phase4 / "js_files.txt"
    js_urls: list[str] = []

    katana_paths = [ctx.phase3 / "katana_crawl.jsonl", ctx.phase3 / "katana_auth_crawl.jsonl"]
    for katana_path in katana_paths:
        for record in read_jsonl(katana_path):
            endpoint = record.get("request", {}).get("endpoint") or record.get("url") or ""
            if endpoint.endswith(".js"):
                js_urls.append(endpoint)

    clean = read_lines(ctx.phase3 / "urls_clean.txt")
    js_urls.extend(u for u in clean if u.endswith(".js"))

    write_lines(js_path, js_urls)
    return js_path


def _check_source_maps(ctx: ReconContext, js_path: Path) -> Path:
    maps_path = ctx.phase4 / "source_maps_found.txt"
    found: list[str] = []

    for url in read_lines(js_path)[:200]:
        map_url = f"{url}.map"
        if curl_status(map_url, rate_limiter=ctx.rate_limiter) == 200:
            found.append(map_url)

    write_lines(maps_path, found)
    if found:
        LOG.warning("CRITICAL: %d source maps found — full source exposed", len(found))
    return maps_path


def _download_js(ctx: ReconContext, js_path: Path) -> tuple[Path, dict[str, str]]:
    download_dir = ctx.phase4 / "downloaded_js"
    url_by_file: dict[str, str] = {}

    for url in read_lines(js_path)[:100]:
        try:
            resp = requests.get(url, timeout=15)
            if not resp.ok:
                continue
            base = url.split("/")[-1][:60] or "bundle.js"
            fname = f"{md5_short(url)}_{base}"
            (download_dir / fname).write_bytes(resp.content[:5_000_000])
            url_by_file[fname] = url
        except requests.RequestException:
            continue

    return download_dir, url_by_file


def _parse_jsluice_output(stdout: str, source_url: str) -> list[dict]:
    records: list[dict] = []
    text = stdout.strip()
    if not text:
        return records

    try:
        data = json.loads(text)
        items = data if isinstance(data, list) else [data]
        for item in items:
            if isinstance(item, dict):
                item.setdefault("source_file", source_url)
                records.append(item)
        return records
    except json.JSONDecodeError:
        pass

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                item.setdefault("source_file", source_url)
                records.append(item)
        except json.JSONDecodeError:
            records.append({"raw": line, "source_file": source_url})

    return records


def _jsluice_extract(
    ctx: ReconContext,
    download_dir: Path,
    url_by_file: dict[str, str],
) -> tuple[Path, Path]:
    endpoints_path = ctx.phase4 / "js_endpoints.jsonl"
    secrets_raw_path = ctx.phase4 / "js_secrets_raw.jsonl"
    jsluice = tool_path("jsluice", ctx.config)

    js_files = [f for f in download_dir.iterdir() if f.is_file()]
    if not jsluice or not js_files:
        if not jsluice:
            LOG.warning("jsluice not found — skipping JS extraction")
        return endpoints_path, secrets_raw_path

    endpoint_records: list[dict] = []
    secret_records: list[dict] = []

    for js_file in js_files:
        source_url = url_by_file.get(js_file.name, js_file.name)
        try:
            content = js_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            LOG.debug("Cannot read %s: %s", js_file, exc)
            continue

        for subcmd, acc in (("urls", endpoint_records), ("secrets", secret_records)):
            result = run_cmd([jsluice, subcmd], stdin=content, timeout=120)
            if result.returncode != 0 and result.stderr:
                LOG.debug("jsluice %s on %s: %s", subcmd, js_file.name, result.stderr.strip())
            acc.extend(_parse_jsluice_output(result.stdout, source_url))

    endpoints_path.write_text(
        "\n".join(json.dumps(r) for r in endpoint_records) + ("\n" if endpoint_records else ""),
        encoding="utf-8",
    )
    secrets_raw_path.write_text(
        "\n".join(json.dumps(r) for r in secret_records) + ("\n" if secret_records else ""),
        encoding="utf-8",
    )
    return endpoints_path, secrets_raw_path


def _trufflehog_github(ctx: ReconContext) -> Path:
    out = ctx.phase4 / "trufflehog_github.jsonl"
    trufflehog = tool_path("trufflehog", ctx.config)
    if not trufflehog:
        return out

    org = github_org_for_target(ctx.config, ctx.target)
    LOG.info("Running trufflehog GitHub org scan: %s", org)
    result = run_cmd(
        [trufflehog, "github", f"--org={org}", "--only-verified", "--json"],
        timeout=1200,
    )
    if result.stdout.strip():
        out.write_text(result.stdout, encoding="utf-8")
    elif result.stderr:
        LOG.warning("trufflehog github: %s", result.stderr.strip()[:300])
    return out


def _trufflehog_scan(ctx: ReconContext, download_dir: Path) -> Path:
    out = ctx.phase4 / "trufflehog_local.jsonl"
    trufflehog = tool_path("trufflehog", ctx.config)
    if not trufflehog or not any(download_dir.iterdir()):
        return out

    result = run_cmd([trufflehog, "filesystem", str(download_dir), "--json"], timeout=600)
    if result.stdout.strip():
        out.write_text(result.stdout, encoding="utf-8")
    elif result.stderr:
        LOG.warning("trufflehog returned no output: %s", result.stderr.strip()[:200])
    return out


def _nuclei_js_scan(ctx: ReconContext, js_path: Path) -> Path:
    out = ctx.phase4 / "nuclei_js.jsonl"
    nuclei = tool_path("nuclei", ctx.config)
    if not nuclei or not js_path.exists():
        return out

    run_cmd(
        [
            nuclei,
            "-l",
            str(js_path),
            "-t",
            "exposures/tokens/",
            "-t",
            "exposures/apis/",
            "-json",
            "-o",
            str(out),
        ],
        timeout=1200,
    )
    return out


def _merge_secrets(ctx: ReconContext) -> Path:
    secrets_path = ctx.phase4 / "secrets.jsonl"
    merged: list[dict] = []

    for src in (
        ctx.phase4 / "js_secrets_raw.jsonl",
        ctx.phase4 / "trufflehog_local.jsonl",
        ctx.phase4 / "trufflehog_github.jsonl",
        ctx.phase4 / "nuclei_js.jsonl",
    ):
        for record in read_jsonl(src):
            merged.append(record)

    secrets_path.write_text(
        "\n".join(json.dumps(r) for r in merged) + ("\n" if merged else ""),
        encoding="utf-8",
    )
    return secrets_path


def _validate_secrets(ctx: ReconContext, secrets_path: Path) -> None:
    """Validate discovered credentials where possible."""
    records = read_jsonl(secrets_path)
    if not records:
        return

    for s in records:
        stype = (s.get("type") or s.get("DetectorName") or "").upper()
        value = str(s.get("value") or s.get("Raw") or "").strip()
        if not value:
            continue

        if "AWS" in stype and value.startswith("AKIA"):
            secret = str(s.get("secret") or s.get("Secret") or "")
            ctx.rate_limiter.wait()
            env = {
                **os.environ,
                "AWS_ACCESS_KEY_ID": value,
                "AWS_SECRET_ACCESS_KEY": secret or "invalid",
                "AWS_DEFAULT_REGION": "us-east-1",
            }
            result = run_cmd(
                ["aws", "sts", "get-caller-identity"],
                env=env,
                timeout=15,
            )
            s["validated"] = result.returncode == 0

        elif "GITHUB" in stype or stype == "GITHUB_TOKEN":
            ctx.rate_limiter.wait()
            status, body, _ = http_get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {value}"},
                rate_limiter=None,
            )
            s["validated"] = status == 200

    secrets_path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )


def run(ctx: ReconContext) -> None:
    phase_banner("JS Analysis + Secret Scanning", 4)

    js_path = _collect_js_files(ctx)
    _check_source_maps(ctx, js_path)
    download_dir, url_by_file = _download_js(ctx, js_path)
    _jsluice_extract(ctx, download_dir, url_by_file)
    _trufflehog_github(ctx)
    _trufflehog_scan(ctx, download_dir)
    _nuclei_js_scan(ctx, js_path)
    secrets_path = _merge_secrets(ctx)
    if is_intrusive(ctx.config):
        _validate_secrets(ctx, secrets_path)
    else:
        LOG.info("Secret validation skipped (needs allow_intrusive:true — auths to 3rd-party)")

    LOG.info(
        "Phase 4 complete: %d JS files, %d secrets",
        len(read_lines(js_path)),
        len(read_jsonl(secrets_path)),
    )
