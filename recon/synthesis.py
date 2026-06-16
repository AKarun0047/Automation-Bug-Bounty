"""Final synthesis — DUMP.md + dump.jsonl."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from recon.context import ReconContext
from recon.utils import read_jsonl, read_lines

LOG = logging.getLogger("recon.synthesis")


def _truncate(value: str, limit: int = 80) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _severity(record: dict) -> str:
    info = record.get("info") or {}
    return str(info.get("severity", record.get("severity", "unknown"))).lower()


def _nuclei_name(record: dict) -> str:
    info = record.get("info") or {}
    return str(info.get("name", record.get("template-id", record.get("templateID", "unknown"))))


def _find_previous_dump(ctx: ReconContext) -> Path | None:
    current = (ctx.out_dir / "dump.jsonl").resolve()
    candidates: list[Path] = []

    parent = ctx.out_dir.parent
    for pattern in (f"recon-{ctx.target}-*/dump.jsonl", f"*/dump.jsonl"):
        for path in parent.glob(pattern):
            if path.resolve() != current:
                candidates.append(path)

    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _format_verified_row(r: dict) -> str:
    ftype = r.get("type", r.get("template-id", "finding"))
    url = r.get("url") or r.get("host") or r.get("matched-at", "")
    conf = r.get("confidence", "")
    manual = r.get("manual_verify", "")
    extra = r.get("reason", "") or ", ".join(r.get("issues") or [])[:80]
    return f"| {conf} | {ftype} | {url} | {_truncate(str(extra or manual), 60)} |"


def _build_unverified_lines(ctx: ReconContext, verified: list[dict], **raw) -> list[str]:
    verified_urls = {r.get("url") or r.get("host") or r.get("matched-at") for r in verified}
    lines = ["# Unverified Findings — Manual Review", "", f"Target: {ctx.target}", ""]

    nuclei = raw["nuclei"]
    unverified_nuclei = [
        r for r in nuclei
        if _severity(r) in ("critical", "high", "medium")
        and (r.get("matched-at") or r.get("host")) not in verified_urls
    ]
    lines.extend(["## Nuclei (raw, not in verified set)", ""])
    if unverified_nuclei:
        for r in unverified_nuclei[:40]:
            lines.append(f"- [{_severity(r)}] {_nuclei_name(r)} @ {r.get('matched-at', r.get('host', ''))}")
    else:
        lines.append("_None._")

    ssrf_urls = raw["ssrf_urls"]
    confirmed_urls = {r.get("original_url") for r in raw["ssrf_confirmed"] if r.get("confirmed")}
    lines.extend(["", "## SSRF Candidates (not confirmed)", ""])
    for u in ssrf_urls[:30]:
        if u not in confirmed_urls:
            lines.append(f"- {u}")

    secrets = raw["secrets"]
    lines.extend(["", "## Secrets (unvalidated)", ""])
    for s in secrets[:30]:
        if not s.get("validated") and not s.get("verified"):
            stype = s.get("type") or s.get("DetectorName", "unknown")
            lines.append(f"- {stype}: {_truncate(str(s.get('value') or s.get('Raw', '')), 30)}")

    jwt_findings = raw["jwt_findings"]
    lines.extend(["", "## JWT (manual tamper required)", ""])
    for j in jwt_findings[:20]:
        lines.append(f"- `{j.get('source')}` alg={j.get('alg')} — {', '.join(j.get('issues') or [])}")

    return lines


def _build_dropped_lines(ctx: ReconContext, dropped: list[dict]) -> list[str]:
    lines = [
        "# Dropped Findings — False Positive Audit Trail",
        "",
        f"Target: {ctx.target}",
        "",
        "| Type | Reason | Detail |",
        "|------|--------|--------|",
    ]
    for d in dropped[:100]:
        dtype = d.get("type", "?")
        reason = d.get("reason", "")
        detail = d.get("url") or d.get("id") or d.get("bucket") or d.get("detector") or ""
        lines.append(f"| {dtype} | {reason} | {detail} |")
    if not dropped:
        lines.append("| — | — | No findings dropped |")
    return lines


def run(ctx: ReconContext) -> tuple[Path, Path]:
    LOG.info("Generating synthesis output...")
    dump_md = ctx.out_dir / "DUMP.md"
    unverified_md = ctx.out_dir / "unverified.md"
    dropped_md = ctx.out_dir / "dropped.md"
    dump_jsonl = ctx.out_dir / "dump.jsonl"

    verified = read_jsonl(ctx.out_dir / "verified_findings.jsonl")
    dropped = read_jsonl(ctx.out_dir / "dropped_findings.jsonl")
    confirmed_v = [r for r in verified if r.get("confidence") == "CONFIRMED"]
    likely_v = [r for r in verified if r.get("confidence") == "LIKELY"]

    subdomains = read_lines(ctx.phase1 / "subdomains.txt")
    assets = read_jsonl(ctx.phase2 / "assets.jsonl")
    urls_clean = read_lines(ctx.phase3 / "urls_clean.txt")
    js_files = read_lines(ctx.phase4 / "js_files.txt")
    secrets = read_jsonl(ctx.phase4 / "secrets.jsonl")
    nuclei = read_jsonl(ctx.phase6 / "nuclei_findings.jsonl")
    takeovers = read_lines(ctx.phase6 / "takeovers.txt")
    actuator = read_lines(ctx.phase6 / "actuator_exposed.txt")
    bypass6 = read_lines(ctx.phase6 / "bypass_found.txt")
    source_maps = read_lines(ctx.phase4 / "source_maps_found.txt")
    api_surface = read_jsonl(ctx.phase7 / "api_surface.jsonl")
    auth_endpoints = read_lines(ctx.phase7 / "auth_endpoints.txt")
    cors = read_lines(ctx.phase7 / "cors_check.txt")
    graphql = read_jsonl(ctx.phase7 / "graphql_introspection.jsonl")
    params_classified = read_jsonl(ctx.phase5 / "params_classified.jsonl")
    ssrf_confirmed = read_jsonl(ctx.phase5 / "ssrf_confirmed.jsonl")
    cache_poison = read_lines(ctx.phase6 / "cache_poison.txt")
    host_poison = read_lines(ctx.phase7 / "host_header_injection.txt")
    cloud_buckets = read_jsonl(ctx.phase1 / "cloud_buckets.jsonl")
    shodan_favicon = read_jsonl(ctx.phase2 / "shodan_favicon.jsonl")
    jwt_findings = read_jsonl(ctx.phase7 / "jwt_found.jsonl")

    critical_high = [r for r in nuclei if _severity(r) in ("critical", "high")]

    prev_dump_path = _find_previous_dump(ctx)
    new_findings: list[dict] = []
    if prev_dump_path:
        try:
            prev = json.loads(prev_dump_path.read_text(encoding="utf-8"))
            prev_keys = {
                r.get("matched-at") or r.get("matched") or json.dumps(r, sort_keys=True)
                for r in prev.get("critical_findings", [])
            }
            new_findings = [
                r
                for r in critical_high
                if (r.get("matched-at") or r.get("matched") or json.dumps(r, sort_keys=True)) not in prev_keys
            ]
        except (json.JSONDecodeError, OSError):
            LOG.debug("Could not load previous dump for delta: %s", prev_dump_path)
    interesting_assets = [a for a in assets if a.get("interesting")]
    non_std_ports: set[str] = set()
    for a in assets:
        url = a.get("url", "")
        if any(f":{p}" in url for p in ("8080", "9090", "3000", "8443", "8000")):
            non_std_ports.add(url)

    cdn_hosts = [a for a in assets if a.get("cdn")]
    direct_ip = [a for a in assets if not a.get("cdn")]

    idor_seq = [p for p in params_classified if p.get("id_type") == "sequential"]
    ssrf_urls = read_lines(ctx.phase5 / "ssrf.txt")
    sqli_urls = read_lines(ctx.phase5 / "sqli.txt")
    redirect_urls = read_lines(ctx.phase5 / "redirect.txt")

    generated = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = [
        f"# Recon Dump: {ctx.target}",
        f"Generated: {generated} | Scope: {', '.join(ctx.config.targets)} | Mode: {ctx.config.mode}",
        "",
        f"**Confirmed: {len(confirmed_v)} | Likely: {len(likely_v)} | Dropped FPs: {len(dropped)}**",
        "",
        "---",
        "",
        "## 0. Verified Findings (paste to Claude)",
        "",
        "| Confidence | Type | URL/Host | Notes |",
        "|------------|------|----------|-------|",
    ]

    for r in (confirmed_v + likely_v)[:50]:
        lines.append(_format_verified_row(r))

    if not confirmed_v and not likely_v:
        lines.append("| — | — | — | _Run verify phase or no findings passed filters_ |")

    lines.extend([
        "",
        "## 1. Target Overview",
        "",
        "| Property | Value |",
        "|----------|-------|",
        f"| Base domain | {ctx.target} |",
        f"| Total subdomains found | {len(subdomains)} |",
        f"| Live hosts | {len(assets)} |",
        f"| Total URLs | {len(urls_clean)} |",
        f"| JS files | {len(js_files)} |",
        f"| Open ports (non-standard) | {', '.join(sorted(non_std_ports)[:10]) or 'none detected'} |",
        f"| CDN | {len(cdn_hosts)} hosts behind CDN |",
        f"| Direct IP (no CDN) | {len(direct_ip)} hosts |",
        "",
        "## 2. Tech Stack (per host)",
        "",
        "| Host | Framework | Server | CDN | WAF | Notes |",
        "|------|-----------|--------|-----|-----|-------|",
    ])

    for a in assets[:50]:
        url = a.get("url", "")
        tech = ", ".join(a.get("tech") or []) or "-"
        server = a.get("webserver") or a.get("server") or "-"
        cdn = "Yes" if a.get("cdn") else "No"
        waf = a.get("waf") or a.get("cdn_name") or a.get("cdn-name") or "-"
        notes = a.get("notes") or ("interesting" if a.get("interesting") else "")
        lines.append(f"| {url} | {tech} | {server} | {cdn} | {waf} | {notes} |")

    lines.extend(["", "## 3. Critical / High Findings", ""])
    if critical_high:
        lines.extend(
            [
                "| Host | Finding | Template | Severity | Matched-At | PoC Request |",
                "|------|---------|----------|----------|------------|-------------|",
            ]
        )
        for r in critical_high[:30]:
            host = r.get("host", "")
            name = _nuclei_name(r)
            template = r.get("template-id") or r.get("templateID", "")
            sev = _severity(r)
            matched = r.get("matched-at") or r.get("matched", "")
            req = _truncate(str(r.get("request", "")), 60)
            lines.append(f"| {host} | {name} | {template} | {sev} | {matched} | `{req}` |")
    else:
        lines.append("_No critical/high nuclei findings._")

    if new_findings:
        lines.extend(["", "## NEW Since Last Run", ""])
        lines.extend(
            ["| Host | Finding | Severity | Matched-At |", "|------|---------|----------|------------|"]
        )
        for r in new_findings[:30]:
            lines.append(
                f"| {r.get('host', '')} | {_nuclei_name(r)} | {_severity(r)} | {r.get('matched-at', '')} |"
            )
    elif prev_dump_path:
        lines.extend(["", "## NEW Since Last Run", "", "_No new critical/high findings since last run._"])

    if actuator:
        lines.extend(["", "### Spring Boot Actuator", ""])
        for line in actuator:
            lines.append(f"- {line}")

    lines.extend(["", "## 4. Attack Surface — Interesting Endpoints", ""])
    lines.extend(["| URL | Status | Auth? | Notes |", "|-----|--------|-------|-------|"])
    for a in interesting_assets[:40]:
        url = a.get("url", "")
        status = a.get("status_code") or a.get("status-code", "")
        auth = "Likely" if status in (401, 403) else "No"
        lines.append(f"| {url} | {status} | {auth} | flagged interesting |")

    for g in graphql:
        if g.get("status") == 200 and "__schema" in str(g.get("body", "")):
            lines.append(f"| {g.get('url')} | 200 | No | GraphQL introspection enabled |")

    lines.extend(["", "## 5. Parameters by Vulnerability Class", ""])
    lines.extend(["### IDOR Candidates (sequential IDs)", ""])
    for p in idor_seq[:20]:
        lines.append(f"- {p.get('url')}")

    lines.extend(["", "### SSRF Candidates", ""])
    for u in ssrf_urls[:20]:
        lines.append(f"- {u}")

    lines.extend(["", "### SQLi Candidates", ""])
    for u in sqli_urls[:20]:
        lines.append(f"- {u}")

    lines.extend(["", "### Open Redirect Candidates", ""])
    for u in redirect_urls[:20]:
        lines.append(f"- {u}")

    lines.extend(["", "## 6. Secrets Found", ""])
    if secrets:
        lines.extend(
            ["| Type | Value (partial) | Verified | Source File |", "|------|----------------|----------|-------------|"]
        )
        for s in secrets[:20]:
            stype = s.get("type") or s.get("DetectorName", "unknown")
            value = _truncate(str(s.get("value") or s.get("Raw", "")), 20)
            verified = s.get("validated", s.get("verified") or s.get("Verified", False))
            source = s.get("source_url") or s.get("SourceMetadata", "")
            lines.append(f"| {stype} | {value} | {verified} | {source} |")
    else:
        lines.append("_No secrets detected._")

    lines.extend(["", "## 7. API Versions", ""])
    lines.extend(["| Endpoint | v1 Exists? | v1 Auth Required? |", "|----------|-----------|-------------------|"])
    for api in api_surface[:30]:
        if api.get("version") == "v2" or "/v2/" in api.get("url", ""):
            v1_url = api.get("url", "").replace("/v2/", "/v1/")
            lines.append(
                f"| {api.get('url')} | {api.get('v1_exists')} | {api.get('v1_auth_required')} |"
            )

    lines.extend(["", "## 8. CORS Issues", ""])
    cors_issues = [c for c in cors if "*" in c or "evil.com" in c.lower()]
    if cors_issues:
        lines.extend(["| Endpoint | Detail |", "|----------|--------|"])
        for c in cors_issues[:20]:
            parts = c.split(" | ")
            lines.append(f"| {parts[0] if parts else c} | {c} |")
    else:
        lines.append("_No obvious CORS misconfigurations._")

    lines.extend(["", "## 9. CNAME Takeover Candidates", ""])
    if takeovers:
        for t in takeovers:
            lines.append(f"- {t}")
    else:
        lines.append("_None detected._")

    lines.extend(["", "## 10. Source Maps", ""])
    if source_maps:
        for sm in source_maps:
            lines.append(f"- **CRITICAL**: {sm}")
    else:
        lines.append("_None found._")

    lines.extend(["", "## 11. Auth Surface", ""])
    lines.extend(["| Endpoint | Notes |", "|----------|-------|"])
    for ep in auth_endpoints[:30]:
        lines.append(f"| {ep} | auth-related |")

    lines.extend(["", "## 12. SSRF Confirmed Probes", ""])
    ssrf_hits = [r for r in ssrf_confirmed if r.get("confirmed")]
    if ssrf_hits:
        for r in ssrf_hits[:15]:
            lines.append(
                f"- **CONFIRMED**: `{r.get('original_url')}` param `{r.get('param')}` payload `{r.get('payload')}`"
            )
    elif ssrf_confirmed:
        lines.append(f"_{len(ssrf_confirmed)} SSRF probes — no confirmed metadata leaks._")
    else:
        lines.append("_No SSRF probes run._")

    lines.extend(["", "## 13. Cloud Buckets", ""])
    if cloud_buckets:
        for b in cloud_buckets[:15]:
            lines.append(f"- {b.get('provider')}: `{b.get('url')}` listable={b.get('listable')}")
    else:
        lines.append("_No exposed cloud buckets found._")

    lines.extend(["", "## 14. Shodan Favicon Matches", ""])
    if shodan_favicon:
        for s in shodan_favicon[:10]:
            lines.append(f"- hash `{s.get('favicon_hash')}` → {s.get('shodan_total')} Shodan hosts")
    else:
        lines.append("_No Shodan favicon lookups (set shodan_api_key)._")

    lines.extend(["", "## 15. JWT Analysis", ""])
    if jwt_findings:
        for j in jwt_findings[:15]:
            issues = ", ".join(j.get("issues") or []) or "none"
            lines.append(f"- `{j.get('source')}` alg={j.get('alg')} — {issues}")
    else:
        lines.append("_No JWTs found in auth surface._")

    lines.extend(["", "## 16. Host Header Poisoning (Password Reset)", ""])
    if host_poison:
        for h in host_poison[:15]:
            lines.append(f"- {h}")
    else:
        lines.append("_No password-reset host header reflections._")

    lines.extend(["", "## 17. Cache Poisoning", ""])
    if cache_poison:
        for c in cache_poison[:15]:
            lines.append(f"- {c}")
    else:
        lines.append("_No cache poisoning candidates._")

    lines.extend(["", "## 18. Header Bypass Candidates", ""])
    for b in bypass6[:20]:
        lines.append(f"- {b}")

    lines.extend(
        [
            "",
            "## 19. Raw HTTP Samples (for PoC authoring)",
            "",
        ]
    )
    for r in critical_high[:5]:
        req = r.get("request", "")
        resp = r.get("response", "")
        if req:
            lines.extend(["```http", str(req)[:1500], "", str(resp)[:1500], "```", ""])

    lines.extend(
        [
            "",
            "---",
            "",
            "## Ask Claude",
            "",
            "Paste this file and say:",
            "",
            f'> "Here is recon output for {ctx.target}. For each finding, write a working PoC HTTP request. '
            "Classify by severity. Identify any vulnerability chains. Flag what needs manual verification.\"",
            "",
        ]
    )

    dump_md.write_text("\n".join(lines), encoding="utf-8")

    unverified_md.write_text(
        "\n".join(
            _build_unverified_lines(
                ctx,
                verified,
                nuclei=nuclei,
                ssrf_urls=ssrf_urls,
                ssrf_confirmed=ssrf_confirmed,
                secrets=secrets,
                jwt_findings=jwt_findings,
            )
        ),
        encoding="utf-8",
    )
    dropped_md.write_text("\n".join(_build_dropped_lines(ctx, dropped)), encoding="utf-8")

    summary = {
        "target": ctx.target,
        "generated": generated,
        "mode": ctx.config.mode,
        "allow_intrusive": ctx.config.allow_intrusive,
        "verification": {
            "confirmed": len(confirmed_v),
            "likely": len(likely_v),
            "dropped": len(dropped),
        },
        "stats": {
            "subdomains": len(subdomains),
            "live_hosts": len(assets),
            "urls": len(urls_clean),
            "js_files": len(js_files),
            "secrets": len(secrets),
            "nuclei_findings": len(nuclei),
            "critical_high": len(critical_high),
        },
        "critical_findings": critical_high[:50],
        "interesting_assets": interesting_assets[:50],
        "secrets": secrets[:50],
        "api_surface": api_surface[:50],
        "takeovers": takeovers,
        "source_maps": source_maps,
        "ssrf_confirmed": ssrf_confirmed[:30],
        "host_header_poison": host_poison[:20],
        "cache_poison": cache_poison[:20],
        "cloud_buckets": cloud_buckets[:30],
        "shodan_favicon": shodan_favicon[:20],
        "jwt_findings": jwt_findings[:30],
        "new_since_last_run": new_findings[:50],
        "verified_findings": verified[:50],
        "dropped_findings": dropped[:50],
    }
    dump_jsonl.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    LOG.info("Synthesis complete: %s, %s, %s, %s", dump_md, unverified_md, dropped_md, dump_jsonl)
    return dump_md, dump_jsonl
