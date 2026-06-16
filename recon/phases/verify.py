"""Verification engine — re-probe findings, assign confidence, kill false positives."""

from __future__ import annotations

import json
import logging

from recon.context import ReconContext
from recon.utils import http_get, phase_banner, read_jsonl, read_lines

LOG = logging.getLogger("recon.verify")

CONFIRMED = "CONFIRMED"
LIKELY = "LIKELY"
UNVERIFIED = "UNVERIFIED"


def _verify_cors(ctx: ReconContext) -> tuple[list[dict], list[dict]]:
    """Real CORS bug needs: ACAO reflects our origin (not *) AND credentials:true."""
    kept, dropped = [], []
    for line in read_lines(ctx.phase7 / "cors_check.txt"):
        parts = dict(p.split("=", 1) for p in line.split(" | ") if "=" in p)
        url = line.split(" | ")[0]
        acao = parts.get("ACAO", "").strip()
        origin = parts.get("origin", "").strip()
        if not acao:
            dropped.append({"type": "cors", "url": url, "reason": "no ACAO header"})
            continue
        if acao == "*":
            dropped.append({"type": "cors", "url": url, "reason": "wildcard ACAO — not exploitable w/ creds"})
            continue
        if origin not in acao:
            dropped.append({"type": "cors", "url": url, "reason": "ACAO does not reflect attacker origin"})
            continue
        ctx.rate_limiter.wait()
        _s, _b, headers = http_get(url, headers={"Origin": origin}, rate_limiter=None)
        creds = headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        rec = {
            "type": "cors",
            "url": url,
            "acao": acao,
            "origin": origin,
            "credentials": creds,
            "confidence": CONFIRMED if creds else LIKELY,
            "fp_risk": "LOW" if creds else "MEDIUM",
            "manual_verify": f"curl -s -I '{url}' -H 'Origin: {origin}' | grep -i access-control",
        }
        kept.append(rec)
    return kept, dropped


def _verify_bypass(ctx: ReconContext) -> tuple[list[dict], list[dict]]:
    """403 bypass real only if body differs and isn't a login page."""
    kept, dropped = [], []
    for line in read_lines(ctx.phase6 / "bypass_found.txt"):
        try:
            url = line.split("BYPASS:")[1].split(" via ")[0].strip()
            header = line.split(" via ")[1].split(" → ")[0].strip()
        except IndexError:
            continue
        if ": " not in header:
            continue
        hname, hval = header.split(": ", 1)
        ctx.rate_limiter.wait()
        status, body, _h = http_get(url, headers={hname: hval}, rate_limiter=None)
        if len(body) < 500:
            dropped.append({"type": "403_bypass", "url": url, "reason": f"body too small ({len(body)}b)"})
            continue
        if "login" in body.lower() or "sign in" in body.lower():
            dropped.append({"type": "403_bypass", "url": url, "reason": "served login page"})
            continue
        kept.append(
            {
                "type": "403_bypass",
                "url": url,
                "header": header,
                "status": status,
                "body_size": len(body),
                "confidence": LIKELY,
                "fp_risk": "MEDIUM",
                "manual_verify": f"curl -s '{url}' -H '{header}' | head -c 500",
            }
        )
    return kept, dropped


def _verify_secrets(ctx: ReconContext) -> tuple[list[dict], list[dict]]:
    kept, dropped = [], []
    for s in read_jsonl(ctx.phase4 / "secrets.jsonl"):
        validated = s.get("validated")
        stype = (s.get("type") or s.get("DetectorName") or "").upper()
        if validated is True:
            s.update({"confidence": CONFIRMED, "fp_risk": "LOW"})
            kept.append(s)
        elif validated is False:
            dropped.append({"type": "secret", "detector": stype, "reason": "validation failed — dead key"})
        else:
            verified_flag = s.get("verified") or s.get("Verified")
            if verified_flag:
                s.update({"confidence": LIKELY, "fp_risk": "MEDIUM"})
                kept.append(s)
            else:
                dropped.append({"type": "secret", "detector": stype, "reason": "unvalidated + low confidence"})
    return kept, dropped


def _verify_nuclei(ctx: ReconContext) -> tuple[list[dict], list[dict]]:
    kept, dropped = [], []
    for r in read_jsonl(ctx.phase6 / "nuclei_findings.jsonl"):
        sev = str((r.get("info") or {}).get("severity", "")).lower()
        extracted = r.get("extracted-results") or r.get("extracted_results")
        matcher = r.get("matcher-status", True)
        if not matcher:
            dropped.append({"type": "nuclei", "id": r.get("template-id"), "reason": "matcher-status false"})
            continue
        if sev in ("critical", "high"):
            r.update(
                {
                    "confidence": CONFIRMED if extracted else LIKELY,
                    "fp_risk": "LOW" if extracted else "MEDIUM",
                }
            )
            kept.append(r)
        elif sev == "medium" and extracted:
            r.update({"confidence": LIKELY, "fp_risk": "MEDIUM"})
            kept.append(r)
        else:
            dropped.append(
                {
                    "type": "nuclei",
                    "id": r.get("template-id"),
                    "reason": f"{sev} w/o extracted-results",
                }
            )
    return kept, dropped


def _verify_buckets(ctx: ReconContext) -> tuple[list[dict], list[dict]]:
    kept, dropped = [], []
    for b in read_jsonl(ctx.phase1 / "cloud_buckets.jsonl"):
        if b.get("listable"):
            b.update({"confidence": CONFIRMED, "fp_risk": "LOW"})
            kept.append(b)
        else:
            dropped.append(
                {
                    "type": "bucket",
                    "bucket": b.get("bucket"),
                    "reason": "exists but not listable (403)",
                }
            )
    return kept, dropped


def run(ctx: ReconContext) -> None:
    phase_banner("Verification", 10)

    kept_all, dropped_all = [], []
    for fn in (_verify_cors, _verify_bypass, _verify_secrets, _verify_nuclei, _verify_buckets):
        try:
            k, d = fn(ctx)
            kept_all.extend(k)
            dropped_all.extend(d)
        except Exception as exc:
            LOG.warning("Verifier %s failed: %s", fn.__name__, exc)

    confirmed = [r for r in kept_all if r.get("confidence") == CONFIRMED]
    likely = [r for r in kept_all if r.get("confidence") == LIKELY]

    out_v = ctx.out_dir / "verified_findings.jsonl"
    out_d = ctx.out_dir / "dropped_findings.jsonl"
    out_v.write_text("\n".join(json.dumps(r) for r in kept_all) + ("\n" if kept_all else ""), encoding="utf-8")
    out_d.write_text("\n".join(json.dumps(r) for r in dropped_all) + ("\n" if dropped_all else ""), encoding="utf-8")

    LOG.info(
        "Verification: %d confirmed, %d likely, %d dropped (FP)",
        len(confirmed),
        len(likely),
        len(dropped_all),
    )
