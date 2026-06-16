"""Cloud storage bucket probing — S3, GCS, Azure."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import requests

from recon.context import ReconContext
from recon.utils import phase_banner, write_lines

LOG = logging.getLogger("recon.phase_cloud")

# Bucket name candidates from target domain
def _bucket_names(target: str) -> list[str]:
    base = target.split(".")[0]
    parts = target.replace(".", "-").split("-")
    names = {
        target.replace(".", "-"),
        target.replace(".", ""),
        base,
        f"{base}-backup",
        f"{base}-dev",
        f"{base}-staging",
        f"{base}-prod",
        f"{base}-assets",
        f"{base}-media",
        f"{base}-static",
        f"{base}-uploads",
        f"{base}-data",
    }
    if len(parts) > 1:
        names.add("-".join(parts))
    return sorted(names)


def _probe_s3(name: str, ctx: ReconContext) -> dict | None:
    url = f"https://{name}.s3.amazonaws.com/"
    try:
        ctx.rate_limiter.wait()
        resp = requests.get(url, timeout=10, allow_redirects=True)
        if resp.status_code in (200, 403):
            listable = "ListBucketResult" in resp.text or "<Contents>" in resp.text
            return {
                "provider": "aws_s3",
                "bucket": name,
                "url": url,
                "status": resp.status_code,
                "listable": listable,
                "snippet": resp.text[:300],
            }
    except requests.RequestException:
        pass
    return None


def _probe_gcs(name: str, ctx: ReconContext) -> dict | None:
    url = f"https://storage.googleapis.com/{name}/"
    try:
        ctx.rate_limiter.wait()
        resp = requests.get(url, timeout=10)
        if resp.status_code in (200, 403):
            listable = "ListBucketResult" in resp.text or "<Contents>" in resp.text
            return {
                "provider": "gcs",
                "bucket": name,
                "url": url,
                "status": resp.status_code,
                "listable": listable,
                "snippet": resp.text[:300],
            }
    except requests.RequestException:
        pass
    return None


def _probe_azure(name: str, ctx: ReconContext) -> dict | None:
    url = f"https://{name}.blob.core.windows.net/?restype=container&comp=list"
    try:
        ctx.rate_limiter.wait()
        resp = requests.get(url, timeout=10)
        if resp.status_code in (200, 403):
            return {
                "provider": "azure_blob",
                "bucket": name,
                "url": url,
                "status": resp.status_code,
                "listable": "EnumerationResults" in resp.text,
                "snippet": resp.text[:300],
            }
    except requests.RequestException:
        pass
    return None


def run(ctx: ReconContext) -> None:
    phase_banner("Cloud Bucket Probing", 1)
    out_jsonl = ctx.phase1 / "cloud_buckets.jsonl"
    out_txt = ctx.phase1 / "cloud_buckets.txt"

    findings: list[dict] = []
    for name in _bucket_names(ctx.target):
        for probe in (_probe_s3, _probe_gcs, _probe_azure):
            result = probe(name, ctx)
            if result:
                findings.append(result)
                LOG.info(
                    "Cloud bucket: %s %s status=%s listable=%s",
                    result["provider"],
                    name,
                    result["status"],
                    result.get("listable"),
                )

    out_jsonl.write_text(
        "\n".join(json.dumps(f) for f in findings) + ("\n" if findings else ""),
        encoding="utf-8",
    )
    write_lines(
        out_txt,
        [f"{f['provider']}: {f['url']} status={f['status']} listable={f['listable']}" for f in findings],
    )
    LOG.info("Cloud bucket probe complete: %d hits", len(findings))
