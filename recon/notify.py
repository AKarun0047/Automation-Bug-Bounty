"""Webhook / Slack notification when recon completes."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import requests

LOG = logging.getLogger("recon.notify")


def send_completion(
    webhook_url: str,
    *,
    target: str,
    out_dir: Path,
    stats: dict | None = None,
    error: str | None = None,
) -> None:
    if not webhook_url:
        return

    status = "failed" if error else "complete"
    dump_path = out_dir / "DUMP.md"
    text_lines = [
        f"*Recon {status}*: `{target}`",
        f"Output: `{out_dir}`",
    ]
    if stats:
        text_lines.append(
            f"Subdomains: {stats.get('subdomains', '?')} | "
            f"Live: {stats.get('live_hosts', '?')} | "
            f"Findings: {stats.get('critical_high', '?')}"
        )
    if dump_path.exists():
        text_lines.append(f"DUMP: `{dump_path}`")
    if error:
        text_lines.append(f"Error: {error}")

    payload = {"text": "\n".join(text_lines)}

    try:
        resp = requests.post(webhook_url, json=payload, timeout=15)
        if not resp.ok:
            LOG.warning("Webhook returned %s: %s", resp.status_code, resp.text[:200])
    except requests.RequestException as exc:
        LOG.warning("Webhook notification failed: %s", exc)
