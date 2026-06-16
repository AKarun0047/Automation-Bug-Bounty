"""Shared utilities for recon orchestration."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qs, urlparse

from recon.config import ReconConfig
from recon.scope import filter_in_scope, is_in_scope

LOG = logging.getLogger("recon")

INTERESTING_KEYWORDS = (
    "admin",
    "dashboard",
    "internal",
    "staging",
    "dev",
    "test",
    "beta",
    "api",
    "portal",
    "vpn",
    "sso",
    "auth",
    "login",
    "console",
    "manage",
    "backoffice",
)

STATIC_EXTENSIONS = re.compile(
    r"\.(css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|mp3|pdf)$",
    re.IGNORECASE,
)


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def tool_path(name: str, config: ReconConfig) -> str | None:
    """Resolve external tool binary; return None if not found."""
    candidate = config.tools_path / name
    if candidate.exists() and os.access(candidate, os.X_OK):
        return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    return None


def run_cmd(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    check: bool = False,
    stdin: str | bytes | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess; pass ``stdin`` to feed the process (e.g. jsluice reads JS from stdin)."""
    LOG.debug("Running: %s", " ".join(cmd))
    merged_env = {**os.environ, **(env or {})}
    text_mode = not isinstance(stdin, bytes)
    result = subprocess.run(
        cmd,
        cwd=cwd,
        timeout=timeout,
        env=merged_env,
        input=stdin,
        capture_output=True,
        text=text_mode,
        check=check,
    )
    if not text_mode:
        return subprocess.CompletedProcess(
            args=result.args,
            returncode=result.returncode,
            stdout=(result.stdout or b"").decode("utf-8", errors="replace"),
            stderr=(result.stderr or b"").decode("utf-8", errors="replace"),
        )
    return result


def run_parallel(
    tasks: Iterable[tuple[str, Callable[[], Any]]],
    max_workers: int = 8,
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(fn): name for name, fn in tasks}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                LOG.warning("Task %s failed: %s", name, exc)
                results[name] = None
    return results


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_lines(path: Path, lines: Iterable[str]) -> None:
    ensure_dir(path.parent)
    unique = list(dict.fromkeys(line.strip() for line in lines if line and line.strip()))
    path.write_text("\n".join(unique) + ("\n" if unique else ""), encoding="utf-8")


def append_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    ensure_dir(path.parent)
    with path.open("a", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            LOG.debug("Skipping invalid JSONL line in %s", path)
    return records


def filter_scope(lines: Iterable[str], config: ReconConfig) -> list[str]:
    kept, rejected = filter_in_scope(list(lines), config)
    if rejected:
        LOG.debug("Scope filter rejected %d hosts", len(rejected))
    return kept


def filter_target_subdomains(lines: Iterable[str], target: str | list[str]) -> list[str]:
    roots = target if isinstance(target, list) else [target]
    roots = [r.lower().strip() for r in roots if r.strip()]
    result: list[str] = []
    for line in lines:
        host = line.lower().strip()
        for root in roots:
            if host == root or host.endswith(f".{root}"):
                result.append(host)
                break
    return list(dict.fromkeys(result))


def is_interesting_url(url: str) -> bool:
    lower = url.lower()
    return any(kw in lower for kw in INTERESTING_KEYWORDS)


def extract_params(url: str) -> list[str]:
    parsed = urlparse(url)
    return list(parse_qs(parsed.query).keys())


def classify_id_type(values: list[str]) -> str | None:
    if not values:
        return None
    uuid_re = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    if all(v.isdigit() for v in values):
        return "sequential"
    if all(uuid_re.match(v) for v in values):
        return "uuid"
    if any(len(v) > 16 and not v.isdigit() for v in values):
        return "hash"
    return None


def http_get(
    url: str,
    timeout: int = 15,
    headers: dict[str, str] | None = None,
    rate_limiter: RateLimiter | None = None,
) -> tuple[int, str, dict[str, str]]:
    import requests

    if rate_limiter:
        rate_limiter.wait()
    try:
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        return resp.status_code, resp.text[:2000], dict(resp.headers)
    except requests.RequestException as exc:
        LOG.debug("HTTP GET failed for %s: %s", url, exc)
        return 0, "", {}


def curl_status(
    url: str,
    timeout: int = 15,
    extra_headers: list[str] | None = None,
    rate_limiter: RateLimiter | None = None,
) -> int:
    if rate_limiter:
        rate_limiter.wait()
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", str(timeout)]
    for header in extra_headers or []:
        cmd.extend(["-H", header])
    cmd.append(url)
    try:
        result = run_cmd(cmd, timeout=timeout + 5)
        code = result.stdout.strip()
        return int(code) if code.isdigit() else 0
    except (subprocess.SubprocessError, ValueError):
        return 0


def md5_short(value: str) -> str:
    import hashlib

    return hashlib.md5(value.encode()).hexdigest()[:8]


def phase_banner(phase: str, number: int) -> None:
    LOG.info("=" * 60)
    LOG.info("Phase %d — %s", number, phase)
    LOG.info("=" * 60)


def rate_sleep(requests_made: int, rate_limit: int, start_time: float) -> None:
    if rate_limit <= 0:
        return
    elapsed = time.time() - start_time
    expected = requests_made / rate_limit
    if expected > elapsed:
        time.sleep(expected - elapsed)


class RateLimiter:
    """Global request rate cap shared across phases."""

    def __init__(self, rate_limit: int) -> None:
        self.rate_limit = rate_limit
        self._count = 0
        self._start = time.time()

    def wait(self) -> None:
        self._count += 1
        rate_sleep(self._count, self.rate_limit, self._start)
