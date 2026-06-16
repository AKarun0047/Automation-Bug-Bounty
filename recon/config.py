"""Configuration loading and validation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
import os

import yaml


DEFAULT_PHASES = {
    "asset_discovery": True,
    "cloud_buckets": True,
    "http_probe": True,
    "url_harvest": True,
    "js_analysis": True,
    "param_discovery": True,
    "vuln_scan": True,
    "auth_surface": True,
    "jwt_analysis": True,
    "verify": True,
    "screenshots": True,
}

DEFAULT_OUT_OF_SCOPE = [
    r".*\.s3\.amazonaws\.com",
    r".*\.cloudfront\.net",
    r".*stripe\.com",
    r".*salesforce\.com",
]


@dataclass
class PhaseToggles:
    asset_discovery: bool = True
    cloud_buckets: bool = True
    http_probe: bool = True
    url_harvest: bool = True
    js_analysis: bool = True
    param_discovery: bool = True
    vuln_scan: bool = True
    auth_surface: bool = True
    jwt_analysis: bool = True
    verify: bool = True
    screenshots: bool = True


@dataclass
class ReconConfig:
    targets: list[str]
    out_dir: Path
    threads: int = 50
    rate_limit: int = 150
    resolvers: Path = Path("./resolvers.txt")
    wordlist_subdomains: Path = Path("./wordlists/subdomains-top1m.txt")
    auth_cookies: str = ""
    burp_collab: str = ""
    tools_path: Path = Path.home() / ".pdtm" / "go" / "bin"
    shodan_api_key: str = ""
    github_org: str = ""
    webhook_url: str = ""
    resume: bool = True
    mode: str = "passive"
    allow_intrusive: bool = False
    scope_roots: list[str] = field(default_factory=list)
    out_of_scope_hosts: set[str] = field(default_factory=set)
    strict_scope: bool = False
    in_scope_regex: list[re.Pattern[str]] = field(default_factory=list)
    out_of_scope_regex: list[re.Pattern[str]] = field(default_factory=list)
    phases: PhaseToggles = field(default_factory=PhaseToggles)
    config_path: Path | None = None
    program_name: str = ""

    @property
    def primary_target(self) -> str:
        return self.targets[0] if self.targets else ""


def _compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(p) for p in patterns]


def _expand_path(value: str | Path, base: Path) -> Path:
    path = Path(str(value).replace("~", str(Path.home())))
    if not path.is_absolute():
        path = (base / path).resolve()
    return path


def _read_host_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    hosts: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            hosts.append(line.split("/")[0])
    return list(dict.fromkeys(hosts))


def load_config(config_path: Path) -> ReconConfig:
    config_path = config_path.resolve()
    base = config_path.parent

    with config_path.open(encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}

    targets: list[str] = []
    if raw.get("scope_file"):
        scope = _expand_path(raw["scope_file"], base)
        if scope.exists():
            targets = [
                line.strip()
                for line in scope.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
    if raw.get("target"):
        targets.append(str(raw["target"]).strip())

    targets = list(dict.fromkeys(t.strip().lower() for t in targets if t.strip()))
    if not targets:
        raise ValueError("No targets configured — set 'target' or 'scope_file' in config")

    scope_roots = list(targets)
    oos_hosts: set[str] = set()
    if raw.get("out_of_scope_file"):
        oos_hosts = set(_read_host_lines(_expand_path(raw["out_of_scope_file"], base)))

    strict_scope = bool(raw.get("strict_scope", False))
    date_str = datetime.now().strftime("%Y%m%d")
    out_dir_raw = raw.get("out_dir") or f"./recon-{scope_roots[0]}-{date_str}"
    out_dir = _expand_path(out_dir_raw, base)

    phases_raw = {**DEFAULT_PHASES, **(raw.get("phases") or {})}
    phases = PhaseToggles(**{k: bool(v) for k, v in phases_raw.items() if hasattr(PhaseToggles, k)})

    in_scope = _compile_patterns(raw.get("in_scope_regex") or [])
    out_of_scope = _compile_patterns(raw.get("out_of_scope_regex") or DEFAULT_OUT_OF_SCOPE)

    tools_path = _expand_path(raw.get("tools_path", "~/.pdtm/go/bin"), base)

    return ReconConfig(
        targets=targets,
        scope_roots=scope_roots,
        out_of_scope_hosts=oos_hosts,
        strict_scope=strict_scope,
        out_dir=out_dir,
        threads=int(raw.get("threads", 50)),
        rate_limit=int(raw.get("rate_limit", 150)),
        resolvers=_expand_path(raw.get("resolvers", "./resolvers.txt"), base),
        wordlist_subdomains=_expand_path(
            raw.get("wordlist_subdomains", "./wordlists/subdomains-top1m.txt"), base
        ),
        auth_cookies=str(raw.get("auth_cookies", "")).strip(),
        burp_collab=str(raw.get("burp_collab", "")).strip(),
        tools_path=tools_path,
        shodan_api_key=str(raw.get("shodan_api_key", "") or os.environ.get("SHODAN_API_KEY", "")).strip(),
        github_org=str(raw.get("github_org", "")).strip(),
        webhook_url=str(raw.get("webhook_url", "")).strip(),
        resume=bool(raw.get("resume", True)),
        mode=str(raw.get("mode", "passive")).strip().lower(),
        allow_intrusive=bool(raw.get("allow_intrusive", False)),
        in_scope_regex=in_scope,
        out_of_scope_regex=out_of_scope,
        phases=phases,
        config_path=config_path,
        program_name=str(raw.get("name", "")).strip(),
    )


def out_dir_for_target(config: ReconConfig, target: str) -> Path:
    """Per-target output directory; subdir when multiple targets."""
    if len(config.targets) == 1:
        return config.out_dir
    return config.out_dir / target


def github_org_for_target(config: ReconConfig, target: str) -> str:
    if config.github_org:
        return config.github_org
    return target.split(".")[0]


def is_in_scope(url_or_host: str, config: ReconConfig) -> bool:
    from recon.scope import is_in_scope as _check

    return _check(url_or_host, config)


def assert_in_scope(host: str, config: ReconConfig) -> None:
    from recon.scope import assert_in_scope as _assert

    _assert(host, config)


# Re-export for convenience
from recon.scope import ScopeViolation  # noqa: E402


def is_active(config: ReconConfig) -> bool:
    return config.mode == "active"


def is_intrusive(config: ReconConfig) -> bool:
    return config.mode == "active" and config.allow_intrusive
