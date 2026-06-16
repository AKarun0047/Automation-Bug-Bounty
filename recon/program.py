"""Program registry — one folder per bug bounty program."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from recon.config import (
    DEFAULT_OUT_OF_SCOPE,
    DEFAULT_PHASES,
    PhaseToggles,
    ReconConfig,
    _compile_patterns,
    _expand_path,
    is_active,
)

LOG = logging.getLogger("recon.program")

DEFAULT_BUGBOUNTY_ROOT = Path.home() / "bugbounty"


@dataclass
class ProgramConfig:
    name: str
    platform: str = ""
    url: str = ""
    rewards: dict[str, int] = field(default_factory=dict)
    forbid_active: bool = False
    last_run: str | None = None
    program_dir: Path = field(default_factory=Path)
    recon: ReconConfig = field(default_factory=lambda: ReconConfig(targets=[], out_dir=Path(".")))

    @property
    def config_path(self) -> Path:
        return self.program_dir / "program.yaml"

    def p1_reward(self) -> int:
        return int(self.rewards.get("p1", 0) or 0)

    def days_since_last_run(self) -> int:
        if not self.last_run:
            return 9999
        try:
            last = date.fromisoformat(str(self.last_run)[:10])
            return (date.today() - last).days
        except ValueError:
            return 9999


def _read_host_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    hosts: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        hosts.append(line.split("/")[0])  # allow URL paths in scope files
    return list(dict.fromkeys(hosts))


def _read_out_of_scope(path: Path) -> set[str]:
    return set(_read_host_list(path))


def load_program(program_dir: Path, *, bugbounty_root: Path | None = None) -> ProgramConfig:
    """Load program.yaml + scope files from a program directory."""
    program_dir = program_dir.resolve()
    raw_path = program_dir / "program.yaml"
    if not raw_path.exists():
        raise FileNotFoundError(f"No program.yaml in {program_dir}")

    with raw_path.open(encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}

    name = str(raw.get("name") or program_dir.name)
    scope_file = _expand_path(raw.get("scope_file", "./scope.txt"), program_dir)
    oos_file = _expand_path(raw.get("out_of_scope_file", "./out-of-scope.txt"), program_dir)

    scope_roots = _read_host_list(scope_file)
    if not scope_roots:
        raise ValueError(f"{name}: scope file empty or missing — {scope_file}")

    oos_hosts = _read_out_of_scope(oos_file)
    bb_root = bugbounty_root or program_dir.parent.parent
    if bb_root.name != "bugbounty" and (program_dir.parent.parent / "resolvers.txt").exists():
        bb_root = program_dir.parent.parent

    date_str = datetime.now().strftime("%Y%m%d")
    runs_dir = program_dir / "runs" / date_str
    runs_dir.mkdir(parents=True, exist_ok=True)

    phases_raw = {**DEFAULT_PHASES, **(raw.get("phases") or {})}
    phases = PhaseToggles(**{k: bool(v) for k, v in phases_raw.items() if hasattr(PhaseToggles, k)})

    in_scope = _compile_patterns(raw.get("in_scope_regex") or [])
    oos_patterns = raw.get("out_of_scope_regex") or DEFAULT_OUT_OF_SCOPE
    out_of_scope = _compile_patterns(oos_patterns)

    resolvers = raw.get("resolvers")
    if resolvers:
        resolvers_path = _expand_path(resolvers, program_dir)
    elif (bb_root / "resolvers.txt").exists():
        resolvers_path = bb_root / "resolvers.txt"
    else:
        resolvers_path = _expand_path("./resolvers.txt", program_dir)

    wordlist = raw.get("wordlist_subdomains")
    if wordlist:
        wordlist_path = _expand_path(wordlist, program_dir)
    elif (bb_root / "wordlists" / "subdomains-top1m.txt").exists():
        wordlist_path = bb_root / "wordlists" / "subdomains-top1m.txt"
    else:
        wordlist_path = _expand_path("./wordlists/subdomains-top1m.txt", program_dir)

    tools_path = _expand_path(raw.get("tools_path", "~/.pdtm/go/bin"), program_dir)

    mode = str(raw.get("mode", "passive")).strip().lower()
    forbid_active = bool(raw.get("forbid_active", False))
    if forbid_active and mode == "active":
        LOG.warning("%s: forbid_active=true — forcing mode=passive", name)
        mode = "passive"

    recon = ReconConfig(
        targets=scope_roots,
        scope_roots=scope_roots,
        out_of_scope_hosts=oos_hosts,
        strict_scope=True,
        out_dir=runs_dir,
        threads=int(raw.get("threads", 50)),
        rate_limit=int(raw.get("rate_limit", 80)),
        resolvers=resolvers_path,
        wordlist_subdomains=wordlist_path,
        auth_cookies=str(raw.get("auth_cookies", "")).strip(),
        burp_collab=str(raw.get("burp_collab", "")).strip(),
        tools_path=tools_path,
        shodan_api_key=str(raw.get("shodan_api_key", "") or os.environ.get("SHODAN_API_KEY", "")).strip(),
        github_org=str(raw.get("github_org", "")).strip(),
        webhook_url=str(raw.get("webhook_url", "")).strip(),
        resume=bool(raw.get("resume", True)),
        mode=mode,
        allow_intrusive=bool(raw.get("allow_intrusive", False)),
        in_scope_regex=in_scope,
        out_of_scope_regex=out_of_scope,
        phases=phases,
        config_path=raw_path,
        program_name=name,
    )

    # Write run-specific recon config for audit trail.
    _write_run_config(runs_dir, raw, recon)

    return ProgramConfig(
        name=name,
        platform=str(raw.get("platform", "")),
        url=str(raw.get("url", "")),
        rewards=dict(raw.get("rewards") or {}),
        forbid_active=forbid_active,
        last_run=str(raw.get("last_run") or "") or None,
        program_dir=program_dir,
        recon=recon,
    )


def _write_run_config(runs_dir: Path, program_raw: dict, recon: ReconConfig) -> None:
    snapshot = {
        **{k: v for k, v in program_raw.items() if k != "phases"},
        "targets": recon.targets,
        "out_dir": str(recon.out_dir),
        "mode": recon.mode,
        "strict_scope": True,
        "scope_roots": recon.scope_roots,
    }
    (runs_dir / "recon.config.yaml").write_text(yaml.dump(snapshot, sort_keys=False), encoding="utf-8")


def load_all_programs(programs_dir: Path) -> list[ProgramConfig]:
    programs_dir = programs_dir.resolve()
    if not programs_dir.exists():
        return []
    programs: list[ProgramConfig] = []
    for entry in sorted(programs_dir.iterdir()):
        if not entry.is_dir():
            continue
        if not (entry / "program.yaml").exists():
            continue
        try:
            programs.append(load_program(entry))
        except (ValueError, FileNotFoundError) as exc:
            LOG.error("Skipping %s: %s", entry.name, exc)
    return programs


def program_priority(program: ProgramConfig) -> tuple[int, int]:
    """Higher P1 reward first; then longer since last run."""
    return (program.p1_reward(), program.days_since_last_run())


def filter_runnable(programs: list[ProgramConfig]) -> list[ProgramConfig]:
    """Skip programs that forbid active scanning when mode is active."""
    runnable: list[ProgramConfig] = []
    for p in programs:
        if p.forbid_active and is_active(p.recon):
            LOG.warning("Skipping %s — forbid_active and mode=active", p.name)
            continue
        runnable.append(p)
    return runnable


def update_last_run(program: ProgramConfig) -> None:
    """Persist last_run date to program.yaml."""
    path = program.config_path
    with path.open(encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}
    raw["last_run"] = date.today().isoformat()
    path.write_text(yaml.dump(raw, sort_keys=False), encoding="utf-8")
    program.last_run = raw["last_run"]
