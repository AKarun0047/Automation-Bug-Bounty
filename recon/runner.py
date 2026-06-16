"""Main recon orchestrator — runs all phases sequentially."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from recon.checkpoint import Checkpoint
from recon.config import ReconConfig, load_config, out_dir_for_target
from recon.context import ReconContext
from recon.notify import send_completion
from recon.phases import (
    asset_discovery,
    auth_surface,
    cloud_buckets,
    http_probe,
    js_analysis,
    jwt_analysis,
    param_discovery,
    url_harvest,
    verify,
    vuln_scan,
)
from recon.synthesis import run as run_synthesis
from recon.utils import read_jsonl, read_lines

LOG = logging.getLogger("recon.runner")

PHASES = [
    ("asset_discovery", asset_discovery.run, 1),
    ("cloud_buckets", cloud_buckets.run, 2),
    ("http_probe", http_probe.run, 3),
    ("url_harvest", url_harvest.run, 4),
    ("js_analysis", js_analysis.run, 5),
    ("param_discovery", param_discovery.run, 6),
    ("vuln_scan", vuln_scan.run, 7),
    ("auth_surface", auth_surface.run, 8),
    ("jwt_analysis", jwt_analysis.run, 9),
    ("verify", verify.run, 10),
]


def _copy_config(config: ReconConfig, ctx: ReconContext) -> None:
    if config.config_path and config.config_path.exists():
        dest = ctx.out_dir / "recon.config.yaml"
        shutil.copy2(config.config_path, dest)


def _collect_stats(ctx: ReconContext) -> dict:
    nuclei = read_jsonl(ctx.phase6 / "nuclei_findings.jsonl")
    critical_high = [
        r
        for r in nuclei
        if str((r.get("info") or {}).get("severity", "")).lower() in ("critical", "high")
    ]
    return {
        "subdomains": len(read_lines(ctx.phase1 / "subdomains.txt")),
        "live_hosts": len(read_jsonl(ctx.phase2 / "assets.jsonl")),
        "urls": len(read_lines(ctx.phase3 / "urls_clean.txt")),
        "critical_high": len(critical_high),
    }


def _run_target(config: ReconConfig, target: str, *, resume: bool | None = None) -> ReconContext:
    out_dir = out_dir_for_target(config, target)
    ctx = ReconContext.for_target(config, target, out_dir)
    _copy_config(config, ctx)

    use_resume = config.resume if resume is None else resume
    checkpoint = Checkpoint(ctx.out_dir, target, enabled=use_resume)

    LOG.info(
        "Starting recon for %s → %s (resume=%s, mode=%s, intrusive=%s)",
        target,
        ctx.out_dir,
        use_resume,
        config.mode,
        config.allow_intrusive,
    )

    error: str | None = None
    try:
        for phase_name, phase_fn, number in PHASES:
            if not getattr(config.phases, phase_name, True):
                LOG.info("Skipping phase %d (%s) — disabled in config", number, phase_name)
                continue
            if checkpoint.is_done(phase_name):
                LOG.info("Skipping phase %d (%s) — checkpoint", number, phase_name)
                continue
            try:
                phase_fn(ctx)
                checkpoint.mark_done(phase_name)
            except Exception as exc:
                LOG.error("Phase %d (%s) failed: %s", number, phase_name, exc, exc_info=True)
                error = f"phase {phase_name}: {exc}"
                raise

        if not checkpoint.is_done("synthesis"):
            run_synthesis(ctx)
            checkpoint.mark_done("synthesis")

        LOG.info("Recon complete for %s. Output: %s", target, ctx.out_dir / "DUMP.md")
    except Exception as exc:
        error = str(exc)
        raise
    finally:
        stats = _collect_stats(ctx) if (ctx.out_dir / "phase1_assets").exists() else {}
        send_completion(
            config.webhook_url,
            target=target,
            out_dir=ctx.out_dir,
            stats=stats,
            error=error,
        )

    return ctx


def run_recon(config_path: Path, *, resume: bool | None = None) -> ReconContext | list[ReconContext]:
    config = load_config(config_path)
    return _run_config(config, resume=resume)


def run_program(program, *, resume: bool | None = None) -> list:
    """Run recon for a loaded program registry entry."""
    from recon.program import update_last_run

    LOG.info(
        "Program %s (%s) — mode=%s strict_scope=True roots=%d",
        program.name,
        program.platform,
        program.recon.mode,
        len(program.recon.scope_roots),
    )
    result = _run_config(program.recon, resume=resume)
    update_last_run(program)
    return result if isinstance(result, list) else [result]


def _run_config(config: ReconConfig, *, resume: bool | None = None) -> ReconContext | list[ReconContext]:
    contexts: list[ReconContext] = []
    for target in config.targets:
        contexts.append(_run_target(config, target, resume=resume))
    return contexts[0] if len(contexts) == 1 else contexts
