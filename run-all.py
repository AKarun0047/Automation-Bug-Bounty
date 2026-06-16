#!/usr/bin/env python3
"""Run recon across all programs in the bug bounty registry."""

from __future__ import annotations

import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from recon.program import (
    DEFAULT_BUGBOUNTY_ROOT,
    filter_runnable,
    load_all_programs,
    program_priority,
)
from recon.runner import run_program
from recon.utils import setup_logging

LOG = logging.getLogger("run-all")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run recon for all bug bounty programs")
    parser.add_argument(
        "--programs-dir",
        type=Path,
        default=DEFAULT_BUGBOUNTY_ROOT / "programs",
        help="Directory containing program folders (default: ~/bugbounty/programs)",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=2,
        help="Max programs to run in parallel (default: 2)",
    )
    parser.add_argument(
        "--program",
        type=str,
        default="",
        help="Run only this program name",
    )
    parser.add_argument("--no-resume", action="store_true", help="Ignore checkpoints")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    setup_logging(verbose=args.verbose)

    programs = load_all_programs(args.programs_dir)
    if args.program:
        programs = [p for p in programs if p.name == args.program]
    if not programs:
        LOG.error("No programs found in %s", args.programs_dir)
        return 1

    programs = filter_runnable(programs)
    programs.sort(key=program_priority, reverse=True)

    LOG.info("Running %d program(s) — max %d parallel", len(programs), args.parallel)
    resume = False if args.no_resume else None
    errors: list[str] = []

    def _run_one(program):
        try:
            run_program(program, resume=resume)
            return program.name, None
        except Exception as exc:
            LOG.error("Program %s failed: %s", program.name, exc, exc_info=True)
            return program.name, str(exc)

    if args.parallel <= 1:
        for p in programs:
            name, err = _run_one(p)
            if err:
                errors.append(f"{name}: {err}")
    else:
        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            futures = {pool.submit(_run_one, p): p for p in programs}
            for future in as_completed(futures):
                name, err = future.result()
                if err:
                    errors.append(f"{name}: {err}")

    if errors:
        LOG.error("%d program(s) failed", len(errors))
        for e in errors:
            LOG.error("  %s", e)
        return 1

    LOG.info("All programs complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
