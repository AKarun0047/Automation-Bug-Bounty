"""CLI entry point: python -m recon"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from recon.runner import run_recon
from recon.utils import setup_logging


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Autonomous recon automation — multi-phase security reconnaissance",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path("recon.config.yaml"),
        help="Path to recon.config.yaml (default: ./recon.config.yaml)",
    )
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        default="",
        help="Override target domain from config",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Ignore checkpoint state and re-run all phases",
    )
    args = parser.parse_args(argv)

    setup_logging(verbose=args.verbose)

    if not args.config.exists():
        print(f"Config not found: {args.config}", file=sys.stderr)
        print("Copy recon.config.yaml and set 'target' or 'scope_file'.", file=sys.stderr)
        return 1

    if args.target:
        import yaml

        with args.config.open(encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        raw["target"] = args.target
        override_path = args.config.parent / ".recon-target-override.yaml"
        override_path.write_text(yaml.dump(raw), encoding="utf-8")
        args.config = override_path

    try:
        result = run_recon(args.config, resume=False if args.no_resume else None)
        if isinstance(result, list):
            for ctx in result:
                print(f"  {ctx.target}: {ctx.out_dir / 'DUMP.md'}")
            print(f"\nRecon complete for {len(result)} targets.")
        else:
            print(f"\nRecon complete. Paste to Claude: {result.out_dir / 'DUMP.md'}")
        return 0
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
