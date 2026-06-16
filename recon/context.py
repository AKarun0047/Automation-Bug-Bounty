"""Runtime context shared across recon phases."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from recon.config import ReconConfig
from recon.utils import RateLimiter


@dataclass
class ReconContext:
    config: ReconConfig
    target: str
    out_dir: Path

    # Phase output directories
    phase1: Path = field(init=False)
    phase2: Path = field(init=False)
    phase3: Path = field(init=False)
    phase4: Path = field(init=False)
    phase5: Path = field(init=False)
    phase6: Path = field(init=False)
    phase7: Path = field(init=False)
    rate_limiter: RateLimiter = field(init=False)

    def __post_init__(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.phase1 = self.out_dir / "phase1_assets"
        self.phase2 = self.out_dir / "phase2_http"
        self.phase3 = self.out_dir / "phase3_urls"
        self.phase4 = self.out_dir / "phase4_js"
        self.phase5 = self.out_dir / "phase5_params"
        self.phase6 = self.out_dir / "phase6_vulns"
        self.phase7 = self.out_dir / "phase7_auth"

        for d in (self.phase1, self.phase2, self.phase3, self.phase4, self.phase5, self.phase6, self.phase7):
            d.mkdir(parents=True, exist_ok=True)

        (self.phase2 / "screenshots").mkdir(exist_ok=True)
        (self.phase4 / "downloaded_js").mkdir(exist_ok=True)
        (self.phase7 / "swagger_found").mkdir(exist_ok=True)
        self.rate_limiter = RateLimiter(self.config.rate_limit)

    @classmethod
    def for_target(cls, config: ReconConfig, target: str, out_dir: Path) -> "ReconContext":
        return cls(config=config, target=target, out_dir=out_dir)

    @classmethod
    def from_config(cls, config: ReconConfig) -> "ReconContext":
        from recon.config import out_dir_for_target

        target = config.primary_target
        return cls.for_target(config, target, out_dir_for_target(config, target))
