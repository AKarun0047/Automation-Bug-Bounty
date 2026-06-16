"""Phase checkpoint/resume — skip completed phases on restart."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

LOG = logging.getLogger("recon.checkpoint")

STATE_FILE = ".recon_state.json"


class Checkpoint:
    def __init__(self, out_dir: Path, target: str, *, enabled: bool = True) -> None:
        self.path = out_dir / STATE_FILE
        self.target = target
        self.enabled = enabled
        self._state = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return {
                "target": self.target,
                "completed_phases": [],
                "started_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": None,
            }
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            LOG.warning("Corrupt checkpoint file — starting fresh")
            return {"target": self.target, "completed_phases": [], "started_at": None, "updated_at": None}

    def _save(self) -> None:
        self._state["target"] = self.target
        self._state["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.path.write_text(json.dumps(self._state, indent=2) + "\n", encoding="utf-8")

    def is_done(self, phase_name: str) -> bool:
        if not self.enabled:
            return False
        return phase_name in self._state.get("completed_phases", [])

    def mark_done(self, phase_name: str) -> None:
        if not self.enabled:
            return
        completed: list[str] = self._state.setdefault("completed_phases", [])
        if phase_name not in completed:
            completed.append(phase_name)
        self._save()
        LOG.debug("Checkpoint: %s complete", phase_name)

    def reset(self) -> None:
        if self.path.exists():
            self.path.unlink()
