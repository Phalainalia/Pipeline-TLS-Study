"""
resume_state.py
Persists and loads experiment progress so a crashed run can resume
from the last unfinished (algo, param, chain_depth, trial) tuple.

State file: results/resume_state.json
Schema:
  {
    "run_id":      "20240101_120000",
    "completed":   [                       # list of completed keys
      "RSA|2048|0|1",
      "RSA|2048|0|2",
      ...
    ],
    "last_update": "2024-01-01T12:05:00"
  }

A "key" uniquely identifies one trial:  algo|param|chain_depth|trial_number
"""

import json, logging, time
from pathlib import Path
from typing import Set

log = logging.getLogger("resume")

_STATE_PATH = Path("results") / "resume_state.json"
_completed:  Set[str] = set()
_run_id:     str      = ""


def _key(algo: str, param: str, depth: int, trial: int) -> str:
    return f"{algo}|{param}|{depth}|{trial}"


def init(run_id: str) -> bool:
    """
    Load existing state if the file exists and belongs to the same run_id.
    Returns True if a previous partial run was found and loaded (resume mode).
    """
    global _completed, _run_id
    _run_id = run_id
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)

    if _STATE_PATH.exists():
        try:
            data = json.loads(_STATE_PATH.read_text())
            if data.get("run_id") == run_id:
                _completed = set(data.get("completed", []))
                log.info(f"[Resume] Loaded {len(_completed)} completed trials from previous run")
                return True
            else:
                log.info(f"[Resume] New run_id detected – starting fresh")
        except Exception as e:
            log.warning(f"[Resume] Could not load state: {e} – starting fresh")

    _completed = set()
    _persist()
    return False


def is_done(algo: str, param: str, depth: int, trial: int) -> bool:
    """Return True if this exact trial was already completed."""
    return _key(algo, param, depth, trial) in _completed


def mark_done(algo: str, param: str, depth: int, trial: int) -> None:
    """Record a trial as completed and persist immediately."""
    _completed.add(_key(algo, param, depth, trial))
    _persist()


def _persist() -> None:
    data = {
        "run_id":      _run_id,
        "completed":   sorted(_completed),
        "last_update": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _STATE_PATH.write_text(json.dumps(data, indent=2))


def clear() -> None:
    """Delete checkpoint (called after a fully successful run)."""
    global _completed
    _completed = set()
    if _STATE_PATH.exists():
        _STATE_PATH.unlink()
    log.info("[Resume] Checkpoint cleared")


def completed_count() -> int:
    return len(_completed)
