"""
metrics.py
Accumulates raw metric dicts and saves to CSV.
The results directory is set once per run by init_run().
"""

import csv, logging, time
from pathlib import Path
from typing import List, Dict, Any, Optional

log = logging.getLogger("metrics")

FIELDNAMES = [
    "timestamp", "trial_number", "iteration",
    "algorithm", "key_size_or_curve", "chain_depth",
    "handshake_time_ms", "certificate_chain_size_bytes",
    "free_heap_bytes", "largest_free_block_bytes",
    "fragmentation_ratio", "handshake_success",
]

_records:     List[Dict[str, Any]] = []
_results_dir: Path                 = Path("results")
_csv_path:    Path                 = _results_dir / "raw_metrics.csv"


def init_run(results_dir: Path) -> None:
    """Set the active results directory for this run (called once from main.py)."""
    global _results_dir, _csv_path
    _results_dir = results_dir
    _csv_path    = results_dir / "raw_metrics.csv"
    results_dir.mkdir(parents=True, exist_ok=True)


def _ensure_csv() -> None:
    _results_dir.mkdir(parents=True, exist_ok=True)
    if not _csv_path.exists():
        with open(_csv_path, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=FIELDNAMES).writeheader()


def record(raw: dict, pki: dict, trial: int, iteration: int) -> Dict[str, Any]:
    """Convert raw serial dict + pki meta into a normalised record and append to CSV."""
    row = {
        "timestamp":                    time.strftime("%Y-%m-%dT%H:%M:%S"),
        "trial_number":                 trial,
        "iteration":                    iteration,
        "algorithm":                    pki["algo"],
        "key_size_or_curve":            pki["param"],
        "chain_depth":                  pki["chain_depth"],
        "handshake_time_ms":            raw.get("HANDSHAKE_MS",        float("nan")),
        "certificate_chain_size_bytes": pki["chain_size"],
        "free_heap_bytes":              raw.get("FREE_HEAP",            float("nan")),
        "largest_free_block_bytes":     raw.get("LARGEST_BLOCK",        float("nan")),
        "fragmentation_ratio":          raw.get("FRAGMENTATION_RATIO",  float("nan")),
        "handshake_success":            int(raw.get("SUCCESS", 0)),
    }
    _records.append(row)
    _ensure_csv()
    with open(_csv_path, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=FIELDNAMES).writerow(row)
    return row


def get_all() -> List[Dict[str, Any]]:
    return list(_records)


def csv_path() -> Path:
    return _csv_path
