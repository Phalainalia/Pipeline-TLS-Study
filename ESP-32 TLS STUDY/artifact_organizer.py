"""
artifact_organizer.py
At the end of each run, collects all output artifacts and moves them
into a self-contained timestamped folder under runs/.

Structure created:
  runs/
  └── 20240101_120000/
      ├── raw_metrics.csv
      ├── statistics.csv
      ├── resume_state.json      (deleted on success; kept on crash for diagnosis)
      ├── manifest.json
      ├── firmware_version.txt
      ├── logs/
      │   └── run.log
      └── plots/
          ├── dashboard.html
          └── *.html

The live results/, logs/, plots/ directories are LEFT IN PLACE so
subsequent tools (statistics_engine, plotter) still find their files.
Only a copy is made into the run archive.
"""

import logging, shutil, time
from pathlib import Path

log = logging.getLogger("organizer")

RUNS_DIR = Path("runs")


def organize(run_id: str, fw_version: str) -> Path:
    """
    Copy all current artifacts into runs/<run_id>/.
    Returns the path to the run folder.
    """
    dest = RUNS_DIR / run_id
    dest.mkdir(parents=True, exist_ok=True)

    copied = []

    # ── results ──────────────────────────────────────────
    results_dest = dest
    for f in Path("results").glob("*.csv"):
        _copy(f, results_dest / f.name, copied)
    manifest_src = Path("results") / "manifest.json"
    if manifest_src.exists():
        _copy(manifest_src, results_dest / "manifest.json", copied)

    # ── firmware metadata ─────────────────────────────────
    fw_file = dest / "firmware_version.txt"
    fw_file.write_text(
        f"firmware_version: {fw_version}\n"
        f"run_id: {run_id}\n"
        f"archived: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
    )
    copied.append(str(fw_file))

    # ── logs ─────────────────────────────────────────────
    logs_dest = dest / "logs"
    logs_dest.mkdir(exist_ok=True)
    for f in Path("logs").glob("*.log"):
        _copy(f, logs_dest / f.name, copied)

    # ── plots ────────────────────────────────────────────
    plots_dest = dest / "plots"
    plots_dest.mkdir(exist_ok=True)
    for f in Path("plots").glob("*.html"):
        _copy(f, plots_dest / f.name, copied)

    log.info(f"[Organizer] Run archived → {dest}  ({len(copied)} files)")
    return dest


def _copy(src: Path, dst: Path, log_list: list) -> None:
    try:
        shutil.copy2(str(src), str(dst))
        log_list.append(str(dst))
    except Exception as e:
        log.warning(f"[Organizer] Could not copy {src} → {dst}: {e}")
