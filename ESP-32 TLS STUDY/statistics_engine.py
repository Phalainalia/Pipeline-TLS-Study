"""
statistics_engine.py
Compute descriptive statistics per experimental configuration.
"""

import logging
from pathlib import Path
import pandas as pd
import numpy as np

log = logging.getLogger("stats")


def _cv(s: pd.Series) -> float:
    m = s.mean()
    return float(s.std() / m) if m != 0 else 0.0


def compute_and_save(results_dir: Path = Path("results")) -> pd.DataFrame:
    csv_path   = results_dir / "raw_metrics.csv"
    stats_path = results_dir / "statistics.csv"

    if not csv_path.exists():
        log.warning("No raw metrics CSV found.")
        return pd.DataFrame()

    df = pd.read_csv(csv_path)
    numeric    = ["handshake_time_ms", "free_heap_bytes",
                  "largest_free_block_bytes", "fragmentation_ratio"]
    group_cols = ["algorithm", "key_size_or_curve", "chain_depth"]

    rows = []
    for keys, grp in df.groupby(group_cols):
        base = dict(zip(group_cols, keys))
        base["n_total"]      = len(grp)
        base["n_success"]    = int(grp["handshake_success"].sum())
        base["failure_rate"] = 1 - base["n_success"] / max(base["n_total"], 1)
        for col in numeric:
            s = grp[col].dropna()
            if s.empty:
                continue
            base[f"{col}_mean"]   = float(s.mean())
            base[f"{col}_median"] = float(s.median())
            base[f"{col}_std"]    = float(s.std())
            base[f"{col}_min"]    = float(s.min())
            base[f"{col}_max"]    = float(s.max())
            base[f"{col}_p95"]    = float(np.percentile(s, 95))
            base[f"{col}_cv"]     = _cv(s)
        rows.append(base)

    stats_df = pd.DataFrame(rows)
    results_dir.mkdir(parents=True, exist_ok=True)
    stats_df.to_csv(stats_path, index=False)
    log.info(f"[Stats] Saved → {stats_path}  ({len(stats_df)} configurations)")
    return stats_df
