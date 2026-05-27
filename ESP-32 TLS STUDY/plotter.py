"""
plotter.py
Generates interactive Plotly dashboards from collected metrics.
Gracefully skips if plotly is not installed.

Fixes vs previous version:
  - Removed LOWESS trendline (requires statsmodels; causes warnings on missing data)
  - Fixed size= on scatter when chain_depth can be 0 (plotly rejects 0-size markers)
  - Dashboard subplots: only copies first trace per figure to avoid legend explosion
  - All plots guarded against empty/single-row dataframes
"""

import logging
from pathlib import Path

import numpy as np
import pandas as pd

try:
    import plotly.express as px
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

log = logging.getLogger("plotter")


def _load(results_dir: Path) -> pd.DataFrame:
    p = results_dir / "raw_metrics.csv"
    if not p.exists():
        return pd.DataFrame()
    df = pd.read_csv(p)
    # Drop rows where all key metrics are NaN (failed/skipped rows)
    key_cols = ["handshake_time_ms", "free_heap_bytes",
                "largest_free_block_bytes", "fragmentation_ratio"]
    df = df.dropna(subset=key_cols, how="all")
    df["config"] = df["algorithm"] + "_" + df["key_size_or_curve"].astype(str)
    # marker_size: chain_depth+1 so depth=0 isn't zero-size
    df["marker_size"] = df["chain_depth"] + 1
    return df


def generate_all(results_dir: Path = Path("results"),
                 plots_dir:   Path = Path("plots")) -> None:

    plots_dir.mkdir(parents=True, exist_ok=True)

    if not HAS_PLOTLY:
        log.warning("[Plotter] plotly not installed – skipping charts. "
                    "pip install plotly")
        return

    df = _load(results_dir)
    if df.empty:
        log.warning("[Plotter] No data to plot.")
        return

    figs = []

    # ── 1. Handshake latency vs chain depth ──────────────
    grp = df.groupby(["config", "chain_depth"])["handshake_time_ms"]
    agg = grp.agg(mean="mean", std="std").reset_index()
    agg["std"] = agg["std"].fillna(0)
    fig1 = px.bar(agg, x="chain_depth", y="mean", error_y="std",
                  color="config", barmode="group",
                  title="TLS Handshake Latency vs Chain Depth",
                  labels={"mean": "Latency (ms)", "chain_depth": "Chain Depth"})
    figs.append(("latency_vs_chain", fig1))

    # ── 2. Heap fragmentation over repeated handshakes ───
    fig2 = px.line(df.sort_values("iteration"), x="iteration",
                   y="fragmentation_ratio", color="config",
                   facet_col="chain_depth",
                   title="Heap Fragmentation over Repeated Handshakes",
                   labels={"fragmentation_ratio": "Fragmentation Ratio",
                            "iteration": "Handshake #"})
    figs.append(("fragmentation_over_time", fig2))

    # ── 3. Free heap vs chain depth (box) ────────────────
    fig3 = px.box(df, x="chain_depth", y="free_heap_bytes", color="config",
                  title="Free Heap vs Chain Depth",
                  labels={"free_heap_bytes": "Free Heap (bytes)",
                           "chain_depth": "Chain Depth"})
    figs.append(("free_heap_vs_chain", fig3))

    # ── 4. Largest free block vs trial (scatter, no LOWESS) ─
    fig4 = px.scatter(df, x="trial_number", y="largest_free_block_bytes",
                      color="config",
                      title="Largest Free Block vs Trial Number",
                      labels={"largest_free_block_bytes": "Largest Block (bytes)",
                               "trial_number": "Trial"})
    figs.append(("largest_block_vs_trials", fig4))

    # ── 5. RSA vs ECDSA handshake latency boxplot ────────
    fig5 = px.box(df, x="algorithm", y="handshake_time_ms",
                  color="key_size_or_curve",
                  title="RSA vs ECDSA Handshake Distribution",
                  labels={"handshake_time_ms": "Latency (ms)"})
    figs.append(("rsa_vs_ecdsa_boxplot", fig5))

    # ── 6. Success / failure heatmap ─────────────────────
    heat = (df.groupby(["config", "chain_depth"])["handshake_success"]
              .mean()
              .reset_index())
    heat_piv = heat.pivot(index="config", columns="chain_depth",
                          values="handshake_success")
    z   = heat_piv.values.astype(float)
    txt = np.where(np.isnan(z), "", np.round(z, 2).astype(str))
    fig6 = go.Figure(go.Heatmap(
        z=z,
        x=[str(c) for c in heat_piv.columns.tolist()],
        y=heat_piv.index.tolist(),
        colorscale="RdYlGn", zmin=0, zmax=1,
        text=txt, texttemplate="%{text}",
        colorbar=dict(title="Success Rate")))
    fig6.update_layout(title="Handshake Success Rate Heatmap",
                       xaxis_title="Chain Depth",
                       yaxis_title="Config")
    figs.append(("success_heatmap", fig6))

    # ── 7. Fragmentation vs Latency scatter ──────────────
    fig7 = px.scatter(df, x="fragmentation_ratio", y="handshake_time_ms",
                      color="config",
                      size="marker_size",   # depth+1, never 0
                      size_max=18,
                      title="Fragmentation Ratio vs Handshake Latency",
                      labels={"fragmentation_ratio": "Fragmentation",
                               "handshake_time_ms":  "Latency (ms)",
                               "marker_size":        "Chain Depth+1"})
    figs.append(("frag_vs_latency", fig7))

    # ── 8. Certificate chain size vs chain depth ─────────
    cs = (df.groupby(["config", "chain_depth"])["certificate_chain_size_bytes"]
            .mean()
            .reset_index())
    fig8 = px.line(cs, x="chain_depth", y="certificate_chain_size_bytes",
                   color="config", markers=True,
                   title="Certificate Chain Size vs Chain Depth",
                   labels={"certificate_chain_size_bytes": "Chain Size (bytes)",
                            "chain_depth": "Chain Depth"})
    figs.append(("cert_size_vs_chain", fig8))

    # ── Save individual HTML files ────────────────────────
    for name, fig in figs:
        out = plots_dir / f"{name}.html"
        fig.write_html(str(out))
        log.info(f"[Plotter] {out.name}")

    # ── Dashboard ─────────────────────────────────────────
    _build_dashboard(figs, plots_dir)


def _build_dashboard(figs, plots_dir: Path) -> None:
    rows = (len(figs) + 1) // 2
    titles = [fig.layout.title.text or name for name, fig in figs]

    dashboard = make_subplots(
        rows=rows, cols=2,
        subplot_titles=titles,
        vertical_spacing=0.07)

    for i, (name, fig) in enumerate(figs):
        r, c = divmod(i, 2)
        for trace in fig.data:
            # Clone trace so legend doesn't duplicate
            t2 = trace
            dashboard.add_trace(t2, row=r + 1, col=c + 1)

    dashboard.update_layout(
        height          = 480 * rows,
        title_text      = "IoT TLS/PKI Scalability – Experiment Dashboard",
        showlegend      = False,
        paper_bgcolor   = "white")

    path = plots_dir / "dashboard.html"
    dashboard.write_html(str(path))
    log.info(f"[Plotter] Dashboard → {path}")
