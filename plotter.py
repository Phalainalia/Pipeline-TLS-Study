"""
plotter.py — Visualizaciones interactivas con Plotly para el estudio TLS.

Genera:
  1. Latencia vs longitud de cadena (con barras de error)
  2. Comparación RSA vs ECDSA (box plots)
  3. Tamaño de certificados vs longitud de cadena
  4. Escalabilidad del handshake (heatmap normalizado)
  5. Dashboard combinado (subplots)
"""

import os
import logging
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

logger = logging.getLogger(__name__)

# ─── Paleta de colores por label ─────────────────────────────────────────────

PALETTE = [
    "#2563EB",  # azul
    "#DC2626",  # rojo
    "#16A34A",  # verde
    "#9333EA",  # violeta
    "#EA580C",  # naranja
    "#0891B2",  # cyan
    "#BE185D",  # rosa
    "#CA8A04",  # amarillo
]

def _color_map(labels: list) -> dict:
    return {lbl: PALETTE[i % len(PALETTE)] for i, lbl in enumerate(sorted(labels))}


# ─── 1. Latencia vs longitud de cadena ───────────────────────────────────────

def plot_latency_vs_chain(summary: pd.DataFrame, plots_dir: str) -> str:
    labels = summary["label"].unique().tolist()
    cmap = _color_map(labels)

    fig = go.Figure()
    for label in sorted(labels):
        grp = summary[summary["label"] == label].sort_values("longitud_cadena")
        fig.add_trace(go.Scatter(
            x=grp["longitud_cadena"],
            y=grp["media_ms"],
            error_y=dict(type="data", array=grp["std_ms"], visible=True, thickness=1.5, width=5),
            mode="lines+markers",
            name=label,
            line=dict(color=cmap[label], width=2),
            marker=dict(size=8),
            hovertemplate=(
                f"<b>{label}</b><br>"
                "Intermediarios: %{x}<br>"
                "Latencia media: %{y:.2f} ms<br>"
                "Desv. estándar: %{error_y.array:.2f} ms<extra></extra>"
            ),
        ))

    fig.update_layout(
        title=dict(text="Latencia del Handshake TLS vs Longitud de Cadena", font_size=18),
        xaxis=dict(title="Número de certificados intermediarios", dtick=1, gridcolor="#e5e7eb"),
        yaxis=dict(title="Tiempo de handshake (ms)", gridcolor="#e5e7eb"),
        legend=dict(title="Esquema criptográfico", bgcolor="rgba(255,255,255,0.8)", borderwidth=1),
        plot_bgcolor="white",
        paper_bgcolor="white",
        hovermode="x unified",
        font=dict(family="Arial, sans-serif"),
    )

    path = os.path.join(plots_dir, "1_latency_vs_chain.html")
    fig.write_html(path)
    logger.info(f"Gráfica guardada: {path}")
    return path


# ─── 2. Box plots RSA vs ECDSA ───────────────────────────────────────────────

def plot_rsa_vs_ecdsa_boxplot(df: pd.DataFrame, plots_dir: str) -> str:
    """
    Compara distribución de tiempos entre RSA y ECDSA usando box plots.
    df: DataFrame completo con todas las observaciones (no el summary).
    """
    labels = df["label"].unique().tolist()
    cmap = _color_map(labels)

    fig = go.Figure()
    for label in sorted(labels):
        grp = df[df["label"] == label]
        fig.add_trace(go.Box(
            y=grp["tiempo_handshake_ms"],
            name=label,
            marker_color=cmap[label],
            boxmean="sd",
            hovertemplate=f"<b>{label}</b><br>%{{y:.2f}} ms<extra></extra>",
        ))

    fig.update_layout(
        title=dict(text="Distribución de Tiempos de Handshake por Esquema Criptográfico", font_size=18),
        yaxis=dict(title="Tiempo de handshake (ms)", gridcolor="#e5e7eb"),
        xaxis=dict(title="Esquema criptográfico"),
        plot_bgcolor="white",
        paper_bgcolor="white",
        showlegend=False,
        font=dict(family="Arial, sans-serif"),
    )

    path = os.path.join(plots_dir, "2_rsa_vs_ecdsa_boxplot.html")
    fig.write_html(path)
    logger.info(f"Gráfica guardada: {path}")
    return path


# ─── 3. Tamaño de certificados vs longitud de cadena ────────────────────────

def plot_cert_size_vs_chain(summary: pd.DataFrame, plots_dir: str) -> str:
    labels = summary["label"].unique().tolist()
    cmap = _color_map(labels)

    fig = go.Figure()
    for label in sorted(labels):
        grp = summary[summary["label"] == label].sort_values("longitud_cadena")
        fig.add_trace(go.Scatter(
            x=grp["longitud_cadena"],
            y=grp["tamaño_certs_bytes"],
            mode="lines+markers",
            name=label,
            line=dict(color=cmap[label], width=2, dash="dash"),
            marker=dict(size=8, symbol="diamond"),
            hovertemplate=(
                f"<b>{label}</b><br>"
                "Intermediarios: %{x}<br>"
                "Tamaño cadena: %{y:,} bytes<extra></extra>"
            ),
        ))

    fig.update_layout(
        title=dict(text="Tamaño Total de Certificados vs Longitud de Cadena", font_size=18),
        xaxis=dict(title="Número de certificados intermediarios", dtick=1, gridcolor="#e5e7eb"),
        yaxis=dict(title="Tamaño total de certificados (bytes)", gridcolor="#e5e7eb"),
        legend=dict(title="Esquema criptográfico", bgcolor="rgba(255,255,255,0.8)", borderwidth=1),
        plot_bgcolor="white",
        paper_bgcolor="white",
        hovermode="x unified",
        font=dict(family="Arial, sans-serif"),
    )

    path = os.path.join(plots_dir, "3_cert_size_vs_chain.html")
    fig.write_html(path)
    logger.info(f"Gráfica guardada: {path}")
    return path


# ─── 4. Heatmap de escalabilidad ─────────────────────────────────────────────

def plot_scalability_heatmap(summary: pd.DataFrame, plots_dir: str) -> str:
    """
    Heatmap: filas = label, columnas = longitud de cadena, valor = media ms.
    """
    pivot = summary.pivot_table(
        index="label", columns="longitud_cadena", values="media_ms", aggfunc="mean"
    )
    pivot = pivot.sort_index()

    fig = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=[f"{c} interm." for c in pivot.columns],
        y=pivot.index.tolist(),
        colorscale="Blues",
        colorbar=dict(title="Latencia (ms)"),
        hovertemplate="Esquema: %{y}<br>Cadena: %{x}<br>Latencia: %{z:.2f} ms<extra></extra>",
        text=[[f"{v:.1f}" for v in row] for row in pivot.values],
        texttemplate="%{text}",
        textfont=dict(size=11),
    ))

    fig.update_layout(
        title=dict(text="Heatmap de Escalabilidad: Latencia (ms) por Esquema y Longitud de Cadena", font_size=16),
        xaxis=dict(title="Longitud de cadena"),
        yaxis=dict(title="Esquema criptográfico"),
        font=dict(family="Arial, sans-serif"),
    )

    path = os.path.join(plots_dir, "4_scalability_heatmap.html")
    fig.write_html(path)
    logger.info(f"Gráfica guardada: {path}")
    return path


# ─── 5. Dashboard combinado ───────────────────────────────────────────────────

def plot_dashboard(summary: pd.DataFrame, df: pd.DataFrame, plots_dir: str) -> str:
    """Dashboard con 4 paneles en una sola figura HTML interactiva."""
    labels = summary["label"].unique().tolist()
    cmap = _color_map(labels)

    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=(
            "Latencia vs Longitud de Cadena",
            "Distribución de Tiempos (Box Plot)",
            "Tamaño de Certificados vs Cadena",
            "Comparación Media por Algoritmo (Chain=0)",
        ),
        horizontal_spacing=0.12,
        vertical_spacing=0.18,
    )

    # Panel 1: Latencia vs cadena
    for label in sorted(labels):
        grp = summary[summary["label"] == label].sort_values("longitud_cadena")
        fig.add_trace(go.Scatter(
            x=grp["longitud_cadena"], y=grp["media_ms"],
            error_y=dict(type="data", array=grp["std_ms"], visible=True),
            mode="lines+markers", name=label,
            line=dict(color=cmap[label], width=2),
            marker=dict(size=7),
            showlegend=True,
            legendgroup=label,
        ), row=1, col=1)

    # Panel 2: Box plot
    for label in sorted(labels):
        grp = df[df["label"] == label]
        fig.add_trace(go.Box(
            y=grp["tiempo_handshake_ms"], name=label,
            marker_color=cmap[label], boxmean=True,
            showlegend=False, legendgroup=label,
        ), row=1, col=2)

    # Panel 3: Tamaño certificados
    for label in sorted(labels):
        grp = summary[summary["label"] == label].sort_values("longitud_cadena")
        fig.add_trace(go.Scatter(
            x=grp["longitud_cadena"], y=grp["tamaño_certs_bytes"],
            mode="lines+markers", name=label,
            line=dict(color=cmap[label], width=2, dash="dot"),
            marker=dict(size=7, symbol="square"),
            showlegend=False, legendgroup=label,
        ), row=2, col=1)

    # Panel 4: Barras comparativas (cadena=0)
    base = summary[summary["longitud_cadena"] == summary["longitud_cadena"].min()].copy()
    base = base.sort_values("media_ms", ascending=True)
    fig.add_trace(go.Bar(
        x=base["label"], y=base["media_ms"],
        error_y=dict(type="data", array=base["std_ms"], visible=True),
        marker_color=[cmap.get(l, "#6b7280") for l in base["label"]],
        showlegend=False,
        hovertemplate="%{x}<br>%{y:.2f} ms<extra></extra>",
    ), row=2, col=2)

    fig.update_layout(
        title=dict(
            text="Dashboard: Estudio Empírico del Costo de Verificación de Certificados TLS",
            font_size=16,
        ),
        height=800,
        plot_bgcolor="white",
        paper_bgcolor="white",
        legend=dict(
            title="Esquema",
            bgcolor="rgba(255,255,255,0.9)",
            borderwidth=1,
            x=1.02, y=1,
        ),
        font=dict(family="Arial, sans-serif"),
    )

    # Ejes
    fig.update_xaxes(gridcolor="#e5e7eb")
    fig.update_yaxes(gridcolor="#e5e7eb")
    fig.update_yaxes(title_text="Latencia (ms)", row=1, col=1)
    fig.update_yaxes(title_text="Latencia (ms)", row=1, col=2)
    fig.update_yaxes(title_text="Bytes", row=2, col=1)
    fig.update_yaxes(title_text="Latencia (ms)", row=2, col=2)
    fig.update_xaxes(title_text="Intermediarios", row=1, col=1, dtick=1)
    fig.update_xaxes(title_text="Intermediarios", row=2, col=1, dtick=1)

    path = os.path.join(plots_dir, "5_dashboard.html")
    fig.write_html(path)
    logger.info(f"Dashboard guardado: {path}")
    return path


# ─── Función principal ────────────────────────────────────────────────────────

def generate_all_plots(csv_path: str, plots_dir: str, summary: pd.DataFrame = None):
    """
    Genera todas las gráficas a partir del CSV de resultados.
    Si ya tienes el summary calculado, pásalo para evitar recalcular.
    """
    from metrics import load_results, compute_summary

    os.makedirs(plots_dir, exist_ok=True)
    df = load_results(csv_path)

    if df.empty:
        logger.warning("No hay datos suficientes para graficar.")
        return []

    if summary is None:
        summary = compute_summary(df)

    paths = []
    paths.append(plot_latency_vs_chain(summary, plots_dir))
    paths.append(plot_rsa_vs_ecdsa_boxplot(df, plots_dir))
    paths.append(plot_cert_size_vs_chain(summary, plots_dir))
    paths.append(plot_scalability_heatmap(summary, plots_dir))
    paths.append(plot_dashboard(summary, df, plots_dir))

    logger.info(f"\n✅ {len(paths)} gráficas generadas en: {plots_dir}")
    return paths
