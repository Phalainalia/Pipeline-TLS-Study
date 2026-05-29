"""
metrics.py — Recolección, almacenamiento y resumen estadístico de resultados.
"""

import os
import csv
import statistics
import logging
from datetime import datetime
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)

COLUMNS = [
    "timestamp",
    "algoritmo",
    "tamaño_clave",
    "curva",
    "longitud_cadena",
    "iteracion",
    "tiempo_handshake_s",
    "tiempo_handshake_ms",
    "tamaño_certificados_bytes",
    "exitoso",
    "label",
]


def init_results_file(results_dir: str) -> str:
    """Crea el directorio y el archivo CSV con encabezados. Retorna el path."""
    Path(results_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(results_dir, f"results_{ts}.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
    logger.info(f"Archivo de resultados inicializado: {path}")
    return path


def append_trial(
    csv_path: str,
    config: dict,
    iteration: int,
    handshake_time_s: float,
    cert_size_bytes: int,
):
    """Agrega una fila de resultado al CSV."""
    exitoso = handshake_time_s >= 0
    row = {
        "timestamp": datetime.now().isoformat(),
        "algoritmo": config["algorithm"],
        "tamaño_clave": config.get("key_size") or "",
        "curva": config.get("curve") or "",
        "longitud_cadena": config["chain_length"],
        "iteracion": iteration,
        "tiempo_handshake_s": round(handshake_time_s, 6) if exitoso else "",
        "tiempo_handshake_ms": round(handshake_time_s * 1000, 3) if exitoso else "",
        "tamaño_certificados_bytes": cert_size_bytes,
        "exitoso": exitoso,
        "label": config["label"],
    }
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writerow(row)


def load_results(csv_path: str) -> pd.DataFrame:
    """Carga el CSV de resultados en un DataFrame."""
    df = pd.read_csv(csv_path)
    # Conservar solo filas exitosas para análisis
    df = df[df["exitoso"] == True].copy()
    df["tiempo_handshake_ms"] = pd.to_numeric(df["tiempo_handshake_ms"], errors="coerce")
    df["tamaño_certificados_bytes"] = pd.to_numeric(df["tamaño_certificados_bytes"], errors="coerce")
    return df


def compute_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calcula estadísticas descriptivas por grupo (label × longitud_cadena).
    dropna=False es necesario porque RSA tiene curva=NaN y ECDSA tiene tamaño_clave=NaN.
    """
    summary = (
        df.groupby(["label", "algoritmo", "tamaño_clave", "curva", "longitud_cadena"], dropna=False)
        .agg(
            n=("tiempo_handshake_ms", "count"),
            media_ms=("tiempo_handshake_ms", "mean"),
            mediana_ms=("tiempo_handshake_ms", "median"),
            std_ms=("tiempo_handshake_ms", "std"),
            min_ms=("tiempo_handshake_ms", "min"),
            max_ms=("tiempo_handshake_ms", "max"),
            tamaño_certs_bytes=("tamaño_certificados_bytes", "first"),
        )
        .reset_index()
    )
    summary["std_ms"] = summary["std_ms"].fillna(0)
    return summary


def print_summary_table(summary: pd.DataFrame):
    """Imprime tabla de resumen en consola."""
    logger.info("\n" + "=" * 80)
    logger.info("RESUMEN DE RESULTADOS")
    logger.info("=" * 80)
    for _, row in summary.iterrows():
        logger.info(
            f"[{row['label']:20s}] cadena={row['longitud_cadena']}  "
            f"media={row['media_ms']:7.2f} ms  "
            f"std={row['std_ms']:6.2f} ms  "
            f"n={row['n']}  "
            f"cert_size={row['tamaño_certs_bytes']} B"
        )
    logger.info("=" * 80 + "\n")


def save_summary(summary: pd.DataFrame, results_dir: str) -> str:
    """Guarda el resumen estadístico en un CSV separado."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(results_dir, f"summary_{ts}.csv")
    summary.to_csv(path, index=False, encoding="utf-8")
    logger.info(f"Resumen guardado en: {path}")
    return path
