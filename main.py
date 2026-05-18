"""
main.py — Pipeline principal del estudio empírico de verificación de certificados TLS.

Uso:
    python main.py                     # usa parámetros de config.py
    python main.py --quick             # modo rápido (5 trials, chains 0-1)
    python main.py --trials 50         # número de trials personalizado
    python main.py --no-plots          # sin gráficas

Cada ejecución genera su propio subdirectorio timestamped dentro de results/ y plots/,
por lo que NUNCA se sobreescriben ejecuciones anteriores.
"""

import os
import sys
import time
import logging
import argparse
from pathlib import Path
from datetime import datetime

import config as cfg
from cert_generator import generate_full_chain
from tls_runner import run_experiment_batch
from metrics import (
    init_results_file,
    append_trial,
    load_results,
    compute_summary,
    print_summary_table,
    save_summary,
)
from plotter import generate_all_plots


# ─── Logging ─────────────────────────────────────────────────────────────────

def setup_logging(logs_dir: str):
    Path(logs_dir).mkdir(parents=True, exist_ok=True)
    level = getattr(logging, cfg.LOG_LEVEL, logging.INFO)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    handlers = [logging.StreamHandler(sys.stdout)]
    if cfg.LOG_TO_FILE:
        handlers.append(logging.FileHandler(os.path.join(logs_dir, f"run_{ts}.log")))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )

logger = logging.getLogger(__name__)


# ─── Argparse ─────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Estudio empírico del costo de verificación de certificados TLS"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Modo rápido: 5 trials, chain_lengths=[0,1], solo RSA-2048 y ECDSA-secp256r1",
    )
    parser.add_argument(
        "--no-plots",
        action="store_true",
        help="Omitir generación de gráficas",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=None,
        help="Número de trials (sobreescribe config.py)",
    )
    return parser.parse_args()


# ─── Pipeline ─────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    # Timestamp único para esta ejecución
    # Garantiza que cada run guarda sus salidas en carpetas propias — nunca se sobreescribe nada
    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Directorios base (se crean si no existen)
    for d in [cfg.CERTS_DIR, cfg.RESULTS_DIR, cfg.PLOTS_DIR, cfg.LOGS_DIR]:
        Path(d).mkdir(parents=True, exist_ok=True)

    # Subdirectorios propios de esta ejecución
    run_results_dir = os.path.join(cfg.RESULTS_DIR, f"run_{run_ts}")
    run_plots_dir   = os.path.join(cfg.PLOTS_DIR,   f"run_{run_ts}")
    Path(run_results_dir).mkdir(parents=True, exist_ok=True)
    Path(run_plots_dir).mkdir(parents=True, exist_ok=True)

    setup_logging(cfg.LOGS_DIR)
    logger.info("=" * 70)
    logger.info("  ESTUDIO EMPÍRICO: COSTO DE VERIFICACIÓN DE CERTIFICADOS TLS")
    logger.info(f"  Run ID: {run_ts}")
    logger.info("=" * 70)

    # Modo rápido
    num_trials = cfg.NUM_TRIALS
    configs = cfg.build_configs()

    if args.quick:
        num_trials = 5
        configs = [
            c for c in configs
            if (c["label"] in ("RSA-2048", "ECDSA-secp256r1"))
            and c["chain_length"] <= 1
        ]
        logger.info("⚡ Modo rápido activado.")

    if args.trials:
        num_trials = args.trials

    if not configs:
        logger.error("No hay configuraciones activas. Revisa config.py.")
        sys.exit(1)

    logger.info(f"Configuraciones a probar  : {len(configs)}")
    logger.info(f"Trials por configuración  : {num_trials}")
    logger.info(f"Total handshakes estimados: {len(configs) * num_trials}")
    logger.info(f"Resultados en             : {run_results_dir}/")
    logger.info(f"Gráficas en               : {run_plots_dir}/")
    logger.info("")

    csv_path = init_results_file(run_results_dir)
    port = cfg.BASE_PORT

    total_start = time.time()

    for idx, conf in enumerate(configs, start=1):
        label     = conf["label"]
        chain_len = conf["chain_length"]
        algorithm = conf["algorithm"]
        key_size  = conf.get("key_size")
        curve     = conf.get("curve")

        logger.info(
            f"[{idx:>3}/{len(configs)}] {label:20s}  cadena={chain_len}  "
            f"trials={num_trials}  puerto={port}"
        )

        cert_subdir = os.path.join(
            cfg.CERTS_DIR,
            f"{label}_chain{chain_len}".replace("-", "_"),
        )

        try:
            chain_info = generate_full_chain(
                output_dir=cert_subdir,
                algorithm=algorithm,
                key_size=key_size,
                curve=curve,
                chain_length=chain_len,
            )
        except Exception as e:
            logger.error(f"  ❌ Error generando certificados: {e}")
            port += 1
            continue

        cert_size = chain_info["cert_chain_size_bytes"]

        try:
            times = run_experiment_batch(
                port=port,
                chain_info=chain_info,
                num_trials=num_trials,
                timeout=cfg.HANDSHAKE_TIMEOUT,
                payload_size=cfg.PAYLOAD_SIZE,
            )
        except Exception as e:
            logger.error(f"  ❌ Error ejecutando handshakes: {e}")
            port += 1
            continue

        successful = sum(1 for t in times if t >= 0)
        failed     = num_trials - successful
        logger.info(
            f"  ✓ {successful}/{num_trials} exitosos  "
            f"cert_size={cert_size} B  "
            f"{'⚠ ' + str(failed) + ' fallos' if failed else ''}"
        )

        for i, t in enumerate(times):
            append_trial(csv_path, conf, iteration=i + 1,
                         handshake_time_s=t, cert_size_bytes=cert_size)

        port += 1
        time.sleep(0.1)

    elapsed = time.time() - total_start
    logger.info(f"\nExperimento completado en {elapsed:.1f} s")
    logger.info(f"Resultados guardados en: {csv_path}")

    # ─── Análisis y resumen ───────────────────────────────────────────────────
    try:
        df = load_results(csv_path)
        if df.empty:
            logger.warning("No se obtuvieron resultados válidos para analizar.")
            return

        summary = compute_summary(df)
        print_summary_table(summary)
        summary_path = save_summary(summary, run_results_dir)
        logger.info(f"Resumen estadístico guardado en: {summary_path}")
    except Exception as e:
        logger.error(f"Error en análisis de resultados: {e}")
        return

    # ─── Gráficas ─────────────────────────────────────────────────────────────
    if not args.no_plots:
        logger.info("\nGenerando gráficas interactivas...")
        try:
            plot_paths = generate_all_plots(csv_path, run_plots_dir, summary=summary)
            logger.info("\n📊 Gráficas generadas:")
            for p in plot_paths:
                logger.info(f"   → {p}")
        except Exception as e:
            logger.error(f"Error generando gráficas: {e}")

    logger.info(f"\n🎉 Pipeline finalizado — Run ID: {run_ts}")
    logger.info(f"   Datos   : {run_results_dir}/")
    logger.info(f"   Gráficas: {run_plots_dir}/")
    logger.info(f"   Logs    : {cfg.LOGS_DIR}/\n")


if __name__ == "__main__":
    main()
