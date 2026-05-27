"""
experiment_runner.py
Orchestrates the full experiment matrix.
Includes end-to-end diagnostic instrumentation.
"""

import logging, time, random
from itertools import product
from pathlib import Path
from typing import Optional

import config
import metrics as M
import resume_state as RS
import manifest as MF
from cert_generator import generate_pki
from tls_server import TLSServer
from serial_controller import SerialController, stats as serial_stats
from statistics_engine import compute_and_save
from plotter import generate_all

log = logging.getLogger("runner")

# ── Run-level diagnostic counters ────────────────────────
_diag = {
    "total_planned":   0,
    "telemetry_ok":    0,
    "telemetry_fail":  0,
    "csv_rows":        0,
    "hs_failures":     0,
    "skipped":         0,
}


def _algo_list():
    combos = []
    if config.ENABLE_RSA:
        for sz in config.RSA_KEY_SIZES:
            combos.append(("RSA", str(sz)))
    if config.ENABLE_ECDSA:
        for curve in config.ECDSA_CURVES:
            combos.append(("ECDSA", curve))
    return combos


def run(server: TLSServer,
        serial: Optional[SerialController],
        results_dir: Path,
        plots_dir:   Path) -> None:

    combos       = _algo_list()
    chain_depths = list(range(config.MAX_CHAIN_DEPTH + 1))
    configs      = list(product(combos, chain_depths))
    total        = len(configs) * config.NUM_TRIALS
    _diag["total_planned"] = total

    MF.update_totals(total, 0, RS.completed_count(), 0)

    for (algo, param), depth in configs:
        log.info(f"\n{'='*60}")
        log.info(f"  Batch: {algo} {param}  chain_depth={depth}")
        log.info(f"{'='*60}")

        # Generate new server cert for this algo/depth; server root CA never changes
        pki = generate_pki(algo, param, depth, config.SERVER_IP)
        server.reconfigure(pki)
        time.sleep(0.5)

        for trial in range(1, config.NUM_TRIALS + 1):

            if RS.is_done(algo, param, depth, trial):
                log.info(f"  [Resume] Skipping {algo} {param} d={depth} t={trial}")
                _diag["skipped"] += 1
                continue

            eid = f"{algo}_{param}_chain{depth}_t{trial}"
            log.info(f"  Trial {trial}/{config.NUM_TRIALS}  ({eid})")

            # ── Collect result ────────────────────────────
            if serial and serial.is_connected():
                serial.send_command(
                    config.SERVER_IP, config.SERVER_PORT,
                    algo, param, depth, trial)

                raw = serial.wait_result(
                    algo=algo, param=param,
                    chain_depth=depth, trial=trial)

                if raw is None:
                    # Hard failure – do NOT silently zero-fill
                    print(f"[ERROR] Missing ESP32 telemetry for {eid}")
                    _diag["telemetry_fail"] += 1
                    MF.update_totals(total,
                                     _diag["telemetry_ok"],
                                     _diag["skipped"],
                                     _diag["telemetry_fail"])
                    continue   # skip CSV row entirely – no fake zeros
                else:
                    _diag["telemetry_ok"] += 1
                    if not raw.get("SUCCESS"):
                        _diag["hs_failures"] += 1
            else:
                # Simulation fallback
                raw = _simulate(algo, param, depth, trial)
                _diag["telemetry_ok"] += 1
                if not raw.get("SUCCESS"):
                    _diag["hs_failures"] += 1

            # ── Validate before writing CSV ───────────────
            print("\n==== Experiment Result ====")
            print(raw)
            print("===========================\n")

            if raw is None:
                print(f"[ERROR] result is None – skipping CSV for {eid}")
                continue

            # ── Persist to CSV ────────────────────────────
            row = M.record(raw, pki, trial, _diag["telemetry_ok"] + _diag["skipped"])
            print(f"[CSV WRITE] {row}")
            _diag["csv_rows"] += 1

            RS.mark_done(algo, param, depth, trial)
            MF.update_totals(total,
                             _diag["telemetry_ok"],
                             _diag["skipped"],
                             _diag["telemetry_fail"])

            _log_trial(raw)
            time.sleep(0.2)

    # ── Final diagnostics summary ─────────────────────────
    print("\n" + "="*60)
    print("  EXPERIMENT DIAGNOSTICS SUMMARY")
    print("="*60)
    print(f"  Total planned trials   : {_diag['total_planned']}")
    print(f"  Telemetry packets OK   : {_diag['telemetry_ok']}")
    print(f"  Telemetry failures     : {_diag['telemetry_fail']}")
    print(f"  Skipped (resume)       : {_diag['skipped']}")
    print(f"  CSV rows written       : {_diag['csv_rows']}")
    print(f"  Handshake failures     : {_diag['hs_failures']}")
    print(f"  Serial lines received  : {serial_stats['lines_received']}")
    print(f"  Serial packets parsed  : {serial_stats['packets_parsed']}")
    print(f"  Serial parse failures  : {serial_stats['packets_failed']}")
    print(f"  Serial timeouts        : {serial_stats['timeouts']}")
    print("="*60 + "\n")

    # ── Post-run analytics ────────────────────────────────
    log.info("[Runner] All trials done. Computing statistics…")
    compute_and_save(results_dir)
    log.info("[Runner] Generating plots…")
    generate_all(results_dir, plots_dir)
    RS.clear()
    log.info("[Runner] Finished.")


def _log_trial(raw: dict) -> None:
    hs   = raw.get("HANDSHAKE_MS", "?")
    heap = raw.get("FREE_HEAP",    "?")
    frag = raw.get("FRAGMENTATION_RATIO")
    frag_s = f"{frag:.4f}" if isinstance(frag, float) else "?"
    log.info(f"  → HS={hs}ms  heap={heap}  frag={frag_s}  "
             f"ok={'✓' if raw.get('SUCCESS') else '✗'}")


# ── Simulation (no ESP32) ─────────────────────────────────
def _simulate(algo: str, param: str, depth: int, trial: int) -> dict:
    base_ms    = 300 if algo == "ECDSA" else 800
    key_factor = {"2048":1.0,"4096":2.2,
                  "secp256r1":0.8,"secp384r1":1.1}.get(str(param), 1.0)
    hs      = base_ms * key_factor * (1 + depth * 0.3) + random.gauss(0, 30)
    free    = max(60_000,
                  220_000 - depth*15_000 - trial*200 + random.gauss(0, 2000))
    largest = max(10_000,
                  free * (0.9 - depth*0.05 - trial*0.001 + random.gauss(0, 0.02)))
    frag    = 1.0 - largest / free
    return {
        "HANDSHAKE_MS":        round(hs, 1),
        "FREE_HEAP":           int(free),
        "LARGEST_BLOCK":       int(largest),
        "FRAGMENTATION_RATIO": round(frag, 4),
        "SUCCESS":             1 if hs < 5000 else 0,
    }
