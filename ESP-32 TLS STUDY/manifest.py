"""
manifest.py
Generates and saves a manifest JSON for every experiment run.

The manifest is written twice:
  1. At run start (status = "started") with full configuration.
  2. At run end   (status = "completed" or "interrupted") with totals.

File: results/manifest.json  (also copied into the timestamped artifact folder
      by artifact_organizer.py at the end of the run).
"""

import json, platform, time, logging
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger("manifest")

_MANIFEST_PATH = Path("results") / "manifest.json"
_manifest: Dict[str, Any] = {}


def _esp32_info(serial_port: str) -> Dict[str, str]:
    """Best-effort ESP32 metadata (static defaults; filled from firmware if available)."""
    return {
        "board":        "ESP32 Dev Module",
        "framework":    "Arduino / PlatformIO",
        "serial_port":  serial_port,
        "cpu_freq_mhz": "240",
        "flash_size":   "4MB",
        "ram_size_kb":  "520",
    }


def create(
    run_id: str,
    fw_version: str,
    serial_port: str,
    simulate: bool,
) -> Dict[str, Any]:
    """
    Build and persist the initial manifest at run start.
    Returns the manifest dict (caller may add fields before saving).
    """
    import config  # imported here to avoid circular import at module level

    global _manifest
    _manifest = {
        "run_id":           run_id,
        "timestamp_start":  time.strftime("%Y-%m-%dT%H:%M:%S"),
        "timestamp_end":    None,
        "status":           "started",
        "firmware_version": fw_version,
        "simulation_mode":  simulate,
        "host_platform":    platform.platform(),
        "python_version":   platform.python_version(),
        "esp32":            _esp32_info(serial_port),
        "experiment_config": {
            "num_trials":       config.NUM_TRIALS,
            "max_chain_depth":  config.MAX_CHAIN_DEPTH,
            "tls_version":      config.TLS_VERSION,
            "handshake_timeout":config.HANDSHAKE_TIMEOUT,
            "server_ip":        config.SERVER_IP,
            "server_port":      config.SERVER_PORT,
            "payload_size":     config.PAYLOAD_SIZE,
            "enabled_algorithms": _algo_summary(),
        },
        "totals": {
            "planned":   0,
            "completed": 0,
            "skipped":   0,
            "failed":    0,
        },
    }
    _save()
    log.info(f"[Manifest] Created → {_MANIFEST_PATH}")
    return _manifest


def _algo_summary() -> list:
    import config
    out = []
    if config.ENABLE_RSA:
        out.append({"algorithm": "RSA", "params": config.RSA_KEY_SIZES})
    if config.ENABLE_ECDSA:
        out.append({"algorithm": "ECDSA", "params": config.ECDSA_CURVES})
    return out


def update_totals(planned: int, completed: int, skipped: int, failed: int) -> None:
    _manifest["totals"] = {
        "planned":   planned,
        "completed": completed,
        "skipped":   skipped,
        "failed":    failed,
    }
    _save()


def finalize(status: str = "completed") -> None:
    _manifest["status"]          = status
    _manifest["timestamp_end"]   = time.strftime("%Y-%m-%dT%H:%M:%S")
    _save()
    log.info(f"[Manifest] Finalized (status={status}) → {_MANIFEST_PATH}")


def path() -> Path:
    return _MANIFEST_PATH


def _save() -> None:
    _MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    _MANIFEST_PATH.write_text(json.dumps(_manifest, indent=2))
