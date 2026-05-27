"""
main.py  –  IoT TLS/PKI Scalability Framework
==============================================
Run:  python main.py [--simulate] [--force-flash]

  --simulate      Skip ESP32; generate synthetic data.
                  Falls back automatically if serial unavailable.
  --force-flash   Re-flash ESP32 even if firmware hash matches.

Boot sequence (hardware mode):
  1. init_session_root()  → creates/reloads one Root CA for the whole session
  2. write_ca_header()    → embeds that CA in esp32/src/root_ca_embed.h
  3. (optional) flash     → pio build + upload
  4. TLS server starts    → using server cert signed by session root
  5. Serial connects      → waits for READY with DTR-pulse reset
  6. Experiments run      → ESP32 trusts every server cert (same root)
"""

import argparse, logging, sys, time
from pathlib import Path

import config

# ── Run folder ───────────────────────────────────────────
_RUN_ID    = time.strftime("%Y%m%d_%H%M%S")
_RUNS_DIR  = Path("runs") / _RUN_ID
_RES_DIR   = _RUNS_DIR / "results"
_PLOTS_DIR = _RUNS_DIR / "plots"
_LOGS_DIR  = _RUNS_DIR / "logs"
for _d in (_RES_DIR, _PLOTS_DIR, _LOGS_DIR):
    _d.mkdir(parents=True, exist_ok=True)
Path("results").mkdir(exist_ok=True)
Path("plots").mkdir(exist_ok=True)
Path("logs").mkdir(exist_ok=True)

# ── Logging ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(_LOGS_DIR / "run.log")),
        logging.FileHandler("logs/run.log"),
    ]
)
log = logging.getLogger("main")

import metrics as M
import resume_state as RS
import manifest as MF
import cert_generator as CG
from firmware_flasher import flash_if_needed, write_ca_header
from tls_server import TLSServer
from serial_controller import SerialController
from experiment_runner import run as run_experiments
from artifact_organizer import organize


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--simulate",    action="store_true")
    parser.add_argument("--force-flash", dest="force_flash", action="store_true")
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("  IoT TLS/PKI Scalability Framework")
    log.info(f"  Run ID : {_RUN_ID}")
    log.info(f"  Mode   : {'SIMULATION' if args.simulate else 'HARDWARE'}")
    log.info(f"  Server : {config.SERVER_IP}:{config.SERVER_PORT}")
    log.info("=" * 60)

    M.init_run(_RES_DIR)
    RS._STATE_PATH = _RES_DIR / "resume_state.json"
    RS.init(_RUN_ID)
    MF._MANIFEST_PATH = _RES_DIR / "manifest.json"
    MF.create(run_id=_RUN_ID, fw_version=config.FIRMWARE_VERSION,
              serial_port=config.SERIAL_PORT, simulate=args.simulate)

    # ── Step 1: Session Root CA ──────────────────────────
    # One Root CA for the ENTIRE session.
    # All server certs in all experiments are signed by this same root.
    # The ESP32 firmware embeds this root and trusts ALL of them.
    log.info("[Main] Initialising session Root CA...")
    ca_pem = CG.init_session_root(algo="RSA", param="2048")
    write_ca_header(ca_pem)
    log.info(f"[Main] Session Root CA ready → {CG.get_session_root_path()}")

    # ── Step 2: Auto-flash (optional) ───────────────────
    if not args.simulate and config.AUTO_FLASH:
        log.info("[Main] Auto-flash: checking firmware hash...")
        flash_if_needed(
            ca_pem=ca_pem, ssid=config.WIFI_SSID,
            password=config.WIFI_PASSWORD, server_ip=config.SERVER_IP,
            serial_port=config.SERIAL_PORT, baudrate=config.SERIAL_BAUDRATE,
            fw_version=config.FIRMWARE_VERSION, force=args.force_flash)

    # ── Step 3: TLS server ───────────────────────────────
    # Generate the first server cert just to start the server.
    # experiment_runner will call server.reconfigure() for each batch.
    _boot_algo = ("RSA", str(config.RSA_KEY_SIZES[0])) \
                  if config.ENABLE_RSA else ("ECDSA", config.ECDSA_CURVES[0])
    from cert_generator import generate_pki
    boot_pki = generate_pki(_boot_algo[0], _boot_algo[1], 0, config.SERVER_IP)

    server = TLSServer(host="0.0.0.0", port=config.SERVER_PORT)
    server.reconfigure(boot_pki)
    server.start()
    server.wait_ready()
    log.info(f"[Main] TLS server listening on 0.0.0.0:{config.SERVER_PORT}")
    log.info(f"[Main] Server cert SAN includes IP {config.SERVER_IP}")

    # ── Step 4: Serial / ESP32 ──────────────────────────
    serial = None
    if not args.simulate:
        try:
            serial = SerialController(
                port=config.SERIAL_PORT,
                baudrate=config.SERIAL_BAUDRATE,
                timeout=config.SERIAL_TIMEOUT)
            serial.connect()   # opens port with DTR=False, then pulses DTR to reset
            log.info(f"[Main] Serial open on {config.SERIAL_PORT}")

            if not serial.wait_ready(timeout=60):
                log.warning("[Main] ESP32 READY not received → simulation fallback")
                serial.disconnect()
                serial = None
            else:
                # Verify the CA compiled into the running firmware matches the
                # session Root CA.  A mismatch means every handshake will fail.
                log.info("[Main] Verifying firmware CA matches session Root CA...")
                if not serial.verify_ca(ca_pem):
                    log.error("=" * 60)
                    log.error("[Main] FIRMWARE CA MISMATCH – aborting experiment")
                    log.error("[Main] The CA compiled into the ESP32 firmware does")
                    log.error("[Main] NOT match the current session Root CA.")
                    log.error("[Main] Every TLS handshake will fail until you reflash.")
                    log.error("[Main]")
                    log.error("[Main] Fix:")
                    log.error("[Main]   cd esp32 && pio run --target upload")
                    log.error("[Main]   (then restart main.py)")
                    log.error("=" * 60)
                    serial.disconnect()
                    server.stop()
                    sys.exit(1)
                log.info("[Main] ✓ Firmware CA verified")
        except Exception as e:
            log.warning(f"[Main] Serial failed ({e}) → simulation fallback")
            serial = None

    if serial is None:
        log.info("[Main] ─── SIMULATION MODE (no ESP32) ───────────────────")

    # ── Step 5: Run experiments ──────────────────────────
    status = "completed"
    try:
        run_experiments(server, serial, _RES_DIR, _PLOTS_DIR)
    except KeyboardInterrupt:
        log.info("[Main] Interrupted by user.")
        status = "interrupted"
    except Exception as e:
        log.error(f"[Main] Fatal error: {e}", exc_info=True)
        status = "error"
    finally:
        if serial:
            serial.disconnect()
        server.stop()

    MF.finalize(status)
    dest = organize(_RUN_ID, config.FIRMWARE_VERSION)
    log.info(f"[Main] Artifacts → {dest}")
    log.info(f"[Main] {status.upper()} — {_RUN_ID}")


if __name__ == "__main__":
    main()
