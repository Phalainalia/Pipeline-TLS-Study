"""
serial_controller.py
ESP32 ↔ Python serial protocol.

Protocol (ESP32 → Python, one result per handshake):
    HANDSHAKE_RESULT,HS=623,HEAP=254188,LFB=143921,FRAG=0.440,SUCCESS=1

Protocol (Python → ESP32, one command per trial):
    CMD:192.168.1.100,8443,RSA,2048,1,3

Boot handshake:
    Python opens port with DTR=False (no reset), then pulses DTR briefly
    to force one clean reset.  ESP32 boots, connects WiFi, prints READY
    (repeated every second for 10s).  Python waits up to READY_TIMEOUT.

All non-result lines are printed with [RAW SERIAL] prefix for visibility.
"""

import logging, time
from typing import Optional

try:
    import serial as _serial_mod
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False

log = logging.getLogger("serial_ctrl")

# ── Module-level diagnostic counters ─────────────────────
stats = {
    "lines_received": 0,
    "packets_parsed": 0,
    "packets_failed": 0,
    "timeouts":       0,
}

RESULT_PREFIX = "HANDSHAKE_RESULT,"
READY_TIMEOUT = 45   # seconds to wait for the READY beacon after reset


# ── Metric parser ─────────────────────────────────────────

def _parse_metrics(line: str) -> Optional[dict]:
    """
    Parse:  HANDSHAKE_RESULT,HS=623,HEAP=254188,LFB=143921,FRAG=0.440,SUCCESS=1
    Returns normalised dict or None.
    """
    print(f"[Parser] Parsing: {line}")

    if RESULT_PREFIX not in line:
        print("[Parser] Invalid packet – missing HANDSHAKE_RESULT prefix")
        return None

    try:
        values: dict = {}
        for part in line.split(",")[1:]:
            part = part.strip()
            if "=" not in part:
                continue
            key, val = part.split("=", 1)
            values[key.strip()] = val.strip()

        parsed = {
            "HANDSHAKE_MS":        float(values["HS"]),
            "FREE_HEAP":           int(values["HEAP"]),
            "LARGEST_BLOCK":       int(values["LFB"]),
            "FRAGMENTATION_RATIO": float(values["FRAG"]),
            "SUCCESS":             int(values["SUCCESS"]),
        }
        print(f"[Parser OK] {parsed}")
        stats["packets_parsed"] += 1
        return parsed

    except Exception as e:
        print(f"[Parser ERROR] {e}  |  raw='{line}'")
        stats["packets_failed"] += 1
        return None


# ── Controller class ──────────────────────────────────────

class SerialController:

    def __init__(self, port: str, baudrate: int, timeout: int = 90):
        self.port     = port
        self.baudrate = baudrate
        self.timeout  = timeout
        self._ser     = None

    # ── Connection ────────────────────────────────────────

    def connect(self):
        """
        Open the serial port WITHOUT triggering an ESP32 reset.

        The key insight from your TEST 2 results:
          - Opening with DTR=True  → ESP32 resets (we miss READY)
          - Opening with DTR=False → ESP32 stays running (we might miss
            READY if it already fired, but we control timing)

        Strategy:
          1. Open with DTR=False  (no accidental reset)
          2. Pulse DTR low→high→low for exactly 120ms  (deliberate reset)
          3. Now we KNOW the reset just happened, so we listen from t=0
          4. wait_ready() has the full timeout to catch READY
        """
        if not HAS_SERIAL:
            raise ImportError("pyserial not installed – pip install pyserial")

        # ── Step 1: open without touching DTR ────────────
        ser = _serial_mod.Serial()
        ser.port     = self.port
        ser.baudrate = self.baudrate
        ser.timeout  = 1           # readline blocks for max 1 second
        ser.dtr      = False       # MUST be set before open()
        ser.rts      = False
        ser.open()

        # Drain any stale bytes in the OS buffer
        time.sleep(0.05)
        ser.reset_input_buffer()
        self._ser = ser
        log.info(f"[Serial] Port open: {self.port} @ {self.baudrate}  DTR=False")

        # ── Step 2: deliberate, timed reset ──────────────
        # Pull DTR high (assert reset on ESP32 EN pin) for 120ms,
        # then release.  This mirrors exactly what esptool does.
        log.info("[Serial] Pulsing DTR to reset ESP32 cleanly...")
        ser.dtr = True
        time.sleep(0.12)          # 120ms is enough to latch the reset
        ser.dtr = False

        # Clear anything that arrived during the pulse
        time.sleep(0.05)
        ser.reset_input_buffer()
        log.info("[Serial] Reset pulse done – ESP32 is booting")

    def disconnect(self):
        if self._ser and self._ser.is_open:
            self._ser.close()
        log.info("[Serial] Disconnected")

    def is_connected(self) -> bool:
        return self._ser is not None and self._ser.is_open

    # ── Boot synchronisation ──────────────────────────────

    def wait_ready(self, timeout: int = READY_TIMEOUT) -> bool:
        """
        Listen for READY from ESP32.

        The firmware prints READY once per second for 10 seconds after
        boot, so even if Python misses the first one there are 9 more.

        We also print every boot line with [BOOT] prefix so you can see
        exactly what the ESP32 is doing during WiFi connect.
        """
        deadline = time.time() + timeout
        log.info(f"[Serial] Waiting for ESP32 READY (up to {timeout}s)...")
        print(f"\n[Serial] Listening for READY on {self.port} ─── "
              f"(ESP32 takes ~3-8s to connect WiFi)")

        while time.time() < deadline:
            line = self._readline()
            if not line:
                continue

            elapsed = time.time() - (deadline - timeout)
            print(f"  [{elapsed:5.1f}s] [BOOT] {repr(line)}")

            if "READY" in line.upper():
                log.info(f"[Serial] ✓ READY received after {elapsed:.1f}s")
                print(f"\n[Serial] ✓ ESP32 is READY\n")
                return True

        log.warning(f"[Serial] Timed out after {timeout}s waiting for READY")
        print(f"\n[Serial] ✗ READY not received within {timeout}s")
        print("  Check: is WiFi connecting? Is baudrate 115200?")
        return False

    # ── Experiment commands ───────────────────────────────

    def send_command(self, server_ip: str, server_port: int,
                     algo: str, param: str, chain_depth: int, trial: int):
        """Send:  CMD:ip,port,algo,param,chain_depth,trial\n"""
        cmd = f"CMD:{server_ip},{server_port},{algo},{param},{chain_depth},{trial}\n"
        self._ser.write(cmd.encode())
        self._ser.flush()
        log.info(f"[Serial →] {cmd.strip()}")

    def wait_result(self, algo: str = "", param: str = "",
                    chain_depth: int = 0, trial: int = 0) -> Optional[dict]:
        """
        Block until HANDSHAKE_RESULT arrives or timeout.
        Every received line is printed with [RAW SERIAL] for full visibility.
        """
        deadline   = time.time() + self.timeout
        t_start    = time.time()
        config_str = f"{algo}_{param}_chain{chain_depth}_t{trial}"

        while time.time() < deadline:
            line = self._readline()
            if not line:
                continue

            print(f"[RAW SERIAL] {repr(line)}")
            stats["lines_received"] += 1

            if RESULT_PREFIX in line:
                result = _parse_metrics(line)
                if result is not None:
                    return result

        elapsed = time.time() - t_start
        stats["timeouts"] += 1
        print(f"[ERROR] Serial timeout after {elapsed:.1f}s ({config_str})")
        log.warning(f"[Serial] Timeout ({elapsed:.1f}s) for {config_str}")
        return None

    # ── Low-level I/O ─────────────────────────────────────

    def _readline(self) -> str:
        try:
            raw = self._ser.readline()
            if not raw:
                return ""
            line = raw.decode(errors="ignore").strip()
            if line:
                log.debug(f"[ESP32→] {line}")
            return line
        except Exception as e:
            log.error(f"[Serial] Read error: {e}")
            return ""

    # ── CA verification ───────────────────────────────────

    def verify_ca(self, expected_pem: str) -> bool:
        """
        Send FLASH_VERIFY to the running firmware and compare the returned
        CA PEM against expected_pem (the current session Root CA).

        Returns True if they match, False otherwise.
        The firmware must be v1.4+ which added the FLASH_VERIFY command.
        """
        self._ser.write(b"FLASH_VERIFY\n")
        self._ser.flush()
        log.info("[Serial] Sent FLASH_VERIFY – reading firmware CA...")

        deadline  = time.time() + 15
        pem_lines = []
        capturing = False

        while time.time() < deadline:
            raw = self._readline()
            if not raw:
                continue
            if "[FLASH_VERIFY_START]" in raw:
                capturing = True
                pem_lines = []
                continue
            if "[FLASH_VERIFY_END]" in raw:
                break
            if capturing:
                pem_lines.append(raw)

        if not pem_lines:
            log.error("[Serial] FLASH_VERIFY: no response – firmware may be < v1.4")
            return False

        firmware_pem  = "\n".join(pem_lines).strip()
        expected_stripped = expected_pem.strip()

        if firmware_pem == expected_stripped:
            log.info("[Serial] ✓ Firmware CA matches session Root CA")
            return True

        log.error("[Serial] ✗ FIRMWARE CA MISMATCH")
        log.error(f"[Serial]   Expected (first 60): {expected_stripped[:60]}")
        log.error(f"[Serial]   Firmware (first 60): {firmware_pem[:60]}")
        return False

    # ── Compat shims ──────────────────────────────────────
    def on_disconnect(self, cb): pass
    def touch_heartbeat(self):  pass
