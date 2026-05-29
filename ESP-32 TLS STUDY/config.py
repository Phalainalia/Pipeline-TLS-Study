"""
config.py – IoT TLS/PKI Scalability Framework
==============================================
Edit the values in this file before running main.py.

Quick-start checklist:
  [ ] WIFI_SSID / WIFI_PASSWORD  – your AP credentials
  [ ] SERVER_IP                  – your PC's LAN IP  (run: ipconfig / ip addr)
  [ ] SERIAL_PORT                – your ESP32 port   (run: ls /dev/cu.* or ls /dev/ttyUSB*)
  [ ] AUTO_FLASH = False         – flash manually first, set True later
"""

# ── WiFi (written into firmware via PlatformIO build flags) ──────────
WIFI_SSID     = "WIFI_SSID"          # ← your SSID
WIFI_PASSWORD = "PASSWORD"          # ← your password

# ── TLS server ────────────────────────────────────────────────────────
# SERVER_IP must be your PC's LAN IP address reachable from the ESP32.
# Find it with:  ip addr (Linux/Mac)  |  ipconfig (Windows)
# Do NOT use 127.0.0.1 – the ESP32 cannot reach localhost.
SERVER_IP   = "IP"           # ← your PC's LAN IP
SERVER_PORT = 8443

# ── Serial (USB cable between PC and ESP32) ───────────────────────────
# macOS common ports:  /dev/cu.usbserial-10  /dev/cu.SLAB_USBtoUART
# Linux common ports:  /dev/ttyUSB0          /dev/ttyACM0
# Windows:             COM3  COM4  COM5  ...
SERIAL_PORT     = "/dev/cu.usbserial-10"   # ← your ESP32 port
SERIAL_BAUDRATE = 115200

# Timeout waiting for ONE handshake result from the ESP32.
# RSA-4096 with chain depth 3 can take 8-12 seconds.
# Add WiFi reconnect margin → 90 seconds is safe.
SERIAL_TIMEOUT = 90

# ── Experiment matrix ────────────────────────────────────────────────
NUM_TRIALS      = 10     # handshakes per configuration
MAX_CHAIN_DEPTH = 3      # 0=root only  1,2,3=intermediaries

ENABLE_RSA    = True
RSA_KEY_SIZES = [2048, 4096]        # drop 4096 for a faster first run

ENABLE_ECDSA  = True
ECDSA_CURVES  = ["secp256r1", "secp384r1"]

# ── TLS ──────────────────────────────────────────────────────────────
TLS_VERSION       = "TLSv1.2"
HANDSHAKE_TIMEOUT = 30    # seconds (also set in ESP32 firmware)
PAYLOAD_SIZE      = 64    # bytes sent after each successful handshake

# ── Firmware automation ──────────────────────────────────────────────
# AUTO_FLASH = True  → Python calls `pio run --target upload` automatically.
#   Requires `pio` on PATH.  Set False to flash manually (recommended first).
# AUTO_FLASH = False → flash manually:  cd esp32 && pio run --target upload
AUTO_FLASH       = False
FIRMWARE_VERSION = "1.4.0"

# ── Misc ─────────────────────────────────────────────────────────────
REPEAT_HANDSHAKES  = True
HEARTBEAT_INTERVAL = 5
HEARTBEAT_TIMEOUT  = 120
