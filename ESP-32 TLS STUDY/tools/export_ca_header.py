"""
tools/export_ca_header.py
=========================
Generates the session Root CA (if not already done) and writes it into
esp32/src/root_ca_embed.h so PlatformIO can compile it into the firmware.

Run this ONCE before flashing, or whenever you delete the certs/ folder.

Usage:
    cd iot_tls_pki_study
    python tools/export_ca_header.py

What it does:
    1. Creates certs/session_root/root_ca.{key,crt}  (reuses if exists)
    2. Writes esp32/src/root_ca_embed.h
    3. Prints the first/last line of the PEM so you can verify it
"""

import sys
from pathlib import Path

# Make project root importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from cert_generator import init_session_root
from firmware_flasher import write_ca_header

def main():
    print("[ExportCA] Initialising session Root CA...")

    # Always use RSA-2048 for the root CA regardless of experiment algo,
    # because this is only for trust anchoring (not performance study).
    ca_pem = init_session_root(algo="RSA", param="2048")

    header_path = Path(__file__).resolve().parent.parent / "esp32" / "src" / "root_ca_embed.h"
    write_ca_header(ca_pem)

    # Quick sanity check
    lines = ca_pem.strip().splitlines()
    print(f"[ExportCA] CA PEM: {lines[0]}")
    print(f"[ExportCA]         ... ({len(lines)-2} body lines) ...")
    print(f"[ExportCA]         {lines[-1]}")
    print(f"[ExportCA] Header written → {header_path}")
    print()
    print("Next step:  cd esp32 && pio run --target upload")

if __name__ == "__main__":
    main()
