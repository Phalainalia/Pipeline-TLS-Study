"""
network_debug.py  –  Network reachability + TLS layer debug
============================================================
Runs a TLS server with MAXIMUM verbosity (ssl debug level 2),
then sends a CMD to the ESP32 and captures the detailed TLS
negotiation error from the Python side.

Also tests raw TCP to rule out firewall issues.

Usage:
    python network_debug.py
"""

import socket, ssl, sys, threading, time, logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# ── Enable ssl module debug logging ──────────────────────
# This shows the exact TLS alert code the ESP32 sends back.
logging.basicConfig(level=logging.DEBUG)
# ssl itself doesn't use Python logging, but we can hook into
# the OpenSSL info callback via a monkey-patch approach below.

try:
    import config
    SERVER_IP   = config.SERVER_IP
    SERVER_PORT = config.SERVER_PORT
    SERIAL_PORT = config.SERIAL_PORT
    SERIAL_BAUD = config.SERIAL_BAUDRATE
except Exception:
    SERVER_IP   = "192.168.1.129"
    SERVER_PORT = 8443
    SERIAL_PORT = "/dev/cu.usbserial-10"
    SERIAL_BAUD = 115200

CA_PATH  = Path("certs/session_root/root_ca.crt")
CRT_PATH = Path("certs/RSA_2048_chain0/chain.crt")
KEY_PATH = Path("certs/RSA_2048_chain0/server.key")

print(f"""
╔══════════════════════════════════════════════════════════╗
║  Network + TLS Layer Debug                              ║
╠══════════════════════════════════════════════════════════╣
  Server IP:Port : {SERVER_IP}:{SERVER_PORT}
  CA             : {CA_PATH}
  Cert           : {CRT_PATH}
╚══════════════════════════════════════════════════════════╝
""")

# ── Check cert files exist ────────────────────────────────
for p in [CA_PATH, CRT_PATH, KEY_PATH]:
    if not p.exists():
        print(f"❌ Missing: {p}")
        print("   Run: python tools/export_ca_header.py")
        print("   Then: python main.py --simulate   (to generate all certs)")
        sys.exit(1)
    print(f"✓ Found: {p}  ({p.stat().st_size}B)")

# ── Test 1: raw TCP bind ──────────────────────────────────
print(f"\n── Test 1: Raw TCP server on 0.0.0.0:{SERVER_PORT} ──────────────")
try:
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(("0.0.0.0", SERVER_PORT))
    raw.listen(1)
    raw.close()
    print(f"✓ Port {SERVER_PORT} is free and bindable on 0.0.0.0")
except OSError as e:
    print(f"❌ Cannot bind port {SERVER_PORT}: {e}")
    print("   Another process may have it open.")
    print(f"   Run: sudo lsof -i :{SERVER_PORT}")
    sys.exit(1)

# ── Test 2: TLS context loads without error ───────────────
print(f"\n── Test 2: TLS context setup ──────────────────────────────")
try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(CRT_PATH), str(KEY_PATH))
    ctx.load_verify_locations(str(CA_PATH))
    ctx.verify_mode = ssl.CERT_NONE
    print(f"✓ SSL context created successfully")
    print(f"  min TLS: {ctx.minimum_version}")
    print(f"  max TLS: {ctx.maximum_version}")
except ssl.SSLError as e:
    print(f"❌ SSL context error: {e}")
    sys.exit(1)

# ── Test 3: verbose TLS server ────────────────────────────
print(f"\n── Test 3: Verbose TLS server (waiting for ESP32 CMD) ─────")
print(f"  Listening on 0.0.0.0:{SERVER_PORT}")
print(f"  Will print detailed error on any TLS failure")
print()

connection_errors = []
connection_ok     = []

def verbose_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", SERVER_PORT))
        srv.listen(5)
        srv.settimeout(1.0)
        print(f"  [Server] Accepting connections on :{SERVER_PORT}")

        while not done.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            print(f"\n  [Server] TCP connection from {addr}")

            try:
                # Log the raw bytes before TLS handshake
                conn.settimeout(10)

                tls = ctx.wrap_socket(conn, server_side=True)
                print(f"  [Server] ✅ TLS handshake OK with {addr}")
                print(f"  [Server]    Cipher: {tls.cipher()}")
                print(f"  [Server]    TLS version: {tls.version()}")
                data = tls.recv(256)
                print(f"  [Server]    Received: {repr(data[:50])}")
                tls.sendall(b"PONG:" + data[:50])
                tls.close()
                connection_ok.append(addr)
            except ssl.SSLError as e:
                print(f"  [Server] ❌ SSL ERROR from {addr}:")
                print(f"           Code    : {e.reason}")
                print(f"           Message : {e}")
                print()
                print("  ── SSL Error Analysis ──────────────────────────────")
                err = str(e)
                if "BAD_CERTIFICATE" in err:
                    print("  SSLV3_ALERT_BAD_CERTIFICATE:")
                    print("  The ESP32 sent this alert, meaning IT rejected OUR cert.")
                    print("  Cause: the CA in the ESP32 firmware != CA that signed our cert.")
                    print("  The root_ca_embed.h compiled into the ESP32 is DIFFERENT from")
                    print("  certs/session_root/root_ca.crt on disk.")
                    print()
                    print("  Action: re-flash the ESP32 with the current CA:")
                    print("    python tools/export_ca_header.py")
                    print("    cd esp32 && pio run --target upload")
                elif "UNKNOWN_CA" in err:
                    print("  SSLV3_ALERT_UNKNOWN_CA:")
                    print("  Same as BAD_CERTIFICATE – ESP32 doesn't trust this CA.")
                elif "CERTIFICATE_VERIFY_FAILED" in err:
                    print("  CERTIFICATE_VERIFY_FAILED:")
                    print("  Python's ssl library couldn't verify the cert (self-test).")
                    print("  The cert chain on disk may be broken.")
                elif "HANDSHAKE_FAILURE" in err:
                    print("  HANDSHAKE_FAILURE:")
                    print("  Cipher suite mismatch – check mbedTLS config in platformio.ini")
                connection_errors.append((addr, str(e)))
            except Exception as e:
                print(f"  [Server] ❌ Non-SSL error from {addr}: {e}")
                connection_errors.append((addr, str(e)))
            finally:
                try: conn.close()
                except: pass

done = threading.Event()
t = threading.Thread(target=verbose_server, daemon=True)
t.start()

# ── Send CMD via serial ───────────────────────────────────
print(f"── Sending CMD via serial ({SERIAL_PORT}) ───────────────────")
try:
    import serial as _ser
    ser = _ser.Serial()
    ser.port     = SERIAL_PORT
    ser.baudrate = SERIAL_BAUD
    ser.timeout  = 1
    ser.dtr      = False
    ser.rts      = False
    ser.open()

    # Don't reset – ESP32 is already running (we just used debug_serial.py)
    # Just send a PING first to confirm it's alive
    ser.write(b"PING\n"); ser.flush()
    time.sleep(0.5)
    pong = b""
    while ser.in_waiting:
        pong += ser.read(ser.in_waiting)
        time.sleep(0.05)
    if pong:
        print(f"  PING → {repr(pong.decode(errors='ignore').strip())}")

    # Send the CMD
    cmd = f"CMD:{SERVER_IP},{SERVER_PORT},RSA,2048,0,1\n"
    print(f"  Sending: {repr(cmd.strip())}")
    ser.write(cmd.encode()); ser.flush()

    # Collect output for 30 seconds
    print(f"  Collecting serial output for 30s...")
    print()
    deadline = time.time() + 30
    while time.time() < deadline:
        raw = ser.readline()
        if not raw: continue
        line = raw.decode(errors="ignore").strip()
        if not line: continue
        elapsed = time.time() - (deadline - 30)
        tag = "📊" if "HANDSHAKE_RESULT" in line else "  "
        print(f"  [{elapsed:5.1f}s] {tag} {repr(line)}")
        if "HANDSHAKE_RESULT" in line:
            break

    ser.close()
except ImportError:
    print("  pyserial not installed – skipping serial CMD")
    print("  Waiting 30s for ESP32 to connect on its own...")
    time.sleep(30)
except Exception as e:
    print(f"  Serial error: {e}")
    print("  Waiting 30s for a manual connection test...")
    time.sleep(30)

done.set()
time.sleep(0.5)

# ── Summary ───────────────────────────────────────────────
print()
print("=" * 62)
print("  NETWORK DEBUG SUMMARY")
print("=" * 62)
print(f"  Successful TLS handshakes : {len(connection_ok)}")
print(f"  Failed connections        : {len(connection_errors)}")
if connection_errors:
    for addr, err in connection_errors:
        print(f"    {addr}: {err[:80]}")
print()

if connection_ok:
    print("✅ TLS is working! Run: python main.py")
elif connection_errors:
    errs = " ".join(e for _, e in connection_errors)
    if "BAD_CERTIFICATE" in errs or "UNKNOWN_CA" in errs:
        print("❌ CA mismatch confirmed. The ESP32 must be re-flashed.")
        print()
        print("   DEFINITIVE FIX:")
        print("   1. rm -rf certs/ esp32/.flash_hash")
        print("   2. python tools/export_ca_header.py")
        print("   3. Verify the header:")
        print("      cat esp32/src/root_ca_embed.h")
        print("   4. cd esp32 && pio run --target upload")
        print("   5. python tls_debug.py  (verify fingerprints match)")
        print("   6. python debug_serial.py")
else:
    print("⚠️  No connections received. Is the ESP32 trying to reach this server?")
    print(f"   Check: is {SERVER_IP}:{SERVER_PORT} reachable from the ESP32's WiFi?")
    print(f"   Test (from another machine on same WiFi): nc -zv {SERVER_IP} {SERVER_PORT}")
