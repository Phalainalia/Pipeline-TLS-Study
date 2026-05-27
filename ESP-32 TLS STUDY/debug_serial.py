"""
debug_serial.py  –  ESP32 serial + TLS end-to-end diagnostic
=============================================================
Run this BEFORE main.py to confirm everything works.

Usage:
    cd iot_tls_pki_study
    python debug_serial.py
    python debug_serial.py --no-reset      # if ESP32 already running
    python debug_serial.py --no-tls-test   # skip TLS server, only check serial

What it tests:
    Step 1 – Serial port opens correctly (DTR=False)
    Step 2 – ESP32 resets cleanly via DTR pulse
    Step 3 – ESP32 boots, WiFi connects, READY received
    Step 4 – Python TLS server starts with the session CA
    Step 5 – Sends CMD:... to ESP32 and waits for HANDSHAKE_RESULT
    Step 6 – Parses result and reports SUCCESS/FAIL with reason
"""

import argparse, ssl, socket, sys, threading, time
from pathlib import Path

# ── Import project modules ────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import serial as _ser_mod
except ImportError:
    print("ERROR: pip install pyserial")
    sys.exit(1)

try:
    import config
    PORT      = config.SERIAL_PORT
    BAUD      = config.SERIAL_BAUDRATE
    SERVER_IP = config.SERVER_IP
    SRV_PORT  = config.SERVER_PORT
except Exception:
    PORT      = "/dev/cu.usbserial-10"
    BAUD      = 115200
    SERVER_IP = "192.168.1.129"
    SRV_PORT  = 8443

# ── Args ─────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("--port",         default=PORT)
parser.add_argument("--baud",         default=BAUD,      type=int)
parser.add_argument("--timeout",      default=60,        type=int)
parser.add_argument("--server-ip",    default=SERVER_IP)
parser.add_argument("--server-port",  default=SRV_PORT,  type=int)
parser.add_argument("--no-reset",     action="store_true")
parser.add_argument("--no-tls-test",  action="store_true")
args = parser.parse_args()

print(f"""
╔══════════════════════════════════════════════════════════╗
║      ESP32 Serial + TLS End-to-End Diagnostic           ║
╠══════════════════════════════════════════════════════════╣
  Serial port : {args.port}  @ {args.baud}
  Server IP   : {args.server_ip}:{args.server_port}
  DTR reset   : {'NO (--no-reset)' if args.no_reset else 'YES'}
  TLS test    : {'NO (--no-tls-test)' if args.no_tls_test else 'YES'}
╚══════════════════════════════════════════════════════════╝
""")

t0 = time.time()
ok = {"serial": False, "ready": False, "tls_server": False, "handshake": False}

# ── Step 1: Open serial ───────────────────────────────────
print("[ STEP 1 ] Opening serial port (DTR=False)...")
try:
    ser = _ser_mod.Serial()
    ser.port     = args.port
    ser.baudrate = args.baud
    ser.timeout  = 1
    ser.dtr      = False
    ser.rts      = False
    ser.open()
    ok["serial"] = True
    print(f"           ✓ Open  DTR={ser.dtr}  RTS={ser.rts}")
except _ser_mod.SerialException as e:
    print(f"           ✗ {e}")
    print(f"  Is another process using {args.port}?  Try: lsof {args.port}")
    sys.exit(1)

time.sleep(0.05)
ser.reset_input_buffer()

# ── Step 2: Reset ESP32 ───────────────────────────────────
print("\n[ STEP 2 ] Resetting ESP32 via DTR pulse...")
if args.no_reset:
    print("           Skipped (--no-reset)")
    ser.write(b"PING\n"); ser.flush()
    print("           Sent PING to check if alive")
else:
    ser.dtr = True;  time.sleep(0.12);  ser.dtr = False
    ser.reset_input_buffer()
    print("           ✓ Reset pulse sent (120ms)")

# ── Step 3: Wait for READY ────────────────────────────────
print(f"\n[ STEP 3 ] Waiting for READY (up to {args.timeout}s)...")
print("           ── Boot output ──────────────────────────────")

deadline   = time.time() + args.timeout
ready_seen = False
boot_lines = []

while time.time() < deadline:
    raw = ser.readline()
    if not raw:
        continue
    line    = raw.decode(errors="ignore").strip()
    elapsed = time.time() - t0
    if not line:
        continue
    boot_lines.append(line)

    prefix = "✅ READY" if "READY" in line.upper() else "  "
    print(f"           {prefix}  [{elapsed:5.1f}s]  {repr(line)}")

    if "READY" in line.upper():
        ready_seen = True
        ok["ready"] = True
        break

if not ready_seen:
    print(f"\n           ✗ READY not received within {args.timeout}s")
    print("  Increase --timeout or check WiFi credentials in firmware")
    ser.close()
    sys.exit(1)

# ── Extra check: verify the CA embedded in firmware has no leading newline ──
# Read root_ca_embed.h and confirm R"( is followed immediately by -----BEGIN
_header = Path(__file__).resolve().parent / "esp32" / "src" / "root_ca_embed.h"
if _header.exists():
    _h_text = _header.read_text()
    if 'R"(-----BEGIN CERTIFICATE-----' not in _h_text:
        print()
        print("  ⚠️  WARNING: esp32/src/root_ca_embed.h looks malformed!")
        print("     The raw string R\"(...)\" should start directly with")
        print("     -----BEGIN CERTIFICATE-----, but it doesn\'t.")
        print("     This causes mbedTLS error -9984 (CERT_VERIFY_FAILED).")
        print("     Fix: python tools/export_ca_header.py  then re-flash.")
        print()
    else:
        print("           ✓ root_ca_embed.h format OK (no leading newline)")

# ── Step 4: Start TLS server ──────────────────────────────
tls_server = None
ca_path    = None
srv_cert   = None
srv_key    = None

if not args.no_tls_test:
    print(f"\n[ STEP 4 ] Starting TLS server on 0.0.0.0:{args.server_port}...")
    try:
        from cert_generator import init_session_root, generate_pki
        ca_pem  = init_session_root(algo="RSA", param="2048")
        pki     = generate_pki("RSA", "2048", 0, args.server_ip)
        ca_path  = pki["ca_cert"]
        srv_cert = pki["server_cert"]
        srv_key  = pki["server_key"]

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(srv_cert, srv_key)
        ctx.load_verify_locations(ca_path)
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind(("0.0.0.0", args.server_port))
        raw_sock.listen(5)
        raw_sock.settimeout(1.0)

        ok["tls_server"] = True
        print(f"           ✓ TLS server listening on :{args.server_port}")
        print(f"           ✓ CA     : {ca_path}")
        print(f"           ✓ Cert   : {srv_cert}")
        print(f"           Server cert SAN includes IP={args.server_ip}")

        # Handle connections in background
        def _srv_loop():
            while ok["tls_server"]:
                try:
                    conn, addr = raw_sock.accept()
                    try:
                        with ctx.wrap_socket(conn, server_side=True) as tls:
                            tls.settimeout(10)
                            data = tls.recv(256)
                            if data:
                                tls.sendall(b"PONG:" + data)
                    except Exception as e:
                        print(f"\n           [TLS server] {addr}: {e}")
                    finally:
                        try: conn.close()
                        except: pass
                except socket.timeout:
                    pass

        threading.Thread(target=_srv_loop, daemon=True).start()

    except Exception as e:
        print(f"           ✗ TLS server failed: {e}")
        import traceback; traceback.print_exc()
        ok["tls_server"] = False
else:
    print("\n[ STEP 4 ] TLS server skipped (--no-tls-test)")
    ok["tls_server"] = True   # don't block step 5

# ── Step 5a: Insecure pre-test (confirms TCP/TLS connectivity) ────────
# ESP32 skips cert verification entirely (setInsecure).
# If this succeeds but Step 5b fails → problem is cert validation only.
# If this also fails → network/firewall/server not reachable.
insecure_ok = False
if not args.no_tls_test:
    print(f"\n[ STEP 5a] Insecure pre-test (cert check disabled) → {args.server_ip}:{args.server_port}")
    insecure_cmd = f"CMD_INSECURE:{args.server_ip},{args.server_port},RSA,2048,0,1\n"
    ser.write(insecure_cmd.encode()); ser.flush()
    print(f"           Sent: {repr(insecure_cmd.strip())}")
    insec_deadline = time.time() + 35
    while time.time() < insec_deadline:
        raw = ser.readline()
        if not raw:
            continue
        line    = raw.decode(errors="ignore").strip()
        elapsed = time.time() - t0
        if not line:
            continue
        prefix = "📊" if "HANDSHAKE_RESULT" in line else "  "
        print(f"           {prefix}  [{elapsed:5.1f}s]  {repr(line)}")
        if "HANDSHAKE_RESULT" in line:
            try:
                parts = dict(seg.split("=",1) for seg in line.split(",")[1:] if "=" in seg)
                insecure_ok = int(parts.get("SUCCESS",0)) == 1
            except Exception:
                pass
            break
    if insecure_ok:
        print("           ✅ Insecure TLS OK – TCP/TLS stack works. Cert validation is the issue.")
    else:
        print("           ❌ Insecure TLS FAILED – check network/server reachability.")
        print(f"              Is the Python TLS server running?  Check firewall on port {args.server_port}.")

# ── Step 5b: Secure CMD and wait for HANDSHAKE_RESULT ────────────────
print(f"\n[ STEP 5b] Sending secure CMD to {args.server_ip}:{args.server_port}...")
cmd = f"CMD:{args.server_ip},{args.server_port},RSA,2048,0,1\n"
ser.write(cmd.encode()); ser.flush()
print(f"           Sent: {repr(cmd.strip())}")
print("           ── ESP32 output ────────────────────────────")

result_deadline = time.time() + 35
result_line     = None

while time.time() < result_deadline:
    raw = ser.readline()
    if not raw:
        continue
    line    = raw.decode(errors="ignore").strip()
    elapsed = time.time() - t0
    if not line:
        continue

    prefix = "📊" if "HANDSHAKE_RESULT" in line else "  "
    print(f"           {prefix}  [{elapsed:5.1f}s]  {repr(line)}")

    if "HANDSHAKE_RESULT" in line:
        result_line = line
        break

ser.close()
# Preserve server status for the summary *before* signalling the thread to stop.
# (ok["tls_server"] doubles as the thread-stop flag; we want the display to
#  reflect whether the server actually ran, not whether the thread is still up.)
_tls_server_ran = ok["tls_server"]
ok["tls_server"] = False   # signal server thread to exit its loop

# ── Step 6: Parse and report ──────────────────────────────
print(f"\n[ STEP 6 ] Parsing result...")

handshake_ok = False
if result_line:
    try:
        parts = {}
        for seg in result_line.split(",")[1:]:
            if "=" in seg:
                k, v = seg.split("=", 1)
                parts[k.strip()] = v.strip()
        hs      = float(parts.get("HS", 0))
        heap    = int(parts.get("HEAP", 0))
        frag    = float(parts.get("FRAG", 0))
        success = int(parts.get("SUCCESS", 0))

        if success and hs > 0:
            handshake_ok = True
            ok["handshake"] = True
            print(f"           ✅ TLS HANDSHAKE SUCCEEDED")
            print(f"              HS={hs:.0f}ms  HEAP={heap}B  FRAG={frag:.3f}")
        else:
            print(f"           ❌ TLS HANDSHAKE FAILED  (SUCCESS={success}, HS={hs}ms)")
            print()
            print("  Likely causes:")
            print("  A) CA mismatch: firmware has a different Root CA than the server cert")
            print("     Fix: python tools/export_ca_header.py  →  pio run -t upload")
            print(f"  B) Server IP not in cert SAN: cert was generated for a different IP")
            print(f"     Fix: ensure config.SERVER_IP = '{args.server_ip}' and regenerate")
            print(f"          by deleting certs/ and running python tools/export_ca_header.py")
            print(f"  C) Python TLS server not reachable from ESP32")
            print(f"     Fix: ping {args.server_ip} from ESP32's network")
            print(f"          check firewall: sudo lsof -i :{args.server_port}")
    except Exception as e:
        print(f"           ✗ Parse error: {e}  raw='{result_line}'")
else:
    print("           ✗ No HANDSHAKE_RESULT received within 35s")
    print("  The ESP32 may have failed to reach the server.")
    print(f"  Is Python's TLS server running and reachable at {args.server_ip}:{args.server_port}?")

# ── Summary ───────────────────────────────────────────────
print(f"""
╔══════════════════════════════════════════════════════════╗
║  DIAGNOSTIC SUMMARY                                      ║
╠══════════════════════════════════════════════════════════╣
  Serial open    : {'✅' if ok['serial']     else '❌'}
  ESP32 READY    : {'✅' if ok['ready']      else '❌'}
  TLS server     : {'✅' if _tls_server_ran  else '❌  (or skipped)'}
  TLS handshake  : {'✅ SUCCESS' if ok['handshake'] else '❌ FAILED'}
╚══════════════════════════════════════════════════════════╝
""")

all_ok = ok['serial'] and ok['ready'] and _tls_server_ran and ok['handshake']
if all_ok:
    print("✅ All checks passed.  Run:  python main.py")
else:
    print("❌ Fix the failed steps above, then re-run this script.")