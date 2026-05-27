"""
flash_verify.py  –  Confirm exactly which CA is running on the ESP32
=====================================================================
Sends "FLASH_VERIFY" over serial, reads back the full CA PEM the ESP32
has in flash, and compares it byte-for-byte with the disk CA.

Also sends CMD_INSECURE: to test TLS without cert verification —
this proves whether the network path works and only the CA is the issue.

Usage:
    python flash_verify.py
"""

import hashlib, re, socket, ssl, sys, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import serial as _ser_mod
except ImportError:
    print("pip install pyserial"); sys.exit(1)

try:
    import config
    SERIAL_PORT = config.SERIAL_PORT
    SERIAL_BAUD = config.SERIAL_BAUDRATE
    SERVER_IP   = config.SERVER_IP
    SERVER_PORT = config.SERVER_PORT
except Exception:
    SERIAL_PORT = "/dev/cu.usbserial-10"
    SERIAL_BAUD = 115200
    SERVER_IP   = "192.168.1.129"
    SERVER_PORT = 8443

DISK_CA   = Path("certs/session_root/root_ca.crt")
HEADER    = Path("esp32/src/root_ca_embed.h")
SRV_CERT  = Path("certs/RSA_2048_chain0/chain.crt")
SRV_KEY   = Path("certs/RSA_2048_chain0/server.key")

def fp(pem: str) -> str:
    import base64
    b64 = "".join(l for l in pem.strip().splitlines() if not l.startswith("---"))
    return hashlib.sha256(base64.b64decode(b64)).hexdigest()[:24]

print("""
╔══════════════════════════════════════════════════════════╗
║  Flash CA Verify + Insecure TLS Test                    ║
╚══════════════════════════════════════════════════════════╝
""")

# ── Open serial ───────────────────────────────────────────
print(f"[1] Opening {SERIAL_PORT}...")
ser = _ser_mod.Serial()
ser.port = SERIAL_PORT; ser.baudrate = SERIAL_BAUD
ser.timeout = 2; ser.dtr = False; ser.rts = False
ser.open()
time.sleep(0.1); ser.reset_input_buffer()
print("    ✓ Open (no reset – ESP32 already running)")

def drain(seconds=1.0):
    lines = []
    deadline = time.time() + seconds
    while time.time() < deadline:
        raw = ser.readline()
        if raw:
            l = raw.decode(errors="ignore").strip()
            if l: lines.append(l)
    return lines

def send(cmd: str):
    ser.write((cmd + "\n").encode()); ser.flush()
    print(f"    → {repr(cmd)}")

# ── Step 1: Send FLASH_VERIFY ─────────────────────────────
print("\n[2] Requesting CA PEM from ESP32 (FLASH_VERIFY)...")
send("FLASH_VERIFY")
time.sleep(0.2)

# Read until [FLASH_VERIFY_END] or timeout
flash_lines = []
pem_lines   = []
in_pem      = False
deadline    = time.time() + 15

while time.time() < deadline:
    raw = ser.readline()
    if not raw: continue
    l = raw.decode(errors="ignore").strip()
    if not l: continue
    flash_lines.append(l)
    print(f"    {repr(l)}")
    if "[FLASH_VERIFY_START]" in l: in_pem = True; continue
    if "[FLASH_VERIFY_END]"   in l: break
    if in_pem: pem_lines.append(l)

flash_pem = "\n".join(pem_lines).strip()

if not flash_pem:
    print("    ✗ No PEM received from ESP32")
    print("      The firmware may be an old build without FLASH_VERIFY support.")
    print("      Re-flash: cd esp32 && pio run --target upload")
    flash_fp = "NONE"
else:
    try:
        flash_fp = fp(flash_pem)
        print(f"\n    ESP32 flash CA fingerprint : {flash_fp}")
    except Exception as e:
        print(f"    ✗ Could not fingerprint ESP32 CA: {e}")
        flash_fp = "ERROR"

# ── Step 2: Compare with disk ─────────────────────────────
print("\n[3] Comparing with disk CA...")
if DISK_CA.exists():
    disk_pem = DISK_CA.read_text()
    disk_fp  = fp(disk_pem)
    print(f"    Disk CA fingerprint        : {disk_fp}")
    print(f"    ESP32 flash CA fingerprint : {flash_fp}")
    if flash_fp == disk_fp:
        print("    ✅ MATCH – ESP32 has the correct CA")
        ca_ok = True
    elif flash_fp == "NONE":
        print("    ⚠️  Could not read ESP32 CA – old firmware, re-flash")
        ca_ok = False
    else:
        print("    ❌ MISMATCH – ESP32 has a DIFFERENT CA than disk")
        print()
        print("    The pio upload completed but the old binary is still running.")
        print("    This can happen if:")
        print("      a) The upload reported success but silently failed")
        print("      b) The ESP32 booted from a backup partition")
        print("      c) The flash is write-protected (rare)")
        print()
        print("    Fix: hold the BOOT button on the ESP32 while running:")
        print("      cd esp32 && pio run --target upload")
        print("    Then press EN/RESET once after upload completes.")
        ca_ok = False
else:
    print("    ✗ Disk CA not found – run: python tools/export_ca_header.py")
    ca_ok = False

# ── Step 3: Insecure TLS test ─────────────────────────────
print(f"\n[4] Insecure TLS test (cert verification DISABLED)...")
print(f"    This proves whether the network path works regardless of CA.")

# ── Generate server certs if missing ──────────────────────
if not (SRV_CERT.exists() and SRV_KEY.exists()):
    print(f"    Server cert files missing – generating now...")
    try:
        from cert_generator import init_session_root, generate_pki
        init_session_root("RSA", "2048")
        pki = generate_pki("RSA", 2048, 0, SERVER_IP)
        SRV_CERT = Path(pki["server_cert"])
        SRV_KEY  = Path(pki["server_key"])
        print(f"    ✓ Certs generated: {SRV_CERT}")
    except Exception as e:
        print(f"    ✗ Could not generate certs: {e}")

print(f"    Starting TLS server on 0.0.0.0:{SERVER_PORT}...")

tls_insecure_ok = False
tls_error       = ""

if SRV_CERT.exists() and SRV_KEY.exists() and DISK_CA.exists():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(SRV_CERT), str(SRV_KEY))
    ctx.verify_mode = ssl.CERT_NONE

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("0.0.0.0", SERVER_PORT))
    srv_sock.listen(5)
    srv_sock.settimeout(1.0)
    print(f"    ✓ Server up on :{SERVER_PORT}")

    def _srv():
        while not done.is_set():
            try:
                conn, addr = srv_sock.accept()
                print(f"\n    [Server] TCP from {addr}")
                try:
                    with ctx.wrap_socket(conn, server_side=True) as tls:
                        tls.settimeout(10)
                        print(f"    [Server] ✅ TLS OK  cipher={tls.cipher()}")
                        data = tls.recv(256)
                        tls.sendall(b"PONG:" + data[:32])
                except ssl.SSLError as e:
                    print(f"    [Server] ❌ SSL: {e}")
                    tls_error = str(e)
                finally:
                    try: conn.close()
                    except: pass
            except socket.timeout:
                pass

    done = threading.Event()
    threading.Thread(target=_srv, daemon=True).start()

    # Send CMD_INSECURE
    cmd = f"CMD_INSECURE:{SERVER_IP},{SERVER_PORT},RSA,2048,0,1"
    print(f"    Sending: {repr(cmd)}")
    send(cmd)

    print(f"    Waiting up to 30s for HANDSHAKE_RESULT...")
    deadline = time.time() + 30
    while time.time() < deadline:
        raw = ser.readline()
        if not raw: continue
        l = raw.decode(errors="ignore").strip()
        if not l: continue
        elapsed = time.time() - (deadline - 30)
        print(f"    [{elapsed:5.1f}s] {repr(l)}")
        if "HANDSHAKE_RESULT" in l:
            parts = dict(seg.split("=",1) for seg in l.split(",")[1:] if "=" in seg)
            success = int(parts.get("SUCCESS", 0))
            hs_ms   = float(parts.get("HS", 0))
            if success and hs_ms > 0:
                tls_insecure_ok = True
                print(f"\n    ✅ INSECURE TLS SUCCEEDED  HS={hs_ms:.0f}ms")
                print(f"    The network path works. Only the CA verification fails.")
                print(f"    → The ESP32 has a wrong/old CA embedded in flash.")
            else:
                print(f"\n    ❌ INSECURE TLS ALSO FAILED  HS={hs_ms}ms")
                print(f"    The problem is NOT just the CA.")
                print(f"    Possible causes:")
                print(f"      • macOS firewall blocking port {SERVER_PORT}")
                print(f"        Test: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall")
                print(f"        Fix:  System Settings → Firewall → turn OFF temporarily")
                print(f"      • Python server not binding to the right interface")
                print(f"        Check: netstat -an | grep {SERVER_PORT}")
                print(f"      • ESP32 WiFi and Mac on different subnets")
                print(f"        ESP32 IP: 192.168.1.210  Mac IP: {SERVER_IP}")
            break
    done.set()
    srv_sock.close()
else:
    print("    Skipped – server cert files missing")
    print("    Run: python main.py --simulate  to generate certs")

ser.close()

# ── Summary ───────────────────────────────────────────────
print(f"""
╔══════════════════════════════════════════════════════════╗
║  FLASH VERIFY SUMMARY                                   ║
╠══════════════════════════════════════════════════════════╣
  Flash CA == Disk CA   : {'✅ YES' if ca_ok else '❌ NO (re-flash required)'}
  Insecure TLS works    : {'✅ YES → re-flash ESP32 to fix CA' if tls_insecure_ok else '❌ NO → network/firewall issue'}
╚══════════════════════════════════════════════════════════╝
""")

if tls_insecure_ok and not ca_ok:
    print("CONCLUSION: Network is fine. ESP32 has wrong CA in flash.")
    print()
    print("DEFINITIVE RE-FLASH PROCEDURE:")
    print("  1. Hold the BOOT button on the ESP32")
    print("  2. While holding BOOT, run:")
    print("       cd esp32 && pio run --target upload")
    print("  3. Release BOOT when you see 'Connecting...' in the PlatformIO output")
    print("  4. Press EN/RESET after 'Hard resetting via RTS pin...' appears")
    print("  5. Run: python flash_verify.py")
elif tls_insecure_ok and ca_ok:
    print("CONCLUSION: CA match confirmed AND network works.")
    print("Something else is wrong. Try: python main.py")
elif not tls_insecure_ok:
    print("CONCLUSION: Even insecure TLS fails → firewall or network problem.")
    print()
    print("Test from your Mac terminal:")
    print(f"  nc -zv {SERVER_IP} {SERVER_PORT}")
    print(f"  sudo lsof -i :{SERVER_PORT}")
    print()
    print("Temporarily disable macOS firewall:")
    print("  System Settings → Network → Firewall → turn off")
    print("  Then retest, then re-enable.")