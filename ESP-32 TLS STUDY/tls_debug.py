"""
tls_debug.py  –  Deep TLS/PKI mismatch diagnostic
==================================================
Run this script to get a complete fingerprint of:
  1. The CA embedded in the firmware (from root_ca_embed.h)
  2. The CA on disk (certs/session_root/root_ca.crt)
  3. The server cert on disk and what CA signed it
  4. A Python-to-Python TLS test to verify the cert chain works
  5. OpenSSL verification of the cert chain

Usage:
    cd iot_tls_pki_study
    python tls_debug.py

The output tells you EXACTLY which bytes don't match.
"""

import hashlib, re, socket, ssl, sys, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("WARNING: pip install cryptography  for full cert inspection")

# ── Helpers ───────────────────────────────────────────────

def sha256_pem(pem_text: str) -> str:
    """SHA-256 of the DER bytes (canonical, ignores PEM whitespace differences)."""
    # Strip PEM armor and decode
    b64 = "".join(
        line for line in pem_text.strip().splitlines()
        if not line.startswith("-----")
    )
    import base64
    der = base64.b64decode(b64)
    return hashlib.sha256(der).hexdigest()[:16]   # first 16 hex chars is enough

def pem_fingerprint(pem_text: str) -> str:
    try:
        return sha256_pem(pem_text)
    except Exception as e:
        return f"ERROR({e})"

def extract_pem_from_header(header_path: Path) -> str | None:
    """Extract the PEM string from root_ca_embed.h."""
    if not header_path.exists():
        return None
    text = header_path.read_text()
    # Match R"(...)" raw string literal
    m = re.search(r'R"\((.+?)\)"', text, re.DOTALL)
    if m:
        return m.group(1).strip()
    # Fallback: look for -----BEGIN ... -----END-----
    m = re.search(r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)', text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return None

def cert_info(pem_text: str, label: str):
    """Print subject, issuer, SAN, validity of a PEM cert."""
    if not HAS_CRYPTO:
        return
    try:
        cert = x509.load_pem_x509_certificate(pem_text.encode(), default_backend())
        print(f"    Subject : {cert.subject.rfc4514_string()}")
        print(f"    Issuer  : {cert.issuer.rfc4514_string()}")
        print(f"    Valid   : {cert.not_valid_before_utc} → {cert.not_valid_after_utc}")
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            print(f"    SANs    : {[str(n.value) for n in san.value]}")
        except x509.ExtensionNotFound:
            print("    SANs    : (none)")
        pub = cert.public_key()
        if hasattr(pub, 'key_size'):
            print(f"    Key     : RSA-{pub.key_size}")
        else:
            print(f"    Key     : ECDSA")
    except Exception as e:
        print(f"    Parse error: {e}")

def fingerprint_of_issuer(pem_text: str) -> str:
    """Return the Subject of the issuer as a short string."""
    if not HAS_CRYPTO:
        return "?"
    try:
        cert = x509.load_pem_x509_certificate(pem_text.encode(), default_backend())
        return cert.issuer.rfc4514_string()
    except:
        return "?"

# ── Paths ─────────────────────────────────────────────────
HEADER_PATH  = Path("esp32/src/root_ca_embed.h")
CA_DISK_PATH = Path("certs/session_root/root_ca.crt")
SRV_CRT_PATH = Path("certs/RSA_2048_chain0/chain.crt")
SRV_KEY_PATH = Path("certs/RSA_2048_chain0/server.key")

print()
print("=" * 62)
print("  TLS/PKI Deep Diagnostic")
print("=" * 62)

# ── 1. CA in firmware header ──────────────────────────────
print()
print("┌─ [1] CA embedded in firmware (root_ca_embed.h) ─────────")
firmware_ca_pem = extract_pem_from_header(HEADER_PATH)
if firmware_ca_pem is None:
    print(f"│  ✗ File not found: {HEADER_PATH}")
    print("│  Run: python tools/export_ca_header.py")
    firmware_ca_fp = "MISSING"
else:
    firmware_ca_fp = pem_fingerprint(firmware_ca_pem)
    print(f"│  File       : {HEADER_PATH}")
    print(f"│  Fingerprint: {firmware_ca_fp}")
    cert_info(firmware_ca_pem, "firmware CA")
    # Show first/last line
    lines = firmware_ca_pem.strip().splitlines()
    print(f"│  PEM[0]     : {lines[0]}")
    print(f"│  PEM[-1]    : {lines[-1]}")
    print(f"│  PEM lines  : {len(lines)}")
print("└" + "─" * 60)

# ── 2. CA on disk ─────────────────────────────────────────
print()
print("┌─ [2] Session Root CA on disk ───────────────────────────")
if not CA_DISK_PATH.exists():
    print(f"│  ✗ Not found: {CA_DISK_PATH}")
    print("│  Run: python tools/export_ca_header.py")
    disk_ca_fp = "MISSING"
else:
    disk_ca_pem = CA_DISK_PATH.read_text()
    disk_ca_fp  = pem_fingerprint(disk_ca_pem)
    print(f"│  File       : {CA_DISK_PATH}")
    print(f"│  Fingerprint: {disk_ca_fp}")
    cert_info(disk_ca_pem, "disk CA")
print("└" + "─" * 60)

# ── 3. Firmware vs disk match ─────────────────────────────
print()
if firmware_ca_fp == "MISSING" or disk_ca_fp == "MISSING":
    print("⚠️  Cannot compare – one or both CAs missing")
elif firmware_ca_fp == disk_ca_fp:
    print(f"✅ [3] CA MATCH: firmware == disk  ({firmware_ca_fp})")
    print("   The ESP32 firmware trusts the same CA that's on disk.")
else:
    print(f"❌ [3] CA MISMATCH:")
    print(f"   Firmware CA  fingerprint: {firmware_ca_fp}")
    print(f"   Disk CA      fingerprint: {disk_ca_fp}")
    print()
    print("   This is the root cause of TLS FAILED.")
    print("   The ESP32 was flashed with a DIFFERENT Root CA than the one")
    print("   currently signing server certs.")
    print()
    print("   Fix:")
    print("     rm -rf certs/")
    print("     python tools/export_ca_header.py")
    print("     cd esp32 && pio run --target upload && cd ..")
    print()
    print("   Then re-run: python tls_debug.py")

# ── 4. Server cert chain ──────────────────────────────────
print()
print("┌─ [4] Server cert chain (chain.crt) ─────────────────────")
if not SRV_CRT_PATH.exists():
    print(f"│  ✗ Not found: {SRV_CRT_PATH}")
    print("│  Run: python main.py --simulate  (generates PKI)")
else:
    chain_text = SRV_CRT_PATH.read_text()
    # Split multiple certs
    pem_blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        chain_text, re.DOTALL)
    print(f"│  File       : {SRV_CRT_PATH}")
    print(f"│  Certs in chain: {len(pem_blocks)}")
    for i, blk in enumerate(pem_blocks):
        label = "server" if i == 0 else f"intermediate-{i}"
        fp    = pem_fingerprint(blk)
        print(f"│  [{i}] {label}")
        print(f"│      Fingerprint: {fp}")
        cert_info(blk, label)

    # Check that the first cert's issuer matches the disk CA subject
    if HAS_CRYPTO and CA_DISK_PATH.exists():
        try:
            srv = x509.load_pem_x509_certificate(pem_blocks[0].encode(), default_backend())
            ca  = x509.load_pem_x509_certificate(CA_DISK_PATH.read_bytes(), default_backend())

            # For depth=0 the server cert is signed directly by root
            issuer_matches = srv.issuer == ca.subject
            print(f"│")
            print(f"│  Server cert issuer == Root CA subject: "
                  f"{'✅ YES' if issuer_matches else '❌ NO'}")
            if not issuer_matches:
                print(f"│  Server issuer : {srv.issuer.rfc4514_string()}")
                print(f"│  Root subject  : {ca.subject.rfc4514_string()}")
        except Exception as e:
            print(f"│  Issuer check error: {e}")
print("└" + "─" * 60)

# ── 5. Python-to-Python TLS verify ───────────────────────
print()
print("┌─ [5] Python ssl self-test (no ESP32 needed) ─────────────")
if not (SRV_CRT_PATH.exists() and SRV_KEY_PATH.exists() and CA_DISK_PATH.exists()):
    print("│  Skipped – cert files missing")
else:
    try:
        ctx_srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx_srv.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx_srv.load_cert_chain(str(SRV_CRT_PATH), str(SRV_KEY_PATH))
        ctx_srv.verify_mode = ssl.CERT_NONE

        ctx_cli = ssl.create_default_context(cafile=str(CA_DISK_PATH))
        ctx_cli.check_hostname = False

        result = {"ok": False, "err": ""}

        def _srv():
            with socket.socket() as raw:
                raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                raw.bind(("127.0.0.1", 29443))
                raw.listen(1)
                raw.settimeout(5)
                try:
                    conn, _ = raw.accept()
                    with ctx_srv.wrap_socket(conn, server_side=True) as s:
                        s.recv(4); s.sendall(b"OK")
                except Exception as e:
                    result["err"] = f"server: {e}"

        t = threading.Thread(target=_srv, daemon=True)
        t.start(); time.sleep(0.2)

        try:
            with socket.create_connection(("127.0.0.1", 29443), timeout=5) as c:
                with ctx_cli.wrap_socket(c) as s:
                    s.sendall(b"hi")
                    r = s.recv(4)
                    if r == b"OK":
                        result["ok"] = True
        except Exception as e:
            result["err"] = f"client: {e}"

        t.join(timeout=3)

        if result["ok"]:
            print("│  ✅ Python ssl: cert chain verifies correctly")
            print("│     This means the PKI on disk is valid.")
            print("│     If ESP32 still fails → firmware has old CA (re-flash).")
        else:
            print(f"│  ❌ Python ssl: FAILED  ({result['err']})")
            print("│     The cert chain on disk itself is broken.")
            print("│     Fix: rm -rf certs/ && python tools/export_ca_header.py")
    except Exception as e:
        print(f"│  Error setting up test: {e}")
        import traceback; traceback.print_exc()
print("└" + "─" * 60)

# ── 6. Header file content dump ───────────────────────────
print()
print("┌─ [6] Full root_ca_embed.h content ──────────────────────")
if HEADER_PATH.exists():
    content = HEADER_PATH.read_text()
    lines   = content.splitlines()
    print(f"│  Lines: {len(lines)}")
    print(f"│  Size : {len(content)} bytes")
    print("│")
    for i, line in enumerate(lines):
        print(f"│  {i+1:3d}: {line}")
else:
    print(f"│  ✗ File not found: {HEADER_PATH}")
print("└" + "─" * 60)

# ── 7. Flash status ───────────────────────────────────────
print()
print("┌─ [7] Flash cache status ────────────────────────────────")
hash_file = Path("esp32/.flash_hash")
if hash_file.exists():
    cached = hash_file.read_text().strip()
    print(f"│  Cached hash : {cached[:32]}...")
    print("│  This is the hash of (CA + WiFi + IP + version) at last flash.")
    print("│  If CA changed since then, the ESP32 still has the old CA.")
    print("│  Delete this file to force re-flash:")
    print("│    rm esp32/.flash_hash")
else:
    print("│  No cached hash – firmware has never been auto-flashed.")
print("└" + "─" * 60)

# ── Summary ───────────────────────────────────────────────
print()
print("=" * 62)
print("  DIAGNOSIS COMPLETE")
print("=" * 62)
if firmware_ca_fp != "MISSING" and disk_ca_fp != "MISSING":
    if firmware_ca_fp == disk_ca_fp:
        print()
        print("  CAs match ✅ → The problem is NOT a CA mismatch.")
        print()
        print("  Other things to check:")
        print("  • macOS firewall blocking port 8443?")
        print("    Test: nc -zv 192.168.1.129 8443")
        print("    Fix:  System Settings → Firewall → allow incoming on 8443")
        print()
        print("  • Python TLS server binding to wrong interface?")
        print("    The server must bind to 0.0.0.0 (all interfaces), not 127.0.0.1")
        print()
        print("  • mbedTLS hostname validation?")
        print("    ESP32 calls client.connect(ip, port) not client.connect(hostname)")
        print("    mbedTLS with WiFiClientSecure does NOT check hostname by default")
        print("    but DOES check IP SANs when setCACert() is used.")
        print()
        print("  Run this to test TCP reachability from another device:")
        print("    nc -zv 192.168.1.129 8443")
    else:
        print()
        print("  CAs DO NOT match ❌ → Root cause found.")
        print("  Follow the Fix instructions in section [3] above.")
print()
