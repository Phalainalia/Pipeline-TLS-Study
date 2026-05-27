"""
cert_generator.py
Automatic PKI generation: Root CA → optional intermediaries → server cert.

KEY DESIGN for ESP32 compatibility:
  - ONE shared Root CA per experiment session (written to certs/session_root/)
  - ALL server certs across all chain depths are signed by that same root CA chain
  - The Root CA embedded in the firmware never changes mid-session
  - Server certs include the actual SERVER_IP in the SAN so mbedTLS accepts them

The ESP32's mbedTLS verifies:
  1. Server cert is signed by a trusted CA  → Root CA must match exactly
  2. Server hostname/IP matches the SAN     → SERVER_IP must be in the cert
  3. Cert is not expired                    → handled (10 year validity for CA)
"""

import datetime, ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

CERTS_DIR = Path("certs")

# ── Session root CA (shared across all configs in one run) ──────────────────
# Generated once per session; all server certs derive from it.
# This is the PEM that gets embedded in the ESP32 firmware.
_SESSION_ROOT_KEY  = None
_SESSION_ROOT_CERT = None
_SESSION_ROOT_PEM  = None   # cached string PEM for firmware_flasher


# ── Helpers ────────────────────────────────────────────────────────────────

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def _name(cn: str):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,       "MX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,  "IoT-PKI-Study"),
        x509.NameAttribute(NameOID.COMMON_NAME,         cn),
    ])

def _gen_key(algo: str, param):
    if algo == "RSA":
        return rsa.generate_private_key(65537, int(param), default_backend())
    curve = {"secp256r1": ec.SECP256R1(), "secp384r1": ec.SECP384R1()}[str(param)]
    return ec.generate_private_key(curve, default_backend())

def _hash_for(key):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return hashes.SHA384() if key.key_size >= 384 else hashes.SHA256()
    return hashes.SHA256()

def _pem_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())

def _pem_cert(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)

def _save(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


# ── Certificate builders ────────────────────────────────────────────────────

def _build_ca_cert(key, cn: str, issuer_name, issuer_key, days=3650):
    subject = _name(cn)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(issuer_key, _hash_for(issuer_key), default_backend())
    )

def _build_server_cert(key, server_ip: str, issuer_cert, issuer_key):
    """
    Build server cert with SAN that includes the actual LAN IP.
    mbedTLS on ESP32 validates the SAN IP entry, not just the CN,
    so this must match the IP the ESP32 dials.

    not_valid_before is backdated by 5 minutes to handle clock skew between
    Python (system clock) and the ESP32 (NTP-synced clock).  Without this,
    mbedTLS rejects the cert with BADCERT_FUTURE if the ESP32's RTC is even
    a few seconds behind Python's clock.
    """
    # Note on mbedTLS IP SAN matching (ESP32 / mbedTLS 2.16.x):
    # When connect("10.x.x.x", port) is called, WiFiClientSecure passes the
    # IP string to mbedtls_ssl_set_hostname().  mbedTLS then checks it as a
    # *hostname* (string match) against DNS SANs first.  The binary iPAddress
    # SAN comparison path is only triggered in some mbedTLS builds/configs.
    # Fix: add server_ip ALSO as a dNSName so the plain string comparison
    # matches, while keeping the proper iPAddress SAN for RFC compliance.
    san_entries = [
        x509.DNSName("iot-tls-server"),
        x509.DNSName("localhost"),
        x509.DNSName(server_ip),           # IP string as DNS SAN – mbedTLS compat
    ]
    try:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(server_ip)))
    except ValueError:
        print(f"[PKI] Warning: '{server_ip}' is not a valid IP – SAN will be DNS-only")

    # 10-min grace: handles NTP failure where ESP32 stale RTC may be up to
    # ~10 minutes behind Python's system clock (5 min wasn't always enough).
    not_before = _now() - datetime.timedelta(minutes=10)
    return (
        x509.CertificateBuilder()
        .subject_name(_name("iot-tls-server"))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        # SubjectKeyIdentifier and AuthorityKeyIdentifier help mbedTLS build
        # the chain without having to fall back to issuer-name matching alone.
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False)
        .sign(issuer_key, _hash_for(issuer_key), default_backend())
    )


# ── Session root CA ────────────────────────────────────────────────────────

def init_session_root(algo: str = "RSA", param: str = "2048") -> str:
    """
    Create (or reload) the one Root CA for this entire experiment session.
    Returns the PEM string.  Call once before any generate_pki() calls.

    The same root is reused for all algorithm/chain combinations so the
    single CA cert in the ESP32 firmware trusts ALL server certs.
    """
    global _SESSION_ROOT_KEY, _SESSION_ROOT_CERT, _SESSION_ROOT_PEM

    root_dir  = CERTS_DIR / "session_root"
    key_path  = root_dir / "root_ca.key"
    cert_path = root_dir / "root_ca.crt"

    if cert_path.exists() and key_path.exists():
        # Reload from disk (supports resume across Python restarts)
        print("[PKI] Reusing existing session Root CA")
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.x509 import load_pem_x509_certificate
        _SESSION_ROOT_KEY  = load_pem_private_key(key_path.read_bytes(), None)
        _SESSION_ROOT_CERT = load_pem_x509_certificate(cert_path.read_bytes())
    else:
        print(f"[PKI] Generating new session Root CA ({algo} {param})")
        root_dir.mkdir(parents=True, exist_ok=True)
        _SESSION_ROOT_KEY  = _gen_key(algo, param)
        _SESSION_ROOT_CERT = _build_ca_cert(
            _SESSION_ROOT_KEY, "IoT-Study-Root-CA",
            _name("IoT-Study-Root-CA"), _SESSION_ROOT_KEY)
        _save(key_path,  _pem_key(_SESSION_ROOT_KEY))
        _save(cert_path, _pem_cert(_SESSION_ROOT_CERT))
        print(f"[PKI] Session Root CA saved → {cert_path}")

    _SESSION_ROOT_PEM = cert_path.read_text()
    return _SESSION_ROOT_PEM


def get_session_root_pem() -> str:
    """Return the session Root CA PEM (for embedding in firmware)."""
    if _SESSION_ROOT_PEM is None:
        raise RuntimeError("Call init_session_root() before get_session_root_pem()")
    return _SESSION_ROOT_PEM


def get_session_root_path() -> str:
    return str(CERTS_DIR / "session_root" / "root_ca.crt")


# ── Per-experiment PKI ─────────────────────────────────────────────────────

def generate_pki(algo: str, param, chain_depth: int, server_ip: str) -> dict:
    """
    Generate server cert + intermediate chain for one experiment configuration.
    All certs are signed back to the shared session Root CA.

    chain_depth = number of intermediate CAs between root and server cert.
    """
    if _SESSION_ROOT_KEY is None:
        raise RuntimeError(
            "Call cert_generator.init_session_root() before generate_pki()")

    tag  = f"{algo}_{param}_chain{chain_depth}"
    base = CERTS_DIR / tag
    base.mkdir(parents=True, exist_ok=True)

    # Walk the intermediate chain from the session root (root → leaf order)
    prev_key  = _SESSION_ROOT_KEY
    prev_cert = _SESSION_ROOT_CERT
    int_pem_list = []   # collect as list so we can reverse below

    for i in range(chain_depth):
        int_key  = _gen_key(algo, param)
        int_cert = _build_ca_cert(
            int_key, f"Intermediate-CA-{i+1}",
            prev_cert.subject, prev_key)
        _save(base / f"intermediate_{i+1}.key", _pem_key(int_key))
        _save(base / f"intermediate_{i+1}.crt", _pem_cert(int_cert))
        int_pem_list.append(_pem_cert(int_cert))
        prev_key, prev_cert = int_key, int_cert

    # Server cert – signed by the last intermediate (or root if depth=0)
    srv_key  = _gen_key(algo, param)
    srv_cert = _build_server_cert(srv_key, server_ip, prev_cert, prev_key)
    _save(base / "server.key", _pem_key(srv_key))
    _save(base / "server.crt", _pem_cert(srv_cert))

    # chain.crt = server cert + intermediates in LEAF-TO-ROOT order
    # RFC 5246 §7.4.2: "each following certificate MUST directly certify
    # the one preceding it."  mbedTLS (ESP32) is strict about this order;
    # OpenSSL is lenient (which is why openssl verify passes even when wrong).
    # int_pem_list was built root→leaf; reverse it so Int-CA-N (direct signer
    # of server cert) comes immediately after the server cert.
    int_pems  = b"".join(reversed(int_pem_list))
    chain_pem = _pem_cert(srv_cert) + int_pems
    _save(base / "chain.crt", chain_pem)

    chain_size = len(chain_pem)
    print(f"[PKI] {tag}  server SAN includes IP={server_ip}  chain={chain_size}B")

    return {
        "tag":         tag,
        "ca_cert":     get_session_root_path(),   # always the session root
        "server_cert": str(base / "chain.crt"),
        "server_key":  str(base / "server.key"),
        "chain_size":  chain_size,
        "chain_depth": chain_depth,
        "algo":        algo,
        "param":       str(param),
    }
