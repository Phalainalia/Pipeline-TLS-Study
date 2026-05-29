"""
cert_generator.py — Generación de certificados X.509 para el experimento TLS.

Genera:
  - CA raíz (autofirmada)
  - Certificados intermedios (cantidad variable)
  - Certificado de servidor firmado por el último de la cadena
"""

import os
import datetime
import logging
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# Mapeo de nombre de curva → objeto EC
CURVE_MAP = {
    "secp256r1": ec.SECP256R1(),
    "secp384r1": ec.SECP384R1(),
    "secp521r1": ec.SECP521R1(),
}

def _make_name(cn: str, org: str = "TLS-Study") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

def _generate_private_key(algorithm: str, key_size: int = None, curve: str = None):
    """Genera clave privada RSA o ECDSA."""
    if algorithm == "RSA":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
    elif algorithm == "ECDSA":
        ec_curve = CURVE_MAP.get(curve)
        if ec_curve is None:
            raise ValueError(f"Curva ECDSA no reconocida: {curve}")
        return ec.generate_private_key(ec_curve, default_backend())
    else:
        raise ValueError(f"Algoritmo no soportado: {algorithm}")

def _hash_for(algorithm: str, curve: str = None):
    """Devuelve el algoritmo de hash apropiado."""
    if algorithm == "RSA":
        return hashes.SHA256()
    # Para ECDSA elegimos hash según curva
    if curve == "secp384r1":
        return hashes.SHA384()
    return hashes.SHA256()

def _save_cert_and_key(cert, key, cert_path: str, key_path: str):
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

def generate_root_ca(output_dir: str, algorithm: str, key_size=None, curve=None) -> dict:
    """Genera CA raíz autofirmada."""
    key = _generate_private_key(algorithm, key_size, curve)
    name = _make_name("TLS-Study Root CA")
    now = datetime.datetime.utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, _hash_for(algorithm, curve), default_backend())
    )

    cert_path = os.path.join(output_dir, "root_ca.crt")
    key_path  = os.path.join(output_dir, "root_ca.key")
    _save_cert_and_key(cert, key, cert_path, key_path)
    logger.debug(f"Root CA generada → {cert_path}")
    return {"cert": cert, "key": key, "cert_path": cert_path, "key_path": key_path}

def generate_intermediate(
    output_dir: str,
    index: int,
    issuer_cert,
    issuer_key,
    algorithm: str,
    key_size=None,
    curve=None,
) -> dict:
    """Genera un certificado intermedio firmado por el emisor."""
    key = _generate_private_key(algorithm, key_size, curve)
    name = _make_name(f"TLS-Study Intermediate CA {index}")
    now = datetime.datetime.utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
        .sign(issuer_key, _hash_for(algorithm, curve), default_backend())
    )

    cert_path = os.path.join(output_dir, f"intermediate_{index}.crt")
    key_path  = os.path.join(output_dir, f"intermediate_{index}.key")
    _save_cert_and_key(cert, key, cert_path, key_path)
    logger.debug(f"Intermediario {index} generado → {cert_path}")
    return {"cert": cert, "key": key, "cert_path": cert_path, "key_path": key_path}

def generate_server_cert(
    output_dir: str,
    issuer_cert,
    issuer_key,
    algorithm: str,
    key_size=None,
    curve=None,
) -> dict:
    """Genera certificado de servidor."""
    key = _generate_private_key(algorithm, key_size, curve)
    name = _make_name("localhost")
    now = datetime.datetime.utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
        .sign(issuer_key, _hash_for(algorithm, curve), default_backend())
    )

    cert_path = os.path.join(output_dir, "server.crt")
    key_path  = os.path.join(output_dir, "server.key")
    _save_cert_and_key(cert, key, cert_path, key_path)
    logger.debug(f"Certificado de servidor generado → {cert_path}")
    return {"cert": cert, "key": key, "cert_path": cert_path, "key_path": key_path}

def build_chain_bundle(output_dir: str, chain_certs: list) -> str:
    """
    Concatena los certificados de la cadena (sin raíz) en un único archivo PEM
    que el servidor envía como cadena intermedia.
    chain_certs: lista de dicts con 'cert' (objeto) en orden servidor→intermediarios
    """
    bundle_path = os.path.join(output_dir, "chain_bundle.pem")
    with open(bundle_path, "wb") as f:
        for item in chain_certs:
            f.write(item["cert"].public_bytes(serialization.Encoding.PEM))
    logger.debug(f"Bundle de cadena guardado → {bundle_path}")
    return bundle_path

def generate_full_chain(
    output_dir: str,
    algorithm: str,
    key_size: int,
    curve: str,
    chain_length: int,
) -> dict:
    """
    Genera la cadena completa:
      root_ca → [intermediarios] → servidor

    chain_length = número de certificados intermediarios (0 = directo root→server)

    Retorna dict con paths relevantes.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    logger.info(
        f"Generando cadena: alg={algorithm} key={key_size or curve} "
        f"chain_length={chain_length}"
    )

    root = generate_root_ca(output_dir, algorithm, key_size, curve)

    issuer_cert = root["cert"]
    issuer_key  = root["key"]
    intermediates = []

    for i in range(chain_length):
        inter = generate_intermediate(
            output_dir, i + 1, issuer_cert, issuer_key, algorithm, key_size, curve
        )
        intermediates.append(inter)
        issuer_cert = inter["cert"]
        issuer_key  = inter["key"]

    server = generate_server_cert(output_dir, issuer_cert, issuer_key, algorithm, key_size, curve)

    # Bundle: servidor + intermediarios (orden TLS estándar)
    chain_for_bundle = [server] + list(reversed(intermediates))
    bundle_path = build_chain_bundle(output_dir, chain_for_bundle)

    # Calcular tamaño total de certificados en la cadena enviada por el servidor
    cert_size = sum(
        len(item["cert"].public_bytes(serialization.Encoding.PEM))
        for item in chain_for_bundle
    )

    return {
        "root_cert_path": root["cert_path"],
        "root_key_path":  root["key_path"],
        "server_cert_path": server["cert_path"],
        "server_key_path":  server["key_path"],
        "chain_bundle_path": bundle_path,
        "cert_chain_size_bytes": cert_size,
        "num_intermediates": chain_length,
    }
