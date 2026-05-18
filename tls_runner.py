"""
tls_runner.py — Ejecución de handshakes TLS en localhost y medición de latencia.

Levanta un servidor TLS mínimo en un hilo separado y ejecuta el handshake
desde el cliente, midiendo el tiempo de round-trip completo.
"""

import ssl
import socket
import time
import threading
import logging
import os

logger = logging.getLogger(__name__)


# ─── Servidor TLS mínimo ─────────────────────────────────────────────────────

class _TLSServer(threading.Thread):
    """Servidor TLS que acepta exactamente N conexiones y luego termina."""

    def __init__(self, port: int, server_cert: str, server_key: str,
                 chain_bundle: str, root_ca: str, num_connections: int,
                 payload_size: int = 0):
        super().__init__(daemon=True)
        self.port = port
        self.server_cert = server_cert
        self.server_key = server_key
        self.chain_bundle = chain_bundle
        self.root_ca = root_ca
        self.num_connections = num_connections
        self.payload_size = payload_size
        self.ready = threading.Event()
        self.error = None
        self._payload = b"X" * payload_size if payload_size > 0 else b"OK"

    def run(self):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            # Cargar cert + cadena intermedia
            ctx.load_cert_chain(certfile=self.chain_bundle, keyfile=self.server_key)
            # Verificar clientes (no requerido, usamos verificación unilateral)
            ctx.verify_mode = ssl.CERT_NONE

            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw_sock.bind(("127.0.0.1", self.port))
            raw_sock.listen(self.num_connections + 5)
            raw_sock.settimeout(30)

            self.ready.set()

            handled = 0
            while handled < self.num_connections:
                try:
                    conn, _ = raw_sock.accept()
                    with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                        tls_conn.settimeout(10)
                        # Leer señal del cliente
                        try:
                            tls_conn.recv(16)
                        except Exception:
                            pass
                        # Enviar payload
                        try:
                            tls_conn.sendall(self._payload)
                        except Exception:
                            pass
                    handled += 1
                except ssl.SSLError as e:
                    logger.debug(f"SSLError en servidor: {e}")
                    handled += 1
                except socket.timeout:
                    break
                except Exception as e:
                    logger.debug(f"Error en servidor: {e}")
                    handled += 1

            raw_sock.close()
        except Exception as e:
            self.error = e
            self.ready.set()
            logger.error(f"Error fatal en servidor TLS: {e}")


# ─── Función principal de medición ───────────────────────────────────────────

def run_handshake(
    port: int,
    root_ca_path: str,
    timeout: float = 10.0,
) -> float:
    """
    Ejecuta un único handshake TLS contra el servidor en `port`.
    Retorna el tiempo de handshake en segundos, o -1.0 si falló.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=root_ca_path)
    ctx.check_hostname = False   # localhost no tiene hostname real
    ctx.verify_mode = ssl.CERT_REQUIRED

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)

    try:
        t0 = time.perf_counter()
        raw.connect(("127.0.0.1", port))
        tls = ctx.wrap_socket(raw, server_hostname="localhost")
        t1 = time.perf_counter()

        handshake_time = t1 - t0

        # Intercambio mínimo de datos
        try:
            tls.sendall(b"PING")
            tls.recv(4096)
        except Exception:
            pass

        tls.close()
        return handshake_time

    except Exception as e:
        logger.debug(f"Error en handshake cliente (puerto {port}): {e}")
        return -1.0
    finally:
        try:
            raw.close()
        except Exception:
            pass


def run_experiment_batch(
    port: int,
    chain_info: dict,
    num_trials: int,
    timeout: float = 10.0,
    payload_size: int = 0,
) -> list:
    """
    Lanza el servidor y ejecuta `num_trials` handshakes TLS contra él.

    chain_info debe contener:
      - server_key_path
      - chain_bundle_path  (cert servidor + intermediarios concatenados)
      - root_cert_path     (CA raíz para verificación del cliente)

    Retorna lista de tiempos en segundos (-1.0 en caso de fallo).
    """
    server = _TLSServer(
        port=port,
        server_cert=chain_info["server_cert_path"],
        server_key=chain_info["server_key_path"],
        chain_bundle=chain_info["chain_bundle_path"],
        root_ca=chain_info["root_cert_path"],
        num_connections=num_trials,
        payload_size=payload_size,
    )
    server.start()

    # Esperar a que el servidor esté listo
    if not server.ready.wait(timeout=15):
        logger.error("El servidor TLS no arrancó a tiempo.")
        return [-1.0] * num_trials

    if server.error:
        logger.error(f"Error al arrancar servidor: {server.error}")
        return [-1.0] * num_trials

    # Pequeña pausa para asegurar que el socket está aceptando
    time.sleep(0.05)

    times = []
    for i in range(num_trials):
        t = run_handshake(port, chain_info["root_cert_path"], timeout)
        times.append(t)
        if t < 0:
            logger.warning(f"  Trial {i+1}/{num_trials}: FALLO")
        else:
            logger.debug(f"  Trial {i+1}/{num_trials}: {t*1000:.2f} ms")

    server.join(timeout=5)
    return times
