"""
tls_server.py
Minimal TLS server that accepts one connection at a time,
performs a handshake, optionally exchanges a ping/pong,
then closes the connection so ESP32 can re-connect cleanly.
"""

import ssl, socket, threading, logging, time
from pathlib import Path

log = logging.getLogger("tls_server")


class TLSServer(threading.Thread):
    """Runs in a background thread. Call reconfigure() between experiments."""

    def __init__(self, host: str, port: int):
        super().__init__(daemon=True)
        self.host    = host
        self.port    = port
        self._ctx    = None
        self._stop   = threading.Event()
        self._ready  = threading.Event()
        self._lock   = threading.Lock()

    def reconfigure(self, pki: dict):
        """Hot-swap certificates without restarting the thread."""
        with self._lock:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(pki["server_cert"], pki["server_key"])
            ctx.load_verify_locations(pki["ca_cert"])
            ctx.verify_mode = ssl.CERT_NONE   # server-side only auth for IoT
            self._ctx = ctx
        log.info(f"[Server] Reconfigured → {pki['tag']}")

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw.bind((self.host, self.port))
            raw.listen(5)
            raw.settimeout(1.0)
            self._ready.set()
            log.info(f"[Server] Listening on {self.host}:{self.port}")
            while not self._stop.is_set():
                try:
                    conn, addr = raw.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn, addr):
        with self._lock:
            ctx = self._ctx
        if ctx is None:
            conn.close()
            return
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(10)
                data = tls.recv(256)
                if data:
                    tls.sendall(b"PONG:" + data)
        except Exception as e:
            log.debug(f"[Server] {addr} → {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def wait_ready(self, timeout=5):
        self._ready.wait(timeout)

    def stop(self):
        self._stop.set()
