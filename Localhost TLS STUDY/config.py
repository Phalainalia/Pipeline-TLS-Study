"""
config.py — Parámetros configurables del experimento TLS.
Modifica estas variables antes de ejecutar main.py.
"""

# ─── Parámetros generales ────────────────────────────────────────────────────

# Número de handshakes por combinación (más = mayor precisión estadística)
NUM_TRIALS = 30

# Longitudes de cadena a probar (0 = solo CA raíz + servidor, 1 = un intermediario, etc.)
CHAIN_LENGTHS = [0, 1, 2, 3]

# Puerto base para el servidor TLS (se incrementa por prueba para evitar colisiones)
BASE_PORT = 54321

# Tiempo máximo de espera por handshake (segundos)
HANDSHAKE_TIMEOUT = 10

# Tamaño del payload TLS (bytes) — 0 = sin payload adicional
PAYLOAD_SIZE = 0

# ─── Algoritmos RSA ──────────────────────────────────────────────────────────

# Activar pruebas RSA
ENABLE_RSA = True

# Tamaños de clave RSA a probar (bits)
RSA_KEY_SIZES = [2048, 3072, 4096]

# ─── Algoritmos ECDSA ────────────────────────────────────────────────────────

# Activar pruebas ECDSA
ENABLE_ECDSA = True

# Curvas ECDSA a probar
ECDSA_CURVES = ["secp256r1", "secp384r1"]

# ─── Directorios de salida ───────────────────────────────────────────────────

CERTS_DIR = "certs"
RESULTS_DIR = "results"
PLOTS_DIR = "plots"
LOGS_DIR = "logs"

# ─── Logging ─────────────────────────────────────────────────────────────────

# Nivel de detalle: DEBUG, INFO, WARNING, ERROR
LOG_LEVEL = "INFO"

# Guardar log en archivo además de consola
LOG_TO_FILE = True

# ─── Construcción de lista de configuraciones ────────────────────────────────

def build_configs():
    """Devuelve lista de dicts con todas las combinaciones a probar."""
    configs = []
    if ENABLE_RSA:
        for size in RSA_KEY_SIZES:
            for chain_len in CHAIN_LENGTHS:
                configs.append({
                    "algorithm": "RSA",
                    "key_size": size,
                    "curve": None,
                    "chain_length": chain_len,
                    "label": f"RSA-{size}",
                })
    if ENABLE_ECDSA:
        for curve in ECDSA_CURVES:
            for chain_len in CHAIN_LENGTHS:
                configs.append({
                    "algorithm": "ECDSA",
                    "key_size": None,
                    "curve": curve,
                    "chain_length": chain_len,
                    "label": f"ECDSA-{curve}",
                })
    return configs
