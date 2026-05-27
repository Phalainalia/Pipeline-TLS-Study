# Estudio de Escalabilidad TLS/PKI

> **Pregunta central:** ¿Cómo escala el costo operativo de la verificación de certificados X.509 según el algoritmo criptográfico, el tamaño de clave y la profundidad de la cadena PKI — tanto en hardware de escritorio como en dispositivos IoT con restricciones de memoria?

---

## Contexto

El handshake TLS es la operación de seguridad más frecuente en la web y en IoT.
Su costo depende de tres factores que este estudio varía sistemáticamente:

| Factor | Valores estudiados |
|---|---|
| Algoritmo / curva | RSA-2048, RSA-3072\*, RSA-4096, ECDSA-secp256r1, ECDSA-secp384r1 |
| Profundidad de cadena PKI | 0, 1, 2, 3 intermediarios |
| Plataforma | Localhost (Python/OpenSSL) · ESP32 (Arduino/mbedTLS) |

\*Solo en el estudio de Localhost.

Cada subestudio corre el **mismo diseño experimental** pero en un entorno diferente, permitiendo aislar el efecto de la plataforma de hardware.

---

## Estructura del Repositorio

```
TLS STUDY/
├── README.md                   ← este archivo
│
├── Localhost TLS STUDY/        ← experimento en hardware de escritorio
│   ├── README.md
│   ├── main.py
│   ├── config.py
│   ├── cert_generator.py
│   ├── tls_runner.py
│   ├── metrics.py
│   ├── plotter.py
│   ├── requirements.txt
│   ├── certs/                  ← PKI generada automáticamente
│   ├── results/                ← CSVs de resultados
│   ├── plots/                  ← dashboards HTML interactivos
│   └── logs/
│
└── ESP-32 TLS STUDY/           ← experimento en hardware IoT (ESP32)
    ├── README.md
    ├── main.py
    ├── config.py
    ├── cert_generator.py
    ├── tls_server.py
    ├── serial_controller.py
    ├── experiment_runner.py
    ├── statistics_engine.py
    ├── plotter.py
    ├── requirements.txt
    ├── esp32/                  ← firmware PlatformIO
    │   ├── platformio.ini
    │   └── src/main.cpp
    ├── certs/                  ← PKI generada automáticamente
    ├── runs/                   ← resultados por corrida
    └── logs/
```

---

## Los Dos Estudios

### Localhost TLS STUDY

Ejecuta todos los handshakes en loopback (`127.0.0.1`). Al eliminar la latencia de red, aísla el **costo computacional puro** de la verificación criptográfica.

- **Plataforma:** Python `ssl` / OpenSSL
- **Métricas:** tiempo de handshake (ms), tamaño de certificados (bytes)
- **Ventaja:** altamente reproducible, sin hardware adicional
- **Limitación:** no captura el impacto en RAM ni el comportamiento bajo restricciones de memoria

**Inicio rápido:**
```bash
cd "Localhost TLS STUDY"
pip install -r requirements.txt
python main.py
```

---

### ESP-32 TLS STUDY

El ESP32 actúa como **cliente TLS real** que se conecta a un servidor Python via WiFi. Permite observar el impacto de la PKI sobre una plataforma con restricciones reales (520 KB SRAM, mbedTLS).

- **Plataforma:** Arduino / mbedTLS 2.x sobre ESP32
- **Métricas:** tiempo de handshake (ms), heap libre (bytes), bloque libre más grande (bytes), ratio de fragmentación de memoria
- **Ventaja:** captura efectos reales de memoria dinámica que no aparecen en localhost
- **Limitación:** varianza mayor por jitter WiFi; requiere hardware físico

**Inicio rápido:**
```bash
cd "ESP-32 TLS STUDY"
pip install -r requirements.txt
# Editar config.py con IP, WiFi y puerto serial correctos
python main.py
```

---

## Complementariedad de los Estudios

| Aspecto | Localhost | ESP32 |
|---|---|---|
| Elimina jitter de red | Sí (loopback) | No (WiFi real) |
| Mide impacto en RAM | No | Sí (heap + fragmentación) |
| Requiere hardware extra | No | Sí (placa ESP32 + cable USB) |
| Protocolo TLS | OpenSSL (TLS 1.2/1.3) | mbedTLS (TLS 1.2) |
| Algoritmos RSA | 2048, 3072, 4096 | 2048, 4096 |
| Reproducibilidad | Alta | Media (jitter WiFi) |
| `NUM_TRIALS` recomendado | 30 | 10–30 |

---

## Métricas Comunes

### Tiempo de handshake TLS

Tiempo total desde que el cliente inicia la conexión TCP hasta que el handshake está completamente establecido. Incluye negociación de versión y cipher suite, intercambio y verificación de la cadena de certificados, y establecimiento del secreto compartido.

### Coeficiente de variación

$$CV = \frac{\sigma}{\mu}$$

Normaliza la dispersión respecto a la media. Útil para comparar la estabilidad entre configuraciones con medias muy distintas. $CV < 0.1$ indica alta estabilidad; $CV > 0.5$ indica que el jitter domina sobre la señal de interés.

---

## Diseño PKI Compartido

Ambos estudios usan el mismo esquema PKI:

```
Root CA (autofirmada)
  └── [Intermediario 1]
        └── [Intermediario 2]
              └── [Intermediario 3]
                    └── Certificado de Servidor
```

- La cadena se construye de forma **leaf-to-root** en el mensaje TLS Certificate (RFC 5246 §7.4.2).
- La **CA raíz** es el ancla de confianza; no se transmite al cliente.
- La profundidad 0 significa que el servidor es firmado directamente por la CA raíz.

---

## Referencias

- RFC 5246 — The Transport Layer Security (TLS) Protocol Version 1.2
- RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 5280 — Internet X.509 PKI Certificate and CRL Profile
- NIST SP 800-57 — Recommendation for Key Management
- Espressif ESP32 Technical Reference Manual
- mbedTLS Documentation — https://mbed-tls.readthedocs.io
