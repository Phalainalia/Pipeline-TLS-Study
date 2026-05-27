# Estudio de Escalabilidad TLS/PKI en ESP32

## Resumen

Este proyecto implementa un pipeline automatizado para evaluar el **costo operativo real** de la verificación de certificados X.509 durante el handshake TLS sobre un microcontrolador ESP32. El ESP32 actúa como cliente TLS real que conecta via WiFi a un servidor Python, permitiendo medir no solo la latencia del handshake sino también el impacto directo sobre la **memoria dinámica** del dispositivo — una métrica crítica en plataformas IoT con recursos restringidos.

A diferencia de un experimento en localhost, aquí intervienen mbedTLS (la pila TLS del ESP32), jitter WiFi real, y las limitaciones físicas de 520 KB SRAM. Esto hace que los resultados sean representativos de un despliegue IoT real.

---

## Objetivo de Investigación

Responder las siguientes preguntas empíricas sobre plataformas IoT embebidas:

1. ¿Cómo escala el tiempo de handshake TLS con la profundidad de la cadena PKI en un ESP32?
2. ¿Es ECDSA más eficiente que RSA en términos de latencia y consumo de heap?
3. ¿Qué impacto tienen cadenas de certificados largas sobre la memoria disponible y su fragmentación?
4. ¿El ESP32 (mbedTLS) puede verificar cadenas PKI de profundidad 2 y 3 sin degradación?

---

## Estructura del Proyecto

```
ESP-32 TLS STUDY/
├── main.py                  # Punto de entrada — orquesta todo el experimento
├── config.py                # Todos los parámetros configurables
├── cert_generator.py        # Generación automática de jerarquías PKI X.509
├── tls_server.py            # Servidor TLS Python (recibe conexiones del ESP32)
├── serial_controller.py     # Protocolo de comunicación Python ↔ ESP32 por USB
├── experiment_runner.py     # Orquestación de trials y configuraciones
├── statistics_engine.py     # Estadísticas descriptivas por configuración
├── plotter.py               # Dashboards interactivos con Plotly
├── firmware_flasher.py      # Flasheo automático via PlatformIO (opcional)
├── requirements.txt         # Dependencias Python
├── esp32/
│   ├── platformio.ini       # Configuración de build PlatformIO
│   └── src/
│       ├── main.cpp         # Firmware Arduino del ESP32
│       └── root_ca_embed.h  # CA raíz embebida (generado automáticamente)
├── certs/
│   ├── session_root/        # CA raíz de sesión (NO borrar entre corridas)
│   └── RSA_*/  ECDSA_*/     # Certificados por configuración (regenerables)
├── runs/                    # Resultados organizados por timestamp de corrida
│   └── YYYYMMDD_HHMMSS/
│       ├── results/
│       │   ├── raw_metrics.csv
│       │   └── statistics.csv
│       └── plots/
│           └── dashboard.html
└── logs/
```

---

## Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────┐
│                       PC (Python)                       │
│                                                         │
│  experiment_runner.py                                   │
│       │ genera certs         │ levanta servidor         │
│       ▼                      ▼                          │
│  cert_generator.py      tls_server.py (:8443)           │
│       │                      ▲                          │
│       │ envía CMD por serial  │ TLS via WiFi             │
│       ▼                      │                          │
│  serial_controller.py        │                          │
└───────┼──────────────────────┼──────────────────────────┘
        │ USB (115200 baud)     │ WiFi LAN
        ▼                      │
┌───────────────────┐          │
│      ESP32        │──────────┘
│  Arduino/mbedTLS  │
│  WiFiClientSecure │
└───────────────────┘
```

El PC genera los certificados, flashea el firmware (si se configura), levanta el servidor TLS, y envía comandos al ESP32 por puerto serial. El ESP32 ejecuta el handshake TLS via WiFi, mide el tiempo y el estado del heap, e imprime los resultados por serial. El PC los captura, los registra en CSV y genera las visualizaciones.

---

## Parámetros del Experimento

Todos los parámetros se configuran en `config.py`:

| Parámetro | Descripción | Valor por defecto |
|---|---|---|
| `WIFI_SSID` / `WIFI_PASSWORD` | Credenciales del AP WiFi | — |
| `SERVER_IP` | IP LAN del PC (reachable desde el ESP32) | `192.168.1.129` |
| `SERVER_PORT` | Puerto del servidor TLS Python | `8443` |
| `SERIAL_PORT` | Puerto USB del ESP32 | `/dev/cu.usbserial-10` |
| `SERIAL_BAUDRATE` | Velocidad serial | `115200` |
| `SERIAL_TIMEOUT` | Timeout por handshake (s) | `90` |
| `NUM_TRIALS` | Handshakes por configuración | `10` |
| `MAX_CHAIN_DEPTH` | Máximo de intermediarios | `3` |
| `RSA_KEY_SIZES` | Tamaños de clave RSA a probar (bits) | `[2048, 4096]` |
| `ECDSA_CURVES` | Curvas ECDSA a probar | `[secp256r1, secp384r1]` |
| `AUTO_FLASH` | Flashear firmware automáticamente | `False` |

---

## Diseño del Experimento

### Generación de Certificados (PKI)

Para cada combinación de algoritmo × parámetro × profundidad de cadena se genera una jerarquía PKI completa:

```
Root CA (RSA-2048, sesión única)
  └── [Intermediario 1  (mismo algo/curva del experimento)]
        └── [Intermediario 2]
              └── [Intermediario 3]
                    └── Certificado de Servidor
                        SAN: IP del PC + DNS entries
```

**Decisión de diseño crítica:** existe una sola CA raíz por sesión (`certs/session_root/`), compartida por todas las configuraciones. Esto permite que el firmware (que tiene la CA raíz compilada) valide certificados de cualquier configuración sin necesidad de reflashear.

La cadena que el servidor envía al ESP32 sigue el orden **leaf-to-root** requerido por RFC 5246 §7.4.2. mbedTLS es estricto al respecto; un orden incorrecto resulta en fallo de verificación aunque OpenSSL lo acepte.

### Ejecución del Handshake TLS

1. Python envía al ESP32 por serial: `CMD:host,port,algo,param,depth,trial`
2. El ESP32 conecta al servidor Python via `WiFiClientSecure.connect()`
3. mbedTLS ejecuta el handshake TLS 1.2 completo, verificando la cadena de certificados contra la CA raíz compilada en el firmware
4. El ESP32 mide con `millis()` y consulta `ESP.getFreeHeap()` y `heap_caps_get_largest_free_block()`
5. Imprime por serial: `HANDSHAKE_RESULT,HS=...,HEAP=...,LFB=...,FRAG=...,SUCCESS=...`
6. Python captura la línea, parsea los valores, y los almacena en CSV

### Variables del Experimento

**Variables independientes:**
- Algoritmo criptográfico (RSA, ECDSA)
- Tamaño de clave o curva elíptica (2048, 4096, secp256r1, secp384r1)
- Profundidad de cadena PKI (0, 1, 2, 3 intermediarios)

**Variables dependientes (métricas medidas en el ESP32):**
- Tiempo de handshake TLS (ms) — proxy del costo computacional + transmisión
- Heap libre al finalizar el handshake (bytes)
- Bloque libre más grande al finalizar el handshake (bytes)
- Ratio de fragmentación de memoria — indicador de presión sobre el heap dinámico
- Éxito del handshake (1 / 0)

**Variables controladas:**
- Hardware: ESP32 devboard (Xtensa LX6 dual-core 240 MHz, 520 KB SRAM)
- Pila TLS: mbedTLS 2.x (incluida en Arduino-ESP32)
- Versión TLS: 1.2
- AP WiFi: mismo punto de acceso para todas las pruebas
- Servidor: mismo proceso Python

---

## Métricas y su Interpretación

### `handshake_time_ms`

Tiempo en milisegundos desde `client.connect()` hasta el retorno, medido con `millis()` en el ESP32. Incluye:
- Establecimiento de conexión TCP via WiFi
- Negociación de cipher suite y versión TLS
- Intercambio y **verificación criptográfica** de la cadena de certificados
- Establecimiento del secreto compartido (intercambio de clave)

> Un incremento con la profundidad de cadena refleja el costo acumulado de verificar cada firma adicional. El jitter WiFi añade varianza que puede dominar sobre la señal en algoritmos rápidos como RSA-2048.

### `free_heap_bytes`

Bytes totales de heap disponibles inmediatamente después del handshake, obtenidos con `ESP.getFreeHeap()`. mbedTLS asigna buffers dinámicamente para el contexto SSL, los registros TLS, y la cadena de certificados.

> Más profundidad de cadena → más memoria consumida. RSA requiere más memoria que ECDSA por el tamaño de sus claves y estructuras de certificado.

### `largest_free_block_bytes`

Tamaño del bloque contiguo más grande disponible en el heap, obtenido con `heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)`.

> Un valor bajo con heap total alto indica **fragmentación severa**: la memoria está disponible pero dispersa en bloques pequeños, impidiendo futuras allocations grandes. Esto puede causar fallos en operaciones posteriores aunque `ESP.getFreeHeap()` muestre bytes disponibles.

### `fragmentation_ratio`

Ver fórmula en la sección siguiente.

### `mean` y `std` por configuración

Media aritmética y desviación estándar de los `NUM_TRIALS` handshakes. Una desviación alta (CV > 0.5) indica que el jitter domina y se necesitan más trials para estimar la media con precisión.

---

## Fórmulas Clave

### Ratio de Fragmentación de Heap

$$F = 1 - \frac{B_{\text{largest}}}{H_{\text{free}}}$$

| Símbolo | Significado |
|---|---|
| $F \in [0, 1]$ | 0 = memoria perfectamente contigua; 1 = completamente fragmentada |
| $B_{\text{largest}}$ | Bloque libre más grande (bytes) |
| $H_{\text{free}}$ | Heap libre total (bytes) |

Un valor de $F = 0.46$ (observado en el experimento) significa que el bloque más grande representa solo el 54 % del heap total libre — los restantes 46 % están dispersos en bloques pequeños que no pueden usarse para allocations grandes.

### Coeficiente de Variación

$$CV = \frac{\sigma}{\mu}$$

Normaliza la dispersión respecto a la media. Permite comparar la estabilidad entre configuraciones con magnitudes muy distintas.

| $CV$ | Interpretación |
|---|---|
| $< 0.1$ | Alta estabilidad — la señal domina |
| $0.1 - 0.5$ | Varianza moderada — útil con $n \geq 15$ |
| $> 0.5$ | El ruido (jitter WiFi, NTP, TCP) domina — requiere más trials |

### Percentil 95

$$P_{95} = \text{valor tal que el 95 \% de los trials caen por debajo}$$

Más útil que el máximo para describir el comportamiento en el peor caso sin que un solo outlier distorsione la métrica.

---

## Cómo Ejecutar

### 1. Instalación de dependencias

```bash
pip install -r requirements.txt
```

Requiere PlatformIO para compilar y flashear el firmware:
```bash
pip install platformio
```

### 2. Configurar `config.py`

```python
WIFI_SSID     = "NombreDetuRed"
WIFI_PASSWORD = "TuContraseña"
SERVER_IP     = "192.168.X.XXX"   # IP LAN del PC (ver abajo)
SERIAL_PORT   = "/dev/cu.usbserial-10"  # macOS; Linux: /dev/ttyUSB0
```

Para encontrar tu IP LAN:
```bash
# macOS
ipconfig getifaddr en0

# Linux
ip addr show | grep 'inet '
```

### 3. Flashear el firmware (primera vez o tras cambiar la CA raíz)

```bash
# Genera la CA raíz y la embebe en el firmware, luego flashea
python firmware_flasher.py
```

O manualmente:
```bash
cd esp32 && pio run --target upload
```

### 4. Correr el experimento

```bash
python main.py
```

---

## Comandos por Escenario

### Misma ubicación, misma placa ya flasheada

```bash
python main.py
```

### Nueva ubicación (IP de red cambió)

```bash
# 1. Actualizar SERVER_IP en config.py
# 2. Borrar certificados de servidor con IP antigua (conservar session_root/)
rm -rf certs/RSA_* certs/ECDSA_*
# 3. Correr normalmente
python main.py
```

### Placa nueva o sin flashear

```bash
# Borrar todo (se generará una nueva CA raíz y se flasheará)
rm -rf certs/
python firmware_flasher.py
python main.py
```

---

## Resultados Generados

Cada corrida crea un directorio fechado dentro de `runs/`:

```
runs/YYYYMMDD_HHMMSS/
├── results/
│   ├── raw_metrics.csv      ← un registro por handshake (160 filas para config por defecto)
│   └── statistics.csv       ← estadísticas agregadas por configuración (16 filas)
└── plots/
    ├── dashboard.html        ← dashboard integrado con todos los paneles
    ├── latency_vs_chain.html
    ├── rsa_vs_ecdsa_boxplot.html
    ├── free_heap_vs_chain.html
    ├── cert_size_vs_chain.html
    ├── fragmentation_over_time.html
    ├── frag_vs_latency.html
    ├── success_heatmap.html
    └── largest_block_vs_trials.html
```

Abrir el dashboard:
```bash
open runs/$(ls runs/ | sort -r | head -1)/plots/dashboard.html
```

---

## Interpretación de Resultados

### ECDSA vs RSA en ESP32

ECDSA produce tiempos de handshake generalmente menores porque:
- Claves más cortas → certificados más pequeños → menos bytes a transmitir y parsear
- La verificación de firmas ECDSA es más rápida que la exponenciación modular RSA en mbedTLS
- Menor consumo de heap por el tamaño de las estructuras de clave

### Impacto de la profundidad de cadena

Cada intermediario adicional requiere:
1. Transmisión del certificado adicional (payload TLS mayor)
2. Parsing del DER X.509
3. Verificación de la firma del emisor (una operación criptográfica completa)
4. Consumo de un bloque de heap para alojar la estructura del certificado en memoria

Se espera un incremento aproximadamente lineal en tiempo y consumo de heap. La señal es más clara en ECDSA-secp384r1 (que tiene menor jitter relativo) que en RSA-2048 (cuyo tiempo absoluto es tan bajo que el jitter WiFi domina).

### Heap y fragmentación

El ratio de fragmentación permanece relativamente estable (~0.46) porque mbedTLS libera todos los buffers del handshake al finalizar la conexión. La diferencia relevante está en el **heap libre total**: cada nivel adicional de cadena consume ~1.5–3 KB adicionales (principalmente del bloque de historia de verificación). RSA-4096 con cadena de profundidad 3 es la configuración más agresiva en consumo de memoria.

---

## Limitaciones del Estudio

- El tiempo de handshake incluye latencia WiFi y TCP, que no puede separarse del costo criptográfico sin instrumentar mbedTLS internamente.
- Con `NUM_TRIALS = 10`, las configuraciones RSA tienen CV > 1.0, lo que significa que el jitter domina. Para conclusiones estadísticamente sólidas se recomienda `NUM_TRIALS >= 30`.
- Los resultados dependen de la calidad del canal WiFi durante la ejecución. Se recomienda correr el experimento en condiciones de RF estables.
- Se estudia solo TLS 1.2 (restricción de mbedTLS en Arduino-ESP32 por defecto).
- La CA raíz usada en la sesión es RSA-2048 independientemente del algoritmo del experimento, por compatibilidad de firmware.

---

## Dependencias

```
cryptography>=41.0
pyserial>=3.5
pandas>=2.0
numpy>=1.26
plotly>=5.18
```

Firmware (PlatformIO):
```
platform  = espressif32
framework = arduino
board     = esp32dev
```

---

## Referencias

- RFC 5246 — The Transport Layer Security (TLS) Protocol Version 1.2
- RFC 5280 — Internet X.509 PKI Certificate and CRL Profile
- NIST SP 800-57 — Recommendation for Key Management
- Espressif ESP32 Technical Reference Manual
- mbedTLS Documentation — https://mbed-tls.readthedocs.io
- PlatformIO ESP32 Arduino — https://docs.platformio.org/en/latest/boards/espressif32/esp32dev.html
