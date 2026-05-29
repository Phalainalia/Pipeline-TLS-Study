# Estudio Empírico del Costo de Verificación de Certificados TLS

## Resumen

Este proyecto implementa un pipeline automatizado para evaluar el **costo operativo real** de validar certificados digitales X.509 durante el handshake TLS. Al ejecutar todo en loopback (`127.0.0.1`), la latencia de red se elimina por completo, aislando el **costo computacional puro** de la criptografía: verificación de firmas, parsing de certificados X.509 y establecimiento del secreto compartido.

El sistema trata TLS como una caja negra y se enfoca en métricas observables sin necesidad de modificar la implementación TLS subyacente (OpenSSL/Python `ssl`).

---

## Objetivo de Investigación

Responder las siguientes preguntas empíricas:

1. ¿Cómo escala el costo de verificación con la longitud de la cadena de certificados?
2. ¿Es ECDSA más eficiente que RSA en la práctica?
3. ¿Qué impacto tiene el tamaño de clave RSA (2048 vs 3072 vs 4096 bits)?
4. ¿Cuál es el trade-off entre nivel de seguridad y latencia observable?

---

## Estructura del Proyecto

```
Localhost TLS STUDY/
├── main.py              # Ejecuta el pipeline completo
├── config.py            # Parámetros configurables del experimento
├── cert_generator.py    # Generación de certificados X.509
├── tls_runner.py        # Handshakes TLS en localhost y medición de latencia
├── metrics.py           # Almacenamiento y estadísticas de resultados
├── plotter.py           # Visualizaciones interactivas con Plotly
├── requirements.txt     # Dependencias Python
├── README.md            # Este archivo
├── certs/               # Certificados generados (creado automáticamente)
├── results/             # CSVs con resultados (creado automáticamente)
├── plots/               # Gráficas HTML interactivas (creado automáticamente)
└── logs/                # Logs de ejecución (creado automáticamente)
```

---

## Parámetros del Experimento

Todos los parámetros se configuran en `config.py`:

| Parámetro | Descripción | Valor por defecto |
|---|---|---|
| `NUM_TRIALS` | Número de handshakes por combinación | `30` |
| `CHAIN_LENGTHS` | Cantidades de intermediarios a probar | `[0, 1, 2, 3]` |
| `RSA_KEY_SIZES` | Tamaños de clave RSA (bits) | `[2048, 3072, 4096]` |
| `ECDSA_CURVES` | Curvas elípticas ECDSA | `[secp256r1, secp384r1]` |
| `ENABLE_RSA` | Activar pruebas RSA | `True` |
| `ENABLE_ECDSA` | Activar pruebas ECDSA | `True` |
| `PAYLOAD_SIZE` | Bytes de payload adicional por conexión | `0` |
| `HANDSHAKE_TIMEOUT` | Tiempo máximo de espera por handshake (s) | `10` |
| `BASE_PORT` | Puerto base para el servidor TLS | `54321` |

---

## Diseño del Experimento

### Generación de Certificados

Para cada combinación de algoritmo × tamaño de clave × longitud de cadena se genera una **jerarquía PKI completa** y autónoma:

```
Root CA (autofirmada)
  └── [Intermediario 1]
        └── [Intermediario 2]
              └── [Intermediario N]
                    └── Certificado de Servidor  (válido para localhost)
```

- La **CA raíz** es autofirmada y actúa como ancla de confianza. No se transmite al cliente.
- Los **certificados intermedios** extienden la cadena de confianza. Su cantidad varía de 0 a N.
- El **certificado de servidor** es emitido por el último eslabón y es válido para `localhost` / `127.0.0.1`.
- La cadena se envía en orden **leaf-to-root** (RFC 5246 §7.4.2): servidor → intermediario N → … → intermediario 1.

### Ejecución del Handshake TLS

1. Se levanta un **servidor TLS mínimo** en `127.0.0.1` en un hilo separado usando Python `ssl`.
2. El cliente establece una conexión TLS y completa el handshake completo (TLS 1.2/1.3).
3. El tiempo se mide con `time.perf_counter()` alrededor de `connect()` + `wrap_socket()`.
4. Se ejecutan `NUM_TRIALS` repeticiones por combinación para obtener estadísticas confiables.
5. Los resultados se guardan en CSV y se generan visualizaciones automáticamente.

### Variables del Experimento

**Variables independientes:**
- Algoritmo criptográfico (RSA, ECDSA)
- Tamaño de clave o curva elíptica (2048, 3072, 4096 bits / secp256r1, secp384r1)
- Longitud de la cadena de certificados (0–N intermediarios)

**Variables dependientes (métricas):**
- Tiempo de handshake TLS (ms) — proxy del costo de verificación
- Tamaño total de certificados enviados (bytes) — costo de transmisión

**Variables controladas:**
- Red: loopback `127.0.0.1` (latencia de red ≈ 0)
- Hardware: misma máquina para cliente y servidor
- Protocolo: TLS 1.2 mínimo
- Carga del sistema: sin carga externa artificial

---

## Métricas y su Interpretación

### `tiempo_handshake_ms`

Tiempo total en milisegundos desde que el cliente inicia la conexión TCP hasta que el handshake TLS está completamente establecido. Incluye:

- Negociación de versión y cipher suite
- Intercambio de certificados y cadena completa
- **Verificación criptográfica** de cada certificado (firma del emisor)
- Establecimiento del secreto compartido

> Un incremento con la longitud de cadena refleja directamente el costo de verificar cada certificado adicional.

### `tamaño_certificados_bytes`

Tamaño total en bytes de todos los certificados que el servidor envía al cliente: certificado del servidor + todos los intermediarios. La CA raíz generalmente no se transmite.

> Certificados más grandes implican mayor costo de transmisión y posiblemente mayor costo de parsing y verificación.

### `media_ms` y `std_ms`

Media aritmética y desviación estándar de los `NUM_TRIALS` handshakes por configuración. Una desviación estándar alta puede indicar variabilidad del sistema operativo o contención de recursos del proceso Python.

---

## Fórmulas Clave

### Coeficiente de Variación

$$CV = \frac{\sigma}{\mu}$$

Normaliza la dispersión respecto a la media. Permite comparar la estabilidad entre configuraciones con magnitudes muy distintas (e.g., ECDSA-secp256r1 vs RSA-4096).

| $CV$ | Interpretación |
|---|---|
| $< 0.1$ | Alta estabilidad — la señal criptográfica domina |
| $0.1 - 0.3$ | Varianza moderada — normal en localhost |
| $> 0.5$ | El overhead del SO / scheduler domina — considerar más trials |

### Intervalo de Confianza (95 %)

$$\bar{x} \pm z_{0.975} \cdot \frac{\sigma}{\sqrt{n}}$$

Con $n = 30$ trials, $z_{0.975} = 1.96$. Usado en las gráficas como barras de error.

### Percentil 95

$$P_{95} = \text{valor tal que el 95\% de los trials caen por debajo}$$

Más representativo que el máximo para describir el peor caso típico.

---

## Cómo Ejecutar

### Instalación de dependencias

```bash
pip install -r requirements.txt
```

### Ejecución completa

```bash
python main.py
```

### Modo rápido (prueba inicial, pocos trials)

```bash
python main.py --quick
```

### Opciones adicionales

```bash
python main.py --trials 50          # Especificar número de trials
python main.py --no-plots           # Ejecutar sin generar gráficas
python main.py --quick --no-plots   # Modo rápido sin gráficas
```

---

## Resultados Generados

### Archivos CSV

- `results/results_<timestamp>.csv` — todas las observaciones individuales (una fila por handshake)
- `results/summary_<timestamp>.csv` — estadísticas descriptivas agregadas por configuración

### Gráficas HTML Interactivas

| Archivo | Contenido |
|---|---|
| `plots/1_latency_vs_chain.html` | Latencia media (con barras de error) vs longitud de cadena |
| `plots/2_rsa_vs_ecdsa_boxplot.html` | Distribución de tiempos por esquema criptográfico |
| `plots/3_cert_size_vs_chain.html` | Tamaño de certificados vs longitud de cadena |
| `plots/4_scalability_heatmap.html` | Heatmap de latencia: algoritmo × longitud de cadena |
| `plots/5_dashboard.html` | Dashboard integrado con los 4 paneles |

---

## Interpretación de Resultados

### RSA vs ECDSA

ECDSA generalmente produce tiempos de handshake menores porque:
- Las claves son significativamente más cortas (256 bits vs 2048+ bits)
- Las operaciones de firma y verificación son más rápidas para el mismo nivel de seguridad equivalente
- Los certificados ocupan menos espacio, reduciendo el costo de transmisión y parsing

### Impacto de la longitud de cadena

Se espera un incremento **aproximadamente lineal** en el tiempo de handshake conforme crece la cadena, porque cada certificado adicional requiere:
1. Transmisión (mayor payload TLS)
2. Parsing del DER X.509
3. Verificación de la firma del emisor (una operación de clave pública completa)

### Tamaño de clave RSA

RSA-4096 muestra tiempos mayores que RSA-2048 porque las operaciones de exponenciación modular son $O(n^3)$ en el tamaño de la clave. En la práctica, el efecto más notorio es en la **firma** del servidor durante el handshake, no solo en la verificación del cliente.

---

## Limitaciones del Estudio

- El experimento se ejecuta en **loopback**, eliminando la latencia de red real. Los tiempos no son directamente comparables a un despliegue en WAN o WiFi.
- Se mide el tiempo **total** del handshake TLS, que incluye TCP, negociación TLS y verificación. No es posible aislar únicamente la verificación criptográfica sin modificar la implementación TLS.
- Los resultados dependen del hardware y la carga del sistema en el momento de ejecución.
- Python introduce overhead del intérprete comparado con implementaciones C nativas (OpenSSL puro). Este overhead es constante entre configuraciones, lo que preserva la validez de las comparaciones relativas.
- No se mide el consumo de memoria (RAM) — para esa métrica, ver el estudio complementario en `ESP-32 TLS STUDY/`.

---

## Dependencias

```
cryptography>=41.0.0
pandas>=2.0.0
plotly>=5.17.0
```

---

## Referencias

- RFC 5246 — The Transport Layer Security (TLS) Protocol Version 1.2
- RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 5280 — Internet X.509 PKI Certificate and CRL Profile
- NIST SP 800-57 — Recommendation for Key Management
