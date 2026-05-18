# Estudio Empírico del Costo de Verificación de Certificados TLS

## Resumen

Este proyecto implementa un pipeline automatizado para evaluar el **costo operativo real** de validar certificados digitales X.509 durante el handshake TLS. El sistema trata TLS como una caja negra y se enfoca en métricas observables: latencia del handshake y tamaño de la cadena de certificados.

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
tls_study/
├── main.py              # Ejecuta el pipeline completo
├── config.py            # Parámetros configurables del experimento
├── cert_generator.py    # Generación de certificados X.509
├── tls_runner.py        # Handshakes TLS en localhost
├── metrics.py           # Medición y almacenamiento de datos
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

| Parámetro        | Descripción                                        | Valor por defecto          |
|------------------|----------------------------------------------------|----------------------------|
| `NUM_TRIALS`     | Número de handshakes por combinación               | 30                         |
| `CHAIN_LENGTHS`  | Números de certificados intermediarios a probar    | [0, 1, 2, 3]               |
| `RSA_KEY_SIZES`  | Tamaños de clave RSA (bits)                        | [2048, 3072, 4096]         |
| `ECDSA_CURVES`   | Curvas elípticas ECDSA                             | [secp256r1, secp384r1]     |
| `ENABLE_RSA`     | Activar pruebas RSA                                | True                       |
| `ENABLE_ECDSA`   | Activar pruebas ECDSA                              | True                       |
| `PAYLOAD_SIZE`   | Bytes de payload adicional por conexión            | 0                          |
| `HANDSHAKE_TIMEOUT` | Tiempo máximo de espera por handshake (s)       | 10                         |

---

## Diseño del Experimento

### Generación de Certificados

Para cada combinación de algoritmo × tamaño de clave × longitud de cadena, se genera una **jerarquía PKI completa** y autónoma:

```
Root CA  →  [Intermediario 1]  →  [Intermediario 2]  →  ...  →  Servidor
```

- La **CA raíz** es autofirmada y actúa como ancla de confianza.
- Los **certificados intermedios** extienden la cadena de confianza. La cantidad varía de 0 a N.
- El **certificado de servidor** es emitido por el último eslabón y válido para `localhost`.

### Ejecución del Handshake TLS

- Se levanta un **servidor TLS mínimo** en `127.0.0.1` usando Python `ssl`.
- El cliente establece una conexión TLS y completa el handshake completo (TLS 1.2/1.3).
- El tiempo se mide con `time.perf_counter()` alrededor del `connect()` + `wrap_socket()`.
- Se ejecutan `NUM_TRIALS` repeticiones por combinación para obtener estadísticas confiables.

### Variables del Experimento

**Variables independientes:**
- Algoritmo criptográfico (RSA, ECDSA)
- Tamaño de clave o curva elíptica
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
- Intercambio de certificados y cadena
- **Verificación criptográfica** de la cadena (firma de cada certificado)
- Establecimiento del secreto compartido

> Un incremento con la longitud de cadena refleja directamente el costo de verificar cada certificado adicional.

### `tamaño_certificados_bytes`
Tamaño total (en bytes) de todos los certificados que el servidor envía al cliente, incluyendo el certificado del servidor y todos los intermediarios. La CA raíz generalmente no se envía.

> Certificates más grandes implican mayor costo de transmisión y posiblemente mayor costo de parsing/verificación.

### `media_ms` y `std_ms` (en el summary)
Media aritmética y desviación estándar de los `NUM_TRIALS` handshakes por combinación. Una desviación estándar alta puede indicar variabilidad del sistema operativo o contención de recursos.

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

### Modo rápido (prueba inicial)

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

- `results/results_<timestamp>.csv`: Todas las observaciones individuales
- `results/summary_<timestamp>.csv`: Estadísticas descriptivas agregadas

### Gráficas HTML Interactivas

1. `plots/1_latency_vs_chain.html`: Latencia media (con barras de error) vs longitud de cadena
2. `plots/2_rsa_vs_ecdsa_boxplot.html`: Distribución de tiempos por esquema
3. `plots/3_cert_size_vs_chain.html`: Tamaño de certificados vs longitud de cadena
4. `plots/4_scalability_heatmap.html`: Heatmap de latencia por esquema y longitud
5. `plots/5_dashboard.html`: Dashboard integrado con los 4 paneles

---

## Interpretación de Resultados

### RSA vs ECDSA
ECDSA generalmente produce tiempos de handshake menores porque:
- Las claves son significativamente más cortas (256 bits vs 2048+ bits)
- Las operaciones de firma/verificación son más rápidas para el mismo nivel de seguridad
- Los certificados ocupan menos espacio en memoria y red

### Impacto de la longitud de cadena
Se espera un incremento **aproximadamente lineal** en el tiempo de handshake conforme crece la cadena, porque cada certificado adicional requiere:
1. Transmisión (mayor payload TLS)
2. Parsing del certificado X.509
3. Verificación de la firma del emisor

### Tamaño de clave RSA
RSA-4096 debería mostrar tiempos mayores que RSA-2048 debido a que las operaciones de exponenciación modular son O(n³) en el tamaño de la clave. En la práctica, el efecto más notorio es en la firma (servidor), no en la verificación (cliente).

---

## Limitaciones del Estudio

- El experimento se ejecuta en **loopback** (localhost), eliminando la latencia de red real.
- Se mide el tiempo **total** del handshake TLS, que incluye TCP, TLS negociación, y verificación. No es posible aislar únicamente la verificación criptográfica sin modificar la implementación TLS.
- Los resultados dependen del hardware y carga del sistema en el momento de ejecución.
- Python introduce overhead del intérprete comparado con implementaciones C nativas (OpenSSL puro).

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
- RFC 5280 — Internet X.509 PKI Certificate and Certificate Revocation List (CRL) Profile
- NIST SP 800-57 — Recommendation for Key Management
