# KLL/Haystack Network Evaluation

Infraestructura experimental para evaluar la implementación distribuida de **KLL/Haystack sobre LMS** bajo condiciones de red controladas y reproducibles.

El objetivo de `neteval/` es medir el comportamiento del protocolo real —contenedores independientes, sockets reales y estado persistente— al variar principalmente:

- el número de Trustees participantes;
- el RTT entre Aggregator y Trustees;
- la contribución de cada fase del protocolo al tiempo total de firma.

La infraestructura está preparada para campañas con **3, 5 y 10 Trustees**.

---

## 1. Arquitectura

El despliegue usa Java 17 y Docker Compose.

```text
                    ┌───────────────┐
                    │      CAS      │
                    └───────▲───────┘
                            │
                      ┌─────┴─────┐
                      │ Aggregator│
                      └─────┬─────┘
                gRPC        │        gRPC
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
         Trustee 0       Trustee 1       Trustee N
```

Roles:

- **Dealer**: ejecuta el setup una sola vez, genera el material LMS/CRV, publica el BulletinBoard y distribuye la configuración de los Trustees.
- **Trustees**: mantienen su material secreto y el estado de KeyIDs consumidos.
- **Aggregator**: coordina las dos rondas de firma y reconstruye la firma LMS final.
- **CAS**: almacena los CRVs y demás blobs públicos direccionados por contenido.

Las firmas producidas se serializan en formato **RFC 8554** y se verifican de forma independiente con **OpenSSL 4.x con soporte LMS**.

---

## 2. Firma distribuida

La firma usa dos rondas Aggregator ↔ Trustees.

```text
Round 1
Aggregator ──parallel──> Trustees
Aggregator <─parallel── Trustees

Round 2
Aggregator ──parallel──> Trustees
Aggregator <─parallel── Trustees
```

Las RPC hacia los Trustees se ejecutan **en paralelo dentro de cada ronda**, con una barrera entre Round 1 y Round 2.

Para una red homogénea, el coste de red esperado en el critical path es aproximadamente:

```text
T_network ≈ 2 × RTT
```

y no `2 × coalition_size × RTT`.

---

## 3. Instrumentación

Se registra instrumentación tanto en el Aggregator como en los Trustees.

El Aggregator recoge, entre otras métricas:

- tiempo total de `AggregatorSign`;
- lectura de Coalition List / CRV;
- duración de Round 1;
- duración individual de cada RPC de Round 1;
- tiempo entre rondas;
- duración de Round 2;
- duración individual de cada RPC de Round 2;
- reconstrucción;
- procesamiento del servidor HTTP;
- serialización;
- tamaños de request/response protobuf.

Cada Trustee registra los tiempos de procesamiento de `ShardSign1` y `ShardSign2`.

Los datos se escriben en JSONL:

```text
neteval/results/<experiment-id>/raw/
```

> Los byte counts instrumentados corresponden a **payload protobuf serializado**, no al número total de bytes transmitidos sobre Ethernet/TCP/HTTP2.

---

## 4. Emulación de red

La emulación está implementada en:

```text
neteval/netem/netem.sh
```

Utiliza Linux `tc`, `netem` y filtros `flower` sobre los host-side veth creados por Docker.

Solo se modifica el tráfico:

```text
Aggregator ↔ Trustees
```

El tráfico hacia CAS y el resto de la red del despliegue permanece sin shaping.

El retraso se aplica simétricamente:

```text
delay por dirección = RTT / 2
```

El script descubre dinámicamente los Trustees activos y soporta las topologías usadas en la evaluación.

Ejemplos:

```bash
sudo neteval/netem/netem.sh apply 80
sudo neteval/netem/netem.sh show
sudo neteval/netem/netem.sh reset
```

`apply 80` configura aproximadamente **80 ms RTT** entre el Aggregator y todos los Trustees activos.

Antes de ejecutar las muestras de un perfil, el runner mide el RTT real desde el network namespace del Aggregator y valida que se encuentre dentro de la tolerancia configurada.

---

## 5. Experiment Runner

El runner principal es:

```text
neteval/runner/run.sh
```

Automatiza el experimento completo:

```text
fresh deployment
→ build
→ Dealer setup
→ startup de Trustees/Aggregator
→ workload determinista
→ reserva de KeyIDs
→ warm-up
→ schedule aleatorio por bloques
→ configuración netem
→ validación RTT
→ firmas
→ verificación OpenSSL
→ colección de métricas
→ validación del dataset
→ cleanup
```

### Seguridad de KeyIDs

LMS es stateful: un KeyID no puede reutilizarse.

`neteval/runner/keyid.py` mantiene un ledger persistente:

```text
neteval/results/<experiment-id>/keyids.jsonl
```

El KeyID se **reserva antes** de intentar la firma. Un KeyID reservado no vuelve a asignarse aunque la ejecución falle posteriormente.

---

## 6. OpenSSL

La validación final usa OpenSSL 4.x porque el OpenSSL estable del sistema puede no incluir soporte LMS.

El runner acepta un prefijo independiente:

```bash
export KLL_OPENSSL_PREFIX="$HOME/.local/openssl-4.0.1-lms"
```

y utiliza:

```text
$KLL_OPENSSL_PREFIX/bin/openssl
```

con las bibliotecas de ese mismo prefijo.

Durante el setup se archivan:

```text
setup/lmspublickey.pem
setup/lmspublickey-openssl.txt
setup/openssl-version.txt
```

Cada firma generada se valida mediante `openssl pkeyutl -verify`.

---

## 7. Configuración experimental final

Parámetros principales preparados para las campañas:

```text
LMS:                 lms_sha256_n32_h10
LMOTS:               sha256_n32_w4
KeyID space:         1024
message size:        1024 bytes
concurrency:         1

Topologías:
  3-of-3
  5-of-5
  10-of-10

Perfiles de red:
  baseline
  RTT 20 ms
  RTT 80 ms
  RTT 200 ms

Warm-up global:      10 firmas
Bloques aleatorios:  5
Measured/block:      10 por perfil
Conditioning:        1 muestra por transición de perfil
```

El orden de perfiles se randomiza independientemente en cada bloque a partir de una seed reproducible.

Con esta configuración, cada campaña produce:

```text
50 measured samples por perfil
200 measured samples totales
```

además de warm-up y conditioning.

---

## 8. Ejecución de las campañas

### 3-of-3

```bash
KLL_OPENSSL_PREFIX="$HOME/.local/openssl-4.0.1-lms" \
KLL_TRUSTEE_COUNT=3 \
KLL_WARMUP_SAMPLES=10 \
KLL_BLOCKS=5 \
KLL_MEASURED_PER_BLOCK=10 \
KLL_PROFILE_SEED=20260817 \
neteval/runner/run.sh final-k3
```

### 5-of-5

```bash
KLL_OPENSSL_PREFIX="$HOME/.local/openssl-4.0.1-lms" \
KLL_TRUSTEE_COUNT=5 \
KLL_WARMUP_SAMPLES=10 \
KLL_BLOCKS=5 \
KLL_MEASURED_PER_BLOCK=10 \
KLL_PROFILE_SEED=20260817 \
neteval/runner/run.sh final-k5
```

### 10-of-10

```bash
KLL_OPENSSL_PREFIX="$HOME/.local/openssl-4.0.1-lms" \
KLL_TRUSTEE_COUNT=10 \
KLL_WARMUP_SAMPLES=10 \
KLL_BLOCKS=5 \
KLL_MEASURED_PER_BLOCK=10 \
KLL_PROFILE_SEED=20260817 \
neteval/runner/run.sh final-k10
```

No debe modificarse el código entre las tres campañas definitivas.

---

## 9. Resultados producidos

Cada ejecución genera:

```text
neteval/results/<experiment-id>/
├── manifest.json
├── schedule.json
├── samples.jsonl
├── keyids.jsonl
├── workload/
├── setup/
├── raw/
├── network/
├── signatures/
└── logs/
```

Contenido principal:

- `manifest.json`: parámetros, Git commit, estado del experimento y provenance;
- `schedule.json`: orden aleatorio de perfiles por bloque;
- `samples.jsonl`: un registro por intento de firma;
- `keyids.jsonl`: ledger irreversible de KeyIDs;
- `raw/`: métricas instrumentadas del Aggregator y Trustees;
- `network/`: configuración `tc/netem`, mappings veth y validaciones RTT;
- `signatures/`: firmas LMS generadas;
- `setup/`: configuración, BulletinBoard, clave pública y datos de OpenSSL;
- `logs/`: build, Dealer y verificaciones.

---

## 10. Validación realizada

Antes de las campañas finales se han validado end-to-end:

- topologías **3-of-3**, **5-of-5** y **10-of-10**;
- perfiles `baseline`, `RTT20`, `RTT80` y `RTT200`;
- paralelización intra-ronda del Aggregator;
- shaping simétrico Aggregator ↔ Trustees;
- descubrimiento dinámico de Trustees/veth;
- validación automática del RTT;
- reserva irreversible de KeyIDs;
- firmas RFC 8554;
- verificación positiva con OpenSSL 4;
- verificación negativa modificando el mensaje;
- cardinalidad esperada de eventos instrumentados;
- cleanup de `netem`, contenedores y volúmenes después de cada experimento;
- árboles LMS `h=10` con espacio de 1024 KeyIDs;
- ejecución aleatorizada por bloques.

El smoke final con 10 Trustees y dos bloques completó correctamente todas las firmas, verificaciones y comprobaciones internas.