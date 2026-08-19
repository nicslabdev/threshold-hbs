# KLL/Haystack Network Evaluation

Infraestructura experimental para evaluar la implementación distribuida de **KLL/Haystack sobre LMS** bajo condiciones de red controladas y reproducibles.

El objetivo de `neteval/` es medir el comportamiento del protocolo real —contenedores independientes, sockets reales y estado persistente— al variar principalmente:

- el número de Trustees participantes;
- el RTT entre Aggregator y Trustees;
- la contribución de cada fase del protocolo al tiempo total de firma;
- el efecto de RTTs heterogéneos entre Trustees.

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

y no:

```text
2 × coalition_size × RTT
```

porque las RPC de todos los Trustees participantes se ejecutan concurrentemente dentro de cada ronda.

Cuando los RTT son heterogéneos, cada ronda completa cuando termina su RPC participante más lenta. De forma aproximada, cuando el retardo de propagación domina:

```text
T_network ≈ 2 × max(RTT_i)
```

La infraestructura incluye una campaña específica para validar experimentalmente este comportamiento.

---

## 3. Instrumentación

Se registra instrumentación tanto en el Aggregator como en los Trustees.

El Aggregator recoge, entre otras métricas:

- tiempo total de `AggregatorSign`;
- lectura de Coalition List / CRV;
- duración de Round 1;
- duración individual de cada RPC de Round 1;
- offsets de inicio y fin de cada RPC de Round 1;
- tiempo entre rondas;
- duración de Round 2;
- duración individual de cada RPC de Round 2;
- offsets de inicio y fin de cada RPC de Round 2;
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

La instrumentación permite comprobar directamente, entre otras propiedades:

```text
T_round ≈ max(T_RPC_i)
```

y determinar qué Trustee completa último cada ronda.

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

### RTT homogéneo

Ejemplos:

```bash
sudo neteval/netem/netem.sh apply 80
sudo neteval/netem/netem.sh show
sudo neteval/netem/netem.sh reset
```

`apply 80` configura aproximadamente **80 ms RTT** entre el Aggregator y todos los Trustees activos.

### RTT heterogéneo

También puede configurarse un RTT distinto para cada Trustee activo.

Por ejemplo, con 10 Trustees:

```bash
sudo neteval/netem/netem.sh apply \
  20 20 20 20 20 20 20 20 20 200
```

configura:

```text
trustee-0 ... trustee-8: 20 ms RTT
trustee-9:                200 ms RTT
```

Antes de ejecutar las muestras de un perfil, el runner mide el RTT real desde el network namespace del Aggregator y valida cada Trustee de forma independiente.

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

### Perfiles de red

El conjunto de perfiles puede seleccionarse mediante:

```bash
KLL_PROFILES_FILE=/path/to/profiles.json
```

El fichero por defecto es:

```text
neteval/runner/profiles.json
```

y contiene los perfiles homogéneos utilizados en la campaña principal.

Los perfiles heterogéneos utilizados en la validación adicional se encuentran en:

```text
neteval/runner/profiles-heterogeneous.json
```

El runner acepta perfiles con:

```json
{
  "profile_id": "rtt80",
  "rtt_ms": 80
}
```

o perfiles con un RTT independiente por Trustee:

```json
{
  "profile_id": "hetero-9x20-1x200",
  "trustee_rtt_ms": [
    20, 20, 20, 20, 20,
    20, 20, 20, 20, 200
  ]
}
```

Los perfiles escalares se normalizan internamente a un RTT por Trustee.

### Seguridad de KeyIDs

LMS es stateful: un KeyID no puede reutilizarse.

`neteval/runner/keyid.py` mantiene un ledger persistente:

```text
neteval/results/<experiment-id>/keyids.jsonl
```

El KeyID se **reserva antes** de intentar la firma. Un KeyID reservado no vuelve a asignarse aunque la ejecución falle posteriormente.

Una vez que Round 1 comienza, el KeyID se considera consumido definitivamente.

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

Cada firma generada se valida mediante:

```bash
openssl pkeyutl -verify
```

La campaña experimental usa únicamente firmas verificadas correctamente.

---

## 7. Configuración experimental principal

Parámetros utilizados en las campañas principales:

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

Dentro de cada campaña, todos los KeyIDs usan la misma coalición completa de Trustees activos.

El orden de perfiles se randomiza independientemente en cada bloque a partir de una seed reproducible.

Con esta configuración, cada campaña principal produce:

```text
50 measured samples por perfil
200 measured samples totales
```

además de warm-up y conditioning.

Las tres campañas principales producen conjuntamente:

```text
600 measured signatures
```

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

No debe modificarse el código entre las campañas definitivas de una misma serie experimental.

---

## 9. Campaña de RTT heterogéneo

La validación adicional utiliza una coalición fija de **10-of-10** y compara tres perfiles:

```text
hom20:
  10 × 20 ms

hetero-9x20-1x200:
   9 × 20 ms
   1 × 200 ms

hom200:
  10 × 200 ms
```

El Trustee de alta latencia del perfil heterogéneo es siempre:

```text
trustee-9
```

La campaña usa la misma metodología de bloques que la evaluación principal:

```text
Warm-up global:      10 firmas
Bloques aleatorios:  5
Perfiles por bloque: 3
Conditioning:        1 por transición/perfil
Measured/block:      10 por perfil
Measured/profile:    50
Measured totales:    150
```

Ejecución:

```bash
KLL_OPENSSL_PREFIX="$HOME/.local/openssl-4.0.1-lms" \
KLL_PROFILES_FILE="$PWD/neteval/runner/profiles-heterogeneous.json" \
KLL_TRUSTEE_COUNT=10 \
KLL_WARMUP_SAMPLES=10 \
KLL_BLOCKS=5 \
KLL_MEASURED_PER_BLOCK=10 \
KLL_PROFILE_SEED=20260818 \
neteval/runner/run.sh hetero-rtt-k10-final
```

---

## 10. Resultados producidos

Cada ejecución genera:

```text
neteval/results/<experiment-id>/
├── manifest.json
├── schedule.json
├── schedule.tsv
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
- `schedule.json`: orden aleatorio de perfiles por bloque y configuración RTT;
- `schedule.tsv`: representación tabular del schedule;
- `samples.jsonl`: un registro por intento de firma;
- `keyids.jsonl`: ledger irreversible de KeyIDs;
- `raw/`: métricas instrumentadas del Aggregator y Trustees;
- `network/`: configuración `tc/netem`, mappings veth, objetivos RTT y validaciones;
- `signatures/`: firmas LMS generadas;
- `setup/`: configuración, BulletinBoard, clave pública y datos de OpenSSL;
- `workload/`: mensaje utilizado en la campaña;
- `logs/`: build, Dealer, curl y verificaciones.

Cada perfil de red archiva además:

```text
network/block-XX/<profile>/
├── configure.txt
├── qdisc-before.txt
├── qdisc-after.txt
├── rtt-targets.tsv
└── rtt.txt
```

---

## 11. Validación realizada

Antes de las campañas finales se validaron end-to-end:

- topologías **3-of-3**, **5-of-5** y **10-of-10**;
- perfiles `baseline`, `RTT20`, `RTT80` y `RTT200`;
- paralelización intra-ronda del Aggregator;
- barrera estricta entre Round 1 y Round 2;
- shaping simétrico Aggregator ↔ Trustees;
- RTT homogéneo y heterogéneo;
- descubrimiento dinámico de Trustees/veth;
- validación automática del RTT por Trustee;
- reserva irreversible de KeyIDs;
- firmas RFC 8554;
- verificación positiva con OpenSSL 4;
- control negativo modificando el mensaje;
- cardinalidad esperada de eventos instrumentados;
- cleanup de `netem`, contenedores y volúmenes después de cada experimento;
- árboles LMS `h=10` con espacio de 1024 KeyIDs;
- ejecución aleatorizada por bloques;
- archivado de configuración, schedule, provenance y métricas.

En las campañas homogéneas, la latencia de firma crece aproximadamente en dos RTT adicionales por cada incremento de RTT, de acuerdo con las dos rondas secuenciales del protocolo.

La campaña heterogénea confirmó además que, con nueve Trustees a aproximadamente 20 ms y uno a 200 ms, el Trustee de 200 ms fue:

```text
Round 1:
  último RPC en completar:      50 / 50
  RPC de mayor duración:        50 / 50

Round 2:
  último RPC en completar:      50 / 50
  RPC de mayor duración:        50 / 50
```

Las medianas observadas fueron:

```text
Aggregator signing latency:

hom20:                   95.269 ms
hetero-9x20-1x200:      447.926 ms
hom200:                 461.763 ms
```

En el perfil heterogéneo:

```text
Round 1:
  median duration:              218.309 ms
  median round - RPC span:        0.195 ms

Round 2:
  median duration:              219.660 ms
  median round - RPC span:        0.246 ms
```

Estos resultados validan experimentalmente que, con la implementación paralela, las latencias de los Trustees no se acumulan serialmente dentro de una ronda. Cada ronda completa esencialmente cuando termina su RPC participante más lenta:

```text
T_round ≈ max(T_RPC_i)
```

y, cuando la heterogeneidad está dominada por retardo de propagación:

```text
T_network ≈ 2 × max(RTT_i)
```

para las dos rondas secuenciales.

---

## 12. Alcance experimental

La evaluación utiliza contenedores independientes y sockets TCP reales, pero todos los contenedores se ejecutan sobre un único host Linux.

`tc/netem` introduce únicamente retardo controlado en los enlaces:

```text
Aggregator ↔ Trustees
```

Las campañas actuales no introducen artificialmente:

- pérdida de paquetes;
- jitter;
- límites de ancho de banda;
- congestión;
- carga concurrente de firmas.

Tampoco pretenden reproducir todos los efectos de un despliegue Internet geográficamente distribuido.

El objetivo de la evaluación es aislar de forma reproducible la sensibilidad de la implementación a:

- RTT;
- tamaño de coalición;
- heterogeneidad de RTT entre Trustees;
- estructura temporal de las dos rondas del protocolo.

Los escenarios con enlaces compartidos de ancho de banda limitado, pérdida, jitter o carga concurrente quedan fuera del alcance de las campañas actuales.