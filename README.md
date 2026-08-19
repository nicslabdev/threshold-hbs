# Threshold Hash-Based Signatures — Implementación Distribuida

Implementación en Java del esquema de firma threshold sobre LMS descrito en el paper:

> **"Turning Hash-Based Signatures into Distributed Signatures and Threshold Signatures"**  
> John Kelsey, Nathalie Lang, Stefan Lucks — IACR Communications in Cryptology, Vol. 2, No. 2, 2025

El sistema transforma el esquema de firma basado en hash LMS (RFC 8554) en un esquema de firma distribuida donde múltiples trustees cooperan para producir firmas válidas. La firma resultante es indistinguible de una firma LMS estándar y puede verificarse con cualquier verificador LMS compatible, incluido OpenSSL.

---

## Características principales

- Implementación del protocolo de firma distribuida en dos rondas (Algorithms 5-11 del paper)
- Despliegue en contenedores Docker independientes para cada rol del protocolo
- Comunicación entre Aggregator y Trustees via gRPC (Protocol Buffers)
- Content Addressable Storage (CAS) propio para almacenar CRVs y la Coalition List
- Persistencia del estado de los Trustees en SQLite
- Verificación de firmas threshold con OpenSSL (validada experimentalmente)
- Evaluación reproducible bajo RTT controlado mediante Linux `tc`/`netem`, incluyendo topologías de 3, 5 y 10 Trustees y perfiles de red homogéneos y heterogéneos

---

## Arquitectura del sistema

```
┌─────────────┐   HTTP PUT    ┌─────────────┐
│   Dealer    │ ────────────► │     CAS     │
│  (efímero)  │               │ (HTTP :8080)│
└──────┬──────┘               └──────┬──────┘
       │ gRPC Setup(K[t])            │ HTTP GET
       ▼                             ▼
┌──────────────┐             ┌─────────────────┐
│  Trustee 0   │ ◄─────────  │                 │
│  (gRPC 9090) │   gRPC      │   Aggregator    │
├──────────────┤  ShardSign  │  (HTTP :8081)   │
│  Trustee 1   │ ─────────►  │                 │
│  (gRPC 9090) │             └─────────────────┘
├──────────────┤
│  Trustee 2   │
│  (gRPC 9090) │
└──────────────┘

Volumen compartido: /bulletin/board.json ← Dealer escribe, Trustees y Aggregator leen
```

### Roles del protocolo

**Dealer** — contenedor efímero que ejecuta el setup:
1. Genera el keypair LMS y las claves PRF `K[t]` para cada trustee
2. Genera los CRVs (Common Reference Values) y los publica en el CAS
3. Publica la Coalition List (CL) en el CAS
4. Escribe el BulletinBoard con la clave pública LMS y los CIDs
5. Distribuye `K[t]` a cada trustee via gRPC y termina

**Trustees** — servidores gRPC que participan en la firma. Cada trustee:
- Guarda su clave PRF `K[t]` en disco (material secreto)
- Mantiene la lista de KeyIDs disponibles en SQLite
- Participa en dos rondas de firma coordinadas por el Aggregator
- Nunca reutiliza un KeyID (propiedad one-time del esquema LMS)

**Aggregator** — servidor HTTP que coordina la firma:
- Recibe peticiones `POST /sign/{keyID}` del exterior
- Descarga el CRV correspondiente del CAS
- Ejecuta las dos rondas del protocolo con los trustees via gRPC
- Reconstruye la firma completa `(R, PATH, Z)` y la devuelve en formato RFC 8554

**CAS** — servidor HTTP de almacenamiento por contenido:
- Almacena blobs identificados por su SHA-256 (CID)
- Endpoints: `POST /blobs` → CID, `GET /blobs/{cid}` → bytes
- Verifica integridad automáticamente en cada descarga

---

## Estructura del proyecto (Maven multi-módulo)

```
threshold-hbs/
├── core/                    Lógica criptográfica pura (sin red ni disco)
│   └── src/main/java/es/uma/nicslab/hbs/
│       ├── lms/             Clases LMS/LM-OTS (BouncyCastle extendido)
│       ├── model/           CRV, SetupDealer, ThresholdSignature, Round1Msg, Round2Msg
│       ├── protocol/        Interfaces y clases del protocolo:
│       │                    BulletinBoard, CASReader, CASWriter, CRVSerializer,
│       │                    CLSerializer, CoalitionEntry, TrusteeProxy,
│       │                    LocalTrusteeProxy, InMemoryCAS, TrusteeState,
│       │                    InMemoryTrusteeState, SigningState, ProtocolRunner
│       ├── roles/           Dealer, Trustee, Aggregator
│       └── util/            PRF, ByteUtils, LMSExporterOpenSSL, ExportFromHex
│
├── proto/                   Contratos gRPC
│   └── trustee.proto
│
├── cas/                     Servidor CAS HTTP (Javalin 5.6.3)
│   └── CASServer, BlobStore, CASClient, HttpCASReader, HttpCASWriter
│
├── trustee-server/          Servidor gRPC del Trustee
│   └── TrusteeGrpcServer, TrusteeServiceImpl, TrusteeConfig, SQLiteTrusteeState
│
├── aggregator-server/       Servidor HTTP del Aggregator
│   └── AggregatorServer, GrpcTrusteeProxy
│
├── dealer-cli/              CLI del Dealer (contenedor efímero)
│   └── DealerMain, SetupConfig
│
├── neteval/                 Infraestructura de evaluación de red reproducible
│   ├── netem/               Emulación Aggregator ↔ Trustees con tc/netem
│   ├── runner/              Runner, perfiles y gestión segura de KeyIDs
│   └── README.md            Metodología y campañas experimentales
│
├── integration-tests/       Tests de integración end-to-end
├── docker-compose.yml
└── setup-config.json
```

---

## Tecnologías

| Componente | Tecnología |
|-----------|-----------|
| Lenguaje | Java 17 |
| Build | Maven (multi-módulo) |
| Criptografía | BouncyCastle 1.84, RFC 8554 (LMS/LM-OTS) |
| Comunicación | gRPC 1.75.0 + Protocol Buffers |
| Servidor HTTP | Javalin 5.6.3 (CAS y Aggregator) |
| Persistencia | SQLite (sqlite-jdbc 3.46.0) |
| Contenedores | Docker + Docker Compose |
| Imagen base | eclipse-temurin:17-jre-alpine |

---

## Protocolo gRPC (trustee.proto)

```protobuf
service TrusteeService {
  rpc Setup      (SetupRequest) returns (SetupResponse);
  rpc ShardSign1 (Sign1Request) returns (Sign1Response);
  rpc ShardSign2 (Sign2Request) returns (Sign2Response);
}

message SetupRequest { bytes prf_key = 1; }
message Sign1Request { int32 key_id = 1; bytes message = 2; int32 n = 3; }
message Sign2Request { int32 key_id = 1; bytes r = 2; bytes chk_i = 3; }
```

`Setup` solo transporta la clave PRF secreta `K[t]`. El resto de parámetros del esquema (clave pública LMS, longitudes, CID de la CL) los lee el trustee del BulletinBoard compartido.

---

## BulletinBoard

Fichero JSON público escrito por el Dealer al finalizar el setup, compartido en un volumen Docker:

```json
{
  "lmsPublicKey": "3082...hex...",
  "clCid":        "a3f8b2...64chars...",
  "lengthCHK":    x,
  "lengthPATH":   y
}
```

---

## Despliegue

### Prerequisitos

- Java 17
- Maven 3.8+
- Docker Desktop

### 1. Compilar

```bash
mvn clean package -DskipTests
```

### 2. Configurar el setup

Edita `setup-config.json` en la raíz del proyecto:

```json
{
  "k": 3,
  "lmsParams":   "lms_sha256_n32_h5",
  "lmotsParams": "sha256_n32_w4",
  "coalitionPattern": [
    [0, 1],
    [1, 2],
    [0, 2]
  ]
}
```

Parámetros LMS disponibles: `lms_sha256_n32_h5` (32 firmas), `lms_sha256_n32_h10` (1024), `lms_sha256_n32_h15` (32768), `lms_sha256_n32_h20` (1048576), `lms_sha256_n24_h5`, `lms_sha256_n24_h10`, `lms_sha256_n24_h15`, `lms_sha256_n24_h20`.

### 3. Arrancar el CAS y los Trustees

```bash
docker compose up -d cas
docker compose up -d trustee-0 trustee-1 trustee-2
```

Verifica que el CAS está `healthy`:

```bash
docker compose ps
```

### 4. Ejecutar el Dealer (setup efímero)

```bash
docker compose --profile setup up dealer
```

Debe terminar con `exited with code 0`. El Dealer genera el keypair LMS, publica los CRVs en el CAS, escribe el BulletinBoard y distribuye las claves PRF a los trustees.

### 5. Arrancar el Aggregator

```bash
docker compose up -d aggregator
```

### 6. Firmar un mensaje

```bash
# Linux/macOS/Git Bash:
curl -X POST http://localhost:8081/sign/0 \
     --data-binary "mensaje a firmar" \
     --output firma.bin

# PowerShell:
Invoke-WebRequest -Uri "http://localhost:8081/sign/0" \
                  -Method POST \
                  -Body "mensaje a firmar" \
                  -OutFile "firma.bin"
```

La respuesta es la firma threshold serializada en formato RFC 8554, compatible con cualquier verificador LMS estándar.

### 7. Verificar con OpenSSL

Exportar la clave pública del BulletinBoard:

```bash
docker compose exec trustee-0 cat /bulletin/board.json
```

Copiar el valor hex de `lmsPublicKey` y ejecutar `ExportFromHex.main()` para obtener `lmspublickey.pem`. Copiar en un archivo `message.bin` el mensaje firmado previamente.

```bash
openssl pkeyutl -verify \
    -in message.bin \
    -sigfile firma.bin \
    -inkey lmspublickey.pem -pubin
```

Resultado esperado: `Signature Verified Successfully`

---

## Variables de entorno

### CAS
| Variable | Default | Descripción |
|----------|---------|-------------|
| `CAS_PORT` | `8080` | Puerto HTTP |
| `CAS_DATA_DIR` | `/data` | Directorio de blobs |

### Trustee
| Variable | Default | Descripción |
|----------|---------|-------------|
| `TRUSTEE_INDEX` | — | Índice del trustee (obligatorio) |
| `TRUSTEE_PORT` | `9090` | Puerto gRPC |
| `TRUSTEE_DB` | `/db/trustee.db` | Ruta SQLite |
| `TRUSTEE_CONFIG` | `/db/trustee-config.bin` | Ruta config PRF |
| `BULLETIN_BOARD_PATH` | `/bulletin/board.json` | Ruta BulletinBoard |
| `CAS_URL` | `http://cas:8080` | URL del CAS |

### Dealer
| Variable | Default | Descripción |
|----------|---------|-------------|
| `SETUP_CONFIG_PATH` | `/config/setup-config.json` | Ruta configuración |
| `BULLETIN_BOARD_PATH` | `/bulletin/board.json` | Ruta BulletinBoard |
| `TRUSTEE_URLS` | — | Direcciones trustees (obligatorio) |
| `CAS_URL` | `http://cas:8080` | URL del CAS |

### Aggregator
| Variable | Default | Descripción |
|----------|---------|-------------|
| `AGGREGATOR_PORT` | `8081` | Puerto HTTP |
| `CAS_URL` | `http://cas:8080` | URL del CAS |
| `BULLETIN_BOARD_PATH` | `/bulletin/board.json` | Ruta BulletinBoard |
| `TRUSTEE_URLS` | — | Direcciones trustees (obligatorio) |

---

## Modelo de seguridad

Siguiendo el modelo del paper:

- Un **Aggregator malicioso** puede impedir que se generen firmas válidas, pero no puede forjarlas
- Un **CRV alterado** en el CAS puede impedir firmas válidas, pero no permite forjas (el CID = SHA-256 del contenido permite detectar alteraciones)
- La **reutilización de KeyIDs** requiere que todos los trustees de una coalición fallen simultáneamente de la misma forma
- La **clave PRF `K[t]`** de cada trustee nunca sale de su contenedor; solo viaja del Dealer al Trustee en el Setup via gRPC

---

## Tests

```bash
# Tests unitarios de core (sin red)
mvn test -pl core

# Tests unitarios del CAS
mvn test -pl cas

# Tests unitarios del trustee (SQLite en memoria)
mvn test -pl trustee-server

# Tests de integración end-to-end (CAS HTTP real + SQLite)
mvn test -pl integration-tests
```

---

## Evaluación de red

La implementación distribuida incluye una infraestructura experimental reproducible en [`neteval/`](neteval/README.md) para estudiar su comportamiento bajo diferentes condiciones Aggregator ↔ Trustees.

La evaluación soporta:

- topologías de 3, 5 y 10 Trustees;
- ejecución paralela de las RPC dentro de cada ronda;
- RTT homogéneo y RTT independiente por Trustee;
- instrumentación por ronda y por RPC;
- warm-up, conditioning y bloques aleatorizados;
- reserva irreversible de KeyIDs;
- verificación independiente de cada firma con OpenSSL.

La metodología, los perfiles experimentales y los comandos de reproducción se documentan en [`neteval/README.md`](neteval/README.md).

---

## Referencia

Kelsey, J., Lang, N., & Lucks, S. (2025). *Turning Hash-Based Signatures into Distributed Signatures and Threshold Signatures*. IACR Communications in Cryptology, 2(2). https://doi.org/10.62056/a6ksudy6b
