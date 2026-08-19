# Threshold Hash-Based Signatures — Distributed Implementation

Java implementation of the threshold signature scheme over LMS described in:

> **"Turning Hash-Based Signatures into Distributed Signatures and Threshold Signatures"**  
> John Kelsey, Nathalie Lang, Stefan Lucks — IACR Communications in Cryptology, Vol. 2, No. 2, 2025

The system transforms the LMS hash-based signature scheme (RFC 8554) into a distributed signing scheme in which multiple Trustees cooperate to produce valid signatures. The resulting signature is indistinguishable from a standard LMS signature and can be verified by any compatible LMS verifier, including OpenSSL.

---

## Main Features

- Implementation of the two-round distributed signing protocol (Algorithms 5–11 of the paper)
- Independent Docker containers for each protocol role
- Aggregator–Trustee communication over gRPC (Protocol Buffers)
- Custom Content Addressable Storage (CAS) for CRVs and the Coalition List
- Persistent Trustee state using SQLite
- Threshold-signature verification with OpenSSL, validated experimentally
- Reproducible evaluation under controlled RTT using Linux `tc`/`netem`, including 3-, 5-, and 10-Trustee topologies and both homogeneous and heterogeneous network profiles

---

## System Architecture

```text
┌─────────────┐   HTTP PUT    ┌─────────────┐
│   Dealer    │ ────────────► │     CAS     │
│ (ephemeral) │               │ (HTTP :8080)│
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

Shared volume: /bulletin/board.json ← written by Dealer, read by Trustees and Aggregator
```

### Protocol Roles

**Dealer** — ephemeral container that performs setup:

1. Generates the LMS key pair and the PRF keys `K[t]` for each Trustee
2. Generates the CRVs (Common Reference Values) and publishes them to the CAS
3. Publishes the Coalition List (CL) to the CAS
4. Writes the BulletinBoard containing the LMS public key and the corresponding CIDs
5. Distributes `K[t]` to each Trustee over gRPC and terminates

**Trustees** — gRPC servers participating in the signing protocol. Each Trustee:

- Stores its PRF key `K[t]` on disk as secret material
- Maintains the list of available KeyIDs persistently in SQLite
- Participates in the two signing rounds coordinated by the Aggregator
- Never reuses a KeyID, preserving the one-time property required by LMS

**Aggregator** — HTTP server coordinating the signing protocol:

- Receives external `POST /sign/{keyID}` requests
- Retrieves the corresponding CRV from the CAS
- Executes the two protocol rounds with the Trustees over gRPC
- Reconstructs the complete `(R, PATH, Z)` signature and returns it in RFC 8554 format

**CAS** — content-addressable HTTP storage service:

- Stores blobs identified by their SHA-256 digest (CID)
- Endpoints: `POST /blobs` → CID, `GET /blobs/{cid}` → bytes
- Automatically verifies content integrity on retrieval

---

## Project Structure (Maven Multi-Module)

```text
threshold-hbs/
├── core/                    Pure cryptographic logic (no network or disk I/O)
│   └── src/main/java/es/uma/nicslab/hbs/
│       ├── lms/             LMS/LM-OTS classes (extended BouncyCastle)
│       ├── model/           CRV, SetupDealer, ThresholdSignature, Round1Msg, Round2Msg
│       ├── protocol/        Protocol interfaces and classes:
│       │                    BulletinBoard, CASReader, CASWriter, CRVSerializer,
│       │                    CLSerializer, CoalitionEntry, TrusteeProxy,
│       │                    LocalTrusteeProxy, InMemoryCAS, TrusteeState,
│       │                    InMemoryTrusteeState, SigningState, ProtocolRunner
│       ├── roles/           Dealer, Trustee, Aggregator
│       └── util/            PRF, ByteUtils, LMSExporterOpenSSL, ExportFromHex
│
├── proto/                   gRPC contracts
│   └── trustee.proto
│
├── cas/                     HTTP CAS server (Javalin 5.6.3)
│   └── CASServer, BlobStore, CASClient, HttpCASReader, HttpCASWriter
│
├── trustee-server/          Trustee gRPC server
│   └── TrusteeGrpcServer, TrusteeServiceImpl, TrusteeConfig, SQLiteTrusteeState
│
├── aggregator-server/       Aggregator HTTP server
│   └── AggregatorServer, GrpcTrusteeProxy
│
├── dealer-cli/              Dealer CLI (ephemeral container)
│   └── DealerMain, SetupConfig
│
├── neteval/                 Reproducible network-evaluation infrastructure
│   ├── netem/               Aggregator ↔ Trustee emulation with tc/netem
│   ├── runner/              Runner, profiles, and safe KeyID management
│   └── README.md            Experimental methodology and campaigns
│
├── integration-tests/       End-to-end integration tests
├── docker-compose.yml
└── setup-config.json
```

---

## Technologies

| Component     | Technology                               |
| ------------- | ---------------------------------------- |
| Language      | Java 17                                  |
| Build system  | Maven (multi-module)                     |
| Cryptography  | BouncyCastle 1.84, RFC 8554 (LMS/LM-OTS) |
| Communication | gRPC 1.75.0 + Protocol Buffers           |
| HTTP server   | Javalin 5.6.3 (CAS and Aggregator)       |
| Persistence   | SQLite (sqlite-jdbc 3.46.0)              |
| Containers    | Docker + Docker Compose                  |
| Base image    | eclipse-temurin:17-jre-alpine            |

---

## gRPC Protocol (`trustee.proto`)

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

`Setup` only transports the secret PRF key `K[t]`. The remaining scheme parameters (LMS public key, field lengths, and Coalition List CID) are read by each Trustee from the shared BulletinBoard.

---

## BulletinBoard

Public JSON file written by the Dealer after setup and shared through a Docker volume:

```json
{
  "lmsPublicKey": "3082...hex...",
  "clCid":        "a3f8b2...64chars...",
  "lengthCHK":    x,
  "lengthPATH":   y
}
```

---

## Deployment

### Prerequisites

- Java 17
- Maven 3.8+
- Docker Desktop

### 1. Build

```bash
mvn clean package -DskipTests
```

### 2. Configure Setup

Edit `setup-config.json` in the project root:

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

Available LMS parameter sets: `lms_sha256_n32_h5` (32 signatures), `lms_sha256_n32_h10` (1024), `lms_sha256_n32_h15` (32768), `lms_sha256_n32_h20` (1048576), `lms_sha256_n24_h5`, `lms_sha256_n24_h10`, `lms_sha256_n24_h15`, `lms_sha256_n24_h20`.

### 3. Start the CAS and Trustees

```bash
docker compose up -d cas
docker compose up -d trustee-0 trustee-1 trustee-2
```

Verify that the CAS is `healthy`:

```bash
docker compose ps
```

### 4. Run the Dealer

```bash
docker compose --profile setup up dealer
```

The Dealer should terminate with `exited with code 0`. It generates the LMS key pair, publishes the CRVs to the CAS, writes the BulletinBoard, and distributes the PRF keys to the Trustees.

### 5. Start the Aggregator

```bash
docker compose up -d aggregator
```

### 6. Sign a Message

```bash
# Linux/macOS/Git Bash:
curl -X POST http://localhost:8081/sign/0 \
     --data-binary "message to sign" \
     --output signature.bin

# PowerShell:
Invoke-WebRequest -Uri "http://localhost:8081/sign/0" \
                  -Method POST \
                  -Body "message to sign" \
                  -OutFile "signature.bin"
```

The response is the threshold signature serialized in RFC 8554 format and can be consumed by a standard LMS verifier.

### 7. Verify with OpenSSL

Export the LMS public key from the BulletinBoard:

```bash
docker compose exec trustee-0 cat /bulletin/board.json
```

Copy the hexadecimal value of `lmsPublicKey` and run `ExportFromHex.main()` to generate `lmspublickey.pem`. Store the previously signed message in `message.bin`.

```bash
openssl pkeyutl -verify \
    -in message.bin \
    -sigfile signature.bin \
    -inkey lmspublickey.pem -pubin
```

Expected result:

```text
Signature Verified Successfully
```

---

## Environment Variables

### CAS

| Variable       | Default | Description            |
| -------------- | ------- | ---------------------- |
| `CAS_PORT`     | `8080`  | HTTP port              |
| `CAS_DATA_DIR` | `/data` | Blob storage directory |

### Trustee

| Variable              | Default                  | Description              |
| --------------------- | ------------------------ | ------------------------ |
| `TRUSTEE_INDEX`       | —                        | Trustee index (required) |
| `TRUSTEE_PORT`        | `9090`                   | gRPC port                |
| `TRUSTEE_DB`          | `/db/trustee.db`         | SQLite database path     |
| `TRUSTEE_CONFIG`      | `/db/trustee-config.bin` | PRF configuration path   |
| `BULLETIN_BOARD_PATH` | `/bulletin/board.json`   | BulletinBoard path       |
| `CAS_URL`             | `http://cas:8080`        | CAS URL                  |

### Dealer

| Variable              | Default                     | Description                  |
| --------------------- | --------------------------- | ---------------------------- |
| `SETUP_CONFIG_PATH`   | `/config/setup-config.json` | Setup configuration path     |
| `BULLETIN_BOARD_PATH` | `/bulletin/board.json`      | BulletinBoard path           |
| `TRUSTEE_URLS`        | —                           | Trustee addresses (required) |
| `CAS_URL`             | `http://cas:8080`           | CAS URL                      |

### Aggregator

| Variable              | Default                | Description                  |
| --------------------- | ---------------------- | ---------------------------- |
| `AGGREGATOR_PORT`     | `8081`                 | HTTP port                    |
| `CAS_URL`             | `http://cas:8080`      | CAS URL                      |
| `BULLETIN_BOARD_PATH` | `/bulletin/board.json` | BulletinBoard path           |
| `TRUSTEE_URLS`        | —                      | Trustee addresses (required) |

---

## Security Model

Following the model of the original scheme:

- A **malicious Aggregator** can prevent valid signatures from being produced, but cannot forge signatures
- A **tampered CRV** in the CAS can prevent successful signing, but cannot enable forgery; since the CID is the SHA-256 digest of the content, modifications can be detected
- **KeyID reuse** requires all Trustees belonging to the corresponding coalition to fail in the same way
- Each Trustee's secret PRF key `K[t]` remains local to the Trustee after setup; it is transmitted only once, from the Dealer to that Trustee, during the setup phase

---

## Tests

```bash
# Core unit tests (no network)
mvn test -pl core

# CAS unit tests
mvn test -pl cas

# Trustee unit tests (SQLite in memory)
mvn test -pl trustee-server

# End-to-end integration tests (real HTTP CAS + SQLite)
mvn test -pl integration-tests
```

---

## Network Evaluation

The distributed implementation includes reproducible experimental infrastructure under [`neteval/`](neteval/README.md) for studying its behavior under different Aggregator–Trustee network conditions.

The evaluation supports:

- 3-, 5-, and 10-Trustee topologies;
- parallel RPC execution within each signing round;
- homogeneous RTT and independent per-Trustee RTT profiles;
- per-round and per-RPC instrumentation;
- warm-up, conditioning, and randomized execution blocks;
- irreversible KeyID reservation;
- independent verification of every generated signature with OpenSSL.

The complete methodology, experimental profiles, and reproduction commands are documented in [`neteval/README.md`](neteval/README.md).

---

## Reference

Kelsey, J., Lang, N., & Lucks, S. (2025). *Turning Hash-Based Signatures into Distributed Signatures and Threshold Signatures*. IACR Communications in Cryptology, 2(2). https://doi.org/10.62056/a6ksudy6b