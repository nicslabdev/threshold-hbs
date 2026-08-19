# Threshold Hash-Based Signatures — Distributed Implementation

Java implementation of the threshold/distributed LMS construction described in:

> **John Kelsey, Nathalie Lang, and Stefan Lucks, _Turning Hash-Based Signatures into Distributed Signatures and Threshold Signatures: Delegate Your Signing Capability, and Distribute it Among Trustees_.**
> IACR Communications in Cryptology, Vol. 2, No. 2, 2025.
> DOI: https://doi.org/10.62056/a6ksudy6b

The implementation transforms LMS/LM-OTS (RFC 8554) signing into a two-round protocol in which a coalition of Trustees cooperates to produce a signature serialized in the standard LMS format. Generated signatures are verified with the LMS implementation in Bouncy Castle and, in the distributed evaluation, independently with OpenSSL 4.

The repository contains both the cryptographic implementation and a deployable distributed system with a Dealer, Trustees, an Aggregator, and a content-addressable store (CAS).

---

## Reproducing the Artifact

The repository exposes four complementary entry points:

| Goal                                        | Entry point                              |
| ------------------------------------------- | ---------------------------------------- |
| Build and validate correctness              | `mvn clean test`                         |
| Run the local cryptographic benchmark       | [`bench/README.md`](bench/README.md)     |
| Run the distributed implementation          | [Deployment](#deployment)                |
| Reproduce the controlled network evaluation | [`neteval/README.md`](neteval/README.md) |

### Build and test

Requirements for the Java build:

- JDK 17
- Maven 3.8+

Run the complete Maven reactor from the repository root:

```bash
mvn clean test
```

At artifact finalization, this command executed **103 tests with 0 failures, 0 errors, and 0 skipped tests**, including:

- 39 `core` tests covering serialization, bulletin-board handling, Trustee state, Dealer setup, Trustee behavior, Aggregator behavior, LMS verification, negative verification cases, and one-time KeyID enforcement;
- 33 CAS tests;
- 22 Trustee-server tests, including SQLite-backed state;
- 9 end-to-end integration tests.

### Local benchmark

A short functional check of the local benchmark can be run with:

```bash
mvn -pl core -DskipTests exec:java \
  -Dexec.mainClass=es.uma.nicslab.hbs.bench.Benchmark \
  -Dexec.args="--smoke"
```

The full benchmark is:

```bash
mvn -pl core -DskipTests exec:java \
  -Dexec.mainClass=es.uma.nicslab.hbs.bench.Benchmark
```

It measures local Dealer setup cost, threshold signing, LMS verification, and a plain LMS baseline without network effects. The full methodology, parameter matrix, historical output used for the paper, and the distinction from the distributed evaluation are documented in [`bench/README.md`](bench/README.md).

### Distributed implementation

The Docker deployment uses real HTTP/gRPC communication, persistent Trustee state, and an external CAS. See [Deployment](#deployment) below for the basic signing workflow.

### Network evaluation

The reproducible network-evaluation harness under [`neteval/`](neteval/README.md) drives Docker deployments with 3, 5, or 10 Trustees and applies controlled Aggregator–Trustee RTTs using Linux `tc`/`netem`. It includes homogeneous and heterogeneous RTT profiles, randomized experimental blocks, warm-up and conditioning runs, metrics collection, one-time KeyID allocation, and independent OpenSSL verification.

---

## Main Features

- Two-round distributed LMS signing protocol based on the Kelsey–Lang–Lucks construction
- Coalition assignment per LMS KeyID
- Standard RFC 8554 signature serialization
- Bouncy Castle LMS verification and independent OpenSSL 4 interoperability checks
- Independent Docker containers for the protocol roles
- Aggregator–Trustee communication over gRPC and Protocol Buffers
- Custom content-addressable storage for CRVs and the Coalition List
- Persistent Trustee state using SQLite
- Atomic one-time KeyID consumption
- Concurrent Trustee RPCs within each distributed signing round, with a strict barrier between Round 1 and Round 2
- Reproducible network evaluation under controlled homogeneous and heterogeneous RTTs

---

## Protocol Overview

### Roles

| Role           | Responsibility                                               | Secret material                |
| -------------- | ------------------------------------------------------------ | ------------------------------ |
| **Dealer**     | Generates the LMS key pair, per-Trustee PRF keys, CRVs, and Coalition List during setup. It distributes each `K[t]` to its Trustee and then terminates. | All `K[t]` values during setup |
| **Trustee**    | Participates in the two signing rounds for the KeyIDs assigned to it and persistently enforces one-time KeyID use. | Its own PRF key `K[t]`         |
| **Aggregator** | Selects the coalition fixed by the Coalition List, coordinates the two rounds, reconstructs the LMS signature, and returns its RFC 8554 serialization. | No Trustee PRF key             |
| **CAS**        | Stores CRVs and the Coalition List as content-addressed public objects. | None                           |

### Two-round signing flow

For a KeyID with coalition `C`:

```text
                  Round 1
Aggregator  --------------------->  Trustees in C
            (KeyID, message)

Aggregator  <---------------------  Trustees in C
              (R_t, CHK_t)

            reconstruct R and CHK
                    |
                    | strict barrier
                    v

                  Round 2
Aggregator  --------------------->  Trustees in C
              (KeyID, R, CHK[t])

Aggregator  <---------------------  Trustees in C
              (Z_t, PATH_t)

        reconstruct (R, PATH, Z)
                    |
                    v
          RFC 8554 LMS signature
```

Within each round, the distributed Aggregator issues the required Trustee calls concurrently. Round 2 starts only after all required Round 1 responses have completed and `R` and `CHK` have been reconstructed.

If any required Trustee returns `⊥` (`null`) in either round, the signing attempt aborts.

### Coalition List and one-time state

The Dealer creates one `CoalitionEntry` per LMS KeyID. Each entry contains:

- the indices of the Trustees authorized for that KeyID; and
- the CID of the corresponding CRV in the CAS.

A Trustee receives the Coalition List during setup and derives the KeyIDs assigned to it. Claiming a KeyID is atomic and irreversible: once a signing attempt begins with that KeyID, the KeyID cannot be reused.

Signing state between Round 1 and Round 2 is maintained independently per KeyID. Multiple distinct KeyIDs may therefore be in flight concurrently, while each individual KeyID remains one-time.

### CRV and domain-separated PRF

For each KeyID, the public CRV contains the LMS signing material XOR-masked with Trustee-derived shares:

| Field  | Content                                                      |
| ------ | ------------------------------------------------------------ |
| `R`    | LMS randomizer masked with the Trustees' `R_t` shares        |
| `CHK`  | Concatenated Round-2 authentication values masked with Trustee shares |
| `PATH` | Merkle authentication path masked with Trustee shares        |
| `SK`   | LM-OTS chain material masked with Trustee shares             |

Trustee shares are deterministically derived from each Trustee's secret `K[t]` using KMAC-256 with domain-separated invocations for `R`, `CHAIN`, `CHK`, `PATH`, and `AUTH`.

The `AUTH` value binds Round 2 to the randomizer reconstructed after Round 1: before producing its Round-2 share, each Trustee checks the received `CHK[t]` against `PRF^AUTH_{K[t]}(KeyID, R, n)`.

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

### Deployment roles

**Dealer** — ephemeral process that performs setup:

1. Generates the LMS key pair and PRF keys `K[t]`.
2. Generates the CRVs and publishes them to the CAS.
3. Publishes the Coalition List to the CAS.
4. Writes the BulletinBoard containing the LMS public key and associated CIDs.
5. Distributes `K[t]` to the corresponding Trustees over gRPC and terminates.

**Trustees** — gRPC servers that:

- store their PRF key `K[t]`;
- maintain available KeyIDs and between-round state persistently in SQLite;
- participate in the two signing rounds;
- reject KeyIDs that are not assigned or have already been consumed.

**Aggregator** — HTTP server that:

- accepts `POST /sign/{keyID}`;
- reads the Coalition List and CRV from the CAS;
- executes the two protocol rounds with the required Trustees;
- reconstructs `(R, PATH, Z)`;
- serializes and returns the resulting LMS signature.

**CAS** — content-addressable HTTP storage that:

- stores blobs identified by their SHA-256 digest;
- exposes `POST /blobs` and `GET /blobs/{cid}`;
- validates content integrity when objects are retrieved.

---

## Project Structure

```text
threshold-hbs/
├── core/                    Cryptographic and protocol logic
│   └── src/main/java/es/uma/nicslab/hbs/
│       ├── bench/           Local in-process benchmark
│       ├── lms/             LMS/LM-OTS classes (extended Bouncy Castle code)
│       ├── model/           CRV, SetupDealer, ThresholdSignature, round messages
│       ├── protocol/        CAS abstractions, CoalitionEntry, TrusteeProxy,
│       │                    BulletinBoard, in-memory state, ProtocolRunner
│       ├── roles/           Dealer, Trustee, Aggregator
│       └── util/            PRF, ByteUtils, LMS/OpenSSL utilities
│
├── proto/                   gRPC contracts
│   └── src/main/proto/trustee.proto
│
├── cas/                     HTTP CAS server and client
├── trustee-server/          Trustee gRPC server and SQLite state
├── aggregator-server/       Aggregator HTTP server and gRPC Trustee proxy
├── dealer-cli/              Ephemeral distributed setup client
├── integration-tests/       End-to-end integration tests
│
├── bench/
│   ├── README.md            Local benchmark methodology and reproduction
│   └── results/
│       └── local-benchmark-2026-08-07.txt
│
├── neteval/
│   ├── README.md            Distributed network-evaluation methodology
│   ├── netem/               Selective Aggregator ↔ Trustee tc/netem shaping
│   └── runner/              Campaign runner, profiles, and KeyID management
│
├── docker-compose.yml
├── docker-compose.metrics.yml
├── setup-config.json
├── pom.xml
└── README.md
```

---

## Technologies

| Component                 | Technology                                |
| ------------------------- | ----------------------------------------- |
| Language                  | Java 17                                   |
| Build system              | Maven multi-module                        |
| Cryptography              | Bouncy Castle 1.84; LMS/LM-OTS (RFC 8554) |
| Trustee RPC               | gRPC 1.75.0 + Protocol Buffers            |
| HTTP services             | Javalin 5.6.3                             |
| Persistence               | SQLite (`sqlite-jdbc` 3.46.0)             |
| Containers                | Docker + Docker Compose                   |
| Container Java runtime    | `eclipse-temurin:17-jre-alpine`           |
| Network emulation         | Linux `tc` / `netem`                      |
| External LMS verification | OpenSSL 4                                 |

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

`Setup` transports the secret PRF key `K[t]`. The remaining public scheme parameters are obtained from the shared BulletinBoard and CAS.

---

## BulletinBoard

The Dealer writes a public JSON file to the shared Docker volume:

```json
{
  "lmsPublicKey": "3082...hex...",
  "clCid": "a3f8b2...64chars...",
  "lengthCHK": 192,
  "lengthPATH": 160
}
```

The concrete field lengths depend on the selected LMS/LM-OTS parameters and coalition configuration.

---

## Deployment

### Prerequisites

For the distributed deployment:

- Java 17
- Maven 3.8+
- Docker Engine or Docker Desktop with Docker Compose
- Python 3
- OpenSSL 4 only if external LMS verification is required

The controlled network evaluation additionally requires Linux with `tc`/`netem`; see [`neteval/README.md`](neteval/README.md).

### 1. Build

```bash
mvn clean package -DskipTests
```

For artifact validation, prefer running `mvn clean test` first.

### 2. Configure setup

Edit `setup-config.json` in the repository root:

```json
{
  "k": 3,
  "lmsParams": "lms_sha256_n32_h5",
  "lmotsParams": "sha256_n32_w4",
  "coalitionPattern": [
    [0, 1],
    [1, 2],
    [0, 2]
  ]
}
```

The coalition pattern is repeated over the available LMS KeyIDs.

### 3. Start the CAS and Trustees

```bash
docker compose up -d cas
docker compose up -d trustee-0 trustee-1 trustee-2
```

Check service state:

```bash
docker compose ps
```

### 4. Run the Dealer

```bash
docker compose --profile setup up dealer
```

The Dealer should terminate successfully after generating and publishing the setup material and provisioning the Trustees.

### 5. Start the Aggregator

```bash
docker compose up -d aggregator
```

### 6. Sign a message

Linux/macOS/Git Bash:

```bash
printf 'message to sign' > message.bin

curl -X POST http://localhost:8081/sign/0 \
  --data-binary @message.bin \
  --output signature.bin
```

PowerShell:

```powershell
"message to sign" | Set-Content -NoNewline message.bin

Invoke-WebRequest \
  -Uri "http://localhost:8081/sign/0" \
  -Method POST \
  -InFile "message.bin" \
  -OutFile "signature.bin"
```

A successful response contains the threshold-generated signature serialized in the RFC 8554 LMS format.

### 7. Verify with OpenSSL

The threshold signature returned by the Aggregator is serialized in the
standard RFC 8554 LMS format. It can therefore be verified independently
with an OpenSSL 4 build with LMS support.

First, extract the LMS public key from the BulletinBoard:

```bash
LMS_PUBLIC_KEY_HEX="$(
  docker compose exec -T trustee-0 \
    cat /bulletin/board.json \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["lmsPublicKey"])'
)"
```

Convert the serialized LMS public key to PEM using the repository utility:

```bash
mvn -q -pl core -DskipTests exec:java \
  -Dexec.mainClass=es.uma.nicslab.hbs.util.ExportFromHex \
  -Dexec.args="$LMS_PUBLIC_KEY_HEX lmspublickey.pem"
```

Then verify the signature against the exact message bytes submitted to the
Aggregator:

```bash
openssl pkeyutl -verify \
  -in message.bin \
  -sigfile signature.bin \
  -inkey lmspublickey.pem \
  -pubin
```

Expected output:

```text
Signature Verified Successfully
```

OpenSSL LMS support requires an OpenSSL 4 build with LMS enabled. The
network-evaluation runner under [`neteval/`](neteval/README.md) automates
this verification for every measured signature.

### 8. Stop the deployment

```bash
docker compose down
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
| -----------------------| --------------------------| --------------------------|
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

## Tests

The recommended command is the complete reactor:

```bash
mvn clean test
```

At artifact finalization, the test inventory was:

| Module / suite      |   Tests |
| ------------------- | ------: |
| `core`              |      39 |
| `cas`               |      33 |
| `trustee-server`    |      22 |
| `integration-tests` |       9 |
| **Total**           | **103** |

All 103 tests passed with no failures, errors, or skipped tests.

Individual suites can also be executed during development:

```bash
mvn test -pl core
mvn test -pl cas
mvn test -pl trustee-server
mvn test -pl integration-tests
```

The `core` role tests cover, among other properties:

- valid threshold signing and RFC 8554 LMS verification;
- signature-field dimensions;
- multiple coalition assignments;
- rejection of KeyID reuse;
- rejection of modified messages at verification;
- malformed Coalition Lists and invalid Trustee indices;
- rejection of out-of-coalition KeyIDs;
- Round 2 without a matching Round 1;
- failed `CHK` authentication;
- independent concurrent signing state for different KeyIDs;
- the single-Trustee coalition edge case.

The integration tests exercise the distributed protocol with real HTTP CAS communication and persistent Trustee state.

---

## Local Benchmark

The local benchmark is intentionally separate from the distributed network evaluation.

It characterizes cryptographic and in-process protocol costs without network delay:

- Dealer setup cost per KeyID;
- local threshold signing;
- LMS verification;
- plain single-signer LMS signing and verification.

The full benchmark uses 8 warm-up iterations and 15 measured repetitions for each tested configuration. See [`bench/README.md`](bench/README.md) for the parameter matrix, commands, expected runtime characteristics, and historical result provenance.

---

## Network Evaluation

The distributed implementation includes a reproducible evaluation harness under [`neteval/`](neteval/README.md).

It supports:

- 3-, 5-, and 10-Trustee deployments;
- homogeneous baseline, 20 ms, 80 ms, and 200 ms RTT profiles;
- independent per-Trustee RTT profiles for heterogeneous-path experiments;
- concurrent Trustee RPCs within each signing round;
- per-round and per-RPC instrumentation;
- warm-up and per-profile conditioning;
- randomized block ordering;
- irreversible KeyID reservation;
- automatic capture of setup, workload, raw metric, network, and signature artifacts;
- independent OpenSSL verification of generated signatures.

The complete methodology and reproduction commands are documented in [`neteval/README.md`](neteval/README.md).

---

## Security and Implementation Notes

The implementation follows the threat model and protocol structure of the referenced Kelsey–Lang–Lucks construction.

Important implementation properties include:

- **One-time KeyIDs.** A Trustee atomically claims a KeyID when Round 1 begins. A consumed KeyID is never made available again.
- **Per-KeyID between-round state.** State is stored independently for each KeyID, allowing distinct signing attempts to be in flight concurrently.
- **Round-2 authentication.** A Trustee only produces its Round-2 share after validating the reconstructed randomizer using its `AUTH` value.
- **Public content integrity.** CRVs and the Coalition List are retrieved from content-addressed storage and bound to their CIDs.
- **Dealer lifecycle.** The Dealer participates only during setup; each Trustee retains only its own PRF key afterward.
- **Abort behavior.** Failure of any required Trustee in either signing round prevents that signature from being completed.

This repository is an implementation and experimental artifact; the security arguments for the construction itself are given in the referenced paper.

---

## Reference

Kelsey, J., Lang, N., & Lucks, S. (2025). *Turning Hash-Based Signatures into Distributed Signatures and Threshold Signatures: Delegate Your Signing Capability, and Distribute it Among Trustees*. IACR Communications in Cryptology, 2(2). https://doi.org/10.62056/a6ksudy6b