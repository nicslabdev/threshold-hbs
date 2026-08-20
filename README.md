# Threshold Hash-Based Signatures — Distributed Implementation

Java implementation of the **threshold/distributed LMS construction** described in:

> **John Kelsey, Nathalie Lang, and Stefan Lucks, _Turning Hash-Based Signatures into Distributed Signatures and Threshold Signatures: Delegate Your Signing Capability, and Distribute it Among Trustees_.**  
> IACR Communications in Cryptology, Vol. 2, No. 2, 2025.
> DOI: https://doi.org/10.62056/a6ksudy6b

The implementation transforms LMS/LM-OTS (RFC 8554) signing into a **two-round distributed protocol** in which a coalition of Trustees cooperates to produce a standard LMS signature. The resulting signature is serialized in RFC 8554 format and can be verified by an ordinary LMS verifier, including Bouncy Castle and OpenSSL 4.

The repository contains both the cryptographic implementation and a deployable distributed system with an ephemeral Dealer, persistent Trustees, an Aggregator, and a content-addressable store (CAS). It also includes local benchmarking and a reproducible network-evaluation harness for controlled homogeneous and heterogeneous RTT experiments.

---

## Table of Contents

- [Overview](#overview)
- [Main Features](#main-features)
- [Protocol Design](#protocol-design)
  - [Roles](#roles)
  - [Two-round signing flow](#two-round-signing-flow)
  - [Coalition List and one-time KeyIDs](#coalition-list-and-one-time-keyids)
  - [CRV and domain-separated PRF](#crv-and-domain-separated-prf)
- [System Architecture](#system-architecture)
  - [Deployment roles](#deployment-roles)
- [Project Structure](#project-structure)
- [Reproducing the Artifact](#reproducing-the-artifact)
  - [Requirements](#requirements)
  - [Build and validate correctness](#build-and-validate-correctness)
  - [Local cryptographic benchmark](#local-cryptographic-benchmark)
  - [Distributed implementation](#distributed-implementation)
  - [Controlled network evaluation](#controlled-network-evaluation)
- [Deployment](#deployment)
  - [1. Build](#1-build)
  - [2. Configure setup](#2-configure-setup)
  - [3. Start the CAS and Trustees](#3-start-the-cas-and-trustees)
  - [4. Run the Dealer](#4-run-the-dealer)
  - [5. Start the Aggregator](#5-start-the-aggregator)
  - [6. Sign a message](#6-sign-a-message)
  - [7. Verify with OpenSSL](#7-verify-with-openssl)
  - [8. Stop the deployment](#8-stop-the-deployment)
- [Implementation Details](#implementation-details)
  - [gRPC protocol](#grpc-protocol)
  - [BulletinBoard](#bulletinboard)
  - [Environment variables](#environment-variables)
- [Testing](#testing)
- [Benchmarking and Experimental Evaluation](#benchmarking-and-experimental-evaluation)
  - [Local benchmark](#local-benchmark)
  - [Distributed network evaluation](#distributed-network-evaluation)
- [Security and Implementation Notes](#security-and-implementation-notes)
- [Reference](#reference)

---

## Overview

This repository implements the Kelsey–Lang–Lucks construction for turning a stateful hash-based signature scheme into a distributed signing protocol while preserving the verification interface of the underlying scheme.

For LMS/LM-OTS, the signing material associated with each LMS **KeyID** is distributed across a predefined coalition of Trustees. No individual Trustee can reconstruct the complete LMS signing secret for that KeyID. Instead, the Trustees participate in two signing rounds coordinated by an untrusted Aggregator, which combines their shares with public masked values and outputs a standard LMS signature.

The implementation uses a **Coalition List (`CL`)** that assigns one Trustee coalition to each LMS KeyID. Coalition membership can therefore vary across the LMS tree rather than requiring the same set of Trustees for every signature. For a given KeyID, all members of its assigned coalition are required; the threshold policy is therefore encoded by the set of coalitions defined during setup.

Two properties are especially important for the implementation:

- **One-time KeyID use.** LMS/LM-OTS is stateful. A Trustee atomically consumes a KeyID when Round 1 begins, preventing that KeyID from being reused.
- **Standard verification.** Threshold-generated signatures preserve the RFC 8554 LMS wire format and are verified without modifying the verifier.

The repository supports both:

1. **Local/in-process execution**, used to validate the cryptographic implementation and measure computation costs without network effects.
2. **Distributed execution**, where the Dealer, Trustees, Aggregator, and CAS run as separate components and communicate using HTTP and gRPC.

---

## Main Features

- Two-round distributed LMS signing based on the Kelsey–Lang–Lucks construction.
- Coalition assignment per LMS KeyID.
- RFC 8554-compatible LMS signature serialization.
- Verification with Bouncy Castle and independent interoperability checks with OpenSSL 4.
- Dockerized Dealer, Trustees, Aggregator, and CAS.
- Aggregator–Trustee communication over gRPC and Protocol Buffers.
- Content-addressable storage for CRVs and the Coalition List.
- Persistent Trustee state using SQLite.
- Atomic, irreversible one-time KeyID consumption.
- Independent between-round state per KeyID.
- Concurrent Trustee RPCs within each signing round.
- Strict barrier between Round 1 and Round 2.
- Local cryptographic benchmarking.
- Reproducible distributed evaluation under controlled homogeneous and heterogeneous RTTs.

---

## Protocol Design

### Roles

| Role           | Responsibility                                               | Secret material                |
| -------------- | ------------------------------------------------------------ | ------------------------------ |
| **Dealer**     | Performs setup, generates the LMS key pair, creates Trustee PRF keys, constructs the CRVs and Coalition List, publishes public setup material, provisions the Trustees, and then terminates. | All `K[t]` values during setup |
| **Trustee**    | Participates in the two signing rounds for its assigned KeyIDs and persistently enforces one-time KeyID use. | Its own PRF key `K[t]`         |
| **Aggregator** | Looks up the coalition assigned to a KeyID, coordinates both signing rounds, reconstructs the LMS signature, and returns its RFC 8554 serialization. | No Trustee PRF key             |
| **CAS**        | Stores CRVs and the Coalition List as content-addressed public objects. | None                           |

### Two-round signing flow

For a KeyID assigned to coalition `C`:

```text
┌────────────────────────────── Round 1 ───────────────────────────────┐
│                                                                      │
│  ┌──────────────┐     (KeyID, message)      ┌────────────────────┐   │
│  │              │ ─────────────────────────►│                    │   │
│  │  Aggregator  │                           │   Trustees in C    │   │
│  │              │ ◄─────────────────────────│                    │   │
│  └──────────────┘       (R_t, CHK_t)        └────────────────────┘   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ reconstruct R and CHK
                                  ▼
                           ── strict barrier ──
                                  │
                                  ▼
┌────────────────────────────── Round 2 ───────────────────────────────┐
│                                                                      │
│  ┌──────────────┐    (KeyID, R, CHK[t])     ┌────────────────────┐   │
│  │              │ ─────────────────────────►│                    │   │
│  │  Aggregator  │                           │   Trustees in C    │   │
│  │              │ ◄─────────────────────────│                    │   │
│  └──────────────┘       (Z_t, PATH_t)       └────────────────────┘   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ reconstruct PATH and Z
                                  ▼
                    ┌────────────────────────────┐
                    │   RFC 8554 LMS signature   │
                    │        (R, PATH, Z)        │
                    └────────────────────────────┘
```

Within each round, the distributed Aggregator issues the required Trustee RPCs **concurrently**. Round 2 begins only after all required Round 1 calls have completed and the Aggregator has reconstructed `R` and `CHK`.

The protocol proceeds as follows.

**Round 1**

1. The Aggregator obtains the coalition `C` assigned to the requested KeyID.
2. It sends `(KeyID, message)` concurrently to every Trustee in `C`.
3. Each Trustee atomically claims the KeyID and computes its shares `R_t` and `CHK_t`.
4. The Aggregator combines the Trustee responses with the public CRV and reconstructs `R` and the per-Trustee authentication values `CHK[t]`.

**Round 2**

1. The Aggregator sends `(KeyID, R, CHK[t])` to each Trustee in `C`.
2. Each Trustee authenticates the reconstructed randomizer before releasing its Round-2 contribution.
3. A successful Trustee returns `(Z_t, PATH_t)`.
4. The Aggregator combines the Trustee shares with the public CRV to reconstruct the final LMS signing values.
5. The resulting `(R, PATH, Z)` object is serialized as a standard RFC 8554 LMS signature.

If any required Trustee returns `⊥` (`null`) or a required RPC fails, the signing attempt aborts.

### Coalition List and one-time KeyIDs

The Dealer creates one `CoalitionEntry` per LMS KeyID. Each entry contains:

- the indices of the Trustees authorized to participate in that KeyID; and
- the CID of the corresponding CRV in the CAS.

The Coalition List therefore fixes the signing coalition during setup. The caller does not dynamically choose the Trustees used for a particular signature.

Each Trustee derives the subset of KeyIDs assigned to it from the Coalition List. When Round 1 begins, the Trustee **atomically and irreversibly claims the KeyID**. This is required because LMS/LM-OTS signing keys are stateful and one-time at the LM-OTS level.

Between-round state is maintained independently for each KeyID. Consequently, different KeyIDs may be in flight concurrently, while an individual KeyID can never be reused.

### CRV and domain-separated PRF

For each KeyID, the public **Common Reference Values (CRV)** contain LMS signing material XOR-masked with Trustee-derived shares:

| Field  | Content                                                      |
| ------ | ------------------------------------------------------------ |
| `R`    | LMS randomizer masked with the Trustees' `R_t` shares        |
| `CHK`  | Concatenated Round-2 authentication values masked with Trustee shares |
| `PATH` | Merkle authentication path masked with Trustee shares        |
| `SK`   | LM-OTS chain material masked with Trustee shares             |

Conceptually, for a field `X` and coalition `C`:

```text
CRV.X = X ⊕ X_1 ⊕ X_2 ⊕ ... ⊕ X_|C|
```

The Trustee shares are deterministically derived from each Trustee's secret `K[t]` using KMAC-256 with domain-separated invocations:

| Label   | Purpose                                                      |
| ------- | ------------------------------------------------------------ |
| `R`     | Randomizer share `R_t`                                       |
| `CHAIN` | LM-OTS Winternitz-chain share                                |
| `CHK`   | Share used to mask the Round-2 authentication values         |
| `PATH`  | Merkle authentication-path share                             |
| `AUTH`  | Authentication value binding Round 2 to the reconstructed `R` |

Before returning its Round-2 contribution, Trustee `t` verifies the received authentication value against:

```text
PRF^AUTH_{K[t]}(KeyID, R, n)
```

This binds Round 2 to the randomizer reconstructed after Round 1.

---

## System Architecture

The distributed implementation separates the protocol roles into independent services:

```text
                         public setup objects
                  ┌────────────────────────────┐
                  │                            ▼
┌─────────────┐   │ HTTP PUT             ┌─────────────┐
│   Dealer    │ ──┴────────────────────► │     CAS     │
│ (ephemeral) │                          │ HTTP :8080  │
└──────┬──────┘                          └──────┬──────┘
       │                                       │
       │ gRPC Setup(K[t])                      │ HTTP GET
       │                                       │
       ▼                                       ▼
┌──────────────────┐                    ┌─────────────────┐
│    Trustee 0     │ ◄────────────────► │                 │
│   gRPC :9090     │                    │                 │
├──────────────────┤                    │   Aggregator    │
│    Trustee 1     │ ◄───── gRPC ─────► │   HTTP :8081    │
│   gRPC :9090     │   ShardSign1/2     │                 │
├──────────────────┤                    │                 │
│    Trustee ...   │ ◄────────────────► │                 │
│   gRPC :9090     │                    └─────────────────┘
└──────────────────┘

Shared volume:
  /bulletin/board.json
  written by the Dealer and read by Trustees and Aggregator
```

The CAS stores the larger public objects by content identifier, while the shared BulletinBoard contains the LMS public key and the CIDs needed to retrieve them.

### Deployment roles

**Dealer** — ephemeral setup process:

1. Generates the LMS key pair.
2. Generates one PRF key `K[t]` for each Trustee.
3. Constructs the CRVs for the available KeyIDs.
4. Publishes the CRVs and Coalition List to the CAS.
5. Writes the BulletinBoard containing the LMS public key and associated CIDs.
6. Provisions each Trustee with its own `K[t]` over gRPC.
7. Terminates.

**Trustees** — persistent gRPC servers that:

- store their PRF key `K[t]`;
- read public setup information from the BulletinBoard and CAS;
- maintain available/consumed KeyIDs in SQLite;
- maintain between-round state per KeyID;
- execute `ShardSign1` and `ShardSign2`;
- reject unassigned or previously consumed KeyIDs.

**Aggregator** — HTTP server that:

- accepts `POST /sign/{keyID}`;
- retrieves the Coalition List and CRV from the CAS;
- contacts the required Trustees concurrently within each round;
- enforces the Round-1/Round-2 barrier;
- reconstructs `(R, PATH, Z)`;
- serializes and returns the RFC 8554 LMS signature.

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
│       ├── lms/             LMS/LM-OTS classes and serialization
│       ├── model/           CRV, setup data, signatures, round messages
│       ├── protocol/        CAS abstractions, CoalitionEntry, TrusteeProxy,
│       │                    BulletinBoard, state, ProtocolRunner
│       ├── roles/           Dealer, Trustee, Aggregator
│       └── util/            PRF, byte utilities, LMS/OpenSSL utilities
│
├── proto/                   gRPC contracts
│   └── src/main/proto/trustee.proto
│
├── cas/                     HTTP CAS server and client
├── trustee-server/          Trustee gRPC server and SQLite-backed state
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

## Reproducing the Artifact

The repository exposes four complementary entry points:

| Goal                                        | Entry point                              |
| ------------------------------------------- | ---------------------------------------- |
| Build and validate correctness              | `mvn clean test`                         |
| Run the local cryptographic benchmark       | [`bench/README.md`](bench/README.md)     |
| Run the distributed implementation          | [Deployment](#deployment)                |
| Reproduce the controlled network evaluation | [`neteval/README.md`](neteval/README.md) |

### Requirements

#### Core build

- JDK 17
- Maven 3.8+

#### Distributed deployment

- Docker Engine or Docker Desktop
- Docker Compose
- Python 3

#### Optional / experiment-specific

- OpenSSL 4 with LMS support, for independent external verification.
- Linux `tc` / `netem`, for the controlled network evaluation.

The Maven build uses Bouncy Castle 1.84. The containerized Java services use an `eclipse-temurin:17-jre-alpine` runtime.

### Build and validate correctness

Run the complete Maven reactor from the repository root:

```bash
mvn clean test
```

At artifact finalization, this executed **103 tests with 0 failures, 0 errors, and 0 skipped tests**:

| Module / suite      |   Tests |
| ------------------- | ------: |
| `core`              |      39 |
| `cas`               |      33 |
| `trustee-server`    |      22 |
| `integration-tests` |       9 |
| **Total**           | **103** |

### Local cryptographic benchmark

A short smoke run is:

```bash
mvn -pl core -DskipTests exec:java \
  -Dexec.mainClass=es.uma.nicslab.hbs.bench.Benchmark \
  -Dexec.args="--smoke"
```

Run the complete local benchmark with:

```bash
mvn -pl core -DskipTests exec:java \
  -Dexec.mainClass=es.uma.nicslab.hbs.bench.Benchmark
```

It measures Dealer setup cost, threshold signing, LMS verification, and a plain LMS baseline **without network effects**.

The complete methodology, parameter matrix, and historical output used for the paper are documented in [`bench/README.md`](bench/README.md).

### Distributed implementation

The Docker deployment uses:

- real HTTP communication between the Aggregator/Dealer and CAS;
- real gRPC communication between the Aggregator/Dealer and Trustees;
- persistent SQLite-backed Trustee state;
- content-addressed public setup objects;
- concurrent Trustee RPCs within each signing round.

See [Deployment](#deployment) for the complete workflow.

### Controlled network evaluation

The reproducible evaluation harness under [`neteval/`](neteval/README.md) drives distributed Docker deployments with 3, 5, or 10 Trustees and applies controlled Aggregator–Trustee delays using Linux `tc`/`netem`.

It supports:

- homogeneous baseline, 20 ms, 80 ms, and 200 ms RTT profiles;
- heterogeneous per-Trustee RTT profiles;
- warm-up and per-profile conditioning;
- randomized experimental blocks;
- per-round and per-RPC instrumentation;
- one-time KeyID allocation;
- automatic result collection;
- independent OpenSSL verification of measured signatures.

See [`neteval/README.md`](neteval/README.md) for the full experimental methodology and reproduction commands.

---

## Deployment

### 1. Build

For artifact validation, first run:

```bash
mvn clean test
```

Then build the deployable modules:

```bash
mvn clean package -DskipTests
```

### 2. Configure setup

Edit `setup-config.json` in the repository root.

Example:

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

Check the deployment state:

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

A successful response contains the threshold-generated signature serialized in RFC 8554 LMS format.

### 7. Verify with OpenSSL

The signature returned by the Aggregator can be verified by an OpenSSL 4 build with LMS support.

First, extract the serialized LMS public key from the BulletinBoard:

```bash
LMS_PUBLIC_KEY_HEX="$(
  docker compose exec -T trustee-0 \
    cat /bulletin/board.json \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["lmsPublicKey"])'
)"
```

Convert it to PEM using the repository utility:

```bash
mvn -q -pl core -DskipTests exec:java \
  -Dexec.mainClass=es.uma.nicslab.hbs.util.ExportFromHex \
  -Dexec.args="$LMS_PUBLIC_KEY_HEX lmspublickey.pem"
```

Verify the signature against the exact message bytes submitted to the Aggregator:

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

The network-evaluation runner under [`neteval/`](neteval/README.md) automates this verification for every measured signature.

### 8. Stop the deployment

```bash
docker compose down
```

---

## Implementation Details

### gRPC protocol

The Trustee service is defined in `proto/src/main/proto/trustee.proto`:

```protobuf
service TrusteeService {
  rpc Setup      (SetupRequest) returns (SetupResponse);
  rpc ShardSign1 (Sign1Request) returns (Sign1Response);
  rpc ShardSign2 (Sign2Request) returns (Sign2Response);
}

message SetupRequest {
  bytes prf_key = 1;
}

message Sign1Request {
  int32 key_id = 1;
  bytes message = 2;
  int32 n = 3;
}

message Sign2Request {
  int32 key_id = 1;
  bytes r = 2;
  bytes chk_i = 3;
}
```

`Setup` provisions the Trustee with its secret PRF key `K[t]`. The remaining public scheme parameters are obtained from the BulletinBoard and CAS.

### BulletinBoard

The Dealer writes a public JSON file to the shared Docker volume.

Example:

```json
{
  "lmsPublicKey": "3082...hex...",
  "clCid": "a3f8b2...64chars...",
  "lengthCHK": 192,
  "lengthPATH": 160
}
```

The concrete field lengths depend on the selected LMS/LM-OTS parameters and coalition configuration.

### Environment variables

#### CAS

| Variable       | Default | Description            |
| -------------- | ------- | ---------------------- |
| `CAS_PORT`     | `8080`  | HTTP port              |
| `CAS_DATA_DIR` | `/data` | Blob storage directory |

#### Trustee

| Variable              | Default                  | Description              |
| --------------------- | ------------------------ | ------------------------ |
| `TRUSTEE_INDEX`       | —                        | Trustee index (required) |
| `TRUSTEE_PORT`        | `9090`                   | gRPC port                |
| `TRUSTEE_DB`          | `/db/trustee.db`         | SQLite database path     |
| `TRUSTEE_CONFIG`      | `/db/trustee-config.bin` | PRF configuration path   |
| `BULLETIN_BOARD_PATH` | `/bulletin/board.json`   | BulletinBoard path       |
| `CAS_URL`             | `http://cas:8080`        | CAS URL                  |

#### Dealer

| Variable              | Default                     | Description                  |
| --------------------- | --------------------------- | ---------------------------- |
| `SETUP_CONFIG_PATH`   | `/config/setup-config.json` | Setup configuration path     |
| `BULLETIN_BOARD_PATH` | `/bulletin/board.json`      | BulletinBoard path           |
| `TRUSTEE_URLS`        | —                           | Trustee addresses (required) |
| `CAS_URL`             | `http://cas:8080`           | CAS URL                      |

#### Aggregator

| Variable              | Default                | Description                  |
| --------------------- | ---------------------- | ---------------------------- |
| `AGGREGATOR_PORT`     | `8081`                 | HTTP port                    |
| `CAS_URL`             | `http://cas:8080`      | CAS URL                      |
| `BULLETIN_BOARD_PATH` | `/bulletin/board.json` | BulletinBoard path           |
| `TRUSTEE_URLS`        | —                      | Trustee addresses (required) |

---

## Testing

The recommended validation command is:

```bash
mvn clean test
```

Individual suites can also be run during development:

```bash
mvn test -pl core
mvn test -pl cas
mvn test -pl trustee-server
mvn test -pl integration-tests
```

The test suite covers, among other properties:

- valid threshold signing and RFC 8554 LMS verification;
- signature-field dimensions;
- multiple coalition assignments;
- malformed Coalition Lists and invalid Trustee indices;
- rejection of out-of-coalition KeyIDs;
- atomic rejection of KeyID reuse;
- Round 2 without matching Round-1 state;
- failed `CHK` authentication;
- verification failure for modified messages;
- independent concurrent state for different KeyIDs;
- the single-Trustee coalition edge case;
- CAS behavior and content integrity;
- SQLite-backed Trustee state;
- end-to-end distributed execution.

At artifact finalization, all **103 tests** passed with no failures, errors, or skipped tests.

---

## Benchmarking and Experimental Evaluation

The repository deliberately separates **local computational benchmarking** from **distributed network evaluation**.

### Local benchmark

The local benchmark runs the protocol in-process and characterizes computation without network latency.

It measures:

- Dealer setup cost per KeyID;
- local threshold signing;
- LMS verification;
- plain single-signer LMS signing and verification.

The full benchmark uses **8 warm-up iterations** and **15 measured repetitions** for each tested configuration.

Run:

```bash
mvn -pl core -DskipTests exec:java \
  -Dexec.mainClass=es.uma.nicslab.hbs.bench.Benchmark
```

For a shorter functional check:

```bash
mvn -pl core -DskipTests exec:java \
  -Dexec.mainClass=es.uma.nicslab.hbs.bench.Benchmark \
  -Dexec.args="--smoke"
```

See [`bench/README.md`](bench/README.md) for the parameter matrix, methodology, expected runtime characteristics, and historical result provenance.

### Distributed network evaluation

The network-evaluation harness under [`neteval/`](neteval/README.md) evaluates the real distributed implementation under controlled network conditions.

It supports:

- 3-, 5-, and 10-Trustee deployments;
- homogeneous baseline, 20 ms, 80 ms, and 200 ms RTT profiles;
- independent per-Trustee RTTs for heterogeneous-path experiments;
- concurrent Trustee calls inside each protocol round;
- a strict Round-1/Round-2 barrier;
- Aggregator, round, and per-RPC timing instrumentation;
- warm-up and per-profile conditioning;
- randomized block ordering;
- irreversible KeyID reservation;
- capture of setup, workload, network, raw metric, and signature artifacts;
- independent OpenSSL verification of generated signatures.

The runner uses Linux `tc`/`netem` to shape only the Aggregator–Trustee communication paths, leaving the rest of the deployment unshaped.

The complete methodology and reproduction workflow are documented in [`neteval/README.md`](neteval/README.md).

---

## Security and Implementation Notes

The implementation follows the protocol structure of the referenced Kelsey–Lang–Lucks construction. The repository is an implementation and experimental artifact; the formal security arguments for the construction itself are given in the referenced paper.

Important implementation properties include:

- **One-time KeyIDs.** A Trustee atomically claims a KeyID when Round 1 begins. A consumed KeyID is never returned to the available set.
- **Per-KeyID between-round state.** State is isolated by KeyID, allowing distinct signing attempts to progress concurrently without permitting reuse of the same KeyID.
- **Round-2 authentication.** A Trustee only releases its Round-2 share after checking that the reconstructed randomizer is consistent with the expected `AUTH` value.
- **Fixed coalition assignment.** The Coalition List determines which Trustees participate in each KeyID; the Aggregator cannot substitute an arbitrary coalition.
- **Public content integrity.** CRVs and the Coalition List are addressed by content identifiers and validated when retrieved from the CAS.
- **Dealer lifecycle.** The Dealer is required only during setup and terminates after provisioning the Trustees and publishing the public setup state.
- **No Trustee holds the complete LMS signing secret.** Each Trustee retains only its own PRF key after setup.
- **Abort on missing shares.** Failure of any Trustee required by the assigned coalition prevents completion of that signature.
- **Verifier compatibility.** The distributed protocol changes the signing procedure, not the LMS verification interface.

---

## Reference

Kelsey, J., Lang, N., & Lucks, S. (2025). *Turning Hash-Based Signatures into Distributed Signatures and Threshold Signatures: Delegate Your Signing Capability, and Distribute it Among Trustees*. **IACR Communications in Cryptology, 2**(2). https://doi.org/10.62056/a6ksudy6b