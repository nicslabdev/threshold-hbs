# KLL/Haystack Network Evaluation

Experimental infrastructure for evaluating the distributed **KLL/Haystack over LMS** implementation under controlled and reproducible network conditions.

The goal of `neteval/` is to measure the behavior of the real protocol — independent containers, real sockets, and persistent state — while primarily varying:

- the number of participating Trustees;
- the RTT between the Aggregator and Trustees;
- the contribution of each protocol phase to total signing time;
- the effect of heterogeneous RTTs across Trustees.

The infrastructure supports campaigns with **3, 5, and 10 Trustees**.

---

## 1. Architecture

The deployment uses Java 17 and Docker Compose.

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

- **Dealer**: runs setup once, generates the LMS/CRV material, publishes the BulletinBoard, and distributes Trustee configuration.
- **Trustees**: maintain their secret material and the state of consumed KeyIDs.
- **Aggregator**: coordinates the two signing rounds and reconstructs the final LMS signature.
- **CAS**: stores CRVs and other public content-addressed blobs.

Generated signatures are serialized in **RFC 8554** format and independently verified with **OpenSSL 4.x with LMS support**.

---

## 2. Distributed Signing

Signing uses two Aggregator ↔ Trustee rounds.

```text
Round 1
Aggregator ──parallel──> Trustees
Aggregator <─parallel── Trustees

Round 2
Aggregator ──parallel──> Trustees
Aggregator <─parallel── Trustees
```

RPCs to Trustees are executed **in parallel within each round**, with a barrier between Round 1 and Round 2.

For a homogeneous network, the expected network contribution to signing latency is approximately:

```text
T_network ≈ 2 × RTT
```

rather than:

```text
2 × coalition_size × RTT
```

because the RPCs for all participating Trustees execute concurrently within each round.

When RTTs are heterogeneous, each round completes when its slowest participating RPC completes. As a first-order approximation, when propagation delay dominates:

```text
T_network ≈ 2 × max(RTT_i)
```

The infrastructure includes a dedicated campaign to validate this behavior experimentally.

---

## 3. Instrumentation

Instrumentation is collected at both the Aggregator and the Trustees.

Among other metrics, the Aggregator records:

- total `AggregatorSign` time;
- Coalition List / CRV retrieval time;
- Round 1 duration;
- individual duration of each Round 1 RPC;
- start and end offsets of each Round 1 RPC;
- time between rounds;
- Round 2 duration;
- individual duration of each Round 2 RPC;
- start and end offsets of each Round 2 RPC;
- reconstruction time;
- HTTP server processing time;
- serialization time;
- protobuf request/response sizes.

Each Trustee records the processing times of `ShardSign1` and `ShardSign2`.

Data is written as JSONL under:

```text
neteval/results/<experiment-id>/raw/
```

> Instrumented byte counts correspond to **serialized protobuf payloads**, not to the total number of bytes transmitted over Ethernet/TCP/HTTP2.

The instrumentation makes it possible to directly verify, among other properties:

```text
T_round ≈ max(T_RPC_i)
```

and to determine which Trustee completes last in each round.

---

## 4. Network Emulation

Network emulation is implemented in:

```text
neteval/netem/netem.sh
```

It uses Linux `tc`, `netem`, and `flower` filters on the host-side veth interfaces created by Docker.

Only the following traffic is shaped:

```text
Aggregator ↔ Trustees
```

Traffic to the CAS and the rest of the deployment network remains unshaped.

Delay is applied symmetrically:

```text
delay per direction = RTT / 2
```

The script dynamically discovers active Trustees and supports the topologies used in the evaluation.

### Homogeneous RTT

Examples:

```bash
sudo neteval/netem/netem.sh apply 80
sudo neteval/netem/netem.sh show
sudo neteval/netem/netem.sh reset
```

`apply 80` configures approximately **80 ms RTT** between the Aggregator and all active Trustees.

### Heterogeneous RTT

A different RTT can also be configured for each active Trustee.

For example, with 10 Trustees:

```bash
sudo neteval/netem/netem.sh apply \
  20 20 20 20 20 20 20 20 20 200
```

configures:

```text
trustee-0 ... trustee-8: 20 ms RTT
trustee-9:                200 ms RTT
```

Before running samples for a profile, the runner measures the actual RTT from the Aggregator network namespace and validates each Trustee independently.

---

## 5. Experiment Runner

The main runner is:

```text
neteval/runner/run.sh
```

It automates the complete experiment:

```text
fresh deployment
→ build
→ Dealer setup
→ Trustee/Aggregator startup
→ deterministic workload
→ KeyID reservation
→ warm-up
→ randomized block schedule
→ netem configuration
→ RTT validation
→ signatures
→ OpenSSL verification
→ metric collection
→ dataset validation
→ cleanup
```

### Network Profiles

The set of profiles can be selected with:

```bash
KLL_PROFILES_FILE=/path/to/profiles.json
```

The default file is:

```text
neteval/runner/profiles.json
```

and contains the homogeneous profiles used in the main campaign.

The heterogeneous profiles used in the additional validation are stored in:

```text
neteval/runner/profiles-heterogeneous.json
```

The runner accepts scalar profiles such as:

```json
{
  "profile_id": "rtt80",
  "rtt_ms": 80
}
```

or profiles with an independent RTT per Trustee:

```json
{
  "profile_id": "hetero-9x20-1x200",
  "trustee_rtt_ms": [
    20, 20, 20, 20, 20,
    20, 20, 20, 20, 200
  ]
}
```

Scalar profiles are internally normalized to one RTT value per Trustee.

### KeyID Safety

LMS is stateful: a KeyID must never be reused.

`neteval/runner/keyid.py` maintains a persistent ledger:

```text
neteval/results/<experiment-id>/keyids.jsonl
```

A KeyID is **reserved before** a signing attempt is issued. A reserved KeyID is never assigned again, even if the execution later fails.

Once Round 1 begins, the KeyID is considered permanently consumed.

---

## 6. OpenSSL

Final validation uses OpenSSL 4.x because the system OpenSSL may not include LMS support.

The runner accepts an independent installation prefix:

```bash
export KLL_OPENSSL_PREFIX="$HOME/.local/openssl-4.0.1-lms"
```

and uses:

```text
$KLL_OPENSSL_PREFIX/bin/openssl
```

together with the libraries from the same prefix.

During setup, the following files are archived:

```text
setup/lmspublickey.pem
setup/lmspublickey-openssl.txt
setup/openssl-version.txt
```

Each generated signature is validated with:

```bash
openssl pkeyutl -verify
```

Only successfully verified signatures are used in the experimental campaign.

---

## 7. Main Experimental Configuration

Parameters used in the main campaigns:

```text
LMS:                 lms_sha256_n32_h10
LMOTS:               sha256_n32_w4
KeyID space:         1024
message size:        1024 bytes
concurrency:         1

Topologies:
  3-of-3
  5-of-5
  10-of-10

Network profiles:
  baseline
  RTT 20 ms
  RTT 80 ms
  RTT 200 ms

Global warm-up:      10 signatures
Randomized blocks:   5
Measured/block:      10 per profile
Conditioning:        1 sample per profile transition
```

Within each campaign, all KeyIDs use the same full coalition of active Trustees.

Profile order is randomized independently in each block from a reproducible seed.

With this configuration, each main campaign produces:

```text
50 measured samples per profile
200 measured samples total
```

in addition to warm-up and conditioning samples.

The three main campaigns jointly produce:

```text
600 measured signatures
```

---

## 8. Running the Campaigns

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

The code must not be modified between final campaigns belonging to the same experimental series.

---

## 9. Heterogeneous RTT Campaign

The additional validation uses a fixed **10-of-10** coalition and compares three profiles:

```text
hom20:
  10 × 20 ms

hetero-9x20-1x200:
   9 × 20 ms
   1 × 200 ms

hom200:
  10 × 200 ms
```

The high-latency Trustee in the heterogeneous profile is always:

```text
trustee-9
```

The campaign uses the same block-based methodology as the main evaluation:

```text
Global warm-up:      10 signatures
Randomized blocks:   5
Profiles per block:  3
Conditioning:        1 per transition/profile
Measured/block:      10 per profile
Measured/profile:    50
Measured total:      150
```

Run with:

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

## 10. Generated Results

Each run generates:

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

Main contents:

- `manifest.json`: parameters, Git commit, experiment status, and provenance;
- `schedule.json`: randomized profile order by block and RTT configuration;
- `schedule.tsv`: tabular representation of the schedule;
- `samples.jsonl`: one record per signing attempt;
- `keyids.jsonl`: irreversible KeyID ledger;
- `raw/`: instrumented Aggregator and Trustee metrics;
- `network/`: `tc/netem` configuration, veth mappings, RTT targets, and validations;
- `signatures/`: generated LMS signatures;
- `setup/`: configuration, BulletinBoard, public key, and OpenSSL information;
- `workload/`: message used in the campaign;
- `logs/`: build, Dealer, curl, and verification logs.

Each network profile also archives:

```text
network/block-XX/<profile>/
├── configure.txt
├── qdisc-before.txt
├── qdisc-after.txt
├── rtt-targets.tsv
└── rtt.txt
```

---

## 11. Validation Performed

Before the final campaigns, the following were validated end to end:

- **3-of-3**, **5-of-5**, and **10-of-10** topologies;
- `baseline`, `RTT20`, `RTT80`, and `RTT200` profiles;
- intra-round Aggregator parallelization;
- strict barrier between Round 1 and Round 2;
- symmetric Aggregator ↔ Trustee shaping;
- homogeneous and heterogeneous RTT;
- dynamic Trustee/veth discovery;
- automatic per-Trustee RTT validation;
- irreversible KeyID reservation;
- RFC 8554 signatures;
- positive verification with OpenSSL 4;
- negative control by modifying the message;
- expected cardinality of instrumented events;
- cleanup of `netem`, containers, and volumes after each experiment;
- LMS `h=10` trees with a 1024-KeyID space;
- randomized block execution;
- archival of configuration, schedule, provenance, and metrics.

In the homogeneous campaigns, signing latency increases by approximately two additional RTTs for each RTT increment, consistent with the protocol's two sequential rounds.

The heterogeneous campaign additionally confirmed that, with nine Trustees at approximately 20 ms and one at 200 ms, the 200 ms Trustee was:

```text
Round 1:
  last RPC to complete:         50 / 50
  longest-duration RPC:        50 / 50

Round 2:
  last RPC to complete:         50 / 50
  longest-duration RPC:        50 / 50
```

Observed medians were:

```text
Aggregator signing latency:

hom20:                   95.269 ms
hetero-9x20-1x200:      447.926 ms
hom200:                 461.763 ms
```

For the heterogeneous profile:

```text
Round 1:
  median duration:              218.309 ms
  median round - RPC span:        0.195 ms

Round 2:
  median duration:              219.660 ms
  median round - RPC span:        0.246 ms
```

These results experimentally validate that, with the parallel implementation, Trustee latencies do not accumulate serially within a round. Each round completes essentially when its slowest participating RPC completes:

```text
T_round ≈ max(T_RPC_i)
```

and, when heterogeneity is dominated by propagation delay:

```text
T_network ≈ 2 × max(RTT_i)
```

for the two sequential rounds.

---

## 12. Experimental Scope

The evaluation uses independent containers and real TCP sockets, but all containers run on a single Linux host.

`tc/netem` introduces only controlled delay on:

```text
Aggregator ↔ Trustees
```

The current campaigns do not artificially introduce:

- packet loss;
- jitter;
- bandwidth limits;
- congestion;
- concurrent signing load.

They also do not attempt to reproduce every effect of a geographically distributed Internet deployment.

The purpose of the evaluation is to reproducibly isolate the implementation's sensitivity to:

- RTT;
- coalition size;
- RTT heterogeneity across Trustees;
- the temporal structure of the protocol's two rounds.

Scenarios involving bandwidth-limited shared links, packet loss, jitter, or concurrent load remain outside the scope of the current campaigns.