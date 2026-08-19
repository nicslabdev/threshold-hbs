# Local KLL/Haystack Benchmark

This directory documents the **local, in-process benchmark** for the threshold LMS implementation.

It is intentionally separate from [`../neteval/README.md`](../neteval/README.md):

- this benchmark measures cryptographic and local protocol costs without network effects;
- `neteval/` evaluates the distributed Docker/gRPC implementation under controlled Aggregator–Trustee RTTs.

The two evaluations are complementary and should not be interpreted as measurements of the same execution environment.

---

## What the Benchmark Measures

The benchmark entry point is:

```text
es.uma.nicslab.hbs.bench.Benchmark
```

It measures three components.

### 1. Dealer setup cost per KeyID

For a small LMS tree with `h=5` (`D=32` KeyIDs), it measures the complete Dealer setup time and reports the mean cost per KeyID.

The full parameter matrix is:

```text
w ∈ {1, 2, 4, 8}
k ∈ {3, 5, 7, 10}
```

where:

- `w` is the LM-OTS Winternitz parameter;
- `k` is the coalition size.

The benchmark also reports an analytical extrapolation to larger tree heights using the measured per-KeyID cost for `w=4, k=3`.

This extrapolation assumes setup cost scales linearly with the number of LMS KeyIDs `D=2^h`; it is not a direct measurement of the larger trees.

### 2. Local threshold signing and LMS verification

For every `(w,k)` configuration, the benchmark:

1. performs local Dealer setup;
2. creates local Trustees using `InMemoryTrusteeState`;
3. executes a complete two-round threshold signing operation in-process;
4. serializes the resulting signature in RFC 8554 LMS format;
5. verifies the signature with the LMS verifier.

The local benchmark uses the sequential in-process reference signing path, `Aggregator.kkAggregatorSign(...)`, so that it characterizes local protocol/cryptographic work without network effects.

This is intentionally different from the distributed evaluation under `neteval/`, where `Aggregator.aggregatorSign(...)` issues Trustee RPCs concurrently within each round.

### 3. Plain LMS baseline

The benchmark also measures conventional single-signer LMS signing and verification with the same LMS/LM-OTS parameter choices.

This provides a non-threshold baseline for the local cryptographic measurements.

---

## Methodology

A full run uses:

```text
LMS tree height:       h = 5
Available KeyIDs:      D = 32
Winternitz parameters: w ∈ {1, 2, 4, 8}
Coalition sizes:       k ∈ {3, 5, 7, 10}
Warm-up iterations:    8
Measured repetitions:  15
```

Every threshold signing attempt uses a fresh LMS KeyID.

Reported statistics are:

- mean;
- population standard deviation.

The benchmark uses `System.nanoTime()` for elapsed-time measurement.

Absolute runtimes depend on the CPU, operating system, JVM, and system load. Reproduction should therefore focus on executing the same benchmark methodology successfully rather than expecting identical millisecond values across machines.

---

## Short Functional Check

Use `--smoke` to verify that the benchmark harness is functional without running the complete parameter matrix:

```bash
mvn -pl core -DskipTests exec:java \
  -Dexec.mainClass=es.uma.nicslab.hbs.bench.Benchmark \
  -Dexec.args="--smoke"
```

Smoke mode uses:

```text
w = 4
k = 3
warm-up iterations = 1
measured repetitions = 2
```

A successful run prints all three benchmark sections and ends with:

```text
BUILD SUCCESS
```

---

## Full Benchmark

From the repository root:

```bash
mvn -pl core -DskipTests exec:java \
  -Dexec.mainClass=es.uma.nicslab.hbs.bench.Benchmark
```

The complete run can take several minutes depending on the machine, particularly because configurations with `w=8` are substantially more expensive.

To save a local run without adding it to Git automatically:

```bash
mvn -pl core -DskipTests exec:java \
  -Dexec.mainClass=es.uma.nicslab.hbs.bench.Benchmark \
  | tee /tmp/kll-local-benchmark.txt
```

---

## Historical Paper Benchmark Output

The repository preserves the original benchmark output used during the local evaluation at:

```text
results/local-benchmark-2026-08-07.txt
```

That file is retained verbatim for provenance.

Its environment was:

```text
Date:        2026-08-07
CPU:         Intel Core i7-8665U @ 1.90 GHz
RAM:         16 GB
OS:          Microsoft Windows 11 Home
JDK:         17.0.6
Warm-up:     8
Trials:      15
```

The historical output was produced by the earlier monolithic implementation before the repository was reorganized into the current Maven multi-module distributed architecture.

The benchmark harness has been ported to the current `core` module while preserving the experimental parameter matrix and methodology. Consequently:

- the historical file should be treated as the provenance record for the paper's original local measurements;
- a current run validates the benchmark on the consolidated implementation;
- current absolute timing values should not be expected to match the historical machine exactly.

---

## Relationship to the Network Evaluation

Do not combine the absolute timings from this benchmark with the distributed RTT measurements as if they were samples from the same experiment.

### Local benchmark

```text
Execution:       in-process
Trustees:        local objects
State:           InMemoryTrusteeState
Network delay:   none
Primary purpose: cryptographic/setup cost
```

### Distributed evaluation (`neteval/`)

```text
Execution:       Docker services
Trustees:        gRPC servers
State:           SQLite
Communication:   real sockets
Network shaping: Linux tc/netem
Primary purpose: distributed latency under controlled RTT
```

The distributed Aggregator parallelizes the Trustee calls within each protocol round. The network evaluation is therefore the appropriate artifact for claims about RTT sensitivity, coalition-size behavior under network delay, and heterogeneous Trustee paths.

See [`../neteval/README.md`](../neteval/README.md) for the full network methodology and reproduction commands.