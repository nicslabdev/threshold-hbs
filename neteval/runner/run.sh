#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RESULTS_ROOT="${REPO_ROOT}/neteval/results"
KLL_OPENSSL_PREFIX="${KLL_OPENSSL_PREFIX:-}"
NETEM_SCRIPT="${REPO_ROOT}/neteval/netem/netem.sh"
EXPERIMENT_COMPLETED=false

OPENSSL_BIN=""
OPENSSL_LD_LIBRARY_PATH=""

COMPOSE_FILES=(
    -f "${REPO_ROOT}/docker-compose.yml"
    -f "${REPO_ROOT}/docker-compose.metrics.yml"
)

RESULT_DIR=""
EXPERIMENT_ID=""
WORKLOAD_FILE=""
MESSAGE_SHA256=""
MESSAGE_BYTES=""
KEY_LIMIT=""

die() {
    echo "ERROR: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 ||
        die "Required command not found: $1"
}

utc_now() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

make_experiment_id() {
    date -u +"%Y%m%dT%H%M%SZ"
}

compose() {
    KLL_METRICS_DIR="${RESULT_DIR}/raw" \
        docker compose "${COMPOSE_FILES[@]}" "$@"
}

create_experiment() {
    EXPERIMENT_ID="${1:-$(make_experiment_id)}"

    [[ "$EXPERIMENT_ID" =~ ^[A-Za-z0-9._-]+$ ]] ||
        die "Invalid experiment ID: $EXPERIMENT_ID"

    RESULT_DIR="${RESULTS_ROOT}/${EXPERIMENT_ID}"

    [[ ! -e "$RESULT_DIR" ]] ||
        die "Experiment directory already exists: $RESULT_DIR"

    mkdir -p \
        "$RESULT_DIR/raw" \
        "$RESULT_DIR/signatures" \
        "$RESULT_DIR/network" \
        "$RESULT_DIR/setup" \
        "$RESULT_DIR/workload" \
        "$RESULT_DIR/logs"

    touch \
        "$RESULT_DIR/keyids.jsonl" \
        "$RESULT_DIR/samples.jsonl"

    local git_commit
    local git_branch
    local git_dirty

    git_commit="$(git rev-parse HEAD)"
    git_branch="$(git branch --show-current)"

    if [[ -n "$(git status --porcelain)" ]]; then
        git_dirty=true
    else
        git_dirty=false
    fi

    python3 - \
        "$RESULT_DIR/manifest.json" \
        "$EXPERIMENT_ID" \
        "$(utc_now)" \
        "$git_commit" \
        "$git_branch" \
        "$git_dirty" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])

manifest = {
    "schema_version": 1,
    "experiment": {
        "experiment_id": sys.argv[2],
        "started_at": sys.argv[3],
        "finished_at": None,
        "status": "created",
    },
    "git": {
        "commit": sys.argv[4],
        "branch": sys.argv[5],
        "dirty": sys.argv[6].lower() == "true",
    },
}

with manifest_path.open("x", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

configure_openssl() {
    [[ -n "$KLL_OPENSSL_PREFIX" ]] ||
        die "KLL_OPENSSL_PREFIX is required (OpenSSL build with LMS support)"

    KLL_OPENSSL_PREFIX="$(
        cd "$KLL_OPENSSL_PREFIX" 2>/dev/null && pwd
    )" ||
        die "Invalid KLL_OPENSSL_PREFIX: $KLL_OPENSSL_PREFIX"

    OPENSSL_BIN="${KLL_OPENSSL_PREFIX}/bin/openssl"

    [[ -x "$OPENSSL_BIN" ]] ||
        die "OpenSSL executable not found: $OPENSSL_BIN"

    local lib64="${KLL_OPENSSL_PREFIX}/lib64"
    local lib="${KLL_OPENSSL_PREFIX}/lib"

    OPENSSL_LD_LIBRARY_PATH=""

    if [[ -d "$lib64" ]]; then
        OPENSSL_LD_LIBRARY_PATH="$lib64"
    fi

    if [[ -d "$lib" ]]; then
        if [[ -n "$OPENSSL_LD_LIBRARY_PATH" ]]; then
            OPENSSL_LD_LIBRARY_PATH="${OPENSSL_LD_LIBRARY_PATH}:${lib}"
        else
            OPENSSL_LD_LIBRARY_PATH="$lib"
        fi
    fi

    [[ -n "$OPENSSL_LD_LIBRARY_PATH" ]] ||
        die "No lib/lib64 directory found under $KLL_OPENSSL_PREFIX"

    echo
    echo "==> Checking LMS-capable OpenSSL"

    env \
        LD_LIBRARY_PATH="${OPENSSL_LD_LIBRARY_PATH}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        "$OPENSSL_BIN" version -a \
        > "$RESULT_DIR/setup/openssl-version.txt"

    cat "$RESULT_DIR/setup/openssl-version.txt"
}

openssl_lms() {
    env \
        LD_LIBRARY_PATH="${OPENSSL_LD_LIBRARY_PATH}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        "$OPENSSL_BIN" "$@"
}

prepare_workload() {
    echo
    echo "==> Preparing deterministic workload"

    WORKLOAD_FILE="$RESULT_DIR/workload/message.bin"

    python3 - \
        "$WORKLOAD_FILE" \
        "$RESULT_DIR/manifest.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

message_path = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])

# Deterministic 1 KiB message:
# bytes 0x00..0xff repeated four times.
message = bytes(range(256)) * 4

assert len(message) == 1024

message_path.write_bytes(message)

sha256 = hashlib.sha256(message).hexdigest()

manifest = json.loads(
    manifest_path.read_text(encoding="utf-8")
)

manifest["workload"] = {
    "message_file": "workload/message.bin",
    "message_bytes": len(message),
    "message_sha256": sha256,
}

manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

print(len(message))
print(sha256)
PY

    local workload_info

    workload_info="$(
        python3 - "$WORKLOAD_FILE" <<'PY'
import hashlib
import sys
from pathlib import Path

data = Path(sys.argv[1]).read_bytes()

print(len(data))
print(hashlib.sha256(data).hexdigest())
PY
    )"

    MESSAGE_BYTES="$(printf '%s\n' "$workload_info" | sed -n '1p')"
    MESSAGE_SHA256="$(printf '%s\n' "$workload_info" | sed -n '2p')"

    [[ "$MESSAGE_BYTES" == "1024" ]] ||
        die "Unexpected workload size: $MESSAGE_BYTES"

    echo "    bytes:  $MESSAGE_BYTES"
    echo "    sha256: $MESSAGE_SHA256"
}

fresh_deployment() {
    echo
    echo "==> Removing previous Docker deployment and volumes"

    compose --profile setup \
        down -v --remove-orphans
}

build_artifacts() {
    echo
    echo "==> Building Java artifacts"

    mvn clean package -DskipTests \
        2>&1 | tee "$RESULT_DIR/logs/maven-build.log"

    echo
    echo "==> Building Docker images"

    compose --profile setup \
        build \
        cas \
        trustee-0 \
        trustee-1 \
        trustee-2 \
        dealer \
        aggregator \
        2>&1 | tee "$RESULT_DIR/logs/docker-build.log"
}

wait_for_trustee() {
    local service="$1"
    local index="$2"
    local marker="Trustee ${index} escuchando en puerto 9090"
    local timeout_seconds=30
    local deadline=$((SECONDS + timeout_seconds))

    while (( SECONDS < deadline )); do
        if compose logs \
            --no-color \
            --tail=100 \
            "$service" 2>&1 |
            grep -Fq "$marker"; then

            local cid
            cid="$(compose ps -q "$service")"

            [[ -n "$cid" ]] ||
                die "$service emitted readiness marker but has no container"

            [[ "$(docker inspect -f '{{.State.Running}}' "$cid")" == "true" ]] ||
                die "$service emitted readiness marker but is no longer running"

            echo "    $service ready"
            return 0
        fi

        sleep 0.2
    done

    echo
    echo "Last logs from $service:" >&2
    compose logs --no-color --tail=100 "$service" >&2 || true

    die "Timeout waiting for $service readiness"
}

start_base_services() {
    echo
    echo "==> Starting CAS and Trustees"

    compose up -d \
        cas \
        trustee-0 \
        trustee-1 \
        trustee-2

    echo
    echo "==> Waiting for Trustee gRPC readiness"

    wait_for_trustee trustee-0 0
    wait_for_trustee trustee-1 1
    wait_for_trustee trustee-2 2
}

archive_setup_input() {
    echo
    echo "==> Archiving setup input"

    cp \
        "$REPO_ROOT/setup-config.json" \
        "$RESULT_DIR/setup/setup-config.json"
}

load_key_space() {
    KEY_LIMIT="$(
        python3 - \
            "$RESULT_DIR/setup/setup-config.json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    config = json.load(f)

name = config["lmsParams"]

match = re.search(r"_h(\d+)$", name)

if match is None:
    raise SystemExit(
        f"Cannot derive LMS tree height from {name!r}"
    )

h = int(match.group(1))
D = 1 << h

print(D)
PY
    )"

    [[ "$KEY_LIMIT" =~ ^[0-9]+$ ]] ||
        die "Invalid derived KeyID limit: $KEY_LIMIT"

    (( KEY_LIMIT > 0 )) ||
        die "Invalid KeyID limit: $KEY_LIMIT"

    echo "    KeyID space: 0..$((KEY_LIMIT - 1))"
}

append_sample_record() {
    local run_id="$1"
    local profile_id="$2"
    local sample_type="$3"
    local key_id="$4"
    local started_at="$5"
    local finished_at="$6"
    local curl_rc="$7"
    local http_status="$8"
    local curl_time_total_s="$9"
    local response_bytes="${10}"
    local response_file="${11}"
    local http_success="${12}"
    local verification_status="${13}"
    local verification_rc="${14}"
    local verification_log="${15}"
    local signature_sha256="${16}"
    local valid="${17}"

    python3 - \
        "$RESULT_DIR/samples.jsonl" \
        "$EXPERIMENT_ID" \
        "$run_id" \
        "$profile_id" \
        "$sample_type" \
        "$key_id" \
        "$MESSAGE_SHA256" \
        "$MESSAGE_BYTES" \
        "$started_at" \
        "$finished_at" \
        "$curl_rc" \
        "$http_status" \
        "$curl_time_total_s" \
        "$response_bytes" \
        "$response_file" \
        "$http_success" \
        "$verification_status" \
        "$verification_rc" \
        "$verification_log" \
        "$signature_sha256" \
        "$valid" <<'PY'
import json
import os
import sys
from pathlib import Path

(
    output,
    experiment_id,
    run_id,
    profile_id,
    sample_type,
    key_id,
    message_sha256,
    message_bytes,
    started_at,
    finished_at,
    curl_rc,
    http_status,
    curl_time_total_s,
    response_bytes,
    response_file,
    http_success,
    verification_status,
    verification_rc,
    verification_log,
    signature_sha256,
    valid,
) = sys.argv[1:]

record = {
    "schema_version": 1,
    "experiment_id": experiment_id,
    "run_id": run_id,
    "profile_id": profile_id,
    "sample_type": sample_type,
    "key_id": int(key_id),
    "message_sha256": message_sha256,
    "message_bytes": int(message_bytes),
    "attempt_started_at": started_at,
    "attempt_finished_at": finished_at,
    "curl_exit_code": int(curl_rc),
    "http_status": (
        int(http_status)
        if http_status and http_status.isdigit()
        else None
    ),
    "http_success": http_success.lower() == "true",
    "curl_time_total_s": (
        float(curl_time_total_s)
        if curl_time_total_s
        else None
    ),
    "response_bytes": int(response_bytes),
    "response_file": response_file or None,
    "verification_status": verification_status,
    "verification_exit_code": (
        int(verification_rc)
        if verification_rc
        else None
    ),
    "verification_log": verification_log or None,
    "signature_sha256": signature_sha256 or None,
    "valid": valid.lower() == "true",
}

line = (
    json.dumps(
        record,
        separators=(",", ":"),
        sort_keys=True,
    )
    + "\n"
).encode("utf-8")

path = Path(output)
path.parent.mkdir(parents=True, exist_ok=True)

fd = os.open(
    path,
    os.O_WRONLY | os.O_CREAT | os.O_APPEND,
    0o644,
)

try:
    os.write(fd, line)
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

run_dealer() {
    echo
    echo "==> Running Dealer"

    compose --profile setup \
        run --rm --no-deps dealer \
        2>&1 | tee "$RESULT_DIR/logs/dealer.log"

    # The archived configuration must be exactly the one that remained
    # present in the repository while the Dealer was executing.
    cmp -s \
        "$REPO_ROOT/setup-config.json" \
        "$RESULT_DIR/setup/setup-config.json" ||
        die "setup-config.json changed while Dealer setup was running"
}

archive_bulletin_board() {
    echo
    echo "==> Archiving BulletinBoard"

    compose exec -T trustee-0 \
        cat /bulletin/board.json \
        > "$RESULT_DIR/setup/bulletin-board.json"

    [[ -s "$RESULT_DIR/setup/bulletin-board.json" ]] ||
        die "Archived BulletinBoard is empty"
}

export_public_key_pem() {
    echo
    echo "==> Exporting LMS public key for OpenSSL"

    local public_key_hex

    public_key_hex="$(
        python3 - \
            "$RESULT_DIR/setup/bulletin-board.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    board = json.load(f)

public_key = board.get("lmsPublicKey")

if not isinstance(public_key, str) or not public_key:
    raise SystemExit("BulletinBoard does not contain a valid lmsPublicKey")

print(public_key)
PY
    )"

    compose --profile setup \
        run --rm --no-deps \
        --entrypoint java \
        dealer \
        -cp /app/app.jar \
        es.uma.nicslab.hbs.util.ExportFromHex \
        "$public_key_hex" \
        /bulletin/lmspublickey.pem

    compose exec -T trustee-0 \
        cat /bulletin/lmspublickey.pem \
        > "$RESULT_DIR/setup/lmspublickey.pem"

    [[ -s "$RESULT_DIR/setup/lmspublickey.pem" ]] ||
        die "Exported LMS public key PEM is empty"

    openssl_lms pkey \
        -pubin \
        -in "$RESULT_DIR/setup/lmspublickey.pem" \
        -text \
        -noout \
        > "$RESULT_DIR/setup/lmspublickey-openssl.txt" ||
        die "Configured OpenSSL cannot parse exported LMS public key"

    (
    cd "$RESULT_DIR/setup"
        sha256sum \
            setup-config.json \
            bulletin-board.json \
            lmspublickey.pem \
            lmspublickey-openssl.txt \
            openssl-version.txt \
            > SHA256SUMS
)
}

wait_for_aggregator() {
    local timeout_seconds=30
    local deadline=$((SECONDS + timeout_seconds))
    local http_code

    while (( SECONDS < deadline )); do
        http_code="$(
            curl \
                -sS \
                --max-time 1 \
                -o /dev/null \
                -w '%{http_code}' \
                http://localhost:8081/ \
                2>/dev/null || true
        )"

        if [[ "$http_code" == "404" ]]; then
            echo "    aggregator HTTP ready"
            return 0
        fi

        sleep 0.2
    done

    compose logs --no-color --tail=100 aggregator >&2 || true
    die "Timeout waiting for Aggregator HTTP readiness"
}

start_aggregator() {
    echo
    echo "==> Starting Aggregator"

    compose up -d aggregator

    wait_for_aggregator
}

archive_deployment_snapshot() {
    echo
    echo "==> Archiving deployment snapshot"

    compose ps \
        > "$RESULT_DIR/setup/docker-compose-ps.txt"

    compose ps -q \
        cas \
        trustee-0 \
        trustee-1 \
        trustee-2 \
        aggregator \
        > "$RESULT_DIR/setup/container-ids.txt"
}

verify_zero_keyids() {
    [[ ! -s "$RESULT_DIR/keyids.jsonl" ]] ||
        die "KeyID ledger is not empty before signing phase"
}

finalize_setup_manifest() {
    python3 - \
        "$RESULT_DIR/manifest.json" \
        "$RESULT_DIR/setup/setup-config.json" \
        "$RESULT_DIR/setup/bulletin-board.json" \
        "$RESULT_DIR/setup/lmspublickey.pem" \
        "$RESULT_DIR/setup/openssl-version.txt" \
        "$KLL_OPENSSL_PREFIX" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
config_path = Path(sys.argv[2])
board_path = Path(sys.argv[3])
pem_path = Path(sys.argv[4])
openssl_version_path = Path(sys.argv[5])
openssl_prefix = sys.argv[6]

openssl_version_text = openssl_version_path.read_text(
    encoding="utf-8"
).strip()

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
config = json.loads(config_path.read_text(encoding="utf-8"))
board = json.loads(board_path.read_text(encoding="utf-8"))

config_sha256 = hashlib.sha256(config_path.read_bytes()).hexdigest()
board_sha256 = hashlib.sha256(board_path.read_bytes()).hexdigest()
pem_sha256 = hashlib.sha256(pem_path.read_bytes()).hexdigest()

public_key = bytes.fromhex(board["lmsPublicKey"])
public_key_sha256 = hashlib.sha256(public_key).hexdigest()

manifest["setup"] = {
    "setup_config_sha256": config_sha256,
    "bulletin_board_sha256": board_sha256,
    "lms_public_key_sha256": public_key_sha256,
    "lms_public_key_pem_sha256": pem_sha256,
    "cl_cid": board["clCid"],
    "total_trustees": config["k"],
    "lms_params": config["lmsParams"],
    "lmots_params": config["lmotsParams"],
    "coalition_pattern": config["coalitionPattern"],
}

manifest["deployment"] = {
    "status": "running",
    "metrics_directory": "raw",
}

manifest["experiment"]["status"] = "ready_for_signing"

manifest["software"] = {
    "openssl": {
        "prefix": openssl_prefix,
        "version_output": openssl_version_text,
    }
}

manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

configure_network_profile() {
    local profile_id="$1"

    mkdir -p "$RESULT_DIR/network/$profile_id"

    case "$profile_id" in

        baseline)
            echo
            echo "==> Configuring network profile: baseline"

            sudo -v

            sudo "$NETEM_SCRIPT" reset \
                > "$RESULT_DIR/network/baseline/reset.txt" 2>&1

            sudo "$NETEM_SCRIPT" show \
                > "$RESULT_DIR/network/baseline/qdisc-before.txt" 2>&1

            if grep -q 'qdisc netem' \
                "$RESULT_DIR/network/baseline/qdisc-before.txt"
            then
                die "Baseline unexpectedly contains an active netem qdisc"
            fi

            capture_profile_rtt \
                baseline \
                0 \
                false
            ;;

        rtt80)
            echo
            echo "==> Configuring network profile: RTT80"

            sudo -v

            sudo "$NETEM_SCRIPT" apply 80 80 80 \
                > "$RESULT_DIR/network/rtt80/apply.txt" 2>&1

            sudo "$NETEM_SCRIPT" show \
                > "$RESULT_DIR/network/rtt80/qdisc-before.txt" 2>&1

            grep -q 'qdisc netem' \
                "$RESULT_DIR/network/rtt80/qdisc-before.txt" ||
                die "RTT80 profile does not contain netem qdiscs"

            capture_profile_rtt \
                rtt80 \
                80 \
                true
            ;;

        *)
            die "Unknown network profile: $profile_id"
            ;;
    esac
}

capture_profile_rtt() {
    local profile_id="$1"
    local target_rtt_ms="$2"
    local validate="$3"

    echo
    echo "==> Capturing RTT for profile: $profile_id"

    local profile_dir="$RESULT_DIR/network/$profile_id"
    local output="$profile_dir/rtt.txt"

    mkdir -p "$profile_dir"

    local agg_cid
    local agg_pid

    agg_cid="$(compose ps -q aggregator)"

    [[ -n "$agg_cid" ]] ||
        die "Aggregator container not found"

    agg_pid="$(
        docker inspect \
            -f '{{.State.Pid}}' \
            "$agg_cid"
    )"

    [[ "$agg_pid" =~ ^[0-9]+$ ]] ||
        die "Invalid Aggregator PID: $agg_pid"

    : > "$output"

    local service
    local cid
    local ip

    for service in trustee-0 trustee-1 trustee-2; do
        cid="$(compose ps -q "$service")"

        [[ -n "$cid" ]] ||
            die "Container not found for $service"

        ip="$(
            docker inspect \
                -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
                "$cid"
        )"

        [[ -n "$ip" ]] ||
            die "Could not determine IP for $service"

        {
            echo "=== $service ($ip) ==="

            sudo nsenter \
                -t "$agg_pid" \
                -n \
                ping \
                -c 10 \
                -W 2 \
                "$ip"

            echo
        } >> "$output"
    done

    if [[ "$validate" == "true" ]]; then
        validate_rtt_profile \
            "$profile_id" \
            "$target_rtt_ms" \
            "$output"
    fi

    echo "    RTT snapshot archived"
}

validate_rtt_profile() {
    local profile_id="$1"
    local target_rtt_ms="$2"
    local rtt_file="$3"

    python3 - \
        "$profile_id" \
        "$target_rtt_ms" \
        "$rtt_file" <<'PY'
import re
import statistics
import sys
from pathlib import Path

profile_id = sys.argv[1]
target = float(sys.argv[2])
path = Path(sys.argv[3])

text = path.read_text(encoding="utf-8")

sections = re.split(
    r"^=== (trustee-\d+) \([^)]+\) ===$",
    text,
    flags=re.MULTILINE,
)

results = {}

for i in range(1, len(sections), 2):
    trustee = sections[i]
    body = sections[i + 1]

    values = [
        float(x)
        for x in re.findall(
            r"time[=<]([0-9.]+)\s*ms",
            body,
        )
    ]

    if len(values) != 10:
        raise SystemExit(
            f"{profile_id}: expected 10 RTT samples for "
            f"{trustee}, found {len(values)}"
        )

    median = statistics.median(values)
    results[trustee] = median

tolerance = max(1.0, 0.05 * target)

for trustee, median in sorted(results.items()):
    error = abs(median - target)

    print(
        f"    {trustee}: median={median:.3f} ms "
        f"target={target:.3f} ms "
        f"error={error:.3f} ms"
    )

    if error > tolerance:
        raise SystemExit(
            f"{profile_id}: RTT validation failed for {trustee}: "
            f"median={median:.3f} ms, "
            f"target={target:.3f} ms, "
            f"tolerance={tolerance:.3f} ms"
        )

print(
    f"    RTT validation passed "
    f"(tolerance ±{tolerance:.3f} ms)"
)
PY
}

warmup_system() {
    echo
    echo "==> Running global warm-up"

    sign_once \
        warmup \
        baseline \
        warmup-001 ||
        die "warmup-001 failed"

    sign_once \
        warmup \
        baseline \
        warmup-002 ||
        die "warmup-002 failed"
}

run_profile_samples() {
    local profile_id="$1"

    echo
    echo "==> Running profile block: $profile_id"

    sign_once \
        conditioning \
        "$profile_id" \
        "${profile_id}-conditioning-001" ||
        die "$profile_id conditioning failed"

    local i

    for i in 1 2 3; do
        printf -v run_id \
            '%s-measured-%03d' \
            "$profile_id" \
            "$i"

        sign_once \
            measured \
            "$profile_id" \
            "$run_id" ||
            die "$run_id failed"
    done
}

capture_profile_final_state() {
    local profile_id="$1"

    echo
    echo "==> Capturing final network state: $profile_id"

    sudo "$NETEM_SCRIPT" show \
        > "$RESULT_DIR/network/$profile_id/qdisc-after.txt" 2>&1
}

validate_er2_results() {
    echo
    echo "==> Validating ER-2 result set"

    python3 - \
        "$RESULT_DIR/keyids.jsonl" \
        "$RESULT_DIR/samples.jsonl" \
        "$RESULT_DIR/raw" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

ledger_path = Path(sys.argv[1])
samples_path = Path(sys.argv[2])
raw_dir = Path(sys.argv[3])

def read_jsonl(path):
    return [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

ledger = read_jsonl(ledger_path)
samples = read_jsonl(samples_path)

if len(ledger) != 10:
    raise SystemExit(
        f"Expected 10 reservations, found {len(ledger)}"
    )

if len(samples) != 10:
    raise SystemExit(
        f"Expected 10 samples, found {len(samples)}"
    )

ids = [r["key_id"] for r in ledger]

if ids != list(range(10)):
    raise SystemExit(
        f"Unexpected KeyID sequence: {ids}"
    )

ledger_runs = {r["run_id"] for r in ledger}
sample_runs = {r["run_id"] for r in samples}

if ledger_runs != sample_runs:
    raise SystemExit(
        "Ledger/sample run_id sets differ"
    )

type_counts = Counter(
    s["sample_type"] for s in samples
)

expected_types = {
    "warmup": 2,
    "conditioning": 2,
    "measured": 6,
}

if dict(type_counts) != expected_types:
    raise SystemExit(
        f"Unexpected sample types: {dict(type_counts)}"
    )

measured_profiles = Counter(
    s["profile_id"]
    for s in samples
    if s["sample_type"] == "measured"
)

if dict(measured_profiles) != {
    "baseline": 3,
    "rtt80": 3,
}:
    raise SystemExit(
        f"Unexpected measured profile counts: "
        f"{dict(measured_profiles)}"
    )

conditioning_profiles = Counter(
    s["profile_id"]
    for s in samples
    if s["sample_type"] == "conditioning"
)

if dict(conditioning_profiles) != {
    "baseline": 1,
    "rtt80": 1,
}:
    raise SystemExit(
        f"Unexpected conditioning counts: "
        f"{dict(conditioning_profiles)}"
    )

for s in samples:
    if s["http_status"] != 200:
        raise SystemExit(
            f"HTTP failure: {s['run_id']}"
        )

    if not s["http_success"]:
        raise SystemExit(
            f"http_success=false: {s['run_id']}"
        )

    if s["verification_status"] != "success":
        raise SystemExit(
            f"Verification failure: {s['run_id']}"
        )

    if s["verification_exit_code"] != 0:
        raise SystemExit(
            f"Verification rc != 0: {s['run_id']}"
        )

    if not s["valid"]:
        raise SystemExit(
            f"Invalid signature: {s['run_id']}"
        )

# Aggregator emits exactly:
# 2 R1 client events + 2 R2 client events +
# 1 aggregator_sign for coalition size 2.
agg = read_jsonl(raw_dir / "aggregator.jsonl")

if len(agg) != 50:
    raise SystemExit(
        f"Expected 50 Aggregator events, found {len(agg)}"
    )

aggregator_signs = [
    r for r in agg
    if r.get("event") == "aggregator_sign"
]

if len(aggregator_signs) != 10:
    raise SystemExit(
        f"Expected 10 aggregator_sign records, "
        f"found {len(aggregator_signs)}"
    )

if {
    r["key_id"] for r in aggregator_signs
} != set(range(10)):
    raise SystemExit(
        "Aggregator key_id coverage is incomplete"
    )

print("ER-2 validation successful")
print("  reservations:  10")
print("  warmup:         2")
print("  conditioning:   2")
print("  measured:       6")
print("  baseline meas.:  3")
print("  RTT80 meas.:     3")
print("  valid:          10/10")
print("  aggregator:     50 events")
PY
}

sign_once() {
    local sample_type="$1"
    local profile_id="$2"
    local run_id="$3"

    echo
    echo "==> Signing: $run_id"
    echo "    type:    $sample_type"
    echo "    profile: $profile_id"

    local key_id

    key_id="$(
        "$REPO_ROOT/neteval/runner/keyid.py" \
            --ledger "$RESULT_DIR/keyids.jsonl" \
            --limit "$KEY_LIMIT" \
            --sample-type "$sample_type" \
            --run-id "$run_id" \
            --profile-id "$profile_id"
    )"

    echo "    KeyID:   $key_id"

    # From this exact point onward the KeyID is permanently burned.

    local key_label
    printf -v key_label '%07d' "$key_id"

    local temp_response
    local signature_file
    local error_file
    local curl_log
    local verification_log

    temp_response="$RESULT_DIR/signatures/.key-${key_label}.response.tmp"
    signature_file="$RESULT_DIR/signatures/key-${key_label}.sig"
    error_file="$RESULT_DIR/signatures/key-${key_label}.error"

    curl_log="$RESULT_DIR/logs/curl-key-${key_label}.log"
    verification_log="$RESULT_DIR/logs/verify-key-${key_label}.log"

    rm -f \
        "$temp_response" \
        "$signature_file" \
        "$error_file"

    local started_at
    local finished_at

    started_at="$(
        date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
    )"

    local curl_stats=""
    local curl_rc=0

    if curl_stats="$(
        curl \
            -sS \
            --max-time 30 \
            -X POST \
            --data-binary @"$WORKLOAD_FILE" \
            -o "$temp_response" \
            -w $'%{http_code}\t%{time_total}\t%{size_download}' \
            "http://localhost:8081/sign/${key_id}" \
            2>"$curl_log"
    )"; then
        curl_rc=0
    else
        curl_rc=$?
    fi

    finished_at="$(
        date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
    )"

    local http_status=""
    local curl_time_total_s=""
    local curl_reported_bytes="0"

    IFS=$'\t' read -r \
        http_status \
        curl_time_total_s \
        curl_reported_bytes \
        <<< "$curl_stats"

    [[ "$curl_reported_bytes" =~ ^[0-9]+$ ]] ||
        curl_reported_bytes=0

    local http_success=false
    local response_file=""
    local response_bytes=0

    local verification_status="not_run"
    local verification_rc=""
    local signature_sha256=""
    local valid=false

    if [[ "$curl_rc" -eq 0 && "$http_status" == "200" ]]; then

        [[ -f "$temp_response" ]] ||
            die "HTTP 200 but response file is missing for KeyID=$key_id"

        mv "$temp_response" "$signature_file"

        response_file="signatures/$(basename "$signature_file")"
        response_bytes="$(stat -c '%s' "$signature_file")"
        http_success=true

        if [[ "$response_bytes" -ne "$curl_reported_bytes" ]]; then
            die \
                "Response size mismatch for KeyID=$key_id: " \
                "curl=$curl_reported_bytes file=$response_bytes"
        fi

        local sha_line
        sha_line="$(sha256sum "$signature_file")"
        signature_sha256="${sha_line%% *}"

        if openssl_lms pkeyutl \
            -verify \
            -in "$WORKLOAD_FILE" \
            -sigfile "$signature_file" \
            -inkey "$RESULT_DIR/setup/lmspublickey.pem" \
            -pubin \
            >"$verification_log" 2>&1
        then
            verification_rc=0
            verification_status="success"
            valid=true
        else
            verification_rc=$?
            verification_status="failure"
            valid=false
        fi

    else

        if [[ -f "$temp_response" ]]; then
            mv "$temp_response" "$error_file"
            response_file="signatures/$(basename "$error_file")"
            response_bytes="$(stat -c '%s' "$error_file")"
        fi
    fi

    append_sample_record \
        "$run_id" \
        "$profile_id" \
        "$sample_type" \
        "$key_id" \
        "$started_at" \
        "$finished_at" \
        "$curl_rc" \
        "$http_status" \
        "$curl_time_total_s" \
        "$response_bytes" \
        "$response_file" \
        "$http_success" \
        "$verification_status" \
        "$verification_rc" \
        "$(
            if [[ -f "$verification_log" ]]; then
                printf 'logs/%s' "$(basename "$verification_log")"
            fi
        )" \
        "$signature_sha256" \
        "$valid"

    echo "    curl rc:       $curl_rc"
    echo "    HTTP:          ${http_status:-none}"
    echo "    HTTP success:  $http_success"
    echo "    bytes:         $response_bytes"
    echo "    verification:  $verification_status"
    echo "    valid:         $valid"

    if [[ "$valid" != "true" ]]; then
        echo "ERROR: signing attempt $run_id was not cryptographically valid" >&2
        return 1
    fi

    return 0
}

shutdown_deployment() {
    echo
    echo "==> Resetting network emulation"

    mkdir -p "$RESULT_DIR/network"

    sudo "$NETEM_SCRIPT" reset \
        > "$RESULT_DIR/network/final-reset.txt" 2>&1 || true

    echo
    echo "==> Stopping deployment"

    compose --profile setup \
        down -v --remove-orphans
}

finalize_er2_manifest() {
    echo
    echo "==> Finalizing ER-2 manifest"

    python3 - \
        "$RESULT_DIR/manifest.json" \
        "$(utc_now)" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
finished_at = sys.argv[2]

manifest = json.loads(
    path.read_text(encoding="utf-8")
)

manifest["experiment"]["finished_at"] = finished_at
manifest["experiment"]["status"] = "completed"

manifest["execution"] = {
    "concurrency": 1,
    "total_signing_attempts": 10,
    "warmup_samples": 2,
    "profiles": [
        {
            "profile_id": "baseline",
            "configured_rtt_ms": 0,
            "conditioning_samples": 1,
            "measured_samples": 3,
        },
        {
            "profile_id": "rtt80",
            "configured_rtt_ms": 80,
            "conditioning_samples": 1,
            "measured_samples": 3,
        },
    ],
}

manifest["deployment"]["status"] = "completed"

path.write_text(
    json.dumps(
        manifest,
        indent=2,
        sort_keys=True,
    ) + "\n",
    encoding="utf-8",
)
PY
}

cleanup_on_exit() {
    local rc=$?

    if [[ "$EXPERIMENT_COMPLETED" == "true" ]]; then
        return
    fi

    echo >&2
    echo "WARNING: experiment aborted; attempting cleanup" >&2

    if [[ -n "$RESULT_DIR" ]]; then
        python3 - \
            "$RESULT_DIR/manifest.json" \
            "$(utc_now)" \
            "$rc" <<'PY' 2>/dev/null || true
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])

if not path.exists():
    raise SystemExit

manifest = json.loads(
    path.read_text(encoding="utf-8")
)

manifest["experiment"]["finished_at"] = sys.argv[2]
manifest["experiment"]["status"] = "failed"
manifest["failure_exit_code"] = int(sys.argv[3])

path.write_text(
    json.dumps(
        manifest,
        indent=2,
        sort_keys=True,
    ) + "\n",
    encoding="utf-8",
)
PY
    fi

    sudo "$NETEM_SCRIPT" reset \
        >/dev/null 2>&1 || true

    compose --profile setup \
        down -v --remove-orphans \
        >/dev/null 2>&1 || true

    return "$rc"
}

print_summary() {
    echo
    echo "ER-2 network-profile experiment complete:"
    echo "  id:            $EXPERIMENT_ID"
    echo "  results:       $RESULT_DIR"
    echo "  profiles:      baseline, rtt80"
    echo "  warmups:       2"
    echo "  conditioning:  2"
    echo "  measured:      6"
    echo "  verified:      10/10"
    echo "  status:        completed"
}

main() {
    for cmd in \
        git \
        python3 \
        date \
        docker \
        mvn \
        grep \
        curl \
        tee \
        cmp \
        sha256sum \
        sudo \
        nsenter \
        ping
    do
        require_command "$cmd"
    done

    docker compose version >/dev/null 2>&1 ||
        die "Docker Compose plugin is not available"

    cd "$REPO_ROOT"

    trap cleanup_on_exit EXIT INT TERM

    create_experiment "${1:-}"
    configure_openssl
    prepare_workload

    fresh_deployment
    build_artifacts

    start_base_services

    archive_setup_input
    load_key_space
    run_dealer
    archive_bulletin_board
    export_public_key_pem

    start_aggregator
    archive_deployment_snapshot

    verify_zero_keyids
    finalize_setup_manifest

    configure_network_profile baseline

    warmup_system
    run_profile_samples baseline
    capture_profile_final_state baseline

    configure_network_profile rtt80

    run_profile_samples rtt80
    capture_profile_final_state rtt80

    validate_er2_results

    shutdown_deployment
    finalize_er2_manifest

    EXPERIMENT_COMPLETED=true

    print_summary
}

main "$@"
