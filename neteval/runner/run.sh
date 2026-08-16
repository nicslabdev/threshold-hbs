#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RESULTS_ROOT="${REPO_ROOT}/neteval/results"
KLL_OPENSSL_PREFIX="${KLL_OPENSSL_PREFIX:-}"
NETEM_SCRIPT="${REPO_ROOT}/neteval/netem/netem.sh"
EXPERIMENT_COMPLETED=false

KLL_TRUSTEE_COUNT="${KLL_TRUSTEE_COUNT:-3}"
MAX_TRUSTEES=10

TRUSTEE_SERVICES=()
KLL_TRUSTEE_URLS=""
SETUP_CONFIG_FILE=""

PROFILES_FILE="${REPO_ROOT}/neteval/runner/profiles.json"
PROFILE_ORDER_FILE=""
KLL_PROFILE_SEED="${KLL_PROFILE_SEED:-20260816}"
MEASURED_SAMPLES_PER_PROFILE="${KLL_MEASURED_SAMPLES:-3}"

OPENSSL_BIN=""
OPENSSL_LD_LIBRARY_PATH=""

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
    KLL_METRICS_DIR="$RESULT_DIR/raw" \
    KLL_TRUSTEE_URLS="$KLL_TRUSTEE_URLS" \
    KLL_SETUP_CONFIG_PATH="$SETUP_CONFIG_FILE" \
    docker compose \
        -f "$REPO_ROOT/docker-compose.yml" \
        -f "$REPO_ROOT/docker-compose.metrics.yml" \
        "$@"
}

prepare_profile_order() {
    echo
    echo "==> Preparing randomized profile order"
    echo "    seed: $KLL_PROFILE_SEED"

    PROFILE_ORDER_FILE="$RESULT_DIR/profile-order.json"

    python3 - \
        "$PROFILES_FILE" \
        "$PROFILE_ORDER_FILE" \
        "$KLL_PROFILE_SEED" <<'PY'
import json
import random
import sys
from pathlib import Path

profiles_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
seed = int(sys.argv[3])

config = json.loads(
    profiles_path.read_text(encoding="utf-8")
)

profiles = config["profiles"]

ids = [p["profile_id"] for p in profiles]

if len(ids) != len(set(ids)):
    raise SystemExit("Duplicate profile_id in profiles.json")

rng = random.Random(seed)

order = profiles.copy()
rng.shuffle(order)

result = {
    "schema_version": 1,
    "seed": seed,
    "profiles": order,
}

output_path.write_text(
    json.dumps(result, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

print("    order:", " -> ".join(
    p["profile_id"] for p in order
))
PY
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

prepare_topology() {
    echo
    echo "==> Preparing experiment topology"

    [[ "$KLL_TRUSTEE_COUNT" =~ ^[0-9]+$ ]] ||
        die "KLL_TRUSTEE_COUNT must be an integer"

    (( KLL_TRUSTEE_COUNT >= 1 )) ||
        die "KLL_TRUSTEE_COUNT must be >= 1"

    (( KLL_TRUSTEE_COUNT <= MAX_TRUSTEES )) ||
        die \
            "KLL_TRUSTEE_COUNT=$KLL_TRUSTEE_COUNT exceeds " \
            "maximum supported topology ($MAX_TRUSTEES)"

    TRUSTEE_SERVICES=()

    local urls=()
    local i

    for ((i = 0; i < KLL_TRUSTEE_COUNT; i++)); do
        TRUSTEE_SERVICES+=("trustee-$i")
        urls+=("trustee-$i:9090")
    done

    KLL_TRUSTEE_URLS="$(
        IFS=,
        echo "${urls[*]}"
    )"

    SETUP_CONFIG_FILE="$RESULT_DIR/setup/setup-config.json"

    python3 - \
        "$REPO_ROOT/setup-config.json" \
        "$SETUP_CONFIG_FILE" \
        "$KLL_TRUSTEE_COUNT" <<'PY'
import json
import sys
from pathlib import Path

template_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
trustee_count = int(sys.argv[3])

config = json.loads(
    template_path.read_text(encoding="utf-8")
)

config["k"] = trustee_count

# Evaluation topology:
# every KeyID uses every active Trustee.
config["coalitionPattern"] = [
    list(range(trustee_count))
]

output_path.write_text(
    json.dumps(
        config,
        indent=2,
        sort_keys=True,
    ) + "\n",
    encoding="utf-8",
)
PY

    echo "    trustees:      $KLL_TRUSTEE_COUNT"
    echo "    services:      ${TRUSTEE_SERVICES[*]}"
    echo "    TRUSTEE_URLS:  $KLL_TRUSTEE_URLS"
    echo "    coalition:     [0..$((KLL_TRUSTEE_COUNT - 1))]"
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
        "${TRUSTEE_SERVICES[@]}" \
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
        "${TRUSTEE_SERVICES[@]}"

    echo
    echo "==> Waiting for Trustee gRPC readiness"

    local i

    for ((i = 0; i < KLL_TRUSTEE_COUNT; i++)); do
        wait_for_trustee \
            "trustee-$i" \
            "$i"
    done
}

archive_setup_input() {
    echo
    echo "==> Archiving setup input"

    cp \
        "$REPO_ROOT/setup-config.json" \
        "$RESULT_DIR/setup/setup-config-template.json"
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

    local config_sha_before
    local config_sha_after

    config_sha_before="$(
        sha256sum "$SETUP_CONFIG_FILE"
    )"
    config_sha_before="${config_sha_before%% *}"

    compose --profile setup \
        run --rm --no-deps dealer \
        2>&1 | tee "$RESULT_DIR/logs/dealer.log"

    config_sha_after="$(
        sha256sum "$SETUP_CONFIG_FILE"
    )"
    config_sha_after="${config_sha_after%% *}"

    [[ "$config_sha_before" == "$config_sha_after" ]] ||
        die "Generated setup configuration changed while Dealer was running"
}

archive_bulletin_board() {
    echo
    echo "==> Archiving BulletinBoard"

    compose exec -T "${TRUSTEE_SERVICES[0]}" \
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

    compose exec -T "${TRUSTEE_SERVICES[0]}" \
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
        "${TRUSTEE_SERVICES[@]}" \
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

coalition_pattern = config["coalitionPattern"]

if len(coalition_pattern) != 1:
    raise SystemExit(
        "Evaluation setup must use one full coalition"
    )

coalition_size = len(coalition_pattern[0])

expected_coalition = list(range(config["k"]))

if coalition_pattern != [expected_coalition]:
    raise SystemExit(
        f"Expected full coalition {expected_coalition}, "
        f"found {coalition_pattern}"
    )

manifest["setup"] = {
    "setup_config_sha256": config_sha256,
    "bulletin_board_sha256": board_sha256,
    "lms_public_key_sha256": public_key_sha256,
    "lms_public_key_pem_sha256": pem_sha256,
    "cl_cid": board["clCid"],
    "total_trustees": config["k"],
    "lms_params": config["lmsParams"],
    "lmots_params": config["lmotsParams"],
    "coalition_size": coalition_size,
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
    local target_rtt_ms="$2"

    local profile_dir="$RESULT_DIR/network/$profile_id"

    mkdir -p "$profile_dir"

    echo
    echo "==> Configuring network profile: $profile_id"
    echo "    configured RTT: ${target_rtt_ms} ms"

    sudo -v

    if [[ "$target_rtt_ms" == "0" ]]; then

        sudo "$NETEM_SCRIPT" reset \
            > "$profile_dir/configure.txt" 2>&1

    else

        sudo "$NETEM_SCRIPT" apply \
            "$target_rtt_ms" \
            > "$profile_dir/configure.txt" 2>&1
    fi

    sudo "$NETEM_SCRIPT" show \
        > "$profile_dir/qdisc-before.txt" 2>&1

    if [[ "$target_rtt_ms" == "0" ]]; then

        if grep -q 'qdisc netem' \
            "$profile_dir/qdisc-before.txt"
        then
            die \
                "Baseline profile unexpectedly contains " \
                "an active netem qdisc"
        fi

    else

        grep -q 'qdisc netem' \
            "$profile_dir/qdisc-before.txt" ||
            die \
                "$profile_id does not contain active " \
                "netem qdiscs"
    fi

    capture_profile_rtt \
        "$profile_id" \
        "$target_rtt_ms"
}

capture_profile_rtt() {
    local profile_id="$1"
    local target_rtt_ms="$2"

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

    for service in "${TRUSTEE_SERVICES[@]}"; do
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
                -i 0.2 \
                -W 2 \
                "$ip"

            echo
        } >> "$output"
    done

    if [[ "$target_rtt_ms" != "0" ]]; then
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
    sign_once warmup warmup warmup-001 ||
        die "warmup-001 failed"

    sign_once warmup warmup warmup-002 ||
        die "warmup-002 failed"
}

prepare_warmup_network() {
    echo
    echo "==> Preparing unshaped network for global warm-up"

    mkdir -p "$RESULT_DIR/network/warmup"

    sudo "$NETEM_SCRIPT" reset \
        > "$RESULT_DIR/network/warmup/reset.txt" 2>&1

    sudo "$NETEM_SCRIPT" show \
        > "$RESULT_DIR/network/warmup/qdisc.txt" 2>&1

    if grep -q 'qdisc netem' \
        "$RESULT_DIR/network/warmup/qdisc.txt"
    then
        die "Warm-up network unexpectedly contains netem"
    fi
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
    local run_id

    for ((i = 1; i <= MEASURED_SAMPLES_PER_PROFILE; i++)); do

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

run_profile_matrix() {
    echo
    echo "==> Running randomized network profile matrix"

    local profiles_tsv
    profiles_tsv="$RESULT_DIR/profile-order.tsv"

    python3 - \
        "$PROFILE_ORDER_FILE" \
        "$profiles_tsv" <<'PY'
import json
import sys
from pathlib import Path

config = json.load(open(sys.argv[1]))

lines = []

for profile in config["profiles"]:
    lines.append(
        f'{profile["profile_id"]}\t{profile["rtt_ms"]}'
    )

Path(sys.argv[2]).write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)
PY

    local profile_id
    local rtt_ms

    while IFS=$'\t' read -r profile_id rtt_ms; do

        configure_network_profile \
            "$profile_id" \
            "$rtt_ms"

        run_profile_samples \
            "$profile_id"

        capture_profile_final_state \
            "$profile_id"

    done < "$profiles_tsv"
}

capture_profile_final_state() {
    local profile_id="$1"

    echo
    echo "==> Capturing final network state: $profile_id"

    sudo "$NETEM_SCRIPT" show \
        > "$RESULT_DIR/network/$profile_id/qdisc-after.txt" 2>&1
}

validate_experiment_results() {
    echo
    echo "==> Validating experiment result set"

    python3 - \
        "$RESULT_DIR/keyids.jsonl" \
        "$RESULT_DIR/samples.jsonl" \
        "$RESULT_DIR/raw/aggregator.jsonl" \
        "$PROFILES_FILE" \
        "$MEASURED_SAMPLES_PER_PROFILE" \
        "$RESULT_DIR/setup/setup-config.json" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

ledger_path = Path(sys.argv[1])
samples_path = Path(sys.argv[2])
agg_path = Path(sys.argv[3])
profiles_path = Path(sys.argv[4])
measured_per_profile = int(sys.argv[5])
setup_path = Path(sys.argv[6])


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
agg = read_jsonl(agg_path)

setup = json.loads(
    setup_path.read_text(encoding="utf-8")
)

profiles_config = json.loads(
    profiles_path.read_text(encoding="utf-8")
)

trustee_count = setup["k"]

expected_coalition = list(range(trustee_count))

if setup["coalitionPattern"] != [expected_coalition]:
    raise SystemExit(
        "Unexpected experimental coalition pattern: "
        f'{setup["coalitionPattern"]}'
    )

profile_ids = [
    p["profile_id"]
    for p in profiles_config["profiles"]
]

profile_count = len(profile_ids)

expected_total = (
    2
    + profile_count
    + profile_count * measured_per_profile
)

expected_keyids = set(range(expected_total))

#
# Ledger and samples
#

if len(ledger) != expected_total:
    raise SystemExit(
        f"Expected {expected_total} reservations, "
        f"found {len(ledger)}"
    )

if len(samples) != expected_total:
    raise SystemExit(
        f"Expected {expected_total} samples, "
        f"found {len(samples)}"
    )

ids = [
    record["key_id"]
    for record in ledger
]

if ids != list(range(expected_total)):
    raise SystemExit(
        f"Unexpected KeyID sequence: {ids}"
    )

if (
    {record["run_id"] for record in ledger}
    !=
    {record["run_id"] for record in samples}
):
    raise SystemExit(
        "Ledger/sample run_id sets differ"
    )

types = Counter(
    sample["sample_type"]
    for sample in samples
)

expected_types = {
    "warmup": 2,
    "conditioning": profile_count,
    "measured": (
        profile_count * measured_per_profile
    ),
}

if dict(types) != expected_types:
    raise SystemExit(
        f"Unexpected sample counts: {dict(types)}"
    )

#
# Per-profile sample counts
#

for profile_id in profile_ids:

    conditioning = [
        sample
        for sample in samples
        if (
            sample["profile_id"] == profile_id
            and
            sample["sample_type"] == "conditioning"
        )
    ]

    measured = [
        sample
        for sample in samples
        if (
            sample["profile_id"] == profile_id
            and
            sample["sample_type"] == "measured"
        )
    ]

    if len(conditioning) != 1:
        raise SystemExit(
            f"{profile_id}: expected one "
            "conditioning sample"
        )

    if len(measured) != measured_per_profile:
        raise SystemExit(
            f"{profile_id}: expected "
            f"{measured_per_profile} measured samples, "
            f"found {len(measured)}"
        )

#
# Cryptographic validity
#

for sample in samples:

    if sample["http_status"] != 200:
        raise SystemExit(
            f"HTTP failure: {sample['run_id']}"
        )

    if not sample["http_success"]:
        raise SystemExit(
            f"HTTP success=false: "
            f"{sample['run_id']}"
        )

    if sample["verification_status"] != "success":
        raise SystemExit(
            f"Verification failure: "
            f"{sample['run_id']}"
        )

    if sample["verification_exit_code"] != 0:
        raise SystemExit(
            f"Verification rc != 0: "
            f"{sample['run_id']}"
        )

    if not sample["valid"]:
        raise SystemExit(
            f"Invalid signature: "
            f"{sample['run_id']}"
        )

#
# Aggregator metrics
#

aggregator_signs = [
    record
    for record in agg
    if record.get("event") == "aggregator_sign"
]

if len(aggregator_signs) != expected_total:
    raise SystemExit(
        f"Expected {expected_total} "
        "aggregator_sign records, "
        f"found {len(aggregator_signs)}"
    )

if {
    record["key_id"]
    for record in aggregator_signs
} != expected_keyids:
    raise SystemExit(
        "Incomplete aggregator_sign KeyID coverage"
    )

expected_trustees = set(range(trustee_count))

for record in aggregator_signs:

    if record["coalition_size"] != trustee_count:
        raise SystemExit(
            f"KeyID {record['key_id']}: "
            f"coalition_size="
            f"{record['coalition_size']}, "
            f"expected={trustee_count}"
        )

    if (
        set(record["trustee_indices"])
        != expected_trustees
    ):
        raise SystemExit(
            f"KeyID {record['key_id']}: "
            "unexpected Trustee set"
        )

events = Counter(
    record["event"]
    for record in agg
)

expected_rpc_events = (
    expected_total * trustee_count
)

if (
    events["grpc_client_round1"]
    != expected_rpc_events
):
    raise SystemExit(
        "Unexpected Round 1 RPC count: "
        f'{events["grpc_client_round1"]}, '
        f"expected {expected_rpc_events}"
    )

if (
    events["grpc_client_round2"]
    != expected_rpc_events
):
    raise SystemExit(
        "Unexpected Round 2 RPC count: "
        f'{events["grpc_client_round2"]}, '
        f"expected {expected_rpc_events}"
    )

if events["aggregator_sign"] != expected_total:
    raise SystemExit(
        "Unexpected aggregator_sign count"
    )

expected_agg_events = (
    expected_total * (2 * trustee_count + 1)
)

if len(agg) != expected_agg_events:
    raise SystemExit(
        f"Expected {expected_agg_events} "
        "Aggregator events, "
        f"found {len(agg)}"
    )

#
# Trustee metrics
#
# Full-coalition experiment:
# every Trustee participates in every signature.
#

for trustee_index in range(trustee_count):

    trustee_path = (
        agg_path.parent
        / f"trustee-{trustee_index}.jsonl"
    )

    if not trustee_path.exists():
        raise SystemExit(
            f"Missing metrics file: "
            f"{trustee_path.name}"
        )

    trustee_records = read_jsonl(
        trustee_path
    )

    trustee_events = Counter(
        record["event"]
        for record in trustee_records
    )

    if (
        trustee_events["trustee_round1"]
        != expected_total
    ):
        raise SystemExit(
            f"trustee-{trustee_index}: "
            "unexpected Round 1 count"
        )

    if (
        trustee_events["trustee_round2"]
        != expected_total
    ):
        raise SystemExit(
            f"trustee-{trustee_index}: "
            "unexpected Round 2 count"
        )

    if len(trustee_records) != 2 * expected_total:
        raise SystemExit(
            f"trustee-{trustee_index}: "
            f"expected {2 * expected_total} events, "
            f"found {len(trustee_records)}"
        )

    for event_name in (
        "trustee_round1",
        "trustee_round2",
    ):
        event_keyids = {
            record["key_id"]
            for record in trustee_records
            if record.get("event") == event_name
        }

        if event_keyids != expected_keyids:
            raise SystemExit(
                f"trustee-{trustee_index}: "
                f"incomplete KeyID coverage for "
                f"{event_name}"
            )

print("Experiment validation successful")
print(f"  trustees:       {trustee_count}")
print(f"  coalition size: {trustee_count}")
print(f"  profiles:       {profile_count}")
print(f"  reservations:   {expected_total}")
print("  warmup:         2")
print(f"  conditioning:   {profile_count}")
print(
    "  measured:       "
    f"{profile_count * measured_per_profile}"
)
print(
    f"  aggregator:     "
    f"{expected_agg_events} events"
)
print(
    f"  trustee events: "
    f"{2 * expected_total} each"
)
print(
    f"  valid:          "
    f"{expected_total}/{expected_total}"
)
PY
}

validate_key_capacity() {
    local required

    required="$(
        python3 - \
            "$PROFILES_FILE" \
            "$MEASURED_SAMPLES_PER_PROFILE" <<'PY'
import json
import sys

config = json.load(open(sys.argv[1]))
measured = int(sys.argv[2])

profiles = len(config["profiles"])

print(2 + profiles * (1 + measured))
PY
    )"

    echo
    echo "==> Checking KeyID capacity"
    echo "    available: $KEY_LIMIT"
    echo "    required:  $required"

    (( required <= KEY_LIMIT )) ||
        die \
            "Experiment requires $required KeyIDs " \
            "but LMS setup provides only $KEY_LIMIT"
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

finalize_experiment_manifest() {
    echo
    echo "==> Finalizing experiment manifest"

    python3 - \
        "$RESULT_DIR/manifest.json" \
        "$PROFILE_ORDER_FILE" \
        "$MEASURED_SAMPLES_PER_PROFILE" \
        "$(utc_now)" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
order_path = Path(sys.argv[2])
measured = int(sys.argv[3])
finished_at = sys.argv[4]

manifest = json.loads(
    manifest_path.read_text(encoding="utf-8")
)

order = json.loads(
    order_path.read_text(encoding="utf-8")
)

profiles = order["profiles"]

manifest["experiment"]["finished_at"] = finished_at
manifest["experiment"]["status"] = "completed"

manifest["execution"] = {
    "concurrency": 1,
    "warmup_samples": 2,
    "conditioning_samples_per_profile": 1,
    "measured_samples_per_profile": measured,
    "total_signing_attempts": (
        2 + len(profiles) * (1 + measured)
    ),
    "profile_order_seed": order["seed"],
    "profile_order": [
        p["profile_id"]
        for p in profiles
    ],
    "profiles": profiles,
}

manifest["deployment"]["status"] = "completed"

manifest_path.write_text(
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
    echo "Network-profile experiment complete:"
    echo "  id:            $EXPERIMENT_ID"
    echo "  results:       $RESULT_DIR"
    echo "  profiles:      4"
    echo "  trustees:      $KLL_TRUSTEE_COUNT"
    echo "  warmups:       2"
    echo "  measured/profile: $MEASURED_SAMPLES_PER_PROFILE"
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

    create_experiment "${1:-}"

    trap cleanup_on_exit EXIT INT TERM

    prepare_topology
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

    validate_key_capacity
    prepare_profile_order

    prepare_warmup_network
    warmup_system

    run_profile_matrix

    validate_experiment_results

    shutdown_deployment
    finalize_experiment_manifest

    EXPERIMENT_COMPLETED=true

    print_summary
}

main "$@"
