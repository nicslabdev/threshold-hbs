#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RESULTS_ROOT="${REPO_ROOT}/neteval/results"
KLL_OPENSSL_PREFIX="${KLL_OPENSSL_PREFIX:-}"

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

verify_zero_keyids() {
    [[ ! -s "$RESULT_DIR/keyids.jsonl" ]] ||
        die "KeyID ledger is not empty before signing phase"
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

print_summary() {
    echo
    echo "Experiment test complete:"
    echo "  id:      $EXPERIMENT_ID"
    echo "  results: $RESULT_DIR"
    echo
    echo "One verified warm-up signature completed."
    echo "Deployment intentionally left running."
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
        sha256sum
    do
        require_command "$cmd"
    done

    docker compose version >/dev/null 2>&1 ||
        die "Docker Compose plugin is not available"

    cd "$REPO_ROOT"

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

    sign_once \
        warmup \
        baseline \
        warmup-001 ||
        die "Automated warm-up failed"

    print_summary
}

main "$@"
