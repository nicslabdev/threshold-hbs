#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RESULTS_ROOT="${REPO_ROOT}/neteval/results"

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

main() {
    require_command git
    require_command python3
    require_command date

    cd "$REPO_ROOT"

    local experiment_id
    experiment_id="${1:-$(make_experiment_id)}"

    [[ "$experiment_id" =~ ^[A-Za-z0-9._-]+$ ]] ||
        die "Invalid experiment ID: $experiment_id"

    local result_dir="${RESULTS_ROOT}/${experiment_id}"

    [[ ! -e "$result_dir" ]] ||
        die "Experiment directory already exists: $result_dir"

    mkdir -p \
        "$result_dir/raw" \
        "$result_dir/signatures" \
        "$result_dir/network" \
        "$result_dir/setup" \
        "$result_dir/workload" \
        "$result_dir/logs"

    touch "$result_dir/keyids.jsonl"

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
        "$result_dir/manifest.json" \
        "$experiment_id" \
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

    echo "Experiment created:"
    echo "  id:      $experiment_id"
    echo "  results: $result_dir"
    echo
    echo "No deployment or signing actions were executed."
}

main "$@"
