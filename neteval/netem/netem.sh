#!/usr/bin/env bash
set -euo pipefail

# KLL network emulation helper.
#
# Applies symmetric delay only between:
#
#   Aggregator <-> every currently running trustee-N service
#
# All other traffic remains in the unshaped default PRIO band.
#
# Usage:
#
#   # Same RTT for every active Trustee:
#   sudo ./neteval/netem/netem.sh apply <RTT_ms>
#
#   # One RTT per active Trustee, ordered by trustee index:
#   sudo ./neteval/netem/netem.sh apply <RTT_T0_ms> ... <RTT_TN_ms>
#
#   sudo ./neteval/netem/netem.sh show
#   sudo ./neteval/netem/netem.sh reset

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$REPO_ROOT"

TRUSTEE_SERVICES=()
TRUSTEE_IPS=()
TRUSTEE_DEVS=()

RTT_MS=()
DELAYS_MS=()

AGG_IP=""
AGG_DEV=""

die() {
    echo "ERROR: $*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || die "Run this script with sudo."

for cmd in docker tc ip nsenter awk sed grep sort; do
    command -v "$cmd" >/dev/null 2>&1 ||
        die "Required command not found: $cmd"
done

service_cid() {
    local service="$1"
    local cid

    cid="$(docker compose ps -q "$service")"

    [[ -n "$cid" ]] ||
        die "Service is not running: $service"

    echo "$cid"
}

service_pid() {
    local cid

    cid="$(service_cid "$1")"

    docker inspect \
        -f '{{.State.Pid}}' \
        "$cid"
}

service_ip() {
    local cid

    cid="$(service_cid "$1")"

    docker inspect \
        -f '{{range $name,$net := .NetworkSettings.Networks}}{{$net.IPAddress}} {{end}}' \
        "$cid" |
        awk '{print $1}'
}

host_veth() {
    local service="$1"
    local pid
    local ip
    local iface
    local peer
    local hostdev

    pid="$(service_pid "$service")"
    ip="$(service_ip "$service")"

    iface="$(
        nsenter -t "$pid" -n \
            ip -o -4 addr show |
        awk -v ip="$ip" '
            $4 ~ ("^" ip "/") {
                iface=$2
                sub(/@.*/, "", iface)
                print iface
                exit
            }
        '
    )"

    [[ -n "$iface" ]] ||
        die "Could not find container interface for $service"

    peer="$(
        nsenter -t "$pid" -n \
            ip -o link show dev "$iface" |
        sed -nE \
            's/^[0-9]+: [^@]+@if([0-9]+):.*/\1/p'
    )"

    [[ -n "$peer" ]] ||
        die "Could not find host peer ifindex for $service"

    hostdev="$(
        ip -o link show |
        awk -F': ' -v idx="$peer" '
            $1 == idx {
                split($2, a, "@")
                print a[1]
                exit
            }
        '
    )"

    [[ -n "$hostdev" ]] ||
        die \
            "Could not find host veth for $service " \
            "(ifindex $peer)"

    echo "$hostdev"
}

is_number() {
    [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

half_ms() {
    awk \
        -v rtt="$1" \
        'BEGIN { printf "%.3f", rtt / 2.0 }'
}

has_our_qdisc() {
    local dev="$1"

    tc qdisc show dev "$dev" |
        grep -qE '^qdisc prio 1: root'
}

remove_our_qdisc() {
    local dev="$1"

    if has_our_qdisc "$dev"; then
        tc qdisc del dev "$dev" root
    fi
}

assert_safe_root() {
    local dev="$1"
    local root

    root="$(
        tc qdisc show dev "$dev" |
        grep ' root ' |
        head -n1 ||
        true
    )"

    if [[ -n "$root" ]] &&
       [[ "$root" != *"qdisc noqueue"* ]] &&
       [[ "$root" != *"qdisc prio 1:"* ]]; then

        die \
            "Refusing to replace existing root qdisc " \
            "on $dev: $root"
    fi
}

discover() {
    AGG_IP="$(service_ip aggregator)"
    AGG_DEV="$(host_veth aggregator)"

    mapfile -t TRUSTEE_SERVICES < <(
        docker compose ps \
            --services \
            --status running |
        grep -E '^trustee-[0-9]+$' |
        sort -V
    )

    (( ${#TRUSTEE_SERVICES[@]} > 0 )) ||
        die "No running Trustee services found"

    TRUSTEE_IPS=()
    TRUSTEE_DEVS=()

    local service

    for service in "${TRUSTEE_SERVICES[@]}"; do

        TRUSTEE_IPS+=(
            "$(service_ip "$service")"
        )

        TRUSTEE_DEVS+=(
            "$(host_veth "$service")"
        )

    done
}

show_mapping() {
    echo "Docker network mapping:"

    printf "  %-12s %-15s %s\n" \
        "service" \
        "IP" \
        "host-veth"

    printf "  %-12s %-15s %s\n" \
        "aggregator" \
        "$AGG_IP" \
        "$AGG_DEV"

    local i

    for ((i = 0; i < ${#TRUSTEE_SERVICES[@]}; i++)); do

        printf "  %-12s %-15s %s\n" \
            "${TRUSTEE_SERVICES[$i]}" \
            "${TRUSTEE_IPS[$i]}" \
            "${TRUSTEE_DEVS[$i]}"

    done
}

install_trustee_direction() {
    local dev="$1"
    local trustee_ip="$2"
    local delay_ms="$3"

    assert_safe_root "$dev"
    remove_our_qdisc "$dev"

    # Band 0 / class 1:1:
    # default, unshaped traffic.
    #
    # Band 1 / class 1:2:
    # only Aggregator -> this Trustee.

    tc qdisc add \
        dev "$dev" \
        root \
        handle 1: \
        prio bands 2 \
        priomap \
            0 0 0 0 \
            0 0 0 0 \
            0 0 0 0 \
            0 0 0 0

    tc qdisc add \
        dev "$dev" \
        parent 1:2 \
        handle 20: \
        netem delay "${delay_ms}ms"

    tc filter add \
        dev "$dev" \
        protocol ip \
        parent 1: \
        prio 10 \
        flower skip_hw \
        src_ip "${AGG_IP}/32" \
        dst_ip "${trustee_ip}/32" \
        classid 1:2
}

install_aggregator_direction() {
    local trustee_count="${#TRUSTEE_SERVICES[@]}"

    assert_safe_root "$AGG_DEV"
    remove_our_qdisc "$AGG_DEV"

    # One default unshaped band plus
    # one shaped band per active Trustee.

    tc qdisc add \
        dev "$AGG_DEV" \
        root \
        handle 1: \
        prio bands "$((trustee_count + 1))" \
        priomap \
            0 0 0 0 \
            0 0 0 0 \
            0 0 0 0 \
            0 0 0 0

    local i
    local band_dec
    local band_hex
    local handle_hex
    local prio

    for ((i = 0; i < trustee_count; i++)); do

        # tc class IDs are hexadecimal.
        #
        # Trustee 0 -> band 1 -> class 1:2
        # Trustee 1 -> band 2 -> class 1:3
        # ...
        # Trustee 8 -> class 1:a
        # Trustee 9 -> class 1:b

        band_dec=$((i + 2))

        printf -v band_hex \
            '%x' \
            "$band_dec"

        printf -v handle_hex \
            '%x' \
            "$((0x20 + i * 0x10))"

        prio=$((10 + i))

        tc qdisc add \
            dev "$AGG_DEV" \
            parent "1:${band_hex}" \
            handle "${handle_hex}:" \
            netem delay "${DELAYS_MS[$i]}ms"

        tc filter add \
            dev "$AGG_DEV" \
            protocol ip \
            parent 1: \
            prio "$prio" \
            flower skip_hw \
            src_ip "${TRUSTEE_IPS[$i]}/32" \
            dst_ip "${AGG_IP}/32" \
            classid "1:${band_hex}"

    done
}

show_one_tc() {
    local service="$1"
    local dev="$2"

    echo
    echo "===== $service ($dev) ====="

    echo "--- qdisc ---"
    tc -s qdisc show dev "$dev"

    echo "--- filters ---"
    tc -s filter show \
        dev "$dev" \
        parent 1: \
        2>/dev/null ||
        true
}

show_tc() {
    local i

    show_one_tc \
        "aggregator" \
        "$AGG_DEV"

    for ((i = 0; i < ${#TRUSTEE_SERVICES[@]}; i++)); do

        show_one_tc \
            "${TRUSTEE_SERVICES[$i]}" \
            "${TRUSTEE_DEVS[$i]}"

    done
}

reset_all() {
    remove_our_qdisc "$AGG_DEV"

    local dev

    for dev in "${TRUSTEE_DEVS[@]}"; do
        remove_our_qdisc "$dev"
    done
}

cmd="${1:-}"

case "$cmd" in

    apply)
        (( $# >= 2 )) ||
            die \
                "Usage: $0 apply " \
                "<RTT_ms> [RTT_ms ...]"

        discover
        show_mapping

        trustee_count="${#TRUSTEE_SERVICES[@]}"

        RTT_MS=()

        # One argument:
        #
        #   apply 80
        #
        # means 80 ms RTT for every active Trustee.

        if (( $# == 2 )); then

            is_number "$2" ||
                die "Invalid RTT: $2"

            for ((i = 0; i < trustee_count; i++)); do
                RTT_MS+=("$2")
            done

        # Otherwise require exactly one RTT per active Trustee.
        #
        # Example with 3 Trustees:
        #
        #   apply 20 80 200

        elif (( $# == trustee_count + 1 )); then

            shift

            for value in "$@"; do

                is_number "$value" ||
                    die "Invalid RTT: $value"

                RTT_MS+=("$value")

            done

        else

            die \
                "Expected either one RTT or exactly " \
                "$trustee_count RTT values"

        fi

        DELAYS_MS=()

        for rtt in "${RTT_MS[@]}"; do
            DELAYS_MS+=(
                "$(half_ms "$rtt")"
            )
        done

        echo
        echo "Applying symmetric delay:"

        for ((i = 0; i < trustee_count; i++)); do

            echo \
                "  ${TRUSTEE_SERVICES[$i]}: " \
                "RTT=${RTT_MS[$i]} ms -> " \
                "${DELAYS_MS[$i]} ms each direction"

            install_trustee_direction \
                "${TRUSTEE_DEVS[$i]}" \
                "${TRUSTEE_IPS[$i]}" \
                "${DELAYS_MS[$i]}"

        done

        install_aggregator_direction

        echo
        echo "Network emulation installed."
        ;;

    show)
        discover
        show_mapping
        show_tc
        ;;

    reset)
        discover
        show_mapping
        reset_all

        echo
        echo "Network emulation removed."
        ;;

    *)
        echo "Usage:"
        echo "  $0 apply <RTT_ms> [RTT_ms ...]"
        echo "  $0 show"
        echo "  $0 reset"
        exit 1
        ;;

esac