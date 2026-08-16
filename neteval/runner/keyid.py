#!/usr/bin/env python3

import argparse
import fcntl
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


VALID_SAMPLE_TYPES = {
    "warmup",
    "conditioning",
    "measured",
}


def die(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Crash-safe one-time KeyID allocator for KLL experiments."
    )

    parser.add_argument(
        "--ledger",
        required=True,
        type=Path,
        help="Append-only keyids.jsonl ledger.",
    )

    parser.add_argument(
        "--limit",
        required=True,
        type=int,
        help="Maximum number of KeyIDs D. Valid IDs are 0..D-1.",
    )

    parser.add_argument(
        "--sample-type",
        required=True,
        choices=sorted(VALID_SAMPLE_TYPES),
    )

    parser.add_argument(
        "--run-id",
        required=True,
        help="Unique runner-side identifier for this signing attempt.",
    )

    parser.add_argument(
        "--profile-id",
        required=True,
        help="Network profile associated with this attempt.",
    )

    return parser.parse_args()


def load_reserved_ids(file_obj) -> set[int]:
    file_obj.seek(0)

    reserved: set[int] = set()

    for line_number, line in enumerate(file_obj, start=1):
        line = line.strip()

        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            die(
                f"Malformed JSON in ledger at line {line_number}: "
                f"{exc.msg}"
            )

        if "key_id" not in record:
            die(f"Missing key_id in ledger at line {line_number}")

        key_id = record["key_id"]

        if not isinstance(key_id, int):
            die(f"Non-integer key_id in ledger at line {line_number}")

        if key_id < 0:
            die(f"Negative key_id in ledger at line {line_number}")

        if key_id in reserved:
            die(
                f"Duplicate key_id={key_id} already present in ledger "
                f"(line {line_number})"
            )

        reserved.add(key_id)

    return reserved


def reserve(args: argparse.Namespace) -> int:
    if args.limit <= 0:
        die("--limit must be greater than zero")

    ledger = args.ledger.resolve()
    ledger.parent.mkdir(parents=True, exist_ok=True)

    # a+ creates the file if needed and preserves all previous reservations.
    with ledger.open("a+", encoding="utf-8") as file_obj:

        # Prevent two runner processes from allocating the same KeyID.
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)

        reserved = load_reserved_ids(file_obj)

        if reserved:
            next_key_id = max(reserved) + 1
        else:
            next_key_id = 0

        if next_key_id >= args.limit:
            die(
                f"KeyID space exhausted: next={next_key_id}, "
                f"limit={args.limit}"
            )

        record = {
            "key_id": next_key_id,
            "sample_type": args.sample_type,
            "run_id": args.run_id,
            "profile_id": args.profile_id,
            "reserved_at": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
        }

        file_obj.seek(0, os.SEEK_END)
        file_obj.write(
            json.dumps(record, separators=(",", ":"), sort_keys=True)
            + "\n"
        )

        # The reservation must reach the filesystem before the KeyID
        # is returned to the caller.
        file_obj.flush()
        os.fsync(file_obj.fileno())

        return next_key_id


def main() -> None:
    args = parse_args()
    key_id = reserve(args)

    # stdout deliberately contains only the allocated integer so Bash can use:
    #
    #   key_id="$(python3 keyid.py ...)"
    #
    print(key_id)


if __name__ == "__main__":
    main()