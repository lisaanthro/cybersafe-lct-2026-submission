#!/usr/bin/env python3
"""Decode a raw 1 MiB CyberSafe disk region read from 0x10100000."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))
from extract_disk import SECTOR_COUNT, SECTOR_SIZE, transform_sector  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("region", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    raw = args.region.read_bytes()
    expected = SECTOR_COUNT * SECTOR_SIZE
    if len(raw) != expected:
        parser.error(f"region must be exactly {expected} bytes")
    if args.output.exists() or args.output.with_suffix(args.output.suffix + ".json").exists():
        parser.error("output already exists")

    decoded = b"".join(
        transform_sector(raw[pos:pos + SECTOR_SIZE], pos // SECTOR_SIZE)
        for pos in range(0, len(raw), SECTOR_SIZE)
    )
    args.output.write_bytes(decoded)
    record = {
        "input": str(args.region.resolve()),
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "source_address": "0x10100000",
        "size_bytes": len(raw),
        "output": str(args.output.resolve()),
        "output_sha256": hashlib.sha256(decoded).hexdigest(),
        "boot_signature_hex": decoded[510:512].hex(),
    }
    args.output.with_suffix(args.output.suffix + ".json").write_text(
        json.dumps(record, indent=2) + "\n"
    )
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
