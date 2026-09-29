#!/usr/bin/env python3
"""Validate UF2 blocks and print the address range reconstructed from them."""

import argparse
import hashlib
import json
from pathlib import Path
import struct


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    args = parser.parse_args()
    raw = args.uf2.read_bytes()
    if not raw or len(raw) % 512:
        parser.error("invalid UF2 length")
    items = []
    declared = None
    for offset in range(0, len(raw), 512):
        block = raw[offset:offset + 512]
        fields = struct.unpack_from("<IIIIIIII", block)
        m0, m1, flags, address, size, number, total, family = fields
        end = struct.unpack_from("<I", block, 508)[0]
        if (m0, m1, end) != (0x0A324655, 0x9E5D5157, 0x0AB16F30):
            raise SystemExit(f"bad magic in block {offset // 512}")
        if size > 476 or number != offset // 512:
            raise SystemExit(f"bad block fields in block {offset // 512}")
        declared = total if declared is None else declared
        if total != declared:
            raise SystemExit("inconsistent total block count")
        items.append((address, block[32:32 + size], flags, family))
    if declared != len(items):
        raise SystemExit("declared block count does not match file")
    result = {
        "file": str(args.uf2.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "valid": True,
        "block_count": len(items),
        "first_address": hex(min(x[0] for x in items)),
        "last_address_exclusive": hex(max(x[0] + len(x[1]) for x in items)),
        "family_id": hex(items[0][3]),
        "payload_bytes": sum(len(x[1]) for x in items),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
