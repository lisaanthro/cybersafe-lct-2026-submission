#!/usr/bin/env python3
"""Decode the 1 MiB CyberSafe USB disk from an RP2040 flash dump.

The implementation mirrors the sector transform in firmware at
0x10000354. It is symmetric: ciphertext XOR keystream = plaintext.
"""
import argparse
import hashlib
import json
from pathlib import Path

FLASH_DISK_OFFSET = 0x100000
SECTOR_SIZE = 512
SECTOR_COUNT = 2048
GOLDEN_RATIO = 0x9E3779B1
BLOCK_STEP = 0x41C64E6D
SECTOR_STEP = 0x38C9CDA0
INITIAL_STATE = 0x9E37A9EA
MASK = 0xFFFFFFFF


def transform_sector(data: bytes, lba: int) -> bytes:
    if len(data) != SECTOR_SIZE:
        raise ValueError("sector must be exactly 512 bytes")
    out = bytearray(data)
    state = (INITIAL_STATE + lba * SECTOR_STEP) & MASK
    for block in range(0, SECTOR_SIZE, 16):
        # Firmware emits the high byte of state + n*0x9e3779b1,
        # for n=-1..14, and advances state once per 16-byte block.
        for i, n in enumerate(range(-1, 15)):
            out[block + i] ^= ((state + n * GOLDEN_RATIO) & MASK) >> 24
        state = (state + BLOCK_STEP) & MASK
    return bytes(out)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("flash", type=Path)
    p.add_argument("output", type=Path)
    args = p.parse_args()
    if args.output.exists():
        p.error("output already exists")
    flash = args.flash.read_bytes()
    disk_size = SECTOR_SIZE * SECTOR_COUNT
    if len(flash) < FLASH_DISK_OFFSET + disk_size:
        p.error("flash dump is shorter than the encoded disk region")
    encoded = flash[FLASH_DISK_OFFSET:FLASH_DISK_OFFSET + disk_size]
    decoded = b"".join(
        transform_sector(encoded[n:n + SECTOR_SIZE], n // SECTOR_SIZE)
        for n in range(0, disk_size, SECTOR_SIZE)
    )
    args.output.write_bytes(decoded)
    evidence = {
        "input": str(args.flash.resolve()),
        "input_sha256": hashlib.sha256(flash).hexdigest(),
        "flash_offset": hex(FLASH_DISK_OFFSET),
        "sector_size": SECTOR_SIZE,
        "sector_count": SECTOR_COUNT,
        "output": str(args.output.resolve()),
        "output_sha256": hashlib.sha256(decoded).hexdigest(),
        "boot_signature_hex": decoded[510:512].hex(),
    }
    args.output.with_suffix(args.output.suffix + ".json").write_text(
        json.dumps(evidence, indent=2) + "\n"
    )
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
