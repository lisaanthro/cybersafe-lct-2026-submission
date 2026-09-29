#!/usr/bin/env python3
"""Create reversible CyberSafe firmware patches and sector-sized UF2 files."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

FLASH_BASE = 0x10000000
SECTOR_SIZE = 4096
UF2_PAYLOAD = 256
UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
UF2_FLAG_FAMILY_ID = 0x00002000
RP2040_FAMILY_ID = 0xE48BFF56

PATCHES = {
    "bypass-compare": [(0xC8C, bytes.fromhex("22 d1"), bytes.fromhex("00 bf"))],
    "skip-password-call": [(0x8A6, bytes.fromhex("00 f0 03 f9"), bytes.fromhex("00 bf 00 bf"))],
    "pin-0000": [(0x5500, bytes.fromhex("08 01 07 00"), bytes.fromhex("00 00 00 00"))],
    "return-from-password": [(0xAB0, bytes.fromhex("f0 b5"), bytes.fromhex("70 47"))],
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_uf2(image: bytes, sectors: list[int]) -> bytes:
    chunks = []
    for sector in sectors:
        sector_data = image[sector:sector + SECTOR_SIZE]
        if len(sector_data) != SECTOR_SIZE:
            raise ValueError("sector outside image")
        for pos in range(0, SECTOR_SIZE, UF2_PAYLOAD):
            chunks.append((FLASH_BASE + sector + pos, sector_data[pos:pos + UF2_PAYLOAD]))
    blocks = []
    for number, (address, payload) in enumerate(chunks):
        header = struct.pack(
            "<IIIIIIII",
            UF2_MAGIC_START0,
            UF2_MAGIC_START1,
            UF2_FLAG_FAMILY_ID,
            address,
            len(payload),
            number,
            len(chunks),
            RP2040_FAMILY_ID,
        )
        blocks.append(header + payload + bytes(476 - len(payload)) + struct.pack("<I", UF2_MAGIC_END))
    return b"".join(blocks)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("flash", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    original = args.flash.read_bytes()
    if len(original) != 0x200000:
        parser.error("expected exactly 2 MiB flash")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "source": str(args.flash.resolve()),
        "source_sha256": sha256(original),
        "note": "UF2 contains every 256-byte page of each touched 4 KiB sector",
        "patches": [],
        "restore": [],
    }
    touched_all = set()
    for name, edits in PATCHES.items():
        patched = bytearray(original)
        touched = set()
        edit_records = []
        for offset, expected, replacement in edits:
            actual = bytes(patched[offset:offset + len(expected)])
            if actual != expected:
                raise SystemExit(f"{name}: unexpected bytes at {offset:#x}: {actual.hex(' ')}")
            patched[offset:offset + len(replacement)] = replacement
            sector = offset // SECTOR_SIZE * SECTOR_SIZE
            touched.add(sector)
            touched_all.add(sector)
            edit_records.append({
                "offset": hex(offset),
                "xip_address": hex(FLASH_BASE + offset),
                "original": expected.hex(" "),
                "replacement": replacement.hex(" "),
            })
        patched = bytes(patched)
        bin_path = args.output_dir / f"{name}.bin"
        uf2_path = args.output_dir / f"{name}.uf2"
        bin_path.write_bytes(patched)
        uf2 = make_uf2(patched, sorted(touched))
        uf2_path.write_bytes(uf2)
        manifest["patches"].append({
            "name": name,
            "edits": edit_records,
            "full_image": str(bin_path.resolve()),
            "full_image_sha256": sha256(patched),
            "uf2": str(uf2_path.resolve()),
            "uf2_sha256": sha256(uf2),
            "uf2_size": len(uf2),
            "touched_sectors": [hex(x) for x in sorted(touched)],
            "hardware_tested": False,
        })

    for sector in sorted(touched_all):
        restore = make_uf2(original, [sector])
        path = args.output_dir / f"restore-sector-{sector:06x}.uf2"
        path.write_bytes(restore)
        manifest["restore"].append({
            "sector": hex(sector),
            "file": str(path.resolve()),
            "sha256": sha256(restore),
            "size": len(restore),
        })

    manifest_path = args.output_dir / "patch-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(manifest, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
