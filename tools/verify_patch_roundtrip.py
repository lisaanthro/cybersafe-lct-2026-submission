#!/usr/bin/env python3
"""Verify that every patch UF2 and restore UF2 reconstructs the intended sectors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1]
PATCH_DIR = ROOT / "evidence" / "patches"
FLASH_BASE = 0x10000000
SECTOR_SIZE = 4096


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_uf2(path: Path) -> dict[int, bytes]:
    raw = path.read_bytes()
    if not raw or len(raw) % 512:
        raise ValueError(f"bad UF2 size: {path}")
    chunks: dict[int, bytes] = {}
    total_expected = len(raw) // 512
    for index in range(total_expected):
        block = raw[index * 512:(index + 1) * 512]
        magic0, magic1, flags, address, size, number, total, family = struct.unpack_from("<8I", block)
        end, = struct.unpack_from("<I", block, 508)
        if (magic0, magic1, end) != (0x0A324655, 0x9E5D5157, 0x0AB16F30):
            raise ValueError(f"bad UF2 magic in {path}")
        if not flags & 0x2000 or family != 0xE48BFF56 or size != 256:
            raise ValueError(f"unexpected UF2 metadata in {path}")
        if number != index or total != total_expected or address in chunks:
            raise ValueError(f"bad UF2 numbering/address in {path}")
        chunks[address] = block[32:32 + size]
    return chunks


def reconstructed(chunks: dict[int, bytes], first: int, size: int) -> bytes:
    return b"".join(chunks[address] for address in range(first, first + size, 256))


def main() -> None:
    manifest = json.loads((PATCH_DIR / "patch-manifest.json").read_text())
    original = Path(manifest["source"]).read_bytes()
    if sha256(original) != manifest["source_sha256"]:
        raise SystemExit("source image hash mismatch")

    patch_results = []
    for item in manifest["patches"]:
        image = Path(item["full_image"]).read_bytes()
        uf2_path = Path(item["uf2"])
        chunks = parse_uf2(uf2_path)
        changed = [index for index, (before, after) in enumerate(zip(original, image)) if before != after]
        expected_changed = []
        for edit in item["edits"]:
            offset = int(edit["offset"], 16)
            before = bytes.fromhex(edit["original"])
            after = bytes.fromhex(edit["replacement"])
            if original[offset:offset + len(before)] != before or image[offset:offset + len(after)] != after:
                raise SystemExit(f"edit mismatch for {item['name']} at {offset:#x}")
            expected_changed.extend(offset + i for i, (a, b) in enumerate(zip(before, after)) if a != b)
        if changed != expected_changed:
            raise SystemExit(f"unexpected full-image differences for {item['name']}")

        sector_checks = []
        for sector_text in item["touched_sectors"]:
            sector = int(sector_text, 16)
            rebuilt = reconstructed(chunks, FLASH_BASE + sector, SECTOR_SIZE)
            expected = image[sector:sector + SECTOR_SIZE]
            sector_checks.append({
                "sector": sector_text,
                "uf2_reconstructs_patched_sector": rebuilt == expected,
                "sector_sha256": sha256(rebuilt),
            })
            if rebuilt != expected:
                raise SystemExit(f"UF2 sector mismatch for {item['name']}")
        patch_results.append({
            "name": item["name"],
            "hardware_tested": item.get("hardware_tested", False),
            "changed_byte_offsets": [hex(x) for x in changed],
            "changed_byte_count": len(changed),
            "no_other_full_image_bytes_changed": True,
            "uf2_sha256": sha256(uf2_path.read_bytes()),
            "sector_checks": sector_checks,
        })

    restore_results = []
    for item in manifest["restore"]:
        sector = int(item["sector"], 16)
        path = Path(item["file"])
        chunks = parse_uf2(path)
        rebuilt = reconstructed(chunks, FLASH_BASE + sector, SECTOR_SIZE)
        expected = original[sector:sector + SECTOR_SIZE]
        if rebuilt != expected:
            raise SystemExit(f"restore mismatch at {sector:#x}")
        restore_results.append({
            "sector": item["sector"],
            "uf2_sha256": sha256(path.read_bytes()),
            "reconstructs_original_sector": True,
            "original_sector_sha256": sha256(expected),
        })

    result = {
        "source_sha256": sha256(original),
        "patches": patch_results,
        "restore_sectors": restore_results,
        "all_checks_passed": True,
    }
    output = PATCH_DIR / "roundtrip-proof.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"output": str(output), "patches": len(patch_results), "restore_sectors": len(restore_results)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
