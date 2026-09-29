#!/usr/bin/env python3
"""Create repeatable proof that the disk XOR is reversible and malleable."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))
from extract_disk import SECTOR_SIZE, transform_sector  # noqa: E402


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("encoded_region", type=Path)
    parser.add_argument("decoded_image", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    encoded = args.encoded_region.read_bytes()
    decoded = args.decoded_image.read_bytes()
    if len(encoded) != len(decoded) or len(encoded) % SECTOR_SIZE:
        parser.error("images must have equal sector-aligned sizes")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    reencoded = b"".join(
        transform_sector(decoded[pos:pos + SECTOR_SIZE], pos // SECTOR_SIZE)
        for pos in range(0, len(decoded), SECTOR_SIZE)
    )
    if reencoded != encoded:
        raise SystemExit("round-trip mismatch")

    old_label = decoded[43:54]
    new_label = b"HACKATHON  "
    changed_plain = bytearray(decoded[:SECTOR_SIZE])
    changed_plain[43:54] = new_label
    # Malleability proof: modify ciphertext directly with C' = C xor P xor P'.
    # No keystream generation is used for this step.
    changed_cipher = bytes(
        cipher ^ old ^ new
        for cipher, old, new in zip(encoded[:SECTOR_SIZE], decoded[:SECTOR_SIZE], changed_plain)
    )
    verified_plain = transform_sector(changed_cipher, 0)
    if verified_plain[43:54] != new_label:
        raise SystemExit("controlled modification failed")

    changed_path = args.output_dir / "sector0-label-modified-cipher.bin"
    changed_path.write_bytes(changed_cipher)
    known_plaintext = decoded[:32]
    keystream = bytes(a ^ b for a, b in zip(encoded[:32], known_plaintext))
    recovered_prefix = bytes(a ^ b for a, b in zip(encoded[:32], keystream))
    result = {
        "encoded_region_sha256": sha256(encoded),
        "decoded_image_sha256": sha256(decoded),
        "reencode_matches_original_ciphertext": True,
        "first_32_keystream_bytes": keystream.hex(" "),
        "known_plaintext_demo": {
            "known_plaintext_first_32_hex": known_plaintext.hex(" "),
            "recovered_keystream_first_32_hex": keystream.hex(" "),
            "ciphertext_xor_recovered_keystream_matches_32_known_bytes": recovered_prefix == known_plaintext,
            "limitation": "This recovers only positions whose plaintext is known. Full-image decoding uses the transform constants recovered from firmware.",
        },
        "full_sector_decode_with_firmware_transform_matches": transform_sector(encoded[:SECTOR_SIZE], 0) == decoded[:SECTOR_SIZE],
        "controlled_change": {
            "location": "FAT boot-sector volume label, byte offsets 43..53",
            "old_ascii": old_label.decode("ascii", "replace"),
            "new_ascii": new_label.decode("ascii"),
            "formula": "C_new = C_old XOR P_old XOR P_new",
            "keystream_generator_used_for_modification": False,
            "modified_cipher_sector": str(changed_path.resolve()),
            "modified_cipher_sha256": sha256(changed_cipher),
            "decode_gives_requested_label": True,
            "device_flash_modified": False,
        },
    }
    output = args.output_dir / "transform-proof.json"
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
