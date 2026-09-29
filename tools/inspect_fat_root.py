#!/usr/bin/env python3
"""Read FAT12 boot and root metadata only. File contents are not opened."""

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    image = args.image.read_bytes()

    bps = int.from_bytes(image[11:13], "little")
    spc = image[13]
    reserved = int.from_bytes(image[14:16], "little")
    fats = image[16]
    root_entries = int.from_bytes(image[17:19], "little")
    total_sectors = int.from_bytes(image[19:21], "little")
    sectors_per_fat = int.from_bytes(image[22:24], "little")
    root_offset = (reserved + fats * sectors_per_fat) * bps

    entries = []
    for index in range(root_entries):
        item = image[root_offset + index * 32:root_offset + (index + 1) * 32]
        if item[0] == 0:
            break
        if item[0] == 0xE5 or item[11] == 0x0F:
            continue
        stem = item[:8].decode("ascii", "replace").rstrip()
        suffix = item[8:11].decode("ascii", "replace").rstrip()
        entries.append({
            "short_name": stem + (("." + suffix) if suffix else ""),
            "attributes": hex(item[11]),
            "first_cluster": int.from_bytes(item[26:28], "little"),
            "size_bytes": int.from_bytes(item[28:32], "little"),
        })

    result = {
        "image": str(args.image.resolve()),
        "oem": image[3:11].decode("ascii", "replace"),
        "filesystem_label": image[54:62].decode("ascii", "replace"),
        "boot_signature_hex": image[510:512].hex(),
        "bytes_per_sector": bps,
        "sectors_per_cluster": spc,
        "fat_count": fats,
        "total_sectors": total_sectors,
        "root_offset": hex(root_offset),
        "root_entries": entries,
        "file_contents_read": False,
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.json:
        args.json.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
