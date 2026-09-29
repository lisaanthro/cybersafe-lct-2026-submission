#!/usr/bin/env python3
"""Run a RAM payload that copies a flash disk sector to SRAM, then read it back."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys

TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))
from extract_disk import transform_sector  # noqa: E402
from picoboot_ram_exec_probe import execute_ram, write_ram  # noqa: E402
from read_picoboot import PicoRead  # noqa: E402

CODE_ADDRESS = 0x20020000
DESTINATION = 0x20020200
FLASH_SOURCE = 0x10100000
SECTOR_SIZE = 512

# Built from copy_sector_payload.S. It calls the ROM cache/XIP setup routines,
# copies one 512-byte sector and returns to the ROM USB loop.
PAYLOAD = bytes.fromhex(
    "70 b5 0f 4c 24 88 0f 4d 2d 88 28 46 0e 49 a0 47 "
    "80 47 28 46 0d 49 a0 47 80 47 28 46 0c 49 a0 47 "
    "80 47 28 46 0b 49 a0 47 80 47 0b 48 0b 49 0c 4a "
    "03 68 0b 60 04 30 04 31 04 3a f9 d1 70 bd 00 00 "
    "18 00 00 00 14 00 00 00 49 46 00 00 45 58 00 00 "
    "46 43 00 00 43 58 00 00 00 00 10 10 00 02 02 20 "
    "00 02 00 00"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_ram_chunks(device: PicoRead, address: int, data: bytes) -> None:
    for pos in range(0, len(data), 256):
        write_ram(device, address + pos, data[pos:pos + 256])


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT_DIR")
    output_dir = Path(sys.argv[1])
    if output_dir.exists():
        raise SystemExit("output directory exists")
    output_dir.mkdir(parents=True)

    device = PicoRead()
    original_code = b""
    original_destination = b""
    restored = False
    try:
        original_code = device.read(CODE_ADDRESS, len(PAYLOAD))
        original_destination = device.read(DESTINATION, SECTOR_SIZE)
        write_ram(device, CODE_ADDRESS, PAYLOAD)
        execute_ram(device, CODE_ADDRESS)
        # Payload leaves SSI in XIP mode. Return it to serial command mode
        # before asking PICOBOOT to read SRAM/flash again.
        device.command(6)
        copied = device.read(DESTINATION, SECTOR_SIZE)
        direct = device.read(FLASH_SOURCE, SECTOR_SIZE)
        if copied != direct:
            raise RuntimeError("RAM payload result differs from flash sector")
        decoded = transform_sector(copied, 0)
        if decoded[3:11] != b"MSDOS5.0" or decoded[510:512] != b"\x55\xaa":
            raise RuntimeError("copied sector did not decode as FAT boot sector")
        write_ram_chunks(device, CODE_ADDRESS, original_code)
        write_ram_chunks(device, DESTINATION, original_destination)
        restored = (
            device.read(CODE_ADDRESS, len(PAYLOAD)) == original_code
            and device.read(DESTINATION, SECTOR_SIZE) == original_destination
        )
        if not restored:
            raise RuntimeError("RAM restore verification failed")
    finally:
        if original_code and original_destination and not restored:
            try:
                write_ram_chunks(device, CODE_ADDRESS, original_code)
                write_ram_chunks(device, DESTINATION, original_destination)
            except Exception as exc:
                print(f"emergency RAM restore failed: {exc}", file=sys.stderr)
        device.close()

    (output_dir / "copied-encoded-sector0.bin").write_bytes(copied)
    (output_dir / "copied-decoded-sector0.bin").write_bytes(decoded)
    result = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "usb_vid_pid": "2e8a:0003",
        "payload_address": hex(CODE_ADDRESS),
        "payload_size": len(PAYLOAD),
        "payload_sha256": sha256(PAYLOAD),
        "flash_source": hex(FLASH_SOURCE),
        "sram_destination": hex(DESTINATION),
        "copied_size": len(copied),
        "copied_sector_sha256": sha256(copied),
        "copy_matches_direct_flash_read": True,
        "decoded_sector_sha256": sha256(decoded),
        "decoded_oem": decoded[3:11].decode("ascii"),
        "decoded_boot_signature_hex": decoded[510:512].hex(),
        "original_ram_restored_and_verified": restored,
        "flash_written": False,
    }
    (output_dir / "proof.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
