#!/usr/bin/env python3
"""Restore the exact verified CyberSafe flash image over PICOBOOT and verify it."""

import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_picoboot import PicoRead  # noqa: E402


FLASH_BASE = 0x10000000
FLASH_SIZE = 0x200000
# RP2040 BOOTSEL accepts a maximum 256-byte PC_WRITE transfer.
WRITE_CHUNK = 0x100
EXPECTED_SHA256 = "640626b93d7492a6efadba09759cf349d84a45b785cd31703ad37912d6cf9eb9"


def out_command(device: PicoRead, command: int, args: bytes, data: bytes = b"") -> None:
    """Run a PICOBOOT OUT command and require a clean status response."""
    device.token += 1
    packet = struct.pack(
        "<IIBBHI16s",
        0x431FD10B,
        device.token,
        command,
        len(args),
        0,
        len(data),
        args,
    )
    device.bulk(device.ep_out, packet)
    if data:
        device.bulk(device.ep_out, data)
    device.bulk(device.ep_in, size=1, allow_short=True)
    status = C.create_string_buffer(16)
    count = device.check(
        device.u.libusb_control_transfer(
            device.h, 0xC1, 0x42, 0, device.interface, status, 16, 2000
        ),
        "command status",
    )
    if count != 16:
        raise RuntimeError("short command status")
    token, error, returned_command, active = struct.unpack_from("<IIBB", status.raw)
    if token != device.token or error or returned_command != command or active:
        raise RuntimeError(
            f"PICOBOOT status token={token} error={error} "
            f"command={returned_command:#x} active={active}"
        )


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} ORIGINAL_FLASH.bin RESULT.json")
    source = Path(sys.argv[1])
    result_path = Path(sys.argv[2])
    if result_path.exists():
        raise SystemExit("result file already exists")
    image = source.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if len(image) != FLASH_SIZE or digest != EXPECTED_SHA256:
        raise SystemExit(
            f"refusing image: size={len(image)}, sha256={digest}; "
            "expected the verified original 2 MiB image"
        )

    device = PicoRead()
    try:
        # PicoRead entered command-XIP mode for safe reads. Exit it before programming.
        device.command(6)
        for sector_offset in range(0, FLASH_SIZE, 0x1000):
            # An explicit erase also puts the external flash into a known serial-command state.
            out_command(
                device,
                0x03,
                struct.pack("<II", FLASH_BASE + sector_offset, 0x1000),
            )
            for page_offset in range(sector_offset, sector_offset + 0x1000, WRITE_CHUNK):
                block = image[page_offset:page_offset + WRITE_CHUNK]
                out_command(
                    device,
                    0x05,
                    struct.pack("<II", FLASH_BASE + page_offset, len(block)),
                    block,
                )
            if (sector_offset + 0x1000) % 0x20000 == 0:
                print(f"programmed {sector_offset + 0x1000:#x}/{FLASH_SIZE:#x}", flush=True)

        device.command(7)
        verify = device.read(FLASH_BASE, FLASH_SIZE)
        verify_digest = hashlib.sha256(verify).hexdigest()
        identical = verify == image
        if not identical:
            for i, (a, b) in enumerate(zip(image, verify)):
                if a != b:
                    raise RuntimeError(
                        f"verification mismatch at flash offset {i:#x}: expected {a:02x}, got {b:02x}"
                    )
            raise RuntimeError("verification length mismatch")
    finally:
        device.close()

    result = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "usb_vid_pid": "2e8a:0003",
        "source": str(source.resolve()),
        "size_bytes": len(image),
        "expected_sha256": digest,
        "readback_sha256": verify_digest,
        "readback_identical": identical,
        "erase_method": "PICOBOOT PC_FLASH_ERASE, 4096-byte sectors",
        "write_method": "PICOBOOT PC_WRITE, 256-byte pages",
    }
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
