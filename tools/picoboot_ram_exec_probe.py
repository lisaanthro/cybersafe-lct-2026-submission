#!/usr/bin/env python3
"""Prove unauthenticated PICOBOOT RAM write and execution, then restore RAM."""

import ctypes as C
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_picoboot import PicoRead  # noqa: E402

CODE_ADDRESS = 0x20020000
MARKER_ADDRESS = 0x20020100
MARKER = 0xC0DEC0DE

# Thumb, Cortex-M0+:
#   ldr r0, [pc, #4]   ; address literal at +8
#   ldr r1, [pc, #8]   ; marker literal at +12
#   str r1, [r0]
#   bx  lr
#   .word MARKER_ADDRESS
#   .word MARKER
PAYLOAD = bytes.fromhex("01 48 02 49 01 60 70 47") + struct.pack("<II", MARKER_ADDRESS, MARKER)


def out_command(device: PicoRead, command: int, args: bytes, data: bytes = b"") -> None:
    if command not in (0x05, 0x08):
        raise ValueError("probe only allows PC_WRITE and PC_EXEC")
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


def write_ram(device: PicoRead, address: int, data: bytes) -> None:
    if not data or len(data) > 256:
        raise ValueError("RAM write must contain 1..256 bytes")
    if not (0x20000000 <= address < address + len(data) <= 0x20042000):
        raise ValueError("probe refuses writes outside RP2040 SRAM")
    out_command(device, 0x05, struct.pack("<II", address, len(data)), data)


def execute_ram(device: PicoRead, address: int) -> None:
    if not (0x20000000 <= address < 0x20042000):
        raise ValueError("probe refuses execution outside RP2040 SRAM")
    out_command(device, 0x08, struct.pack("<I", address))


def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) == 2 else Path("ram-exec-proof.json")
    if output.exists():
        raise SystemExit("output exists")
    device = PicoRead()
    original_code = b""
    original_marker = b""
    restored = False
    try:
        original_code = device.read(CODE_ADDRESS, len(PAYLOAD))
        original_marker = device.read(MARKER_ADDRESS, 4)
        write_ram(device, MARKER_ADDRESS, bytes(4))
        write_ram(device, CODE_ADDRESS, PAYLOAD)
        execute_ram(device, CODE_ADDRESS)
        after = device.read(MARKER_ADDRESS, 4)
        if after != struct.pack("<I", MARKER):
            raise RuntimeError(f"payload marker mismatch: {after.hex()}")
        write_ram(device, CODE_ADDRESS, original_code)
        write_ram(device, MARKER_ADDRESS, original_marker)
        restored = (
            device.read(CODE_ADDRESS, len(PAYLOAD)) == original_code
            and device.read(MARKER_ADDRESS, 4) == original_marker
        )
        if not restored:
            raise RuntimeError("RAM restore verification failed")
    finally:
        if original_code and original_marker and not restored:
            try:
                write_ram(device, CODE_ADDRESS, original_code)
                write_ram(device, MARKER_ADDRESS, original_marker)
            except Exception as exc:
                print(f"emergency RAM restore failed: {exc}", file=sys.stderr)
        device.close()

    result = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "usb_vid_pid": "2e8a:0003",
        "code_address": hex(CODE_ADDRESS),
        "marker_address": hex(MARKER_ADDRESS),
        "payload_hex": PAYLOAD.hex(" "),
        "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
        "marker_after_exec": hex(MARKER),
        "pc_write_worked": True,
        "pc_exec_worked": True,
        "payload_returned_to_usb_bootloader": True,
        "original_ram_restored_and_verified": restored,
        "flash_written": False,
    }
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
