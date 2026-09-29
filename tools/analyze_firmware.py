#!/usr/bin/env python3
"""Extract the CyberSafe facts used in the report from a raw flash dump."""

import argparse
import hashlib
import json
from pathlib import Path


def u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little")


def u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("flash", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    flash = args.flash.read_bytes()
    if len(flash) < 0x200000:
        parser.error("expected a complete 2 MiB dump")

    pin = list(flash[0x5500:0x5504])
    branch = u16(flash, 0xC8C)
    if branch & 0xFF00 != 0xD100:
        raise SystemExit(f"unexpected instruction at 0xc8c: {branch:#06x}")
    displacement = (branch & 0xFF) << 1
    if displacement & 0x100:
        displacement -= 0x200
    branch_target = 0xC8C + 4 + displacement

    strings = {}
    for value in (
        b"POSILABS", b"PositiveLabs", b"RP2040 Flash MSC",
        b"Flash Disk", b"usb_token", b"Mar 11 2026",
    ):
        offset = flash.find(value)
        strings[value.decode()] = hex(offset) if offset >= 0 else None

    result = {
        "flash": str(args.flash.resolve()),
        "size_bytes": len(flash),
        "sha256": hashlib.sha256(flash).hexdigest(),
        "device_strings": strings,
        "pin": {
            "flash_offset": "0x5500",
            "xip_address": "0x10005500",
            "raw_hex": flash[0x5500:0x5504].hex(" "),
            "digits": pin,
            "rendered": "".join(str(x) for x in pin),
        },
        "comparison": {
            "loop_offset": "0xc82",
            "compare_offset": "0xc8a",
            "conditional_branch_offset": "0xc8c",
            "conditional_branch_raw": flash[0xC8C:0xC8E].hex(" "),
            "decoded": "BNE",
            "failure_target": hex(branch_target),
            "success_offset": "0xc9a",
            "delay_instruction_offset": "0xc8e",
            "delay_instruction_raw": flash[0xC8E:0xC90].hex(" "),
            "delay_ms_after_each_matching_digit": 50,
            "success_flag_address": "0x20002ed2",
        },
        "main_flow": {
            "password_function_offset": "0xab0",
            "call_to_password_function_offset": "0x8a6",
            "usb_initialization_continues_at": "0x8aa",
        },
        "gpio": {
            "encoder_phase_a": 29,
            "encoder_phase_b": 27,
            "encoder_button": 28,
            "code_leds": list(flash[0x5504:0x5508]),
            "digit_ring_leds": list(flash[0x5508:0x5512]),
        },
        "disk_transform": {
            "function_offset": "0x354",
            "flash_offset": "0x100000",
            "xip_address": hex(u32(flash, 0x4F8)),
            "sector_step": hex(u32(flash, 0x4F0)),
            "initial_state": hex(u32(flash, 0x4F4)),
            "block_step": hex(u32(flash, 0x530)),
            "golden_ratio": hex(u32(flash, 0x538)),
            "uses_pin_or_unique_chip_id": False,
        },
        "patch_points": [
            {
                "name": "ignore_wrong_digit",
                "offset": "0xc8c",
                "original": flash[0xC8C:0xC8E].hex(" "),
                "replacement": "00 bf",
                "replacement_instruction": "NOP",
            },
            {
                "name": "skip_password_call",
                "offset": "0x8a6",
                "original": flash[0x8A6:0x8AA].hex(" "),
                "replacement": "00 bf 00 bf",
                "replacement_instruction": "NOP; NOP",
            },
            {
                "name": "password_0000",
                "offset": "0x5500",
                "original": flash[0x5500:0x5504].hex(" "),
                "replacement": "00 00 00 00",
                "replacement_instruction": "data",
            },
            {
                "name": "return_from_password_function",
                "offset": "0xab0",
                "original": flash[0xAB0:0xAB2].hex(" "),
                "replacement": "70 47",
                "replacement_instruction": "BX LR",
            },
        ],
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.json:
        args.json.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
