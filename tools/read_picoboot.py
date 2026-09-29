#!/usr/bin/env python3
"""Read an RP2040 memory range over PICOBOOT using the installed libusb.

Protocol: raspberrypi/pico-sdk, boot/picoboot.h; raspberrypi/picotool.
Does not implement flash writes, erasure, execution, or device reboot.
"""
import argparse
import ctypes as C
import ctypes.util
import hashlib
import json
from pathlib import Path
import struct
from datetime import datetime, timezone


class PicoRead:
    def __init__(self):
        library = ctypes.util.find_library("usb-1.0") or "/opt/homebrew/lib/libusb-1.0.dylib"
        self.u = C.CDLL(library)
        signatures = {
            "init": ([C.POINTER(C.c_void_p)], C.c_int),
            "exit": ([C.c_void_p], None),
            "open_device_with_vid_pid": ([C.c_void_p, C.c_uint16, C.c_uint16], C.c_void_p),
            "close": ([C.c_void_p], None),
            "claim_interface": ([C.c_void_p, C.c_int], C.c_int),
            "release_interface": ([C.c_void_p, C.c_int], C.c_int),
            "control_transfer": ([C.c_void_p, C.c_uint8, C.c_uint8, C.c_uint16, C.c_uint16, C.c_void_p, C.c_uint16, C.c_uint], C.c_int),
            "bulk_transfer": ([C.c_void_p, C.c_ubyte, C.c_void_p, C.c_int, C.POINTER(C.c_int), C.c_uint], C.c_int),
            "clear_halt": ([C.c_void_p, C.c_ubyte], C.c_int),
            "error_name": ([C.c_int], C.c_char_p),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.u, "libusb_" + name)
            fn.argtypes, fn.restype = args, result
        self.ctx = C.c_void_p()
        self.check(self.u.libusb_init(C.byref(self.ctx)), "init")
        self.h = self.u.libusb_open_device_with_vid_pid(self.ctx, 0x2e8a, 0x0003)
        if not self.h:
            self.u.libusb_exit(self.ctx)
            raise RuntimeError("RP2040 2e8a:0003 unavailable; check BOOTSEL and USB access permissions")
        self.interface = None
        self.claimed = False
        self.exclusive = False
        self.token = 0
        try:
            buf = C.create_string_buffer(512)
            n = self.u.libusb_control_transfer(self.h, 0x80, 6, 0x0200, 0, buf, len(buf), 2000)
            self.check(n, "configuration descriptor")
            desc = buf.raw[:n]
            pos, selected, endpoints = 0, False, []
            while pos + 2 <= len(desc):
                length, kind = desc[pos:pos+2]
                if length < 2 or pos + length > len(desc):
                    raise RuntimeError("Malformed USB descriptor")
                d = desc[pos:pos+length]
                if kind == 4:
                    selected = d[5] == 0xff and d[4] == 2
                    if selected:
                        self.interface = d[2]
                elif kind == 5 and selected and d[3] & 3 == 2:
                    endpoints.append(d[2])
                pos += length
            if self.interface is None or len(endpoints) != 2:
                raise RuntimeError("PICOBOOT interface not found")
            self.ep_in = next(e for e in endpoints if e & 0x80)
            self.ep_out = next(e for e in endpoints if not e & 0x80)
            self.check(self.u.libusb_claim_interface(self.h, self.interface), "claim PICOBOOT")
            self.claimed = True
            for ep in endpoints:
                self.check(self.u.libusb_clear_halt(self.h, ep), "clear endpoint halt")
            self.check(self.u.libusb_control_transfer(self.h, 0x41, 0x41, 0, self.interface, None, 0, 2000), "reset PICOBOOT protocol")
            self.command(1, b"\x01")
            self.exclusive = True
            self.command(6)
            self.command(7)
        except Exception:
            self.close()
            raise

    def check(self, result, where):
        if result < 0:
            raise RuntimeError(f"{where}: {self.u.libusb_error_name(result).decode()}")
        return result

    def bulk(self, endpoint, data=None, size=0, allow_short=False):
        buf = C.create_string_buffer(data, len(data)) if data is not None else C.create_string_buffer(max(size, 1))
        length = len(data) if data is not None else size
        done = C.c_int()
        self.check(self.u.libusb_bulk_transfer(self.h, endpoint, buf, length, C.byref(done), 10000), f"endpoint {endpoint:#x}")
        if not allow_short and done.value != length:
            raise RuntimeError(f"Short transfer: {done.value}/{length}")
        return buf.raw[:done.value]

    def command(self, cmd, args=b"", size=0):
        if cmd not in (1, 6, 7, 0x84):
            raise ValueError("This tool only supports reading and flash read-mode setup")
        self.token += 1
        packet = struct.pack("<IIBBHI16s", 0x431fd10b, self.token, cmd, len(args), 0, size, args)
        self.bulk(self.ep_out, packet)
        result = self.bulk(self.ep_in, size=size) if size else b""
        if cmd & 0x80:
            self.bulk(self.ep_out, b"\x00")
        else:
            self.bulk(self.ep_in, size=1, allow_short=True)
        status = C.create_string_buffer(16)
        n = self.check(self.u.libusb_control_transfer(self.h, 0xc1, 0x42, 0, self.interface, status, 16, 2000), "command status")
        if n != 16:
            raise RuntimeError("Short command status")
        token, error, command, active = struct.unpack_from("<IIBB", status.raw)
        if token != self.token or error or command != cmd or active:
            raise RuntimeError(f"PICOBOOT status token={token} error={error} command={command:#x} active={active}")
        return result

    def read(self, address, size):
        chunks = []
        for offset in range(0, size, 65536):
            count = min(65536, size-offset)
            chunks.append(self.command(0x84, struct.pack("<II", address+offset, count), count))
        return b"".join(chunks)

    def close(self):
        if self.exclusive:
            try:
                self.command(1, b"\x00")
            except Exception as exc:
                print("Release exclusive access:", exc)
            self.exclusive = False
        if self.claimed:
            self.u.libusb_release_interface(self.h, self.interface)
            self.claimed = False
        if self.h:
            self.u.libusb_close(self.h)
            self.h = None
        if self.ctx:
            self.u.libusb_exit(self.ctx)
            self.ctx = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--address", type=lambda v: int(v, 0), default=0x10000000)
    parser.add_argument("--size", type=lambda v: int(v, 0), default=0x10000)
    parser.add_argument("--verify", action="store_true", help="Read twice and compare")
    args = parser.parse_args()
    if args.size <= 0 or args.size % 4 or args.address % 4:
        parser.error("address and size must be aligned to four bytes")
    if not (0x10000000 <= args.address < args.address+args.size <= 0x11000000 or 0x20000000 <= args.address < args.address+args.size <= 0x20042000):
        parser.error("Only the RP2040 flash window or SRAM can be read")
    if args.output.exists() or args.output.with_suffix(args.output.suffix+".json").exists():
        parser.error("Output already exists; choose a new filename")
    device = PicoRead()
    try:
        print(f"PICOBOOT interface={device.interface} IN={device.ep_in:#x} OUT={device.ep_out:#x}", flush=True)
        first = device.read(args.address, args.size)
        if args.verify and device.read(args.address, args.size) != first:
            raise RuntimeError("Independent reads differ")
    finally:
        device.close()
    args.output.write_bytes(first)
    record = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "usb_vid_pid": "2e8a:0003", "address": hex(args.address),
        "size_bytes": len(first), "sha256": hashlib.sha256(first).hexdigest(),
        "two_reads_identical": bool(args.verify), "pin_entered": False,
        "flash_written": False, "path": str(args.output.resolve()),
    }
    args.output.with_suffix(args.output.suffix+".json").write_text(json.dumps(record, indent=2)+"\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
