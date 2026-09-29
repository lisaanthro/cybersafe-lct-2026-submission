#!/usr/bin/env python3
"""Issue a USB-level reset to the RP2040 BOOTSEL device."""

import ctypes as C
import ctypes.util


def main() -> None:
    path = ctypes.util.find_library("usb-1.0") or "/opt/homebrew/lib/libusb-1.0.dylib"
    usb = C.CDLL(path)
    usb.libusb_init.argtypes = [C.POINTER(C.c_void_p)]
    usb.libusb_init.restype = C.c_int
    usb.libusb_exit.argtypes = [C.c_void_p]
    usb.libusb_open_device_with_vid_pid.argtypes = [C.c_void_p, C.c_uint16, C.c_uint16]
    usb.libusb_open_device_with_vid_pid.restype = C.c_void_p
    usb.libusb_reset_device.argtypes = [C.c_void_p]
    usb.libusb_reset_device.restype = C.c_int
    usb.libusb_close.argtypes = [C.c_void_p]

    ctx = C.c_void_p()
    rc = usb.libusb_init(C.byref(ctx))
    if rc < 0:
        raise SystemExit(f"libusb_init: {rc}")
    handle = usb.libusb_open_device_with_vid_pid(ctx, 0x2E8A, 0x0003)
    if not handle:
        usb.libusb_exit(ctx)
        raise SystemExit("RP2040 BOOTSEL device not found")
    try:
        rc = usb.libusb_reset_device(handle)
        if rc < 0:
            raise SystemExit(f"libusb_reset_device: {rc}")
        print("USB reset sent to 2e8a:0003")
    finally:
        usb.libusb_close(handle)
        usb.libusb_exit(ctx)


if __name__ == "__main__":
    main()
