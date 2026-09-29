    .syntax unified
    .cpu cortex-m0plus
    .thumb
    .section .text,"ax",%progbits
    .global firmware_start
firmware_start:
    .incbin "/Users/ilinivan/cybersafe-report/evidence/patches/bypass-compare.bin", 0, 0x7000
