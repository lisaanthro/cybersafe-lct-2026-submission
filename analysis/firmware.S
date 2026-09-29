.syntax unified
.cpu cortex-m0plus
.thumb
.section .text,"ax",%progbits
.global firmware_start
firmware_start:
    .incbin "evidence/reproduction-final/flash.bin", 0, 0x7000
.global firmware_end
firmware_end:
