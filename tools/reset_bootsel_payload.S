.syntax unified
.cpu cortex-m0plus
.thumb
.section .text,"ax",%progbits
.global payload
.thumb_func
payload:
    ldr r2, =0x18
    ldrh r2, [r2]
    ldr r0, =0x14
    ldrh r0, [r0]
    ldr r1, =0x4255
    blx r2
    mov r2, r0
    movs r0, #0
    movs r1, #0
    blx r2
1:  b 1b
    .ltorg
