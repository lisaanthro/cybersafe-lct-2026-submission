.syntax unified
.cpu cortex-m0plus
.thumb
.section .text,"ax",%progbits
.global payload
.thumb_func
payload:
    push {r4, r5, r6, lr}
    ldr r4, =0x18
    ldrh r4, [r4]
    ldr r5, =0x14
    ldrh r5, [r5]

    mov r0, r5
    ldr r1, =0x4649
    blx r4
    blx r0

    mov r0, r5
    ldr r1, =0x5845
    blx r4
    blx r0

    mov r0, r5
    ldr r1, =0x4346
    blx r4
    blx r0

    mov r0, r5
    ldr r1, =0x5843
    blx r4
    blx r0

    ldr r0, =0x10100000
    ldr r1, =0x20020200
    ldr r2, =512
1:
    ldr r3, [r0]
    str r3, [r1]
    adds r0, #4
    adds r1, #4
    subs r2, #4
    bne 1b
    pop {r4, r5, r6, pc}
    .ltorg
