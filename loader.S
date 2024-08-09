/* the loader must de-obfuscate the following stage while not containing any 0xFF or 0xFE bytes
 * this is why the code here looks so scuffed */
.arm

.global start
start:
    cpsid if

    /* r0 : copy dst */
    mov r0, #0x80000000
    /* r1 : src ptr */
    mov r2, pc
    bl preafter

    /* unmask payload loop */
loop:
    sub r2, pc, #4
    ldrb r3, [r1], #1

    /* if not F0, then regular write */
    cmp r3, #0xF0
    bne continue

    /* if F0, load next ch and check */
    ldrb r3, [r1], #1

    /* it's 0xF0 again meaning end of payload */
    cmp r3, #0xF0
    beq quit

    /* it's masked char, do the masking */
    eor r3, #0x10

continue:
    strb r3, [r0], #1
    mov pc, r2

quit:
    /* clean dcache */
    mov r0, #0x80000000
    add r1, r0, #0x100000

    sub r2, pc, #4
    mcr p15, 0, r0, c7, c10, 1
    add r0, r0, #32
    cmp r0, r1
    movne pc, r2

    /* invalidate icache */
    mov r0, #0
    mcr p15, 0, r0, c7, c5, 0

    /* jump to the real payload */
    mov pc, #0x80000000

preafter:
    mov r1, pc
    mov pc, r2
after:
/* following must be payload binary data, put deadbeef here and validate in python that it's there to make sure our objcopy worked ok */
    .word 0xDEADBEEF
