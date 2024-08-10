/* the loader must de-obfuscate the following stage while not containing any 0xFF or 0xFE bytes
 * this is why the code here looks so scuffed */
.arm

.global start
start:
ldr r0, =0x480504bc
ldr r0, [r0]
add r0, r0, #0x10000
ldr r1, =0x10000
mov r2, #0x80

sub r3, pc, #4

loop:
strb r2, [r0, r1]
subs r1, #1
movne pc, r3

inf:
sub pc, pc, #8
