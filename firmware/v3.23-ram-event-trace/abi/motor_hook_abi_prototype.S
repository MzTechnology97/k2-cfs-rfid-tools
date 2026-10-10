/* OFFLINE EMULATOR ONLY. No permission to patch a live CFS. */
.syntax unified
.thumb
.cpu cortex-m4
.section .text.hook,"ax",%progbits
.global motor_hook_entry
.thumb_func
motor_hook_entry:
    /* Preserve caller-clobbered registers and LR. */
    push.w {r0, r1, r2, r3, r12, lr}
    mrs r0, APSR
    push {r0, r4}
    ldr r0, [sp, #8]    /* Saved original incoming R0 */
    bl cfs_trace_mock
    pop {r0, r4}
    msr APSR_nzcvq, r0
    pop.w {r0, r1, r2, r3, r12, lr}
    /* Replay precisely the overwritten original 4 bytes. */
    push.w {r4, r5, r6, r7, r8, lr}
    b.w 0x0801E0D0      /* Original function continuation */
.thumb_func
cfs_trace_mock:
    /* Synthetic clobbering callback, NOT an actual ring logger. */
    movs r0, #0x77
    movs r1, #0x55
    movs r2, #0x33
    movs r3, #0x11
    mov.w r12, #0x99
    bx lr
