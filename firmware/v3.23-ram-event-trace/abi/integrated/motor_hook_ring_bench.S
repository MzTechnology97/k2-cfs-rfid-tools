/* EMULATOR ONLY. Ring logger attached to synthetic motor entry. */
.syntax unified
.thumb
.cpu cortex-m4
.section .text.hook,"ax",%progbits
.global motor_hook_entry
.thumb_func
motor_hook_entry:
  push.w {r0,r1,r2,r3,r12,lr}
  mrs r0,APSR
  push {r0,r4}
  ldr r0,[sp,#8]
  bl cfs_trace_log
  pop {r0,r4}
  msr APSR_nzcvq,r0
  pop.w {r0,r1,r2,r3,r12,lr}
  push.w {r4,r5,r6,r7,r8,lr}
  b.w 0x0801E0D0