/* OFFLINE EMULATOR ONLY. This branch is never written to the MCU. */
.syntax unified
.thumb
.cpu cortex-m4
.section .text.patch,"ax",%progbits
.global motor_redirect
.thumb_func
motor_redirect:
    b.w 0x08050000
