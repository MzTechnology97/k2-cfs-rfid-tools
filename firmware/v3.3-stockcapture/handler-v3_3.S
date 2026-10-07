.syntax unified
.thumb
.cpu cortex-m3

.equ SEND_RESPONSE,      0x0801BAF2
.equ LEGACY_AUTH_READ,   0x0801A39E
.equ ALT_AUTH_READ,      0x08022082
.equ STOCK_51,           0x0801C704
.equ STOCK_INVALID,      0x0801C7F8
.equ STOCK_DONE,         0x0801C808
.equ STOCK_STATE,        0x200001F0
.equ BLOCK_TABLE,        0x200001F8
.equ HW_FLAG,            0x20000000
.equ INTERNAL_RECORD,    0x20004460
.equ RECORD_SIZE,        76
.equ OVERRIDE_MAGIC,     0x324F324B  @ "K2O2"
.equ NEIGH_MAGIC,        0x324E324B  @ "K2N2"
.equ CAP1_MAGIC,         0x3343324B  @ "K2C3"
.equ CAP2_MAGIC,         0x3344324B  @ "K2D3"

@ API7
@ 0 INFO
@ 5 STOCK_STATE
@ 6 INTERNAL_RECORD_76
@ 7 ARM_KEYS3: reader,slot,key0[6],key1[6],key2[6]
@ 8 CLEAR_KEYS: reader,slot
@ 9 RUNTIME_INFO: hw_flag, legacy_block0, legacy_block1, legacy_block2
@
@ No RFID operation is started from opcode 0x57. The six patched stock read
@ callsites remain inside Creality's original RFID worker/task:
@   legacy: 0x0801A4CC, 0x0801A52C, 0x0801A590 -> LEGACY_AUTH_READ
@   secure: 0x080225D0, 0x08022604, 0x08022638 -> ALT_AUTH_READ
@
@ Scratch (only while an override is armed):
@   target: bytes 4..19 = marker/masks/key0
@   next:   bytes 4..19 = key1/key2/marker
@   next+2: bytes 4..7 CAP1_MAGIC, 8..19 Bambu block4[0..11]
@   next+3: bytes 4..7 CAP2_MAGIC, 8..11 block4[12..15],
@           12..15 block5[0..3] (RGBA)
@ Stock data fields at 20..75 are never modified by the override/capture path.

.section .text.handler,"ax",%progbits
.global handler_start
.global legacy_read0_wrapper
.global legacy_read1_wrapper
.global legacy_read2_wrapper
.global alt_read_wrapper
.type handler_start,%function
.thumb_func
handler_start:
    cmp     r0, #0x51
    beq     stock_51
    cmp     r0, #0x57
    bne     stock_invalid

    push    {r5-r7, lr}
    sub     sp, #8
    ldrb    r5, [r4, #4]
    cmp     r5, #0
    beq     op_info
    cmp     r5, #5
    beq     op_state
    cmp     r5, #6
    beq     op_internal
    cmp     r5, #7
    beq     op_arm3
    cmp     r5, #8
    beq     op_clear
    cmp     r5, #9
    beq     op_runtime
    b       status_bad

op_info:
    ldrb    r0, [r4, #1]
    cmp     r0, #4
    bne     status_bad
    adr     r2, info_payload
    movs    r3, #6
    movs    r1, #0
    b       send

validate_slot:
    ldrb    r6, [r4, #5]
    cmp     r6, #2
    bhs     status_bad
    ldrb    r7, [r4, #6]
    cmp     r7, #2
    bhs     status_bad
    bx      lr

internal_ptr:
    lsls    r0, r6, #1
    adds    r0, r0, r7
    movs    r1, #RECORD_SIZE
    muls    r0, r1
    ldr     r2, internal_base
    adds    r2, r2, r0
    bx      lr

neighbor_ptr:
    @ r0=record -> r1=next record, wrapping slot3->slot0
    ldr     r1, internal_base
    add.w   r2, r1, #228
    cmp     r0, r2
    beq     neighbor_done
    add.w   r1, r0, #RECORD_SIZE
neighbor_done:
    bx      lr

internal_tag_valid:
    ldrb    r0, [r2, #60]
    cmp     r0, #4
    bne     internal_invalid
    ldrb    r0, [r2, #61]
    cmp     r0, #0
    bne     internal_invalid
    ldrb    r0, [r2, #74]
    cmp     r0, #8
    bne     internal_invalid
    ldrb    r0, [r2, #62]
    ldrb    r1, [r2, #63]
    orrs    r0, r1
    ldrb    r1, [r2, #64]
    orrs    r0, r1
    ldrb    r1, [r2, #65]
    orrs    r0, r1
    beq     internal_invalid
    movs    r0, #1
    bx      lr
internal_invalid:
    movs    r0, #0
    bx      lr

clear_full:
    @ Global one-shot scratch: clear bytes 4..19 in all four records.
    push    {r4-r6, lr}
    ldr     r4, internal_base
    movs    r5, #4
    movs    r6, #0
clear_full_loop:
    str     r6, [r4, #4]
    str     r6, [r4, #8]
    str     r6, [r4, #12]
    str     r6, [r4, #16]
    add.w   r4, r4, #RECORD_SIZE
    subs    r5, r5, #1
    bne     clear_full_loop
    pop     {r4-r6, pc}

op_state:
    ldrb    r0, [r4, #1]
    cmp     r0, #4
    bne     status_bad
    ldr     r2, state_base
    movs    r3, #4
    movs    r1, #0
    b       send

op_internal:
    ldrb    r0, [r4, #1]
    cmp     r0, #6
    bne     status_bad
    bl      validate_slot
    bl      internal_ptr
    movs    r3, #76
    movs    r1, #0
    b       send

op_runtime:
    ldrb    r0, [r4, #1]
    cmp     r0, #4
    bne     status_bad
    ldr     r0, hw_flag_ptr
    ldrb    r0, [r0]
    strb    r0, [sp, #0]
    ldr     r0, block_table_ptr
    ldrb    r1, [r0, #0]
    strb    r1, [sp, #1]
    ldrb    r1, [r0, #1]
    strb    r1, [sp, #2]
    ldrb    r1, [r0, #2]
    strb    r1, [sp, #3]
    mov     r2, sp
    movs    r3, #4
    movs    r1, #0
    b       send

op_arm3:
    @ body length = 3 common + payload(21) = 24
    ldrb    r0, [r4, #1]
    cmp     r0, #24
    bne     status_bad
    bl      validate_slot
    bl      internal_ptr
    mov     r7, r2
    bl      internal_tag_valid
    cmp     r0, #0
    beq.w   status_no_tag

    mov     r0, r7
    bl      clear_full
    mov     r0, r7
    bl      neighbor_ptr
    mov     r6, r1                  @ neighbor

    @ key0 -> target +12..17
    add.w   r0, r4, #7
    add.w   r1, r7, #12
    movs    r2, #6
copy_key0:
    ldrb    r3, [r0]
    strb    r3, [r1]
    adds    r0, r0, #1
    adds    r1, r1, #1
    subs    r2, r2, #1
    bne     copy_key0

    @ key1+key2 -> neighbor +4..15
    add.w   r0, r4, #13
    add.w   r1, r6, #4
    movs    r2, #12
copy_key12:
    ldrb    r3, [r0]
    strb    r3, [r1]
    adds    r0, r0, #1
    adds    r1, r1, #1
    subs    r2, r2, #1
    bne     copy_key12

    ldr     r0, neigh_magic_word
    str     r0, [r6, #16]
    movs    r0, #3
    strb    r0, [r7, #8]           @ mode=3 keys
    movs    r0, #0
    strb    r0, [r7, #9]           @ hitmask
    strb    r0, [r7, #10]          @ okmask
    strb    r0, [r7, #11]          @ failmask
    movs    r0, #0
    strh    r0, [r7, #18]
    ldr     r0, magic_word
    str     r0, [r7, #4]           @ arm LAST

    add.w   r2, r7, #62
    movs    r3, #4
    movs    r1, #0
    b       send

op_clear:
    ldrb    r0, [r4, #1]
    cmp     r0, #6
    bne     status_bad
    bl      validate_slot
    bl      internal_ptr
    mov     r0, r2
    bl      clear_full
    movs    r1, #0
    movs    r2, #0
    movs    r3, #0
    b       send

status_no_tag:
    movs    r1, #2
    b       send_empty
status_bad:
    movs    r1, #1
send_empty:
    movs    r2, #0
    movs    r3, #0
send:
    movs    r0, #0x57
    bl      SEND_RESPONSE
    add     sp, #8
    pop     {r5-r7, lr}
    b.w     STOCK_DONE

stock_51:
    b.w     STOCK_51
stock_invalid:
    b.w     STOCK_INVALID

@ -----------------------------------------------------------------------
@ Common override helpers used ONLY from the original stock RFID tasks.
@ -----------------------------------------------------------------------

find_override_by_uid:
    @ r0 = pointer to 4-byte UID. Return r0 = matching armed record or zero.
    ldr     r1, internal_base
    movs    r2, #4
find_loop:
    ldr     r3, [r1, #4]
    ldr     ip, magic_word
    cmp     r3, ip
    bne     find_next
    ldrb    r3, [r1, #8]
    cmp     r3, #3
    bne     find_next
    ldrb    r3, [r1, #60]
    cmp     r3, #4
    bne     find_next
    ldrb    r3, [r1, #61]
    cmp     r3, #0
    bne     find_next
    ldrb    r3, [r1, #74]
    cmp     r3, #8
    bne     find_next
    ldrb    r3, [r0, #0]
    ldrb    ip, [r1, #62]
    cmp     r3, ip
    bne     find_next
    ldrb    r3, [r0, #1]
    ldrb    ip, [r1, #63]
    cmp     r3, ip
    bne     find_next
    ldrb    r3, [r0, #2]
    ldrb    ip, [r1, #64]
    cmp     r3, ip
    bne     find_next
    ldrb    r3, [r0, #3]
    ldrb    ip, [r1, #65]
    cmp     r3, ip
    bne     find_next
    mov     r0, r1
    bx      lr
find_next:
    add.w   r1, r1, #RECORD_SIZE
    subs    r2, r2, #1
    bne     find_loop
    movs    r0, #0
    bx      lr

key_ptr_for_index:
    @ r0=target record, r1=index 0..2 -> r0=KeyA pointer or zero.
    cmp     r1, #0
    bne     key_not0
    add.w   r0, r0, #12
    bx      lr
key_not0:
    push    {r4, lr}
    mov     r4, r1
    bl      neighbor_ptr
    ldr     r2, [r1, #16]
    ldr     r3, neigh_magic_word
    cmp     r2, r3
    bne     key_bad_neighbor
    cmp     r4, #1
    ite     eq
    addeq.w r0, r1, #4
    addne.w r0, r1, #10
    pop     {r4, pc}
key_bad_neighbor:
    movs    r0, #0
    pop     {r4, pc}

disarm_preserve_result:
    @ Failure: preserve masks 9..11, wipe target key and all helper scratch.
    push    {r4-r6, lr}
    mov     r4, r0
    movs    r6, #0
    str     r6, [r4, #4]
    strb    r6, [r4, #8]
    str     r6, [r4, #12]
    str     r6, [r4, #16]
    movs    r5, #3
disarm_fail_next:
    mov     r0, r4
    bl      neighbor_ptr
    mov     r4, r1
    str     r6, [r4, #4]
    str     r6, [r4, #8]
    str     r6, [r4, #12]
    str     r6, [r4, #16]
    subs    r5, r5, #1
    bne     disarm_fail_next
    pop     {r4-r6, pc}

disarm_preserve_capture:
    @ Success after index2: preserve masks and CAP1/CAP2, wipe only keys/markers.
    push    {r4, lr}
    mov     r4, r0
    movs    r3, #0
    str     r3, [r4, #4]
    strb    r3, [r4, #8]
    str     r3, [r4, #12]
    str     r3, [r4, #16]
    mov     r0, r4
    bl      neighbor_ptr
    str     r3, [r1, #4]
    str     r3, [r1, #8]
    str     r3, [r1, #12]
    str     r3, [r1, #16]
    pop     {r4, pc}

capture_result:
    @ r0=target, r1=index, r2=16-byte legacy destination.
    push    {r4-r7, lr}
    mov     r4, r0
    mov     r5, r1
    mov     r6, r2
    cmp     r5, #0
    beq     capture_block4
    cmp     r5, #1
    bne     capture_done
    @ index1/block5: save RGBA bytes 0..3 in CAP2 +12.
    mov     r0, r4
    bl      neighbor_ptr
    mov     r0, r1
    bl      neighbor_ptr
    mov     r0, r1
    bl      neighbor_ptr
    ldr     r2, [r6]
    str     r2, [r1, #12]
    b       capture_done
capture_block4:
    @ CAP1 = two records ahead, CAP2 = three records ahead.
    mov     r0, r4
    bl      neighbor_ptr
    mov     r0, r1
    bl      neighbor_ptr
    mov     r7, r1
    mov     r0, r7
    bl      neighbor_ptr
    mov     r4, r1
    ldr     r0, cap1_magic_word
    str     r0, [r7, #4]
    ldmia   r6!, {r0-r2}
    add.w   r7, r7, #8
    stmia   r7!, {r0-r2}
    ldr     r0, [r6]
    ldr     r2, cap2_magic_word
    str     r2, [r4, #4]
    str     r0, [r4, #8]
capture_done:
    pop     {r4-r7, pc}

update_result:
    @ r0=target, r1=index, r2=success bool. Clobbers r3/ip.
    push    {r4-r6, lr}
    mov     r4, r0
    mov     r5, r1
    mov     r6, r2
    movs    r3, #1
    lsl.w   r3, r3, r5
    ldrb    ip, [r4, #9]
    orr.w   ip, ip, r3
    strb    ip, [r4, #9]
    cbz     r6, update_fail
    ldrb    ip, [r4, #10]
    orr.w   ip, ip, r3
    strb    ip, [r4, #10]
    cmp     r5, #2
    bne     update_done
    mov     r0, r4
    bl      disarm_preserve_capture
    b       update_done
update_fail:
    ldrb    ip, [r4, #11]
    orr.w   ip, ip, r3
    strb    ip, [r4, #11]
    mov     r0, r4
    bl      disarm_preserve_result
update_done:
    pop     {r4-r6, pc}

@ -----------------------------------------------------------------------
@ Legacy backend wrappers. Same ABI as 0x0801A39E.
@ fifth argument (destination pointer) is at entry_sp[0].
@ -----------------------------------------------------------------------
.thumb_func
legacy_read0_wrapper:
    mov.w   ip, #0
    b       legacy_common
.thumb_func
legacy_read1_wrapper:
    mov.w   ip, #1
    b       legacy_common
.thumb_func
legacy_read2_wrapper:
    mov.w   ip, #2
    b       legacy_common

legacy_common:
    push    {r4-r7, lr}
    sub     sp, #12
    mov     r4, r0                  @ reader
    mov     r5, r1                  @ UID*
    mov     r6, r2                  @ stock KeyA*
    mov     r7, r3                  @ block
    str     ip, [sp, #8]            @ read index
    mov     r0, r5
    bl      find_override_by_uid
    str     r0, [sp, #4]            @ armed record or zero
    cbz     r0, legacy_stock_key
    ldr     r1, [sp, #8]
    bl      key_ptr_for_index
    cbz     r0, legacy_stock_key
    mov     r2, r0
    b       legacy_call
legacy_stock_key:
    mov     r2, r6
legacy_call:
    ldr     ip, [sp, #32]           @ original fifth argument
    str     ip, [sp, #0]
    mov     r0, r4
    mov     r1, r5
    mov     r3, r7
    bl      LEGACY_AUTH_READ
    mov     r6, r0                  @ preserve result
    ldr     r0, [sp, #4]
    cbz     r0, legacy_return
    ldr     r1, [sp, #8]
    cmp     r6, #0
    bne     legacy_failed
    ldr     r2, [sp, #0]
    bl      capture_result
    ldr     r0, [sp, #4]
    ldr     r1, [sp, #8]
    movs    r2, #1
    b       legacy_update
legacy_failed:
    movs    r2, #0
legacy_update:
    bl      update_result
legacy_return:
    mov     r0, r6
    add     sp, #12
    pop     {r4-r7, pc}

@ -----------------------------------------------------------------------
@ Secure/FM15L013 backend wrapper. Same ABI as 0x08022082.
@ entry_sp[0]=stock KeyA*, entry_sp[4]=UID*.
@ index is command-0xFF84 (FF84/FF85/FF86 => 0/1/2).
@ -----------------------------------------------------------------------
.thumb_func
alt_read_wrapper:
    push    {r4-r7, lr}
    sub     sp, #12
    mov     r4, r0                  @ command
    mov     r5, r1                  @ encrypted output
    mov     r6, r2                  @ aux
    mov     r7, r3                  @ RFID MCU slot token
    ldr     r0, [sp, #36]           @ original UID*
    bl      find_override_by_uid
    str     r0, [sp, #8]            @ armed record or zero
    cbz     r0, alt_stock_key
    movw    r1, #0xFF84
    subs    r1, r4, r1
    bl      key_ptr_for_index
    cbz     r0, alt_stock_key
    mov     ip, r0
    b       alt_prepare
alt_stock_key:
    ldr     ip, [sp, #32]           @ original stock KeyA*
alt_prepare:
    str     ip, [sp, #0]
    ldr     ip, [sp, #36]
    str     ip, [sp, #4]
    mov     r0, r4
    mov     r1, r5
    mov     r2, r6
    mov     r3, r7
    bl      ALT_AUTH_READ
    mov     r6, r0
    ldr     r0, [sp, #8]
    cbz     r0, alt_return
    movw    r1, #0xFF84
    subs    r1, r4, r1
    movw    r2, #0x9000
    cmp     r6, r2
    ite     eq
    moveq   r2, #1
    movne   r2, #0
    bl      update_result
alt_return:
    mov     r0, r6
    add     sp, #12
    pop     {r4-r7, pc}

.balign 4
state_base:       .word STOCK_STATE
internal_base:    .word INTERNAL_RECORD
hw_flag_ptr:      .word HW_FLAG
block_table_ptr:  .word BLOCK_TABLE
magic_word:       .word OVERRIDE_MAGIC
neigh_magic_word: .word NEIGH_MAGIC
cap1_magic_word:  .word CAP1_MAGIC
cap2_magic_word:  .word CAP2_MAGIC
@ API7: bit3=three-key override, bit5=state, bit6=stock capture, bit7=internal.
info_payload: .byte 7, 2, 2, 0xE8, 3, 16
handler_end:
.size handler_start, .-handler_start