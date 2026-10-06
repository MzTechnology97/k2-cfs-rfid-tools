#!/usr/bin/env python3
from pathlib import Path
import argparse, hashlib, json
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB, KS_MODE_LITTLE_ENDIAN
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

EXPECTED_SHA256 = "5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea"
APP_BASE = 0x08010000
COMMAND = 0x57

HOOK_OFFSET = 0x0000C3A0
HOOK_ADDR = APP_BASE + HOOK_OFFSET
EXPECTED_HOOK = bytes.fromhex("2ae2afe1")
STOCK_INVALID = 0x0801C7F8
STOCK_51 = 0x0801C704
STOCK_DONE = 0x0801C808

READER_PROBE = 0x0801959E
RFID_MODE = 0x0801914C
CARD_AUTH = 0x080195D8
CARD_READ = 0x08019824
SEND_RESPONSE = 0x0801BAF2
CARD_CACHE = 0x20004410
STOCK_STATE = 0x200001F0

FORBIDDEN_CALLS = {
    0x0801970E: "mifare_write_block",
    0x08017F7E: "bl24cxx_write",
}

def sha256(b): return hashlib.sha256(b).hexdigest()
def align4(n): return (n + 3) & ~3

def asm(src, address):
    ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN)
    enc, _ = ks.asm(src, addr=address, as_bytes=True)
    return bytes(enc)

def build_handler(addr):
    # Packet layout recovered from stock dispatcher:
    # [0]=address, [1]=length, [2]=status, [3]=opcode, [4..]=payload.
    # Keystone mis-resolves some absolute BL/B.W operands in large multi-label
    # Thumb blocks. Assemble symbolic placeholders first, then rewrite every
    # external absolute call/jump as a MOVW/MOVT + BLX/BX veneer.
    src = f"""
        cmp r0, #0x51
        beq stock_51
        cmp r0, #{COMMAND}
        bne stock_invalid

        push {{r4-r7}}
        sub sp, #32

        ldrb r6, [r4, #4]
        cmp r6, #0
        beq op_info
        cmp r6, #1
        beq op_cached
        cmp r6, #2
        beq op_poll
        cmp r6, #3
        beq op_read
        cmp r6, #4
        beq op_read_auth
        cmp r6, #5
        beq op_stock_state
        b status_bad_request

    validate_reader_slot:
        ldrb r6, [r4, #5]
        cmp r6, #2
        bhs status_bad_request
        ldrb r7, [r4, #6]
        cmp r7, #2
        bhs status_bad_request
        bx lr

    cache_ptr:
        movw r2, #{CARD_CACHE & 0xffff}
        movt r2, #{CARD_CACHE >> 16}
        add.w r2, r2, r6, lsl #5
        ldrb r3, [r4, #6]
        add.w r2, r2, r3, lsl #4
        bx lr

    ensure_stock_idle:
        movw r2, #{STOCK_STATE & 0xffff}
        movt r2, #{STOCK_STATE >> 16}
        ldrb r0, [r2, #2]
        cmp r0, #4
        blo status_stock_busy
        bx lr

    op_info:
        ldrb r0, [r4, #1]
        cmp r0, #4
        bne status_bad_request
        movs r0, #3
        strb r0, [sp, #0]
        movs r0, #2
        strb r0, [sp, #1]
        strb r0, [sp, #2]
        movs r0, #0x7f
        strb r0, [sp, #3]
        movs r0, #0xff
        strb r0, [sp, #4]
        movs r0, #16
        strb r0, [sp, #5]
        movs r3, #6
        mov r2, sp
        movs r1, #0
        movs r0, #{COMMAND}
        bl 0x{SEND_RESPONSE:08x}
        b diag_done

    op_cached:
        ldrb r0, [r4, #1]
        cmp r0, #6
        bne status_bad_request
        bl validate_reader_slot
        bl cache_ptr
        movs r3, #16
        movs r1, #0
        movs r0, #{COMMAND}
        bl 0x{SEND_RESPONSE:08x}
        b diag_done

    op_stock_state:
        ldrb r0, [r4, #1]
        cmp r0, #4
        bne status_bad_request
        movw r2, #{STOCK_STATE & 0xffff}
        movt r2, #{STOCK_STATE >> 16}
        movs r3, #4
        movs r1, #0
        movs r0, #{COMMAND}
        bl 0x{SEND_RESPONSE:08x}
        b diag_done

    op_poll:
        ldrb r0, [r4, #1]
        cmp r0, #6
        bne status_bad_request
        bl validate_reader_slot
        bl ensure_stock_idle
        mov r0, r6
        mov r1, r7
        bl 0x{READER_PROBE:08x}
        cmp r0, #0
        bne probe_failed_direct
        bl cache_ptr
        mov r7, r2
        mov r0, r6
        movs r1, #0
        bl 0x{RFID_MODE:08x}
        mov r2, r7
        movs r3, #16
        movs r1, #0
        movs r0, #{COMMAND}
        bl 0x{SEND_RESPONSE:08x}
        b diag_done

    op_read:
        ldrb r0, [r4, #1]
        cmp r0, #7
        bne status_bad_request
        bl validate_reader_slot
        bl ensure_stock_idle
        ldrb r7, [r4, #7]
        @ API v2: unauthenticated 0x30 read accepts the full 8-bit index.
        mov r0, r6
        ldrb r1, [r4, #6]
        bl 0x{READER_PROBE:08x}
        cmp r0, #0
        bne probe_failed_direct
        mov r0, r6
        mov r1, r7
        mov r2, sp
        movs r3, #0
        bl 0x{CARD_READ:08x}
        mov r7, r0
        mov r0, r6
        movs r1, #0
        bl 0x{RFID_MODE:08x}
        cmp r7, #0
        bne status_read_failed
        movs r0, #{COMMAND}
        movs r1, #0
        mov r2, sp
        movs r3, #16
        bl 0x{SEND_RESPONSE:08x}
        b diag_done

    op_read_auth:
        ldrb r0, [r4, #1]
        cmp r0, #13
        bne status_bad_request
        bl validate_reader_slot
        bl ensure_stock_idle
        ldrb r7, [r4, #7]
        cmp r7, #0x40
        bhs status_bad_request

        mov r0, r6
        ldrb r1, [r4, #6]
        bl 0x{READER_PROBE:08x}
        cmp r0, #0
        bne probe_failed_direct

        bl cache_ptr
        ldrb r0, [r2, #0]
        cmp r0, #4
        bne auth_uid_cl2
        ldrb r0, [r2, #1]
        cmp r0, #0
        bne auth_uid_cl2
        adds r3, r2, #2
        b auth_uid_ready
    auth_uid_cl2:
        adds r3, r2, #6
    auth_uid_ready:
        mov r0, r6
        bic r1, r7, #3
        adds r2, r4, #8
        bl 0x{CARD_AUTH:08x}
        cmp r0, #0
        bne auth_failed_cleanup

        mov r0, r6
        mov r1, r7
        mov r2, sp
        movs r3, #0
        bl 0x{CARD_READ:08x}
        mov r7, r0
        mov r0, r6
        movs r1, #0
        bl 0x{RFID_MODE:08x}
        cmp r7, #0
        bne status_read_failed
        movs r0, #{COMMAND}
        movs r1, #0
        mov r2, sp
        movs r3, #16
        bl 0x{SEND_RESPONSE:08x}
        b diag_done

    auth_failed_cleanup:
        mov r0, r6
        movs r1, #0
        bl 0x{RFID_MODE:08x}
        b status_auth_failed

    probe_failed_direct:
        adds r1, r0, #1
        b send_empty

    status_bad_request:
        movs r1, #1
        b send_empty
    status_auth_failed:
        movs r1, #5
        b send_empty
    status_read_failed:
        movs r1, #6
        b send_empty
    status_stock_busy:
        movs r1, #7

    send_empty:
        movs r0, #{COMMAND}
        movs r2, #0
        movs r3, #0
        bl 0x{SEND_RESPONSE:08x}

    diag_done:
        add sp, #32
        pop {{r4-r7}}
        b.w 0x{STOCK_DONE:08x}

    stock_51:
        b.w 0x{STOCK_51:08x}
    stock_invalid:
        b.w 0x{STOCK_INVALID:08x}
    """
    import re
    intended_calls = []
    def call_veneer(m):
        target = int(m.group(1), 16)
        intended_calls.append(target)
        thumb = target | 1
        return (
            f"movw r12, #{thumb & 0xffff}\n"
            f"movt r12, #{thumb >> 16}\n"
            "blx r12"
        )
    def jump_veneer(m):
        target = int(m.group(1), 16) | 1
        return (
            f"movw r12, #{target & 0xffff}\n"
            f"movt r12, #{target >> 16}\n"
            "bx r12"
        )
    src = re.sub(r"bl 0x([0-9A-Fa-f]+)", call_veneer, src)
    src = re.sub(r"b\.w 0x([0-9A-Fa-f]+)", jump_veneer, src)
    return asm(src, addr), intended_calls

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--input",required=True)
    ap.add_argument("--output",required=True)
    ap.add_argument("--manifest",required=True)
    ap.add_argument("--disasm",required=True)
    a=ap.parse_args()
    src=Path(a.input).read_bytes()
    if sha256(src)!=EXPECTED_SHA256:
        raise SystemExit("wrong source SHA-256")
    if src[HOOK_OFFSET:HOOK_OFFSET+4]!=EXPECTED_HOOK:
        raise SystemExit("dispatcher hook bytes mismatch: "+src[HOOK_OFFSET:HOOK_OFFSET+4].hex())
    inject_off=align4(len(src)); inject_addr=APP_BASE+inject_off
    handler, intended_calls = build_handler(inject_addr)
    hook=asm(f"b.w 0x{inject_addr:08x}",HOOK_ADDR)
    if len(hook)!=4: raise SystemExit("hook is not 4 bytes")
    out=bytearray(src)
    out[HOOK_OFFSET:HOOK_OFFSET+4]=hook
    if len(out)<inject_off: out.extend(b"\x00"*(inject_off-len(out)))
    out.extend(handler)
    Path(a.output).write_bytes(out)

    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    dis=[]
    for i in md.disasm(handler,inject_addr):
        dis.append(f"{i.address:08x}: {i.bytes.hex():<12} {i.mnemonic:<8} {i.op_str}")
    Path(a.disasm).write_text("\n".join(dis)+"\n",encoding="utf-8")
    calls = intended_calls
    bad=[{"address":f"0x{x:08x}","name":FORBIDDEN_CALLS[x]} for x in calls if x in FORBIDDEN_CALLS]
    if bad:
        raise SystemExit("forbidden call target in handler: "+json.dumps(bad))
    manifest={
      "schema":3,
      "diagnostic_api_version":3,
      "candidate_revision":"2.1",
      "target_sha256":EXPECTED_SHA256,
      "source_size":len(src),
      "output_size":len(out),
      "output_sha256":sha256(out),
      "application_base":f"0x{APP_BASE:08x}",
      "hook":{"offset":f"0x{HOOK_OFFSET:x}","address":f"0x{HOOK_ADDR:08x}","original":EXPECTED_HOOK.hex(),"patched":hook.hex()},
      "handler":{"offset":f"0x{inject_off:x}","address":f"0x{inject_addr:08x}","size":len(handler)},
      "command":"0x57",
      "subcommands":{
        "0":"info",
        "1":"cached-tag-info",
        "2":"poll",
        "3":"read-block",
        "4":"read-block-auth-a",
        "5":"stock-state"
      },
      "status":{"0":"ok","1":"bad_request","2":"request/no-tag failure","3":"anticollision failure","4":"select failure","5":"auth failure","6":"read failure","7":"stock RFID busy"},
      "limits":{"physical_readers":2,"slots_per_reader":2,"unauthenticated_read_index":"0..255","authenticated_block":"0..63"},
      "stock_state":{"address":"0x200001f0","active_slot_offset":2,"idle_when":"value >= 4","busy_when":"value < 4","guard_scope":"active diagnostic RF commands only"},
      "external_calls":[f"0x{x:08x}" for x in sorted(set(calls))],
      "forbidden_calls_present":bad,
      "flash_performed":False
    }
    Path(a.manifest).write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(manifest,indent=2))

if __name__=="__main__":
    main()