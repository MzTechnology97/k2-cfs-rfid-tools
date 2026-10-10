#!/usr/bin/env python3
"""Read-only ROM/RAM + proposed hook preflight.

NEVER produces a flashable firmware image and does not alter printer.
"""
import hashlib
import json
import argparse
from pathlib import Path
from struct import pack, unpack_from
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT=Path(__file__).parent
parser=argparse.ArgumentParser()
parser.add_argument('--firmware',required=True,type=Path)
args=parser.parse_args()
FW=args.firmware
IMAGE=FW.read_bytes()
BASE=0x08010000
HOOK=0x0801E0CC
LIMIT=0x0803B800  # INFERRED from earlier benchmarks; NOT VERIFIED
VMEM=0x20006EE8
SIDECAR_END=0x20006F28
PROPOSED_RING_END=SIDECAR_END+512
HEAP_LITERAL=0x08027960
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)

# Disassemble actual 4-byte instruction precisely before proposing a hook.
entry=HOOK-BASE
ins=list(md.disasm(IMAGE[entry:entry+8],HOOK))
assert ins[0].address==HOOK and ins[0].size==4
assert ins[0].mnemonic.startswith('push') and 'r8' in ins[0].op_str and 'lr' in ins[0].op_str
original=IMAGE[entry:entry+4].hex()

# Enumerate 32-bit Thumb BL callers of the central speed/duty function.
def callers(target):
 found=[]
 for off in range(0,len(IMAGE)-3,2):
  hi=unpack_from('<H',IMAGE,off)[0]
  lo=unpack_from('<H',IMAGE,off+2)[0]
  if hi&0xF800!=0xF000 or lo&0xD000!=0xD000:continue
  ins=list(md.disasm(IMAGE[off:off+4],BASE+off))
  if len(ins)!=1 or ins[0].mnemonic!='bl':continue
  if int(ins[0].op_str.lstrip('#'),0)==target:found.append(hex(BASE+off))
 return found

assert unpack_from('<I',IMAGE,0)[0]==VMEM
assert unpack_from('<I',IMAGE,HEAP_LITERAL-BASE)[0]==SIDECAR_END
assert IMAGE[0x0801E164-BASE:0x0801E166-BASE]==bytes.fromhex('10b5')
pwm_callers=callers(HOOK)
forward_callers=callers(0x0801E164)
reverse_callers=callers(0x0801E17E)
# ROM image already consumes 178140 bytes and the standalone ARM tracer
# uses 320 bytes; 36 bytes are not enough for tracer+hook+readback.
core_text_bytes=320
report={
 'status':'OFFLINE DESIGN ONLY — NOT A FLASHABLE BUILD',
 'firmware_sha256':hashlib.sha256(IMAGE).hexdigest(),
 'firmware_bytes':len(IMAGE),
 'end_address':hex(BASE+len(IMAGE)),
 'inferred_unverified_flash_limit':hex(LIMIT),
 'remaining_bytes_to_inferred_limit':LIMIT-(BASE+len(IMAGE)),
 'ring_model_bytes':512,
 'ring_record_bytes':16,
 'ring_max_records':30,
 'ram_initial_sp':hex(VMEM),
 'current_heap_start':hex(SIDECAR_END),
 'proposed_ring_span_uncommitted':[hex(SIDECAR_END),hex(PROPOSED_RING_END)],
 'candidate_new_heap_start_uncommitted':hex(PROPOSED_RING_END),
 'heap_end_hypothesis':'0x20010000 — NOT VERIFIED WITH DYNAMIC ALLOCATIONS',
 'ring_ram_reservation_verified':False,
 'central_pwm_setter_candidate':hex(HOOK),
 'original_4byte_prologue':original,
 'first_instructions':[[hex(i.address),i.mnemonic,i.op_str] for i in ins[:2]],
 'direct_bl_callers_pwm':pwm_callers,
 'direct_bl_callers_forward':len(forward_callers),
 'direct_bl_callers_reverse':len(reverse_callers),
 'observed_paths':'0x0801E164 (forward) and 0x0801E17E (reverse) call/tail-branch to 0x0801E0CC; verify all motors and return semantics before hook',
 'motor_hook_abi_proven':False,
 'hook_covers_all_cfs_motors':False,
 'original_task_clock_identified':False,
 'arm_tracer_compiled_text_bytes':core_text_bytes,
 'arm_hook_trampoline_estimated_bytes':'nonzero — not implemented',
 'arm_readback_dispatch_estimated_bytes':'nonzero — not implemented',
 'flash_capacity_confirmed':False,
 'safe_to_flash':False,
 'release_blockers':[
  'MCU application partition maximum and bootloader page map unverified',
  'Even 320-byte ring core > 36-byte headroom to unverified flash limit',
  'RAM range 0x20006F28..0x20007127 must be proven unused and heap head moved only after review',
  'True task single-writer + IRQ context not established, no atomicity guarantee',
  'Motor command entry hook ABI and return/clock correctness not validated',
  'Firmware read-only dump transport not implemented or emulated',
  'No independent motor-active guard or atomic SET/RESET authorisation implemented'
 ]
}
out=ROOT/'V323_STATIC_FEASIBILITY.json'
out.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({key:report[key] for key in ('status','remaining_bytes_to_inferred_limit','ring_model_bytes','central_pwm_setter_candidate','original_4byte_prologue','direct_bl_callers_forward','direct_bl_callers_reverse','flash_capacity_confirmed','safe_to_flash')},indent=2))
print('FULL_REPORT',out,'BLOCKERS',len(report['release_blockers']))
