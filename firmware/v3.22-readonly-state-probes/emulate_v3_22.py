#!/usr/bin/env python3
"""Execute actual v3.22 *unflashed* image on emulated Cortex M3. NO printer access."""
from pathlib import Path
import sys,re,subprocess,struct,json
# Optional dependency: pip install unicorn
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
p=Path(__file__).resolve().parent
fw=(p/'CFS-v3_22-PROBE-EXPERIMENTAL-UNFLASHED.bin').read_bytes()
base=0x08010000
nm=subprocess.check_output(['arm-none-eabi-nm','-n',str(p/'handler-v3_22.elf')],text=True)
sym={z[2]:int(z[0],16) for l in nm.splitlines() if len(z:=l.split())==3 and re.fullmatch('[0-9a-f]+',z[0])}
def cpu():
 u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
 u.mem_map(0x08000000,0x40000);u.mem_write(base,fw)
 u.mem_map(0x20000000,0x10000)
 u.mem_write(0x20000014,struct.pack('<I',0x200037e2))
 u.mem_write(0x200037e2,bytes([0,255,100,200,0,155,255,80]))
 u.mem_write(0x200001f2,bytes([4]))
 return u
def invoke(u,op,param=7,value=0):
 # Asserts that on-device stores are either response scratch, stack,
 # or the dedicated 64-byte volatile storage; never motor/RFID RAM.
 request=bytearray(16);request[1]=4 if op==0x10 else 7 if op==0x12 else 5;request[4]=op;request[5]=param
 request[6:8]=struct.pack('<H',value)
 u.mem_write(0x20008000,bytes(request))
 u.reg_write(UC_ARM_REG_R4,0x20008000)
 u.reg_write(UC_ARM_REG_R0,0x57)
 u.reg_write(UC_ARM_REG_SP,0x2000e000)
 u.reg_write(UC_ARM_REG_LR,0x0803d001)
 u.reg_write(UC_ARM_REG_PC,sym['handler_start']|1)
 result=[];writes=[];steps=[]
 def on_code(uc,addr,size,user):
  steps.append(addr)
  if len(steps)>800:raise RuntimeError('Excessive CPU steps')
  if addr==0x0801baf2:
   ptr=uc.reg_read(UC_ARM_REG_R2);size=uc.reg_read(UC_ARM_REG_R3)
   result.append({'status':uc.reg_read(UC_ARM_REG_R1),'payload':bytes(uc.mem_read(ptr,size)).hex()})
   uc.emu_stop()
 def on_write(uc,access,addr,size,value,user):
  writes.append((addr,size))
  assert (0x20006ee8<=addr and addr+size<=0x20006f28) or (0x2000df00<=addr and addr+size<=0x2000e100), ('Unexpected RAM write',hex(addr),size)
 h=u.hook_add(UC_HOOK_CODE,on_code);w=u.hook_add(UC_HOOK_MEM_WRITE,on_write)
 try:u.emu_start(sym['handler_start']|1,0x0803d001,count=800)
 finally:u.hook_del(h);u.hook_del(w)
 assert result,('No response',op,param)
 return result[0],writes
spec=[3200,700,5000,1000,160,120,100,800,200,1000,10,400,100,1250,3000,25,3,1000,30000,300,3]
u=cpu()
info,w=invoke(u,0x10);assert info=={'status':0,'payload':'021c01d7'},info
baseline=[invoke(u,0x11,i)[0] for i in range(28)]
values=[int.from_bytes(bytes.fromhex(row['payload'])[1:],'little') for row in baseline]
assert values[:7]==[255,100,200,155,255,80,0]
assert values[7:]==spec
out={'info':info,'default_get_count':28}

# Four NONCONFIG diagnostic GET IDs must return exact RAM bytes.
# They do not grant permission to write any CFS parameter; the contents
# are deliberately opaque until hardware movement correlation is complete.
u.mem_write(0x2000057e, bytes.fromhex('12 34 56 78'))
u.mem_write(0x20003904, bytes.fromhex('9a bc de f0'))
candidate_expected={28:0x3412,29:0x7856,30:0xbc9a,31:0xf0de}
for ident,val in candidate_expected.items():
    diag,writes=invoke(u,0x11,ident)
    assert diag['status']==0,(ident,diag)
    assert int.from_bytes(bytes.fromhex(diag['payload'])[1:],'little')==val,(ident,diag)
    assert all(0x2000df00 <= addr and addr+size <= 0x2000e100 for addr,size in writes),('READONLY_GET_WROTE_NONSTACK_RAM',ident,writes)
    assert invoke(u,0x12,ident,1)[0]['status']==1,('SET_ENABLED_UNEXPECTEDLY',ident)
    assert invoke(u,0x13,ident)[0]['status']==1,('RESET_ENABLED_UNEXPECTEDLY',ident)
assert invoke(u,0x11,32)[0]['status']==1
out['readonly_internal_probe_get_ids']=[28,29,30,31]
out['readonly_probe_values_verified']=True
out['probe_ids_reject_set_and_reset']=True
out['GET32_rejected']=True

for i,v in enumerate(spec,7):
 # Exercise first-SET, as well as overwriting a set value with a valid new value.
 proposed=v+1 if v+1<=([10000,5000,15000,5000,255,255,255,5000,2000,5000,1000,2000,1000,3000,10000,100,10,10000,60000,5000,10][i-7]) else v-1
 response,w=invoke(u,0x12,i,proposed)
 assert response=={'status':0,'payload':(bytes([i])+struct.pack('<H',proposed)).hex()},(i,response)
 result,_=invoke(u,0x11,i)
 assert int.from_bytes(bytes.fromhex(result['payload'])[1:],'little')==proposed,(i,result)
 # Reset then compare with immutable firmware default.
 reset,_=invoke(u,0x13,i)
 assert reset=={'status':0,'payload':''}
 got,_=invoke(u,0x11,i)
 assert int.from_bytes(bytes.fromhex(got['payload'])[1:],'little')==v,(i,got)
out['set_get_reset_individual_count']=21
# First six stock params and ID 6 must reject writes
for i in range(7):assert invoke(u,0x12,i,10)[0]['status']==1
out['stock_parameter_writes_rejected']=7
# Range guards. All 21 must reject upper and lower out-of-bounds.
bounds=[(100,10000),(100,5000),(500,15000),(100,5000),(1,255),(1,255),(1,255),(100,5000),(10,2000),(100,5000),(1,1000),(50,2000),(10,1000),(250,3000),(500,10000),(5,100),(1,10),(100,10000),(1000,60000),(50,5000),(1,10)]
for i,(lo,hi) in enumerate(bounds,7):
 assert invoke(u,0x12,i,lo-1)[0]['status']==1,(i,'low')
 assert invoke(u,0x12,i,hi+1)[0]['status']==1,(i,'high')
out['invalid_bounds_rejected']=42
# Ensure invalid sidecar never becomes visible to the controller.
u.mem_write(0x20006ee8,struct.pack('<I',0x35564643))
u.mem_write(0x20006eec,struct.pack('<I',1))
u.mem_write(0x20006ef0,struct.pack('<H',65535))
assert int.from_bytes(bytes.fromhex(invoke(u,0x11,7)[0]['payload'])[1:],'little')==3200
out['corrupt_runtime_value_guarded']=True
# GET does not cause memory write.
r,w=invoke(u,0x11,7)
assert not any(0x20006ee8<=addr<0x20006f28 for addr,size in w)
out['get_does_not_modify_storage']=True
# The original 0x0A BOX_STATE handler returns [0x200037D0 + 2] as the
# actual CFS operating state, separate from a retained RFID slot byte.
# Verify that a remembered RFID slot no longer blocks a genuine IDLE CFS.
u.mem_write(0x200001f2,b'\x01')
u.mem_write(0x200037d2,b'\x00')
result,w=invoke(u,0x12,7,3300)
assert result['status']==0,result
assert invoke(u,0x13,7)[0]['status']==0
out['retained_rfid_slot_still_allows_idle_set_reset']=True
# Every known moving/unknown CFS status must reject both SET and RESET
# without writing any bytes of the volatile sidecar.
for state in [1,2,3,4,5,6,0xFF]:
 u.mem_write(0x200037d2,bytes([state]))
 for op in (0x12,0x13):
  result,w=invoke(u,op,7,3300)
  assert result['status']==7,(state,op,result)
  assert not any(0x20006ee8<=addr<0x20006f28 for addr,size in w),(state,op,w)
out['busy_state_rejects_set']=True
out['busy_state_rejects_reset']=True
out['moving_and_unknown_states_rejected']=7
u.mem_write(0x200037d2,b'\x00')
out['no_live_hardware_operations']=True
(p/'arm-emulation.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))

# Execute the REAL Thumb instructions of two stock MOVW callsites after BL patch.
# With no override they must match stock v3.19 for all callee-visible
# registers except LR, which is correctly clobbered by a BL callsite patch.
# All callsites are inside stock functions that saved LR on entry. With valid override they must alter just r0/r1.
from unicorn import UC_HOOK_CODE
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,
      UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
      UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,
      UC_ARM_REG_R12,UC_ARM_REG_SP,UC_ARM_REG_LR]
ROM_DEFAULTS={7:3200,8:700}
CASES=[(7,0x08011116,UC_ARM_REG_R0),(8,0x080112CA,UC_ARM_REG_R1)]
# Use the known baseline full firmware from v3.19 lab, not direct hardware.
BASELINE_FW=p.parent/'v3.19-volatile-ram'/'cfs0_050_G32-cfs0_000_153-runtime-config-v3_19-VOLATILE-RAM-BENCH.bin'
assert BASELINE_FW.exists()

def emulate_callsite(image,callsite,expected_register):
    em=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    em.mem_map(0x08000000,0x40000);em.mem_write(base,image)
    em.mem_map(0x20000000,0x10000)
    em.mem_write(0x20000014,struct.pack('<I',0x200037e2))
    em.mem_write(0x200037e2,bytes([0,255,100,200,0,155,255,80]))
    em.mem_write(0x200001f2,b'\x04')
    em.reg_write(UC_ARM_REG_CPSR,0x00000033)
    for z,reg in enumerate(REGS):em.reg_write(reg,(0x11110000+z*0x120) if reg not in (UC_ARM_REG_SP,UC_ARM_REG_LR) else (0x2000E000 if reg==UC_ARM_REG_SP else 0x0803D001))
    em.reg_write(UC_ARM_REG_APSR,0xA0000000)
    initial={x:em.reg_read(x) for x in REGS}
    apsr_pre=em.reg_read(UC_ARM_REG_APSR)
    hit=[];steps=[]
    def code(uc,addr,size,user):
        steps.append(addr)
        if addr==callsite+4:
            hit.append(addr);uc.emu_stop()
        if len(steps)>400:raise RuntimeError('Wrapper not returning')
    em.hook_add(UC_HOOK_CODE,code)
    em.emu_start(callsite|1,0x0803D001,count=400)
    assert hit and steps[0]==callsite,('hook not hit',callsite,steps[:12])
    values={x:em.reg_read(x) for x in REGS}
    after=em.reg_read(UC_ARM_REG_APSR)
    for reg,v in initial.items():
        if reg not in (expected_register,UC_ARM_REG_LR):assert values[reg]==v,(hex(callsite),reg,hex(v),hex(values[reg]))
    assert after==apsr_pre,('APSR modified',hex(callsite),hex(apsr_pre),hex(after))
    return values[expected_register],len(steps)

# Two stock defaults must remain byte-for-byte behavior-equivalent without overrides.
stock_fw=BASELINE_FW.read_bytes();regression=[]
for id,site,outreg in CASES:
  expected=ROM_DEFAULTS[id]
  stock_value,steps_stock=emulate_callsite(stock_fw,site,outreg)
  hooked_value,steps_hooked=emulate_callsite(fw,site,outreg)
  assert stock_value==hooked_value==expected,(id,stock_value,hooked_value)
  regression.append({'id':id,'callsite':hex(site),'stock_equals_hook_default':True,
                     'stock_value':stock_value,'patched_value':hooked_value,'wrapper_instruction_count':steps_hooked})
# Keep override via memory writes while calling stock code at original hook addresses.
for id,site,outreg in CASES:
  u=cpu()
  proposed=ROM_DEFAULTS[id]+13
  assert invoke(u,0x12,id,proposed)[0]['status']==0
  # The emulator full-body helper already validated sidecar. Repeat in the
  # callsite emulator with exact valid magic/mask/value bits installed.
  injected=bytearray(fw)
  em=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
  em.mem_map(0x08000000,0x40000);em.mem_write(base,bytes(injected))
  em.mem_map(0x20000000,0x10000)
  em.mem_write(0x20000014,struct.pack('<I',0x200037e2))
  em.mem_write(0x200037e2,bytes([0,255,100,200,0,155,255,80]))
  em.mem_write(0x200001f2,b'\x04')
  em.mem_write(0x20006EE8,struct.pack('<II',0x35564643,1<<(id-7)))
  em.mem_write(0x20006EF0+2*(id-7),struct.pack('<H',proposed))
  em.reg_write(UC_ARM_REG_CPSR,0x00000033)
  for z,reg in enumerate(REGS):em.reg_write(reg,(0x11110000+z*0x120) if reg not in (UC_ARM_REG_SP,UC_ARM_REG_LR) else (0x2000E000 if reg==UC_ARM_REG_SP else 0x0803D001))
  em.reg_write(UC_ARM_REG_APSR,0xA0000000)
  apsr0=em.reg_read(UC_ARM_REG_APSR);initial={x:em.reg_read(x) for x in REGS}
  seen=[]
  def stop(uc,addr,size,data):
    if addr==site+4:seen.append(addr);uc.emu_stop()
  em.hook_add(UC_HOOK_CODE,stop)
  em.emu_start(site|1,0x0803D001,count=400)
  assert seen,hex(site)
  assert em.reg_read(outreg)==proposed,(id,em.reg_read(outreg),proposed)
  assert em.reg_read(UC_ARM_REG_APSR)==apsr0
  for reg,value in initial.items():
    if reg not in (outreg,UC_ARM_REG_LR):assert em.reg_read(reg)==value,(id,reg)
  regression[id-7]['valid_override_applied_without_register_or_APSR_change']=True
out['physical_movw_hooks_emulated']=regression
(p/'arm-emulation.json').write_text(json.dumps(out,indent=2)+'\n')
print('HOOK_REGRESSION',json.dumps(regression,indent=2))
