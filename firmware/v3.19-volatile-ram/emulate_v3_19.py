#!/usr/bin/env python3
"""Execute actual v3.19 image on emulated Cortex M3. NO printer access."""
from pathlib import Path
import sys,re,subprocess,struct,json
# Optional dependency: pip install unicorn
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
p=Path(__file__).resolve().parent
fw=(p/'cfs0_050_G32-cfs0_000_153-runtime-config-v3_19-VOLATILE-RAM-BENCH.bin').read_bytes()
base=0x08010000
nm=subprocess.check_output(['arm-none-eabi-nm','-n',str(p/'handler-v3_19.elf')],text=True)
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
info,w=invoke(u,0x10);assert info=={'status':0,'payload':'021c01f7'},info
baseline=[invoke(u,0x11,i)[0] for i in range(28)]
values=[int.from_bytes(bytes.fromhex(row['payload'])[1:],'little') for row in baseline]
assert values[:7]==[255,100,200,155,255,80,0]
assert values[7:]==spec
out={'info':info,'default_get_count':28}
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
# Non-idle guard, without any sidecar writes.
u.mem_write(0x200001f2,b'\x00')
response,w=invoke(u,0x12,7,3300)
assert response['status']==7 and not any(0x20006ee8<=addr<0x20006f28 for addr,size in w)
out['busy_state_rejects_set']=True
out['no_live_hardware_operations']=True
(p/'V319_ARM_EMULATION.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))
