"""Execute the OEM RAW-copy and both measurement UID getter callsites.

Only RF selection is modeled by the caller's hardware fixture. The source RAW
metadata, memcpy, getter(s), caller argument setup and UID compare run as ARM.
"""
import struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R8,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
from arm_addresses import code,RETURN
CALLER_STACK=0x2000E000

def segment(arm,start,stops=None,stack=CALLER_STACK):
    stops={RETURN&~1} if stops is None else {code(x) for x in stops}
    cpu=arm.u;hit=[]
    cpu.reg_write(UC_ARM_REG_SP,stack);cpu.reg_write(UC_ARM_REG_LR,RETURN)
    def stop(u,address,size,user):
        if address in stops:hit.append(address);u.emu_stop()
    handle=cpu.hook_add(UC_HOOK_CODE,stop)
    arm.returned=False
    try:cpu.emu_start(code(start)|1,RETURN,count=300000)
    finally:cpu.hook_del(handle)
    assert hit or (stops=={RETURN&~1} and arm.returned),('OEM segment did not stop',hex(start),hex(cpu.reg_read(UC_ARM_REG_PC)))
    return hit[0] if hit else RETURN&~1

def observe_pair(arm,first,second=None,length=0,atqa=b'\x04\x00',sak=8):
    first=bytes(first);second=first if second is None else bytes(second)
    assert len(first)==len(second)==4 and len(atqa)==2
    slot=arm.slot;reader,local=slot//2,slot%2;cpu=arm.u
    cpu.mem_write(CALLER_STACK+12,struct.pack('<II',reader,local))
    cpu.mem_write(CALLER_STACK+48,b'\xa5'*16)
    results=[]
    for index,uid in enumerate((first,second)):
        raw=atqa+uid+bytes(8)+bytes((sak,length))
        cpu.mem_write(0x20004410+slot*16,raw)
        cpu.reg_write(UC_ARM_REG_R0,reader);cpu.reg_write(UC_ARM_REG_R1,local)
        segment(arm,0x0801A608,stack=0x2000EE00)
        assert cpu.reg_read(UC_ARM_REG_R0)==0,'modeled RF selection must succeed before an observation'
        cpu.reg_write(UC_ARM_REG_R8,slot)
        if index==0:
            segment(arm,0x08012B72,(0x08012B7C,))
            results.append(cpu.reg_read(UC_ARM_REG_R0))
        else:
            segment(arm,0x08012DCC,(0x08012DD6,))
            results.append(cpu.reg_read(UC_ARM_REG_R0))
            # Actual MOV R2,R0, stack buffer arguments, wrapper and CBZ branch.
            stop=segment(arm,0x08012DD6,(0x08012DE2,0x08012E1C))
    return {'getter_returns':results,'compare_return':cpu.reg_read(UC_ARM_REG_R0),
            'equal_branch':stop==code(0x08012E1C),
            'buffers':[bytes(cpu.mem_read(CALLER_STACK+x,8)) for x in (48,56)],
            'record_byte75':cpu.mem_read(0x20004460+slot*76+75,1)[0],
            'compare_status':struct.unpack('<I',cpu.mem_read(0x20006F28+slot*64+40,4))[0]}
