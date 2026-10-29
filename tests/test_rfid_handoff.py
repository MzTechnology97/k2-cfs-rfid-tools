"""RH1 wire and cooperative-thread handoff against candidate ARM, without hardware.

RF reader operations and RTOS context switches are modeled; the original message
validator, API7 wrappers, command dispatcher and quality hooks execute as ARM.
"""
from arm_addresses import code, physical_symbols, ACTUAL_BASE, RETURN
import json,struct
from test_spool_family import FamilyArm,SYMS,UID,u32,bits,ROOT
from test_accounting import AuditArm
from arm_base import RETURN
from unicorn.arm_const import *
SESSION=0x72683101
KEYS=b''.join(bytes((0xa1+i,))*6 for i in range(3))

def state(p):
    assert len(p)==40 and p[:4]==b'RHO1' and p[4]==1
    return dict(phase=p[5],slot=p[6],result=p[7],session=struct.unpack_from('<I',p,8)[0],
                token=struct.unpack_from('<I',p,12)[0],request=struct.unpack_from('<I',p,16)[0],
                uid=p[20:24],remaining=struct.unpack_from('<I',p,24)[0],
                flags=struct.unpack_from('<I',p,28)[0],generation=struct.unpack_from('<I',p,32)[0])
def config(a,session=SESSION,enable=1,wait=1000,lease=10000):
    return a.command(bytes((0x21,enable,0,0))+u32(session)+struct.pack('<HH',wait,lease))
def poll(a,session=SESSION):
    status,p=a.command(bytes((0x23,0,0,0))+u32(session))
    assert status==0,(status,p)
    return state(p)
def start(a,request=123,session=SESSION):
    return a.command(bytes((0x22,a.slot,0,0))+u32(session)+u32(request))
def response(a,q,action='keys',session=None,uid=None,token=None):
    sub=0x24 if action=='keys' else 0x25
    return a.command(bytes((sub,a.slot,0,0))+u32(q['session'] if session is None else session)
        +u32(q['token'] if token is None else token)+(q['uid'] if uid is None else uid)
        +(KEYS if action=='keys' else b''))

class HandoffArm(FamilyArm):
    def __init__(self,slot=1):
        self.native_validator=False;self.cooperative=False;self.paused=False
        self.auth_stock=0;self.auth_override=[];self.wait_delays=0
        self.pin_present=True;self.hub_empty=True;self.cleanup_calls=0
        super().__init__(slot)
        self.set_time(1000)
    def set_time(self,value):
        self.now=value
        self.u.mem_write(0x200009e4,u32(value))
    def on_code(self,cpu,address,size,user):
        if address==code(0x08012358):self.cleanup_calls+=1
        if address in (code(0x0801b78c),code(0x0801b79c)):
            cpu.reg_write(UC_ARM_REG_R0,int(not self.pin_present) if address==code(0x0801b78c) else int(self.hub_empty))
            self.ret(cpu);return
        if self.native_validator:
            if address==code(0x0801a4a0):
                self.trace.append((address,cpu.reg_read(UC_ARM_REG_PRIMASK),cpu.reg_read(UC_ARM_REG_SP)))
                return
            if address==code(0x0801a670):
                AuditArm.on_code(self,cpu,address,size,user);return
            if address in (code(0x080102e2),code(0x0801959e),code(0x0801914c),code(0x080198c4),code(0x0802d074)):
                assert not cpu.reg_read(UC_ARM_REG_PRIMASK)
                cpu.reg_write(UC_ARM_REG_R0,0);self.ret(cpu);return
            if address==code(0x0801a39e):
                assert not cpu.reg_read(UC_ARM_REG_PRIMASK),'RF attempted while IRQs masked'
                block=cpu.reg_read(UC_ARM_REG_R3);idx=block-4
                key=bytes(cpu.mem_read(cpu.reg_read(UC_ARM_REG_R2),6))
                dest=struct.unpack('<I',cpu.mem_read(cpu.reg_read(UC_ARM_REG_SP),4))[0]
                if not 0<=idx<3 or key!=bytes((0xa1+idx,))*6:
                    self.auth_stock+=1;cpu.reg_write(UC_ARM_REG_R0,1)
                else:
                    self.auth_override.append(idx)
                    data=(b'PETG HF'+bytes(9)) if idx==0 else bytes(range(16))
                    cpu.mem_write(dest,data);cpu.reg_write(UC_ARM_REG_R0,0)
                self.ret(cpu);return
            if address in (code(0x0801e166),code(0x0801e198),code(0x08011c5a),code(0x08012aca),code(0x08013060)):
                raise AssertionError(('Motor/reposition call inside auth handoff',hex(address)))
        if address==code(0x0802ee28) and self.cooperative:
            assert not cpu.reg_read(UC_ARM_REG_PRIMASK),'Thread waited with IRQs masked'
            self.wait_delays+=1;self.paused=True;cpu.emu_stop();return
        super().on_code(cpu,address,size,user)
    def prepare_rf(self):
        self.u.reg_write(UC_ARM_REG_R8,self.slot)
        self.call(SYMS['rfid_pre_measure_settle_call_wrapper'])
        self.u.mem_write(0x200001f0,bytes((0x80,0,self.slot,0)))
        self.u.mem_write(0x200037d2,b'\x01')
        self.u.mem_write(0x2000391c,b'\x04')
        self.u.mem_write(0x2000b080,UID+UID)
        self.u.reg_write(UC_ARM_REG_R8,self.slot)
        self.u.reg_write(UC_ARM_REG_R1,0x2000b084)
        self.u.reg_write(UC_ARM_REG_R2,4)
        self.call(SYMS['uid_compare_wrapper'],0x2000b080)
        self.u.mem_write(0x20004410+self.slot*16,b'\x04\x00'+UID+bytes(8)+b'\x08\x04')
        self.u.mem_write(0x200001f8,b'\x04\x05\x06')
        self.u.reg_write(UC_ARM_REG_R0,self.slot//2)
        self.u.reg_write(UC_ARM_REG_R1,self.slot%2)
        self.u.reg_write(UC_ARM_REG_R2,3)
        self.u.reg_write(UC_ARM_REG_SP,0x2000e000)
        self.u.reg_write(UC_ARM_REG_LR,RETURN)
        self.native_validator=True;self.cooperative=True
    def validate(self,action='keys',stale_checks=False):
        self.prepare_rf();pc=SYMS['msg_validate_wrapper'];seen=[];answered=False
        for step in range(400):
            self.paused=False;self.returned=False
            self.u.emu_start(pc|1,RETURN,count=300000)
            if self.returned:break
            assert self.paused,hex(self.u.reg_read(UC_ARM_REG_PC))
            ctx=self.u.context_save()
            delay=self.u.reg_read(UC_ARM_REG_R0)
            self.cooperative=False
            q=poll(self);seen.append(q)
            if q['phase']==2 and not answered:
                assert q['uid']==UID and q['session']==SESSION and q['token'] and q['remaining']>0,q
                if stale_checks:
                    proof=bytes(self.u.mem_read(0x20006f28+self.slot*64,64))
                    assert self.command(bytes((7,self.slot//2,self.slot%2))+KEYS)[0]==7
                    assert self.command(bytes((8,self.slot//2,self.slot%2)))[0]==7
                    for overrides in ({'uid':b'\x09'*4},{'session':SESSION+1},{'token':q['token']+1}):
                        assert response(self,q,**overrides)[0]==1
                        assert bytes(self.u.mem_read(0x20006f28+self.slot*64,64))==proof
                if action!='timeout':
                    status,p=response(self,q,action);assert status==0,(status,p)
                    assert state(p)['phase'] in (1,3),state(p)
                    if action=='keys':assert response(self,q,action)[0]==0
                    answered=True
            self.u.context_restore(ctx)
            self.set_time(self.now+max(1,delay));self.ret(self.u)
            pc=self.u.reg_read(UC_ARM_REG_PC)
            self.cooperative=True
        else:raise AssertionError('Handoff failed to return')
        self.cooperative=False;self.native_validator=False
        return self.u.reg_read(UC_ARM_REG_R0),seen
    def finish_measurement(self,success):
        self.u.reg_write(UC_ARM_REG_R8,self.slot)
        self.u.reg_write(UC_ARM_REG_R5,0 if success else 3)
        self.u.reg_write(UC_ARM_REG_R9,int(success))
        self.u.reg_write(UC_ARM_REG_S16,bits(510))
        self.call(SYMS['sgf_capture_wrapper'])
        self.geometry(85)
        self.u.mem_write(0x2000391c,b'\x01')
        self.u.mem_write(0x200037d2,b'\x00')
        self.u.mem_write(0x200001f0,b'\x40\x00\x04\x00')
        self.call(SYMS['rfh_tick'])
        return poll(self)

def run():
    a=HandoffArm()
    status,p=a.command(b'\x20')
    assert status==0 and p==b'RHI1\x01\x28\x04\x07'+struct.pack('<HH',5000,10000),(status,p)
    assert config(a)[0]==0
    assert poll(a)['flags']&3==3
    # START executes the OEM enqueue routine and immediately returns.
    status,p=start(a);assert status==0 and state(p)['phase']==1
    assert a.u.mem_read(0x2000391c,1)[0]==0
    queued=bytes(a.u.mem_read(0x20000024,16))
    assert start(a)[0]==0 and bytes(a.u.mem_read(0x20000024,16))==queued
    # Restore fixture to a clean start for a full cooperative read.
    a=HandoffArm();config(a);poll(a)
    result,seen=a.validate(stale_checks=True)
    assert result==0 and a.auth_stock>=1 and a.auth_override==[0,1,2],(result,a.auth_stock,a.auth_override)
    assert any(q['phase']==2 for q in seen)
    q=a.finish_measurement(True);assert q['phase']==4 and q['result']==2,q
    sample=a.query();assert sample['flags']==19 and sample['generation']==q['generation'],(sample,q)
    assert a.catalog()[0]==0 and a.bind()[0]==0
    assert a.query()['initial']==100 and a.query()['total']==327000
    success={'stock_auth_calls':a.auth_stock,'api7_auth_indices':a.auth_override,
             'yield_points':a.wait_delays,'capture_flags':sample['flags']}
    # Manual START keeps the OEM read-enabled setting until worker completion,
    # then its cleanup restores that setting exactly once.
    b=HandoffArm();config(b);poll(b);b.u.mem_write(0x20000025,b'\x00')
    assert start(b)[0]==0 and b.u.mem_read(0x20000025,1)==b'\x01'
    result,_=b.validate();assert result==0
    q=b.finish_measurement(True)
    assert q['phase']==4 and q['result']==2 and q['request']==123
    assert not q['flags']&4 and b.u.mem_read(0x20000025,1)==b'\x00'
    b.call(SYMS['rfh_tick']);assert b.cleanup_calls==1
    # An override armed for another slot cannot be destroyed by an auto handoff.
    b=HandoffArm();config(b);poll(b)
    other=(b.slot+1)%4
    b.u.mem_write(0x20004460+other*76+4,u32(0x324f324b))
    b.prepare_rf();b.cooperative=False;b.returned=False
    b.u.emu_start(SYMS['msg_validate_wrapper']|1,RETURN,count=300000)
    assert b.returned and b.u.reg_read(UC_ARM_REG_R0)!=0 and not b.auth_override
    assert bytes(b.u.mem_read(0x20004460+other*76+4,4))==u32(0x324f324b)
    # The host is optional; disabled boot must not introduce a handoff wait.
    a=HandoffArm();a.prepare_rf();a.cooperative=False;a.returned=False
    a.u.emu_start(SYMS['msg_validate_wrapper']|1,RETURN,count=300000)
    assert a.returned and a.u.reg_read(UC_ARM_REG_R0)!=0 and not a.auth_override
    # A bounded wait/decline returns failure to the existing OEM cleanup path.
    endings={}
    for action,wanted in [('decline',3),('timeout',4)]:
        b=HandoffArm();config(b);poll(b)
        result,_=b.validate(action);assert result!=0 and not b.auth_override
        q=b.finish_measurement(False)
        assert q['phase']==4 and q['result']==wanted,q
        endings[action]=q['result']
    for present,empty in [(False,True),(True,False)]:
        b=HandoffArm();config(b);poll(b);b.pin_present=present;b.hub_empty=empty
        assert start(b)[0] in (1,7)
        assert b.u.mem_read(0x2000391c,1)[0]==1
    wire_cases=0
    for wait,lease in [(499,1000),(5001,1000),(500,999),(500,10001)]:
        b=HandoffArm();before=bytes(b.u.mem_read(0x20007088,96))
        assert config(b,wait=wait,lease=lease)[0]==1
        assert bytes(b.u.mem_read(0x20007088,96))==before
        wire_cases+=1
    b=HandoffArm()
    for p in [b'\x20\x00',b'\x21',b'\x23',b'\x24',b'\x25',
              bytes((0x21,1,1,0))+u32(SESSION)+struct.pack('<HH',1000,10000)]:
        before=bytes(b.u.mem_read(0x20007088,96))
        assert b.command(p)[0]==1 and bytes(b.u.mem_read(0x20007088,96))==before
        wire_cases+=1
    b=HandoffArm();b.u.mem_write(0x20000000,b'\x01')
    assert config(b)[0]==1;wire_cases+=1
    data={'passed':True,'success':success,'terminal_results':endings,'extra_wire_cases':wire_cases,
          'no_hardware_access':True,
          'limits':['Pin states, RF backend and RTOS scheduling are modeled.',
                    'No physical scan duration or motor timing is qualified by this test.']}
    (ROOT/'work/build/rfid-handoff-results.json').write_text(json.dumps(data,indent=2)+'\n')
    print(json.dumps(data,indent=2))
if __name__=='__main__':run()
