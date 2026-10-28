"""Execute SGF1 candidate ARM; emulate RF transport only, never access hardware."""
from pathlib import Path
import hashlib,json,struct,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
import test_accounting as old
from arm_base import START,END,GATE_CALLSITE,RETURN
from unicorn.arm_const import *
IMAGE=(ROOT/'work/build/candidate.bin').read_bytes()
SYMS=json.loads((ROOT/'work/build/symbols.json').read_text())
SLOT_RAM=0x20006f28
CAT=0x20007028
FRAME=0x2000d000
UID=bytes.fromhex('01020304')
def u32(x):return struct.pack('<I',x)
def bits(x):return struct.unpack('<I',struct.pack('<f',x))[0]

class FamilyArm(old.AuditArm):
    def __init__(self,slot=1):
        self.reply=None;self.auth=[];self.fail_index=None;self.epoch_race=False;self.heap_mode=False;self.heap_seen=[];self.tail_mode=False
        super().__init__(IMAGE,slot,vendor='thirdparty')
        self.set_uid(UID)
    def set_uid(self,value):
        self.tag_uid=bytes(value)
        self.u.mem_write(0x20004460+self.slot*76+62,self.tag_uid)
    def on_code(self,cpu,address,size,user):
        if address==0x0801a670:
            cpu.reg_write(UC_ARM_REG_R0,1);self.ret(cpu);return
        if self.tail_mode and address in (0x0801b150,0x0801b334,0x08012444,0x08012488,0x0801e198,0x0801a27a,0x08011c5a):
            self.ret(cpu);return
        if self.heap_mode:
            if address in (0x08027886,0x0802a584,0x08031d66,0x0802d57e):
                self.ret(cpu);return
            if address==0x0802d5e0:
                self.heap_seen.append((cpu.reg_read(UC_ARM_REG_R0),cpu.reg_read(UC_ARM_REG_R1)))
                self.ret(cpu);return
        if address==0x0801c808:
            self.returned=True;cpu.emu_stop();return
        if address==0x0801baf2 and cpu.reg_read(UC_ARM_REG_R0)==0x57:
            ptr=cpu.reg_read(UC_ARM_REG_R2);n=cpu.reg_read(UC_ARM_REG_R3)
            assert not cpu.reg_read(UC_ARM_REG_PRIMASK)
            self.reply=(cpu.reg_read(UC_ARM_REG_R1),bytes(cpu.mem_read(ptr,n)) if n else b'')
            self.ret(cpu);return
        if address==0x0801a39e:
            block=cpu.reg_read(UC_ARM_REG_R3);idx=block-4
            dest=struct.unpack('<I',cpu.mem_read(cpu.reg_read(UC_ARM_REG_SP),4))[0]
            assert 0<=idx<=2 and dest==0x2000b100
            assert cpu.reg_read(UC_ARM_REG_R0)==self.slot//2
            assert bytes(cpu.mem_read(cpu.reg_read(UC_ARM_REG_R1),4))==self.tag_uid
            assert bytes(cpu.mem_read(cpu.reg_read(UC_ARM_REG_R2),6))==bytes((0xa1+idx,))*6
            self.auth.append(idx)
            if self.epoch_race:
                p=SLOT_RAM+self.slot*64
                epoch=struct.unpack('<I',cpu.mem_read(p+60,4))[0]
                cpu.mem_write(p+60,u32(epoch+1));self.epoch_race=False
            data=(b'PETG HF'+bytes(9)) if idx==0 else bytes(range(16))
            cpu.mem_write(dest,data)
            cpu.reg_write(UC_ARM_REG_R0,int(idx==self.fail_index));self.ret(cpu);return
        if address==0x0802ee28: # A modeled delay; no wait or motor operation.
            self.ret(cpu);return
        super().on_code(cpu,address,size,user)
    def command(self,payload):
        frame=bytearray(64);frame[1]=len(payload)+3;frame[4:4+len(payload)]=payload
        self.u.mem_write(FRAME,bytes(frame));self.u.reg_write(UC_ARM_REG_R4,FRAME)
        self.reply=None;self.call(SYMS['handler_start'],0x57)
        assert self.reply is not None;return self.reply
    def catalog(self,core=3000,full=5100,total=327000,rev=1,id=1):
        return self.command(bytes((0x18,id,0,0))+struct.pack('<IHHI',rev,core,full,total))
    def query(self):
        status,p=self.command(bytes((0x17,self.slot)));assert status==0 and len(p)==64 and p[:4]==b'SGD1'
        return {'flags':p[5],'profile':p[6],'generation':struct.unpack_from('<I',p,8)[0],
                'uid':p[12:16],'raw_bits':p[16:20].hex(),'revision':struct.unpack_from('<I',p,28)[0],
                'total':struct.unpack_from('<I',p,32)[0],'used':struct.unpack_from('<I',p,36)[0],
                'initial':p[40],'percent':p[41],'valid':p[42],'type':p[43],
                'current_uid':p[24:28],'raw':p}
    def bind(self,id=1,uid=None,gen=None,rev=1):
        q=self.query()
        return self.command(bytes((0x1a,self.slot,id,0))+(self.tag_uid if uid is None else uid)+
                            u32(q['generation'] if gen is None else gen)+u32(rev))
    def scan(self,c=510.0,legacy_percent=85,mismatch=False,status=0,native=0,comparison_length=4,run_tail=False,drop_auth=False):
        # The real API7 ARM path, then the existing pre-measure hook.
        keys=b''.join(bytes((0xa1+i,))*6 for i in range(3))
        assert self.command(bytes((7,self.slot//2,self.slot%2))+keys)[0]==0
        self.u.reg_write(UC_ARM_REG_R8,self.slot)
        self.call(SYMS['rfid_pre_measure_settle_call_wrapper'])
        # Three real legacy wrapper calls, with deterministic backend replies.
        self.u.mem_write(0x2000b000,self.tag_uid)
        for i in range(3):
            self.u.reg_write(UC_ARM_REG_R0,self.slot//2)
            self.u.reg_write(UC_ARM_REG_R1,0x2000b000)
            self.u.reg_write(UC_ARM_REG_R2,0x2000b020)
            self.u.reg_write(UC_ARM_REG_R3,4+i)
            self.u.mem_write(0x2000ee00,u32(0x2000b100))
            self.call(SYMS['legacy_read%d_wrapper'%i])
            if self.fail_index==i:break
        # Real original UID memcmp plus the existing API7 suppression path.
        self.u.mem_write(0x2000b080,self.tag_uid)
        self.u.mem_write(0x2000b084,b'\x09\x08\x07\x06' if mismatch else self.tag_uid)
        self.u.reg_write(UC_ARM_REG_R1,0x2000b084);self.u.reg_write(UC_ARM_REG_R2,4)
        self.call(SYMS['uid_compare_wrapper'],0x2000b080)
        if drop_auth:
            self.call(SYMS['sgf_cancel_transients'])
            self.u.reg_write(UC_ARM_REG_R1,0x2000b084);self.u.reg_write(UC_ARM_REG_R2,4)
            self.call(SYMS['uid_compare_wrapper'],0x2000b080)
        if comparison_length!=4:
            self.u.reg_write(UC_ARM_REG_R1,0x2000b084);self.u.reg_write(UC_ARM_REG_R2,comparison_length)
            self.call(SYMS['uid_compare_wrapper'],0x2000b080)
        if run_tail:
            self.u.mem_write(0x200001f2,bytes((self.slot,)))
            self.u.reg_write(UC_ARM_REG_R0,self.slot//2);self.u.reg_write(UC_ARM_REG_R1,self.slot%2);self.u.reg_write(UC_ARM_REG_R2,3)
            self.call(SYMS['msg_validate_wrapper']);assert self.u.reg_read(UC_ARM_REG_R0)==0
            self.u.reg_write(UC_ARM_REG_R4,1);self.u.reg_write(UC_ARM_REG_R8,self.slot);self.u.reg_write(UC_ARM_REG_R9,0)
            self.u.reg_write(UC_ARM_REG_R10,0x2000391c);self.u.reg_write(UC_ARM_REG_R11,0x2000391c+self.slot)
            self.u.reg_write(UC_ARM_REG_S16,bits(0));self.u.reg_write(UC_ARM_REG_S17,bits(c))
            self.u.reg_write(UC_ARM_REG_S20,bits(100))
            self.u.mem_write(0x2000ee0c,struct.pack('<II',self.slot//2,self.slot%2))
            self.tail_mode=True;self.call(0x08012e66,0);self.tail_mode=False
            self.last_tail_r9=self.u.reg_read(UC_ARM_REG_R9)
        else:
            self.u.reg_write(UC_ARM_REG_R8,self.slot);self.u.reg_write(UC_ARM_REG_R5,status)
            self.u.reg_write(UC_ARM_REG_R9,native);self.u.reg_write(UC_ARM_REG_S16,bits(c))
            self.call(SYMS['sgf_capture_wrapper'])
            self.geometry(legacy_percent)
        # This is what the current decoder finally does after reading CAP.
        assert self.command(bytes((8,self.slot//2,self.slot%2)))[0]==0
        return self.query()
    def protected_ram(self):return bytes(self.u.mem_read(0x20000000,0xd000))

def expect_readonly_rejection(a,payload,wanted=1):
    before=a.protected_ram();status,_=a.command(payload)
    assert status==wanted,(status,wanted)
    assert before==a.protected_ram(),'Rejected mutation modified RAM'

def boot_and_abi():
    b=FamilyArm();b.heap_mode=True
    b.u.mem_write(0x20006ee4,b'BEFR'+b'\xa5'*384+b'AFTR')
    b.call(SYMS['heap_init_sidecar_wrapper'])
    assert b.heap_seen==[(0x20007068,0x20010000)],b.heap_seen
    assert bytes(b.u.mem_read(0x20006ee4,4))==b'BEFR'
    assert bytes(b.u.mem_read(0x20007068,4))==b'AFTR'
    assert bytes(b.u.mem_read(0x20006ee8,8))==bytes(8)
    assert bytes(b.u.mem_read(0x20006ef0,56))==b'\xa5'*56
    assert bytes(b.u.mem_read(SLOT_RAM,320))==bytes(320)
    count=0;maximum_stack=0
    for s in range(4):
        for mask in [0,1]:
            b=FamilyArm(s)
            # OEM VFP arithmetic has already activated FP context at this hook.
            b.u.reg_write(UC_ARM_REG_R8,s);b.call(SYMS['sgf_capture_wrapper'])
            # Test the exact replacement of VMOV; R0 alone is its output.
            for i in range(13):b.u.reg_write(globals()['UC_ARM_REG_R%d'%i],0x12340000+i)
            b.u.reg_write(UC_ARM_REG_R8,s);b.u.reg_write(UC_ARM_REG_R5,0);b.u.reg_write(UC_ARM_REG_R9,0)
            for i in range(32):b.u.reg_write(globals()['UC_ARM_REG_S%d'%i],bits(10.0+i))
            b.u.reg_write(UC_ARM_REG_S16,bits(510));b.u.reg_write(UC_ARM_REG_FPSCR,0xa0000001)
            b.u.reg_write(UC_ARM_REG_PRIMASK,mask);b.u.reg_write(UC_ARM_REG_APSR,0x98000000)
            regs={i:b.u.reg_read(globals()['UC_ARM_REG_R%d'%i]) for i in range(1,13)}
            fp=[b.u.reg_read(globals()['UC_ARM_REG_S%d'%i]) for i in range(32)]
            b.call(SYMS['sgf_capture_wrapper'])
            assert b.u.reg_read(UC_ARM_REG_R0)==bits(510)
            assert regs=={i:b.u.reg_read(globals()['UC_ARM_REG_R%d'%i]) for i in range(1,13)}
            assert fp==[b.u.reg_read(globals()['UC_ARM_REG_S%d'%i]) for i in range(32)]
            assert b.u.reg_read(UC_ARM_REG_FPSCR)==0xa0000001
            assert b.u.reg_read(UC_ARM_REG_APSR)&0xf8000000==0x98000000
            assert b.u.reg_read(UC_ARM_REG_PRIMASK)==mask
            # Test the geometry hook with an active profile, including its FP math.
            b=FamilyArm(s);assert b.catalog()[0]==0;b.scan();assert b.bind()[0]==0
            for i in range(32):b.u.reg_write(globals()['UC_ARM_REG_S%d'%i],bits(20.0+i))
            fp=[b.u.reg_read(globals()['UC_ARM_REG_S%d'%i]) for i in range(32)]
            b.u.reg_write(UC_ARM_REG_FPSCR,0x60000001);b.u.reg_write(UC_ARM_REG_PRIMASK,mask)
            for i in range(13):b.u.reg_write(globals()['UC_ARM_REG_R%d'%i],0x56780000+i)
            b.u.reg_write(UC_ARM_REG_R4,85);b.u.reg_write(UC_ARM_REG_R8,s)
            b.u.reg_write(UC_ARM_REG_R9,0);b.u.reg_write(UC_ARM_REG_R11,0x2000391c+s)
            regs={i:b.u.reg_read(globals()['UC_ARM_REG_R%d'%i]) for i in range(13)}
            b.u.reg_write(UC_ARM_REG_APSR,0xa8000000);b.clear_audit();b.call(SYMS['geometry_percent_store_wrapper'])
            assert regs=={i:b.u.reg_read(globals()['UC_ARM_REG_R%d'%i]) for i in range(13)}
            assert b.u.reg_read(UC_ARM_REG_R4)==85
            assert fp==[b.u.reg_read(globals()['UC_ARM_REG_S%d'%i]) for i in range(32)]
            assert b.u.reg_read(UC_ARM_REG_FPSCR)==0x60000001
            assert b.u.reg_read(UC_ARM_REG_APSR)&0xf8000000==0xa8000000
            assert b.u.reg_read(UC_ARM_REG_PRIMASK)==mask
            maximum_stack=max(maximum_stack,0x2000ee00-min(x[2] for x in b.trace));count+=2
    return {'boot_heap_and_clear':True,'abi_cases':count,'maximum_observed_geometry_hook_stack_bytes':maximum_stack}

def protocol_interleavings():
    def prepared():
        a=FamilyArm();a.catalog();a.scan();a.clear_audit();return a
    a=prepared();q=a.query();payload=bytes((0x1a,a.slot,1,0))+a.tag_uid+u32(q['generation'])+u32(1)
    a.clear_audit();a.command(payload);boundaries=len(a.trace)
    for at in range(1,boundaries+1):
        b=prepared();b.injection_at=at
        b.injection=lambda a:a.u.mem_write(0x20004460+a.slot*76+62,b'\x55\x66\x77\x88')
        status,_=b.command(payload);assert status in (0,1)
        assert b.delivered is not None
        assert b.query()['profile']==0,'Binding migrated to another UID'
    # A modeled IRQ reader must see the old or new complete catalog, never a mix.
    a=FamilyArm();a.catalog();payload=bytes((0x18,1,0,0))+struct.pack('<IHHI',2,3100,6200,330000)
    old_catalog=bytes(a.u.mem_read(CAT,16));a.clear_audit();a.command(payload)
    new_catalog=bytes(a.u.mem_read(CAT,16));catalog_boundaries=len(a.trace)
    for at in range(1,catalog_boundaries+1):
        b=FamilyArm();b.catalog();b.clear_audit();observed=[]
        b.injection_at=at;b.injection=lambda a:observed.append(bytes(a.u.mem_read(CAT,16)))
        assert b.command(payload)[0]==0 and observed and observed[0] in (old_catalog,new_catalog)
    return {'uid_change_boundaries':boundaries,'catalog_reader_boundaries':catalog_boundaries,
            'modeled_irqs_deferred_by_primask':True}

def main():
    results={};cases=0
    a=FamilyArm();info=a.command(b'\x16');assert info==(0,b'SGF1\x01\x04\x04\x0f\x40\x00\x14\x00')
    assert a.catalog()[0]==0
    q=a.scan();assert q['flags']==19 and q['profile']==0 and q['initial']==85 and q['used']==0,q
    assert a.bind()[0]==0
    q=a.query();assert (q['profile'],q['percent'],q['initial'],q['total'])==(1,100,100,327000),q
    assert a.response()['slot_value']==100
    results['new_spool_geometry_binding']={'initial_percent':q['initial'],'total_mm':q['total']};cases+=1
    a.position(495145);a.call(START,a.slot);a.position(499145);a.call(GATE_CALLSITE)
    assert a.state()['used_mm']>3900
    a.u.mem_write(0x200037d2,b'\x02')
    before=a.state()
    payload=bytes((0x1a,a.slot,1,0))+a.tag_uid+u32(q['generation'])+u32(1)
    expect_readonly_rejection(a,payload,7)
    after=a.scan(460,60);assert a.state()==before and after['percent']==99,(before,a.state(),after)
    a.call(END,a.slot);a.u.mem_write(0x200037d2,b'\0')
    used=a.scan(460,60);assert used['initial']==71 and used['used']==0 and used['total']==327000,used
    assert a.response()['slot_value']==71
    results['used_spool_reread']={'initial_percent':used['initial'],'used_mm_since_scan':used['used']};cases+=2
    # A retry of the same binding cannot roll the counter back.
    a.u.mem_write(a.row,u32(1200));before=a.state();assert a.bind()[0]==0;assert a.state()==before;cases+=1
    # Another UID with identical material cannot inherit this association.
    a.set_uid(b'\x11\x22\x33\x44');other=a.scan();assert other['profile']==0 and other['initial']==85;cases+=1
    # Stale UID, generation, revision and unconfigured family all reject atomically.
    for uid,gen,rev,id in [(UID,other['generation'],1,1),(a.tag_uid,other['generation']-1,1,1),
                           (a.tag_uid,other['generation'],2,1),(a.tag_uid,other['generation'],1,2)]:
        expect_readonly_rejection(a,bytes((0x1a,a.slot,id,0))+uid+u32(gen)+u32(rev));cases+=1
    for c in [float('nan'),float('inf'),-1.0,-0.0,49.0,2001.0]:
        b=FamilyArm();assert b.catalog()[0]==0;q=b.scan(c);assert not q['flags']&1
        expect_readonly_rejection(b,bytes((0x1a,b.slot,1,0))+b.tag_uid+u32(q['generation'])+u32(1));cases+=1
    for kind in ['mismatch','partial','epoch_race','rf_error','stale_auth']:
        b=FamilyArm();assert b.catalog()[0]==0
        if kind=='partial':b.fail_index=1
        if kind=='epoch_race':b.epoch_race=True
        q=b.scan(mismatch=kind=='mismatch',status=int(kind=='rf_error'),native=1,drop_auth=kind=='stale_auth')
        assert q['flags']&3!=3,(kind,q)
        expect_readonly_rejection(b,bytes((0x1a,b.slot,1,0))+b.tag_uid+u32(q['generation'])+u32(1));cases+=1
    # Actual stock caller promotes R9 to1 after API7 validation. It is not a vendor flag.
    b=FamilyArm();b.catalog();q=b.scan(run_tail=True)
    assert b.last_tail_r9==1 and q['flags']==19 and q['initial']==84,q
    assert b.bind()[0]==0 and b.query()['percent']==100
    results['actual_oem_message_to_geometry_tail']={'r9':b.last_tail_r9,'capture_flags':q['flags'],'stock_initial_percent':q['initial']};cases+=1
    # Catalog bounds, immutability by revision, reserved bytes and exact lengths.
    b=FamilyArm();assert b.catalog()[0]==0
    bad=[bytes((0x18,1,0,0))+struct.pack('<IHHI',2,499,5100,327000),
         bytes((0x18,1,0,0))+struct.pack('<IHHI',2,3000,3050,327000),
         bytes((0x18,1,0,0))+struct.pack('<IHHI',1,3000,5200,327000),
         bytes((0x18,1,1,0))+struct.pack('<IHHI',2,3000,5100,327000),
         b'\x18\x01',b'\x17\x04',b'\x1a\x01']
    for payload in bad:expect_readonly_rejection(b,payload);cases+=1
    for box in [1,2,3,4,5]:
        b.u.mem_write(0x200037d2,bytes((box,)))
        expect_readonly_rejection(b,bytes((0x18,2,0,0))+struct.pack('<IHHI',1,3000,5100,327000),7);cases+=1
    b.u.mem_write(0x200037d2,b'\0')
    for mode in [1,2]:
        b.u.mem_write(0x20004590+3*100+22,bytes((mode,)))
        expect_readonly_rejection(b,bytes((0x18,2,0,0))+struct.pack('<IHHI',1,3000,5100,327000),7);cases+=1
    b.u.mem_write(0x20004590+3*100+22,b'\0')
    # Disabling a profile cannot make an old revision reusable (ABA protection).
    b=FamilyArm();b.catalog();b.scan();assert b.catalog(core=0,full=0,total=0,rev=0)[0]==0
    expect_readonly_rejection(b,bytes((0x18,1,0,0))+struct.pack('<IHHI',1,3000,6000,327000));cases+=1
    assert b.catalog(full=6000,rev=2)[0]==0
    q=b.query();expect_readonly_rejection(b,bytes((0x1a,b.slot,1,0))+b.tag_uid+u32(q['generation'])+u32(1));cases+=1
    for n in [0,3,7]:
        b=FamilyArm();b.catalog();q=b.scan(comparison_length=n);assert not q['flags']&1
        expect_readonly_rejection(b,bytes((0x1a,b.slot,1,0))+b.tag_uid+u32(q['generation'])+u32(1));cases+=1
    for s in range(4):
        b=FamilyArm(s);assert b.catalog()[0]==0;q=b.scan();assert q['flags']==19;assert b.bind()[0]==0;cases+=1
    # A bad new measurement must not replace an already calibrated balance.
    b=FamilyArm();b.catalog();b.scan();b.bind();b.u.mem_write(b.row,u32(1200));before=b.state()
    q=b.scan(mismatch=True);assert b.state()==before and q['flags']&4;cases+=1
    # Beginning another scan invalidates the prior measurement even with the same UID.
    b=FamilyArm();b.catalog();b.scan();q=b.query();b.call(SYMS['sgf_begin'],b.slot)
    expect_readonly_rejection(b,bytes((0x1a,b.slot,1,0))+b.tag_uid+u32(q['generation'])+u32(1));cases+=1
    results['boot_and_abi']=boot_and_abi()
    results['protocol_interleavings']=protocol_interleavings()
    results.update({'passed':True,'protocol_and_lifecycle_cases':cases,'image_sha256':hashlib.sha256(IMAGE).hexdigest(),
                    'no_hardware_access':True,'limits':['RF transport replies and sensor/motor timing are modeled.','Geometries used in tests are synthetic, not Bambu calibration.']})
    (ROOT/'work/build/sgf-test-results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))
if __name__=='__main__':main()
