"""R3 actual OEM UID observations, conservative fallback and R2 regression.

One image at 0x08003000. No live devices; RF selection is modeled, while RAW
copy, both real getter callsites, UID compare, validation and capture run as ARM.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
from test_rfid_handoff_physical import PhysicalArm,historical_baseline,UID,ROOT
from arm_uid_observation import observe_pair,segment,CALLER_STACK
from arm_addresses import code
R2_COMMIT='6eb38f0cd9f06e89760fd36a8c842ea09f08023b'
R2_SHA='27cd264f36a217a98552351578f37fb4060e3d631793cc801242c0deaa6ec046'

def observed(a,**kwargs):
    a.u.reg_write(UC_ARM_REG_R8,a.slot);a.call('rfid_pre_measure_settle_call_wrapper')
    return observe_pair(a,UID,**kwargs)

def qualify(image,symbols):
    equal_cases=[];mismatch_cases=[];guards=[];maximum_stack=0
    for slot in range(4):
        for length in (0,4):
            a=PhysicalArm(image,symbols,slot);q=observed(a,length=length)
            assert q['getter_returns']==[4,4] and q['equal_branch'] and q['compare_status']==1,q
            assert q['buffers']==[UID+b'\xa5'*4]*2 and q['record_byte75']==length,q
            equal_cases.append({'slot':slot,'byte75':length,'returns':q['getter_returns']})
            a=PhysicalArm(image,symbols,slot);q=observed(a,second=b'\x09\x08\x07\x06',length=length)
            assert not q['equal_branch'] and q['compare_status']==2 and q['compare_return'],q
            assert q['record_byte75']==length and not a.validator_calls and not a.auth_override
            mismatch_cases.append({'slot':slot,'byte75':length,'OEM_retry_branch':True})
        # Preserve existing nonzero lengths; no normalization of 1/3/7/10.
        for length in (1,3,7,10):
            a=PhysicalArm(image,symbols,slot);q=observed(a,length=length)
            wanted=length if length>=4 else 0
            assert q['getter_returns']==[wanted,wanted] and q['record_byte75']==length,q
            if wanted:assert q['buffers'][0][:4]==UID
            else:assert q['buffers']==[b'\xa5'*8]*2 and q['compare_status']==0
            guards.append({'slot':slot,'case':'UID length %d preserved'%length})
        for label,hw,atqa,sak,uid in [('secure',1,b'\x04\x00',8,UID),('unknown HW',255,b'\x04\x00',8,UID),
             ('ATQA',0,b'\x44\x00',8,UID),('SAK',0,b'\x04\x00',0,UID),('zero UID',0,b'\x04\x00',8,bytes(4))]:
            a=PhysicalArm(image,symbols,slot);a.u.mem_write(0x20000000,bytes((hw,)))
            a.u.reg_write(UC_ARM_REG_R8,slot);a.call('rfid_pre_measure_settle_call_wrapper')
            q=observe_pair(a,uid,length=0,atqa=atqa,sak=sak)
            assert q['getter_returns']==[0,0] and q['buffers']==[b'\xa5'*8]*2 and q['compare_status']==0,q
            assert q['record_byte75']==0
            guards.append({'slot':slot,'case':label})
    # Invalid tuple or null destination must not copy another logical slot.
    for reader,local,out in [(2,0,0x2000B000),(0,2,0x2000B000),(255,0,0x2000B000),(0,0,0)]:
        a=PhysicalArm(image,symbols);before=bytes(a.u.mem_read(0x20004410,0x180))
        a.u.mem_write(0x2000B000,b'\xa5'*16)
        a.u.reg_write(UC_ARM_REG_R1,local);a.u.reg_write(UC_ARM_REG_R2,out);a.call('legacy_uid_observation',reader)
        assert a.u.reg_read(UC_ARM_REG_R0)==0 and not a.uid_getter_calls
        assert bytes(a.u.mem_read(0x20004410,0x180))==before and bytes(a.u.mem_read(0x2000B000,16))==b'\xa5'*16
        guards.append({'case':'invalid getter arguments','reader':reader,'local':local,'destination':hex(out)})
    # The OEM never reaches either getter after a failed RF observation.
    a=PhysicalArm(image,symbols);a.select_failure=True
    a.u.mem_write(CALLER_STACK+12,struct.pack('<II',0,1))
    before=bytes(a.u.mem_read(0x20004460+a.slot*76,76))
    stop=segment(a,0x08012B44,(0x08012B18,0x08012B50))
    assert stop==code(0x08012B18) and not a.uid_getter_calls
    assert bytes(a.u.mem_read(0x20004460+a.slot*76,76))==before
    guards.append({'case':'RF failure remains in OEM polling before getter'})
    abi_cases=0
    for slot in range(4):
        for length in (0,4):
            for mask in (0,1):
                a=PhysicalArm(image,symbols,slot);a.u.mem_write(0x20004460+slot*76+75,bytes((length,)))
                expected={reg:0x12340000+i for i,reg in enumerate([UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11])}
                for reg,value in expected.items():a.u.reg_write(reg,value)
                fp=[]
                for i in range(32):
                    value=0x3F800000+i*0x10000;fp.append(value);a.u.reg_write(globals()['UC_ARM_REG_S%d'%i],value)
                a.u.reg_write(UC_ARM_REG_FPSCR,0xA0000001);a.u.reg_write(UC_ARM_REG_PRIMASK,mask)
                a.u.reg_write(UC_ARM_REG_R1,slot%2);a.u.reg_write(UC_ARM_REG_R2,0x2000B000)
                a.call('legacy_uid_observation',slot//2)
                assert a.u.reg_read(UC_ARM_REG_R0)==4 and bytes(a.u.mem_read(0x2000B000,4))==UID
                assert all(a.u.reg_read(reg)==value for reg,value in expected.items())
                assert [a.u.reg_read(globals()['UC_ARM_REG_S%d'%i]) for i in range(32)]==fp
                assert a.u.reg_read(UC_ARM_REG_FPSCR)==0xA0000001 and a.u.reg_read(UC_ARM_REG_PRIMASK)==mask
                assert a.u.reg_read(UC_ARM_REG_SP)==0x2000EE00 and a.u.mem_read(0x20004460+slot*76+75,1)[0]==length
                maximum_stack=max(maximum_stack,0x2000EE00-a.minimum_sp);abi_cases+=1
    # Model a UID-changing IRQ at each instruction boundary. A copy must be
    # entirely before or after that writer, never a mixture of the two UIDs.
    baseline=PhysicalArm(image,symbols);trace=[]
    baseline.u.hook_add(UC_HOOK_CODE,lambda u,a,s,d:trace.append(a))
    baseline.u.reg_write(UC_ARM_REG_R1,1);baseline.u.reg_write(UC_ARM_REG_R2,0x2000B000);baseline.call('legacy_uid_observation',0)
    irq_cases=0
    for at in range(1,len(trace)):
        a=PhysicalArm(image,symbols);counter=[0];delivered=[False];other=b'\x09\x08\x07\x06'
        def writer(cpu,address,size,user):
            counter[0]+=1
            if counter[0]>=at and not delivered[0] and not cpu.reg_read(UC_ARM_REG_PRIMASK):
                cpu.mem_write(0x20004460+a.slot*76+62,other);delivered[0]=True
        a.u.hook_add(UC_HOOK_CODE,writer)
        a.u.reg_write(UC_ARM_REG_R1,1);a.u.reg_write(UC_ARM_REG_R2,0x2000B000);a.call('legacy_uid_observation',0)
        assert delivered[0] and bytes(a.u.mem_read(0x2000B000,4)) in (UID,other)
        assert a.u.reg_read(UC_ARM_REG_PRIMASK)==0 and a.u.mem_read(0x20004460+a.slot*76+75,1)[0]==0
        irq_cases+=1
    # Mandatory exact R2 reconstruction: the same actual path authenticates
    # but has no UID-pair proof; R3 must establish that proof instead.
    r2,old_symbols=historical_baseline(R2_COMMIT,R2_SHA)
    a=PhysicalArm(r2,old_symbols);a.config();a.poll();result,_=a.validate();a.finish()
    status,old=a.command(bytes((0x17,a.slot)))
    assert result==0 and status==0 and a.uid_pair['getter_returns']==[0,0] and old[5]==2
    a=PhysicalArm(image,symbols);a.config();a.poll();result,_=a.validate();a.finish()
    status,new=a.command(bytes((0x17,a.slot)))
    assert result==0 and status==0 and a.uid_pair['getter_returns']==[4,4] and new[5]==19
    return {'passed':True,'sha256':hashlib.sha256(image).hexdigest(),'actual_app_base':'0x08003000',
            'equal_cases':equal_cases,'mismatch_cases':mismatch_cases,'guard_cases':guards,
            'abi_cases':abi_cases,'modeled_irq_boundaries':irq_cases,'maximum_observed_getter_stack_bytes':maximum_stack,
            'R2_negative':{'commit':R2_COMMIT,'sha256':R2_SHA,'flags':old[5],'getter_returns':[0,0]},
            'R3_positive':{'flags':new[5],'getter_returns':[4,4],'record_byte75_unchanged':True},
            'limits':['Reader selection and IRQ scheduling are modeled; no physical motors/RF or MCU timing is exercised.']}

def run():
    build=ROOT/'work/build';result=qualify((build/'candidate.bin').read_bytes(),json.loads((build/'symbols.json').read_text()))
    (build/'uid-observation-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':run()
