"""Actual-base RH1 regression: one BIN at 0x08003000, no nominal alias.

Only explicit code entrypoints/symbols are rebased. RAM, UID/key data and GPR
values are never rewritten. RF/GPIO/RTOS I/O is modeled; the OEM validator,
API7 wrappers, enqueue, worker finalizer, heap setup and cleanup execute as ARM.
"""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,sys,tempfile
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_MODE_MCLASS,UC_HOOK_CODE
from unicorn.arm_const import *
from arm_uid_observation import observe_pair
ROOT=Path(__file__).resolve().parents[1]
BIAS=0xD000
ACTUAL_BASE=0x08003000
RETURN=0x0807E001
FRAME=0x2000D000
UID=bytes.fromhex('01020304')
SESSION=0x72683201
KEYS=b''.join(bytes((0xa1+i,))*6 for i in range(3))
TARGETS={'validator':0x0801A670,'enqueue':0x0801233C,'cleanup':0x08012358,
         'select':0x0801959E,'delay':0x0802EE28,'hub_gpio':0x0801B79C,'entry_gpio':0x0801B78C,'uid_getter':0x0801A70C}
def code(nominal):
    assert 0x08010000<=nominal<0x08080000,hex(nominal)
    return nominal-BIAS
def u32(value):return struct.pack('<I',value)
def bits(value):return struct.unpack('<I',struct.pack('<f',value))[0]
def state(p):
    assert len(p)==40 and p[:5]==b'RHO1\x01'
    return {'phase':p[5],'slot':p[6],'result':p[7],
            'session':struct.unpack_from('<I',p,8)[0],
            'token':struct.unpack_from('<I',p,12)[0],
            'request':struct.unpack_from('<I',p,16)[0],'uid':p[20:24],
            'remaining':struct.unpack_from('<I',p,24)[0],
            'flags':struct.unpack_from('<I',p,28)[0],
            'generation':struct.unpack_from('<I',p,32)[0]}
class UnrebasedTarget(AssertionError):pass

class PhysicalArm:
    def __init__(self,image,symbols,slot=1):
        self.image=image;self.symbols=symbols;self.slot=slot
        self.u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
        self.u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)
        self.u.mem_map(0x08000000,0x80000)
        self.u.mem_write(ACTUAL_BASE,image)  # The only image write/map.
        self.u.mem_map(0x20000000,0x10000)
        self.u.mem_map(0xE000E000,0x2000)
        self.u.mem_write(0xE000ED88,u32(0x00F00000))
        self.u.reg_write(UC_ARM_REG_CONTROL,0)
        self.u.reg_write(UC_ARM_REG_XPSR,0x01000000)
        self.u.reg_write(UC_ARM_REG_FPEXC,0x40000000)
        self.u.reg_write(UC_ARM_REG_FPSCR,0)
        self.u.mem_write(0x200001F0,b'\x40\x00\x04\x00')
        self.u.mem_write(0x2000391C,b'\x01')
        r=bytearray(76);r[60:62]=b'\x04\x00';r[62:66]=UID;r[74]=8;r[75]=0
        self.u.mem_write(0x20004460+slot*76,bytes(r))
        self.u.mem_write(0x2000391E+slot,b'\x01')
        self.row=0x20004590+slot*100
        self.u.mem_write(self.row+4,u32(330000))
        self.u.mem_write(self.row+20,bytes((85,0,0,1)))
        self.u.mem_write(self.row+99,b'\x04')
        self.u.mem_write(0x20003974+slot,b'\x55')
        self.now=1000;self.set_time(self.now)
        self.reply=None;self.returned=False;self.cooperative=False;self.paused=False
        self.auth_stock=0;self.auth_override=[];self.validator_calls=0
        self.cleanup_calls=0;self.enqueue_calls=0;self.delay_calls=0;self.pin_calls=[]
        self.pin_present=True;self.hub_empty=True;self.heap_mode=False;self.heap_seen=[];self.select_failure=False;self.uid_getter_calls=0
        self.minimum_sp=0x20010000
        self.u.hook_add(UC_HOOK_CODE,self.on_code)
    def set_time(self,value):self.now=value;self.u.mem_write(0x200009E4,u32(value))
    def ret(self,cpu):cpu.reg_write(UC_ARM_REG_PC,cpu.reg_read(UC_ARM_REG_LR))
    def on_code(self,cpu,address,size,user):
        self.minimum_sp=min(self.minimum_sp,cpu.reg_read(UC_ARM_REG_SP))
        if address in TARGETS.values():
            raise UnrebasedTarget('absolute BLX reached nominal address '+hex(address))
        if address in (RETURN&~1,code(0x0801C808),code(0x080133A8)):
            self.returned=True;cpu.emu_stop();return
        if address==code(0x0801BAF2):
            assert cpu.reg_read(UC_ARM_REG_R0)==0x57
            assert not cpu.reg_read(UC_ARM_REG_PRIMASK),'SEND under IRQ mask'
            n=cpu.reg_read(UC_ARM_REG_R3);ptr=cpu.reg_read(UC_ARM_REG_R2)
            self.reply=(cpu.reg_read(UC_ARM_REG_R1),bytes(cpu.mem_read(ptr,n)) if n else b'')
            self.ret(cpu);return
        if self.heap_mode:
            if address in {code(x) for x in (0x08027886,0x0802A584,0x08031D66,0x0802D57E)}:
                self.ret(cpu);return
            if address==code(0x0802D5E0):
                self.heap_seen.append((cpu.reg_read(UC_ARM_REG_R0),cpu.reg_read(UC_ARM_REG_R1)))
                self.ret(cpu);return
        if address==code(TARGETS['enqueue']):self.enqueue_calls+=1
        if address==code(TARGETS['cleanup']):self.cleanup_calls+=1
        if address==code(0x0801A70C):self.uid_getter_calls+=1
        if address==code(TARGETS['validator']):
            assert not cpu.reg_read(UC_ARM_REG_PRIMASK)
            self.validator_calls+=1  # Execute original OEM instructions.
        if address in (code(TARGETS['hub_gpio']),code(TARGETS['entry_gpio'])):
            self.pin_calls.append((address,cpu.reg_read(UC_ARM_REG_R0)))
            cpu.reg_write(UC_ARM_REG_R0,int(self.hub_empty) if address==code(TARGETS['hub_gpio']) else int(not self.pin_present))
            self.ret(cpu);return
        if address in {code(x) for x in (0x080102E2,0x0801959E,0x0801914C,0x080198C4,0x0802D074)}:
            assert not cpu.reg_read(UC_ARM_REG_PRIMASK)
            cpu.reg_write(UC_ARM_REG_R0,int(self.select_failure) if address==code(0x0801959E) else 0);self.ret(cpu);return
        if address==code(0x0801A39E):
            assert not cpu.reg_read(UC_ARM_REG_PRIMASK),'RF backend under IRQ mask'
            idx=cpu.reg_read(UC_ARM_REG_R3)-4
            key=bytes(cpu.mem_read(cpu.reg_read(UC_ARM_REG_R2),6))
            destination=struct.unpack('<I',cpu.mem_read(cpu.reg_read(UC_ARM_REG_SP),4))[0]
            assert cpu.reg_read(UC_ARM_REG_R0)==self.slot//2
            assert bytes(cpu.mem_read(cpu.reg_read(UC_ARM_REG_R1),4))==UID
            if not 0<=idx<3 or key!=bytes((0xa1+idx,))*6:
                self.auth_stock+=1;cpu.reg_write(UC_ARM_REG_R0,1)
            else:
                self.auth_override.append(idx)
                cpu.mem_write(destination,b'PETG HF'+bytes(9) if idx==0 else bytes(range(16)))
                cpu.reg_write(UC_ARM_REG_R0,0)
            self.ret(cpu);return
        if address==code(TARGETS['delay']):
            assert not cpu.reg_read(UC_ARM_REG_PRIMASK),'RTOS wait under IRQ mask'
            self.delay_calls+=1
            if self.cooperative:self.paused=True;cpu.emu_stop()
            else:self.ret(cpu)
            return
        if address in {code(x) for x in (0x0801E164,0x0801E166,0x0801E198,0x08011C5A,0x08012ACA,0x08013060)}:
            raise AssertionError('motor/reposition reached during handoff '+hex(address))
    def call(self,target,r0=None):
        if isinstance(target,str):target=self.symbols[target]
        if r0 is not None:self.u.reg_write(UC_ARM_REG_R0,r0)
        self.u.reg_write(UC_ARM_REG_SP,0x2000EE00)
        self.u.reg_write(UC_ARM_REG_LR,RETURN)
        self.returned=False
        self.u.emu_start(code(target)|1,RETURN,count=300000)
        assert self.returned,('call did not return',hex(target),hex(self.u.reg_read(UC_ARM_REG_PC)))
    def command(self,payload):
        frame=bytearray(64);frame[:4]=bytes((1,len(payload)+3,0xFF,0x57));frame[4:4+len(payload)]=payload
        self.u.mem_write(FRAME,bytes(frame));self.u.reg_write(UC_ARM_REG_R4,FRAME)
        self.reply=None;self.call('handler_start',0x57)
        assert self.reply is not None;return self.reply
    def config(self,wait=1000,lease=10000):
        return self.command(bytes((0x21,1,0,0))+u32(SESSION)+struct.pack('<HH',wait,lease))
    def poll(self):
        status,p=self.command(bytes((0x23,0,0,0))+u32(SESSION));assert status==0;return state(p)
    def start(self,request=123):return self.command(bytes((0x22,self.slot,0,0))+u32(SESSION)+u32(request))
    def answer(self,q,action='keys',session=SESSION,token=None,uid=UID):
        return self.command(bytes((0x25 if action=='decline' else 0x24,self.slot,0,0))+u32(session)+u32(q['token'] if token is None else token)+uid+(b'' if action=='decline' else KEYS))
    def prepare_rf(self):
        self.u.reg_write(UC_ARM_REG_R8,self.slot);self.call('rfid_pre_measure_settle_call_wrapper')
        self.u.mem_write(0x200001F0,bytes((0x80,0,self.slot,0)))
        self.u.mem_write(0x200037D2,b'\x01');self.u.mem_write(0x2000391C,bytes((4,self.slot)))
        self.u.mem_write(0x200001F8,b'\x04\x05\x06')
        self.uid_pair=observe_pair(self,UID,length=getattr(self,'uid_length',0))
        assert self.uid_pair['equal_branch'],self.uid_pair
        self.u.reg_write(UC_ARM_REG_R0,self.slot//2);self.u.reg_write(UC_ARM_REG_R1,self.slot%2);self.u.reg_write(UC_ARM_REG_R2,3)
        self.u.reg_write(UC_ARM_REG_SP,0x2000E000);self.u.reg_write(UC_ARM_REG_LR,RETURN)
    def validate(self,action='keys',stale_checks=False):
        self.prepare_rf();self.cooperative=True;pc=code(self.symbols['msg_validate_wrapper']);answered=False;offers=[]
        for step in range(400):
            self.returned=False;self.paused=False;self.u.emu_start(pc|1,RETURN,count=300000)
            if self.returned:break
            assert self.paused,hex(self.u.reg_read(UC_ARM_REG_PC))
            context=self.u.context_save();delay=self.u.reg_read(UC_ARM_REG_R0)
            self.cooperative=False;q=self.poll()
            if q['phase']==2 and not answered:
                offers.append(q)
                assert q['uid']==UID and q['session']==SESSION and q['token'] and q['remaining']
                if stale_checks:
                    assert self.command(bytes((7,self.slot//2,self.slot%2))+KEYS)[0]==7
                    assert self.command(bytes((8,self.slot//2,self.slot%2)))[0]==7
                    assert self.answer(q,session=SESSION+1)[0]==1
                    assert self.answer(q,token=q['token']+1)[0]==1
                    assert self.answer(q,uid=b'\x09'*4)[0]==1
                if action!='timeout':
                    assert self.answer(q,action)[0]==0
                    if action=='keys':assert self.answer(q,action)[0]==0
                    answered=True
            self.u.context_restore(context);self.set_time(self.now+max(1,delay));self.ret(self.u)
            pc=self.u.reg_read(UC_ARM_REG_PC);self.cooperative=True
        else:raise AssertionError('bounded handoff did not return')
        self.cooperative=False;return self.u.reg_read(UC_ARM_REG_R0),offers
    def finish(self,success=True):
        self.u.reg_write(UC_ARM_REG_R8,self.slot);self.u.reg_write(UC_ARM_REG_R5,0 if success else 3)
        self.u.reg_write(UC_ARM_REG_R9,int(success));self.u.reg_write(UC_ARM_REG_S16,bits(510))
        self.call('sgf_capture_wrapper')
        # Original worker finalizer, including force flag cleanup and delay300.
        self.call(0x080126CA)
        self.u.mem_write(0x200001F0,b'\x40\x00\x04\x00')
        self.call('rfh_tick');return self.poll()

def qualify(image,symbols):
    a=PhysicalArm(image,symbols)
    assert a.command(b'\x16')==(0,b'SGF1\x01\x04\x04\x1f\x40\x00\x14\x00')
    for slot in range(4):
        status,p=a.command(bytes((0x17,slot)));assert status==0 and len(p)==64 and p[:5]==b'SGD1'+bytes((slot,))
    status,p=a.command(b'\x20');assert status==0 and p==b'RHI1\x01\x28\x04\x07'+struct.pack('<HH',5000,10000)
    # Execute actual original heap initialization with modeled RTOS allocator.
    a=PhysicalArm(image,symbols);a.heap_mode=True
    a.u.mem_write(0x20006EE4,b'BEFR'+b'\xa5'*512+b'AFTR')
    a.call('heap_init_sidecar_wrapper')
    assert a.heap_seen==[(0x200070E8,0x20010000)],a.heap_seen
    assert bytes(a.u.mem_read(0x20006EE4,4))==b'BEFR'
    assert bytes(a.u.mem_read(0x200070E8,4))==b'AFTR'
    assert bytes(a.u.mem_read(0x20006F28,448))==bytes(448)
    successes=[]
    for slot in range(4):
        a=PhysicalArm(image,symbols,slot);assert a.config()[0]==0;assert a.poll()['flags']&3==3
        a.u.mem_write(0x20000025,b'\x00')
        status,p=a.start();assert status==0 and state(p)['phase']==1
        assert a.enqueue_calls==1 and a.u.mem_read(0x2000391C,1)[0]==0
        assert a.start()[0]==0 and a.enqueue_calls==1
        a.call(0x080134B8) # OEM FSM state0 consumes only the forced job, no motor.
        assert bytes(a.u.mem_read(0x2000391C,2))==bytes((3,slot))
        result,offers=a.validate(stale_checks=True)
        assert result==0 and a.auth_stock==3 and a.auth_override==[0,1,2]
        assert a.validator_calls==2 and len(offers)==1
        assert a.uid_pair['getter_returns']==[4,4] and a.uid_pair['record_byte75']==0
        assert a.uid_pair['compare_status']==1
        q=a.finish();assert q['phase']==4 and q['result']==2 and q['request']==123
        assert not q['flags']&4 and a.u.mem_read(0x20000025,1)[0]==0
        assert a.u.mem_read(0x20000030+slot,1)[0]==0
        a.call('rfh_tick');assert a.cleanup_calls==1
        status,p=a.command(bytes((0x17,slot)));assert status==0 and p[5]==19 and struct.unpack_from('<I',p,8)[0]==q['generation']
        assert a.command(bytes((0x18,1,0,0))+struct.pack('<IHHI',1,3000,5100,327000))[0]==0
        status,p=a.command(bytes((0x1A,slot,1,0))+UID+u32(q['generation'])+u32(1))
        assert status==0 and p[40]==100 and struct.unpack_from('<I',p,32)[0]==327000
        successes.append({'slot':slot,'stock_auth_failures':a.auth_stock,'api7_indices':a.auth_override,
                          'validators':a.validator_calls,'enqueue':a.enqueue_calls,'cleanup':a.cleanup_calls})
    endings={}
    for action,wanted in [('decline',3),('timeout',4)]:
        a=PhysicalArm(image,symbols);a.config();a.poll();result,_=a.validate(action)
        assert result and not a.auth_override
        q=a.finish(False);assert q['phase']==4 and q['result']==wanted;endings[action]=wanted
    for present,empty in [(False,True),(True,False)]:
        a=PhysicalArm(image,symbols);a.config();a.poll();a.pin_present=present;a.hub_empty=empty
        assert a.start()[0]==7 and not a.enqueue_calls
    return {'passed':True,'sha256':hashlib.sha256(image).hexdigest(),'actual_base':hex(ACTUAL_BASE),
            'nominal_alias':False,'ram_rebased':False,'gpr_data_rebased':False,'slots':successes,'endings':endings,
            'limits':['RF/GPIO and RTOS scheduling are modeled; mechanics and MCU latency are not qualified.']}

BASELINE_COMMIT='81b82dd79ceefb46e86b7aebf79c532f7eb53bc7'
BASELINE_SHA='b7cd0ab36011af9cd5af8f1ae4932008110a8fbdd174086c1a0043f2f5010158'

def historical_baseline(commit=BASELINE_COMMIT,expected_sha=BASELINE_SHA):
    """Rebuild the exact defective release; missing history is a test failure."""
    names=['handler.S','spool_family.c','rfid_handoff.c','build.py','preflight.py','link.ld']
    with tempfile.TemporaryDirectory(prefix='cfs-rh1-b7cd-') as temporary:
        folder=Path(temporary);source=folder/'firmware/cfg6-spool-profiles';source.mkdir(parents=True)
        for name in names:
            artifact='firmware/cfg6-spool-profiles/'+name
            command=['git','-C',str(ROOT),'show',commit+':'+artifact]
            fetched=subprocess.run(command,capture_output=True)
            assert fetched.returncode==0,('mandatory historical source unavailable',artifact,fetched.stderr.decode(errors='replace'))
            (source/name).write_bytes(fetched.stdout)
        built=subprocess.run([sys.executable,str(source/'build.py'),'--base',str(ROOT/'work/base-pinned.bin'),
                              '--out',str(folder/'baseline.bin'),'--build-dir',str(folder/'build')],capture_output=True,text=True)
        assert built.returncode==0,('mandatory b7cd reconstruction failed',(built.stdout+built.stderr)[-4000:])
        image=(folder/'baseline.bin').read_bytes()
        symbols=json.loads((folder/'build/symbols.json').read_text())
        assert hashlib.sha256(image).hexdigest()==expected_sha,'historical reconstruction SHA differs from the pinned firmware'
        return image,symbols

def run():
    ap=argparse.ArgumentParser();ap.add_argument('--image',type=Path,default=ROOT/'work/build/candidate.bin')
    ap.add_argument('--symbols',type=Path,default=ROOT/'work/build/symbols.json')
    ap.add_argument('--negative-image',type=Path);ap.add_argument('--negative-symbols',type=Path)
    ap.add_argument('--out',type=Path,default=ROOT/'work/build/rfid-handoff-physical-results.json');args=ap.parse_args()
    image=args.image.read_bytes();symbols=json.loads(args.symbols.read_text());result=qualify(image,symbols)
    if args.negative_image:
        assert args.negative_symbols is not None,'explicit historical image requires matching symbols'
        old_image=args.negative_image.read_bytes();old_symbols=json.loads(args.negative_symbols.read_text())
    else:
        old_image,old_symbols=historical_baseline()
    assert hashlib.sha256(old_image).hexdigest()==BASELINE_SHA,'negative control must be the exact b7cd firmware'
    a=PhysicalArm(old_image,old_symbols);a.config();a.poll()
    try:a.start()
    except UnrebasedTarget as exc:
        result['negative_control']={'source_commit':BASELINE_COMMIT,'sha256':BASELINE_SHA,'rejected':True,'reason':str(exc)}
    else:raise AssertionError('physical fixture accepted the old nominal-pointer firmware')
    args.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':run()
