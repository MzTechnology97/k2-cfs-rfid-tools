"""CFG6 offline ISA/ABI differential verification of all 15 new callsites."""
from pathlib import Path
import json,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UcError
from unicorn.arm_const import *
HERE=Path(__file__).resolve().parent
STOCK=(HERE.parent/"v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin").read_bytes()
MOD=(HERE/"CFG6-ALL-ADVANCED-LAB-NOT-FOR-FLASH.bin").read_bytes()
ADDR=0x08010000
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,
      UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
      UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_SP,UC_ARM_REG_LR]
SITES=[
("id9_timeout",0x08011CB6,9,5000,5500,"r1"),
("id11_speed",0x08012A9E,11,160,180,"speed"),
("id12_speed",0x08012AC0,12,120,150,"speed"),
("id13_speed",0x08012E8A,13,100,130,"speed"),
("id14_seek_duration",0x08012A76,14,800,1000,"r5"),
("id15_settle",0x08012AAE,15,200,250,"delay"),
("id16_post_auth",0x08012E7A,16,1000,1250,"delay"),
("id17_pre_measure",0x08012A60,17,400,500,"delay"),
("id18_neighbor_delay",0x0801304A,18,400,500,"r7"),
("id19_neighbor_settle",0x08013078,19,100,160,"delay"),
("id21_timeout_branchA",0x08032D46,21,3000,3500,"r1"),
("id21_timeout_branchB",0x08032DAC,21,3000,3500,"r1"),
("id23_neighbor_retry",0x0801307C,23,3,4,"cmp_r4"),
("id24_detooth_timeout",0x080108F0,24,1000,2000,"cmp_r5"),
("id27_load_retry",0x08012616,27,3,2,"loop")
]
def run(img,addr,id,val,kind,override=False,detooth_off=False):
    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    u.mem_map(0x08000000,0x40000)
    u.mem_write(ADDR,img)
    u.mem_map(0x20000000,0x10000)
    u.mem_write(0x20000014,struct.pack("<I",0x200037E2))
    u.mem_write(0x200037E2,bytes([0,255,100,200,0,155,255,80]))
    u.mem_write(0x20005005,b"\x6f")
    if override or detooth_off:
        index=id-7
        bits=(1<<index if override else 0)|(1<<21 if detooth_off else 0)
        u.mem_write(0x20006EE8,struct.pack("<II",0x35564643,bits))
        if override:u.mem_write(0x20006EE8+8+index*2,struct.pack("<H",val))
        if detooth_off:u.mem_write(0x20006EE8+50,b"\x00")
    u.reg_write(UC_ARM_REG_CPSR,0x33)
    for pos,r in enumerate(REGS):
        u.reg_write(r,(0x500+pos*167) if pos<13 else (0x2000E000 if r==UC_ARM_REG_SP else 0x0803F001))
    u.reg_write(UC_ARM_REG_R4,2)
    u.reg_write(UC_ARM_REG_R5,1500 if kind=="cmp_r5" else 1000)
    u.reg_write(UC_ARM_REG_R0,0x20005000 if kind=="load" else (val if not override and kind in ("speed","delay") else 0))
    if kind in ("speed","delay"):
        stock_val=next(q[3] for q in SITES if q[1]==addr)
        u.reg_write(UC_ARM_REG_R0,stock_val)
    u.reg_write(UC_ARM_REG_APSR,0xA0000000)
    results=[]
    finished=[]
    stop={0x080125B6,0x0801261A} if kind=="loop" else {addr+4}
    def on_code(cpu,pc,n,_):
        if pc in stop:
            finished.append(pc)
            cpu.emu_stop()
        elif pc in (0x0801E164,0x0802EE28):
            results.append((pc,cpu.reg_read(UC_ARM_REG_R0),
                            cpu.reg_read(UC_ARM_REG_R1),
                            cpu.reg_read(UC_ARM_REG_R2),
                            cpu.reg_read(UC_ARM_REG_R3)))
            cpu.reg_write(UC_ARM_REG_R0,0x1234)
            cpu.reg_write(UC_ARM_REG_PC,cpu.reg_read(UC_ARM_REG_LR))
    u.hook_add(UC_HOOK_CODE,on_code)
    try:u.emu_start(addr|1,0x0803F001,count=250)
    except UcError as exc:raise AssertionError((kind,hex(addr),"uc fault",str(exc),hex(u.reg_read(UC_ARM_REG_PC))))
    assert finished,(kind,hex(addr),"never returned",results)
    return [u.reg_read(r) for r in REGS],u.reg_read(UC_ARM_REG_APSR)&0xf0000000,results,finished[0]
checks=[]
for label,addr,id,old,val,kind in SITES:
    before=run(STOCK,addr,id,old,kind,False)
    baseline=run(MOD,addr,id,old,kind,False)
    changed=run(MOD,addr,id,val,kind,True)
    assert before[0][:14]==baseline[0][:14] and before[1:]==baseline[1:],(label,"default mismatches stock",before,baseline)
    if kind in ("speed","delay"):
        assert len(changed[2])==1 and changed[2][0][1]==val,(label,"changed callee arg",changed[2])
        assert before[0]==changed[0],(label,"callee changed regs")
    elif kind=="r1":
        assert changed[0][1]==val,(label,changed[0][1])
    elif kind=="r5":
        assert changed[0][5]==val,(label,changed[0][5])
    elif kind=="r7":
        assert changed[0][7]==val,(label,changed[0][7])
    elif kind=="loop":
        assert before[3]==0x080125B6 and baseline[3]==0x080125B6,(label,"baseline loop")
        assert changed[3]==0x0801261A,(label,"custom should exit")
        assert changed[1]!=baseline[1],(label,"custom cmp flags")

    elif kind in ("cmp_r4","cmp_r5"):
        assert changed[1]!=baseline[1],(label,"comparison flags unchanged")
    if kind not in ("cmp_r4","cmp_r5","loop"):
        assert baseline[1]==changed[1],(label,"unexpected APSR change",hex(baseline[1]),hex(changed[1]))
    changes=[i for i,(a,b) in enumerate(zip(before[0][:14],changed[0][:14])) if a!=b]
    allowed={"r1":[1],"r5":[5],"r7":[7],"loop":[],
             "speed":[],"delay":[],"cmp_r4":[],"cmp_r5":[]}[kind]
    assert changes==allowed,(label,"unexpected register mutation",changes,allowed)
    checks.append({"callsite":hex(addr),"id":id,"label":label,"stock_default":old,
                   "custom_value":val,"abi_stock_match":True,
                   "register_delta":changes,"flags_stock_match":True})
# ID6 sidecar flag really suppresses the stock de-tooth action via BLS
# (comparison N/Z/C/V), not merely a value readback.
normal=run(MOD,0x080108F0,24,1000,"cmp_r5",False)
disabled=run(MOD,0x080108F0,24,1000,"cmp_r5",False,True)
assert (normal[1]&0x40000000)==0,("normal detooth unexpectedly skipped",hex(normal[1]))
assert (disabled[1]&0x40000000)!=0,("ID6 disable failed to force stock BLS",hex(disabled[1]))
assert normal[0][:14]==disabled[0][:14],("ID6 bypass corrupted registers",)
checks.append({"id":6,"label":"reverse_detooth_disable_effect",
               "normal_flags":hex(normal[1]),"disabled_flags":hex(disabled[1]),
               "stock_BLS_action_skipped_when_disabled":True})
print(json.dumps({"pass":True,"tested_sites":len(checks),"cases":checks},indent=2))
