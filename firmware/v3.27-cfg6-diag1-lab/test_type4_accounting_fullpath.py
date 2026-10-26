"""End-to-end *offline* stock CFS type-4 manager path:
RS485 print start state -> patched slot gate -> full stock accounting math
-> setter that feeds 0x03. External odometer and diagnostic LOG functions
are emulated. No CM5 printer communication or physical motion.
"""
from pathlib import Path
import json,struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UcError
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parent
STOCK=(ROOT.parent/"v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin").read_bytes()
TRIAL=(ROOT/"CFG6-READONLY-DIAG1-NOT-FOR-FLASH.bin").read_bytes()
SLOTBASE=0x20004590
START=0x08013684
TASK=0x0801AC94
RETURN=0x08013690
LOG=0x0802D074
ODOM=0x0801B730
SET=0x080123E4
U32=lambda f:struct.unpack("<I",struct.pack("<f",f))[0]
R32=lambda b:struct.unpack("<I",b)[0]
def scenario(rom,kind,delta,secure=0,slot=1,initial=42,old_used=0,first_odom=100.0,active=True,mode=1):
    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    u.mem_map(0x08000000,0x40000)
    u.mem_write(0x08010000,rom)
    u.mem_map(0x20000000,0x10000)
    u.mem_write(0x20000000,bytes((secure,)))
    u.mem_write(0x200001F2,bytes((slot,)))
    u.mem_write(0x200001F3,bytes((initial,)))
    u.mem_write(0x20003974+slot,bytes((initial,)))
    u.mem_write(0x2000391C+slot+2,b"\x01") # Stock 0x03 getter validity marker
    row=SLOTBASE+100*slot
    def w(at,data):u.mem_write(at,data)
    w(row,struct.pack("<I",old_used))
    w(row+4,struct.pack("<I",330000))
    w(row+12,struct.pack("<f",first_odom))
    w(row+20,bytes((initial,0,mode,int(active))))
    w(row+99,bytes((kind,)))
    u.mem_write(0x20000014,struct.pack("<I",0x200037E2))
    u.mem_write(0x200037E2,bytes([0,255,100,200,0,155,255,80]))
    u.reg_write(UC_ARM_REG_CPSR,0x33)
    u.reg_write(UC_ARM_REG_FPEXC,0x40000000)
    u.reg_write(UC_ARM_REG_FPSCR,0)
    u.reg_write(UC_ARM_REG_SP,0x2000EF00)
    u.reg_write(UC_ARM_REG_LR,0x0803F001)
    events=[]
    seen=[]
    # Captures behaviour of the stock % setter that CMD 0x03 then reads.
    def on_code(c,addr,size,data):
        if addr==TASK:seen.append("task")
        if addr==0x0801367A and "task" not in seen:seen.append("skip");c.emu_stop();return
        if addr==RETURN:
            seen.append("return");c.emu_stop();return
        if addr==ODOM:
            c.reg_write(UC_ARM_REG_S0,U32(first_odom+delta))
            c.reg_write(UC_ARM_REG_PC,c.reg_read(UC_ARM_REG_LR))
            events.append(("odom",round(first_odom+delta,2)))
            return
        if addr==LOG:
            c.reg_write(UC_ARM_REG_PC,c.reg_read(UC_ARM_REG_LR))
            return
        if addr==SET:
            sl=c.reg_read(UC_ARM_REG_R0)
            pct=c.reg_read(UC_ARM_REG_R1)
            if sl!=slot or pct>100:raise AssertionError(("invalid setter",sl,pct,slot))
            events.append(("stock_setter_enter",sl,pct))
            # Execute original stock setter instructions, unmodified.
        # Stop after stock percent recalculation, rather than invoking RFID backend.
        if addr==0x0801AE3E:
            events.append(("after_stock_setter",))
            seen.append("completed_percentage_path");c.emu_stop()
    def record_write(c,access,addr,size,val,other):
        if (addr <= 0x200001F3 < addr + size) or (addr <= row+20 < addr+size):
            events.append(("raw_write",hex(addr),size,hex(val),hex(c.reg_read(UC_ARM_REG_PC))))
    u.hook_add(UC_HOOK_MEM_WRITE,record_write)
    u.hook_add(UC_HOOK_CODE,on_code)
    try:u.emu_start(START|1,0x0803F001,count=15000)
    except UcError as e:raise AssertionError(("unicorn exception",str(e),hex(u.reg_read(UC_ARM_REG_PC)),events,seen))
    u.reg_write(UC_ARM_REG_R0,slot)
    u.reg_write(UC_ARM_REG_LR,0x0803F001)
    u.reg_write(UC_ARM_REG_SP,0x2000EF00)
    u.emu_start(0x080123CE|1,0x0803F001,count=100)
    stock_get=u.reg_read(UC_ARM_REG_R0)
    def u32(addr):return R32(u.mem_read(addr,4))
    return dict(seen=seen,events=events,used_mm=u32(row),
                odom=struct.unpack("<f",u.mem_read(row+12,4))[0],
                mode=u.mem_read(row+22,1)[0],
                percent=u.mem_read(0x20003974+slot,1)[0],
                cmd03_getter=stock_get,initial=initial)

checks=[]
scenarios=[
    ("type4 5mm below threshold",TRIAL,4,5,0,0),
    ("type4 25mm no whole percent",TRIAL,4,25,0,25),
    ("type4 4100mm percent should drop",TRIAL,4,4100,0,4100),
    ("type7 no chip blocked",TRIAL,7,4100,0,0),
    ("stock type4 no chip blocked",STOCK,4,4100,0,0),
    ("type4 secure chip original pass",STOCK,4,4100,1,4100)
]
for desc,rom,kind,delta,secure,used in scenarios:
 v=scenario(rom,kind,delta,secure=secure)

 assert v["used_mm"]==used,(desc,v)
 assert v["cmd03_getter"]==v["percent"],(desc,"stock 0x03 getter mismatch",v)
 if used>=3300:
  assert v["percent"]==41,(desc,v)
 else:assert v["percent"]==42,(desc,v)
 if used==0 and (kind==7 or rom is STOCK and not secure):assert "skip" in v["seen"],(desc,v)
 elif used >= 3300:assert "completed_percentage_path" in v["seen"],(desc,v)
 checks.append({"test":desc,**v})
print(json.dumps({"pass":True,"cases":checks},indent=2))
