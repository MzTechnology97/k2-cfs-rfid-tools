#!/usr/bin/env python3
import argparse, hashlib, pathlib, struct, subprocess, tempfile, json

APP_BASE=0x08010000
HANDLER_ADDR=0x0803AE38
CRC_OFF=0x20C
LEN_OFF=0x20E
META_END=0x212
EXPECTED_BASE_SHA='5bab3acff49253a54089e779ea473d2cf587db09ab0d9c07c4d6c2e31b810388'

def run(*a): subprocess.check_call(list(map(str,a)))
def output(*a): return subprocess.check_output(list(map(str,a)),text=True)
def crc16_bypass(data):
    crc=0
    for value in data:
        crc ^= value<<8
        for _ in range(8):
            crc=(((crc<<1)^0x8005)&0xffff) if crc&0x8000 else ((crc<<1)&0xffff)
    return crc
def symbols(elf):
    d={}
    for line in output('arm-none-eabi-nm','-n',elf).splitlines():
        p=line.split()
        if len(p)==3:
            try:d[p[2]]=int(p[0],16)
            except ValueError:pass
    return d
def thumb_bl(src,dst):
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td)
        (td/'x.S').write_text('.syntax unified\n.thumb\n.cpu cortex-m3\n.section .text,"ax",%%progbits\n.global x\n.thumb_func\nx:\n bl 0x%08x\n'%dst)
        (td/'x.ld').write_text('SECTIONS { . = 0x%08x; .text : { *(.text) } }\n'%src)
        run('arm-none-eabi-gcc','-c','-mcpu=cortex-m3','-mthumb','-ffreestanding','-nostdlib','-o',td/'x.o',td/'x.S')
        run('arm-none-eabi-ld','-T',td/'x.ld','-o',td/'x.elf',td/'x.o')
        run('arm-none-eabi-objcopy','-O','binary',td/'x.elf',td/'x.bin')
        b=(td/'x.bin').read_bytes()
        if len(b)!=4: raise RuntimeError('bad BL size')
        return b

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--base',required=True)
    ap.add_argument('--out',required=True)
    args=ap.parse_args()
    here=pathlib.Path(__file__).resolve().parent
    base=pathlib.Path(args.base).read_bytes()
    if hashlib.sha256(base).hexdigest()!=EXPECTED_BASE_SHA:
        raise SystemExit('unexpected hardware-validated v3.3 base')
    off=HANDLER_ADDR-APP_BASE

    obj=here/'handler-v3_12.o'; elf=here/'handler-v3_12.elf'; raw=here/'handler-v3_12.bin'
    run('arm-none-eabi-gcc','-c','-mcpu=cortex-m3','-mthumb','-ffreestanding','-nostdlib','-o',obj,here/'handler-v3_12.S')
    run('arm-none-eabi-ld','-T',here/'link.ld','-o',elf,obj)
    run('arm-none-eabi-objcopy','-O','binary',elf,raw)
    handler=raw.read_bytes(); syms=symbols(elf)
    image=bytearray(base[:off]+handler)

    patches=[
      (0x0801A4CC,'legacy_read0_wrapper'),
      (0x0801A52C,'legacy_read1_wrapper'),
      (0x0801A590,'legacy_read2_wrapper'),
      (0x080225D0,'alt_read_wrapper'),
      (0x08022604,'alt_read_wrapper'),
      (0x08022638,'alt_read_wrapper'),
      (0x08012DDC,'uid_compare_wrapper'),
      (0x08012E62,'msg_validate_wrapper'),
      (0x08013380,'remaining_gate_wrapper'),
      (0x08013394,'remaining_init_wrapper'),
      (0x0801BF9E,'remaining_valid_wrapper'),
    ]
    report=[]
    for callsite,name in patches:
        target=syms[name]
        pos=callsite-APP_BASE
        before=bytes(image[pos:pos+4])
        patch=thumb_bl(callsite,target)
        image[pos:pos+4]=patch
        report.append((callsite,name,target,before.hex(),patch.hex()))

    struct.pack_into('<I',image,LEN_OFF,len(image))
    check=bytearray(image); check[CRC_OFF:META_END]=b'\0'*(META_END-CRC_OFF)
    crc=crc16_bypass(check)
    struct.pack_into('<H',image,CRC_OFF,crc)
    struct.pack_into('<I',image,LEN_OFF,len(image))
    pathlib.Path(args.out).write_bytes(image)

    allowed=set(range(CRC_OFF,META_END))
    for a,_,_,_,_ in report:
        allowed.update(range(a-APP_BASE,a-APP_BASE+4))
    allowed.update(range(off,max(len(base),len(image))))
    changed=[i for i in range(min(len(base),len(image))) if base[i]!=image[i]]
    unexpected=[i for i in changed if i not in allowed]
    if unexpected:
        raise SystemExit('unexpected changes: '+','.join(hex(APP_BASE+i) for i in unexpected[:16]))

    v={
      'base_v33_sha256':hashlib.sha256(base).hexdigest(),
      'sha256':hashlib.sha256(image).hexdigest(),
      'size':len(image),'handler_size':len(handler),'crc16':'0x%04X'%crc,
      'handler_addr':'0x%08X'%HANDLER_ADDR,
      'nominal_total_mm':330000,
      'initial_percent_source':'stock area_percent; K2RL pre-geometry latch + gate override at 0x08013380 + recover 0x20003974+slot when r9 passes 0xFF',
      'runtime_type':4,
      'patches':[{'callsite':'0x%08X'%a,'symbol':n,'target':'0x%08X'%t,'before':bef,'after':aft} for a,n,t,bef,aft in report],
      'unexpected_changed_bytes':len(unexpected),
      'tag_writes_added':False,
      'eeprom_writes_added':False,
      'host_extra_changes_required':False,
    }
    (here/'static-validation.json').write_text(json.dumps(v,indent=2)+'\n')
    print(json.dumps(v,indent=2))

if __name__=='__main__': main()
