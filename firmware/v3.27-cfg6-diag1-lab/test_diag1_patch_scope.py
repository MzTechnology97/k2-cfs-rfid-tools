#!/usr/bin/env python3
"""Verify DIAG1 patch scope: only metadata, BL targets and separate ARM handler.
No hardware access.
"""
import json,struct,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
BASE=0x08010000
OLD_ROOT=ROOT.parent/"v3.26-cfg6-type4-fix"
NEW=json.loads((ROOT/"static-validation.json").read_text())
OLD=json.loads((OLD_ROOT/"static-validation.json").read_text())
assert OLD["sha256"]=="7b45e5152fdd124a50fd29877a1a9ed595769107ba9fc009b2ba7d7388dbaceb"
old_image=(OLD_ROOT/"CFG6-TYPE4-RESCAN-FIX-NOT-FOR-FLASH.bin").read_bytes()
new_image=(ROOT/"CFG6-READONLY-DIAG1-NOT-FOR-FLASH.bin").read_bytes()
assert hashlib.sha256(old_image).hexdigest()==OLD["sha256"]
assert hashlib.sha256(new_image).hexdigest()==NEW["sha256"]
assert len(OLD["patches"])==len(NEW["patches"])==32
hooks={}
for old,new in zip(OLD["patches"],NEW["patches"]):
 assert old["callsite"]==new["callsite"] and old["symbol"]==new["symbol"]
 assert old["before"]==new["before"],(old,new)
 hooks[old["callsite"]]=(old,new)
assert len(hooks)==32
handler_addr=int(OLD["handler_addr"],16)
assert handler_addr==int(NEW["handler_addr"],16)
handler_off=handler_addr-BASE
assert len(old_image)>=handler_off and len(new_image)>len(old_image)
allowed=set(range(0x20C,0x212))  # CRC, length and version header metadata
for address in hooks:
 a=int(address,16)-BASE
 assert a>=0 and a+4<=handler_off
 allowed.update(range(a,a+4))
unintended=[BASE+i for i in range(handler_off)
             if old_image[i]!=new_image[i] and i not in allowed]
assert not unintended,[hex(a) for a in unintended[:24]]
assert new_image[0x200:0x20C]==old_image[0x200:0x20C]
assert NEW["cfs_runtime_diag_read_only"] is True
assert OLD["runtime_config_api"]["capability_mask"]==NEW["runtime_config_api"]["capability_mask"]=="0xE3"
print("PASS: 32 original hook callsites and semantics preserved")
print("PASS: no differences outside callsites, CRC/length metadata and handler region")
print("PASS: original Creality version, runtime feature bitset and image bounds")
