#!/usr/bin/env python3
from pathlib import Path
import argparse, hashlib, json, re
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

EXPECTED_SOURCE_SHA = "5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea"
APP_BASE = 0x08010000
HOOK_OFFSET = 0xC3A0
HOOK_ADDR = APP_BASE + HOOK_OFFSET
ORIGINAL_HOOK = bytes.fromhex("2ae2afe1")
EXPECTED_CALLS = {
    0x0801914C: "rfid_mode_cleanup",
    0x0801959E: "reader_probe",
    0x080195D8: "mifare_auth_key_a",
    0x08019824: "mifare_read_block",
    0x0801BAF2: "rs485_response",
}
EXPECTED_JUMPS = {0x0801C808, 0x0801C704, 0x0801C7F8}
FORBIDDEN = {
    0x0801970E: "mifare_write_block",
    0x08017F7E: "bl24cxx_write",
}

def h(b): return hashlib.sha256(b).hexdigest()

def imm(op):
    m=re.search(r"#?(0x[0-9a-fA-F]+|\d+)",op)
    return int(m.group(1),0) if m else None

def reconstruct_veneers(ins):
    found=[]
    i=0
    while i+2<len(ins):
        a,b,c=ins[i:i+3]
        if a.mnemonic=="movw" and b.mnemonic=="movt" and c.mnemonic in ("blx","bx"):
            if a.op_str.startswith("ip,") and b.op_str.startswith("ip,") and c.op_str=="ip":
                lo=imm(a.op_str); hi=imm(b.op_str)
                if lo is not None and hi is not None:
                    raw=(hi<<16)|lo
                    found.append({
                        "address":a.address,
                        "kind":"call" if c.mnemonic=="blx" else "jump",
                        "raw":raw,
                        "target":raw & ~1,
                        "thumb":bool(raw&1),
                    })
                    i+=3
                    continue
        i+=1
    return found

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--source",required=True)
    ap.add_argument("--patched",required=True)
    ap.add_argument("--manifest",required=True)
    ap.add_argument("--report",required=True)
    a=ap.parse_args()
    src=Path(a.source).read_bytes()
    out=Path(a.patched).read_bytes()
    man=json.loads(Path(a.manifest).read_text())
    errors=[]
    if h(src)!=EXPECTED_SOURCE_SHA: errors.append("source SHA mismatch")
    if src[HOOK_OFFSET:HOOK_OFFSET+4]!=ORIGINAL_HOOK: errors.append("source hook bytes mismatch")
    if len(out)<=len(src): errors.append("patched image did not append handler")
    changed=[i for i,(x,y) in enumerate(zip(src,out[:len(src)])) if x!=y]
    expected_changed=list(range(HOOK_OFFSET,HOOK_OFFSET+4))
    if changed!=expected_changed:
        errors.append(f"unexpected changes in original image: {changed[:64]}")
    handler_off=int(man["handler"]["offset"],16)
    handler_addr=int(man["handler"]["address"],16)
    handler_size=man["handler"]["size"]
    if handler_off<len(src): errors.append("handler overlaps stock image")
    if handler_off+handler_size!=len(out): errors.append("handler extent/output size mismatch")
    if handler_addr!=APP_BASE+handler_off: errors.append("handler runtime address mismatch")

    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    hook=list(md.disasm(out[HOOK_OFFSET:HOOK_OFFSET+4],HOOK_ADDR))
    if len(hook)!=1 or hook[0].mnemonic!="b.w":
        errors.append("hook is not one B.W")
        hook_target=None
    else:
        hook_target=imm(hook[0].op_str)
        if hook_target!=handler_addr: errors.append(f"hook target mismatch: {hook_target!r}")

    handler=out[handler_off:handler_off+handler_size]
    ins=list(md.disasm(handler,handler_addr))
    if not ins or ins[-1].address+len(ins[-1].bytes)!=handler_addr+handler_size:
        errors.append("handler disassembly does not cover full handler")

    veneers=reconstruct_veneers(ins)
    calls={v["target"] for v in veneers if v["kind"]=="call"}
    jumps={v["target"] for v in veneers if v["kind"]=="jump"}
    if calls!=set(EXPECTED_CALLS):
        errors.append("external call allowlist mismatch: "+repr(sorted(hex(x) for x in calls)))
    if jumps!=EXPECTED_JUMPS:
        errors.append("stock jump target mismatch: "+repr(sorted(hex(x) for x in jumps)))
    if any(not v["thumb"] for v in veneers):
        errors.append("non-Thumb veneer target")
    bad=[{"target":hex(v["target"]),"name":FORBIDDEN[v["target"]]} for v in veneers if v["target"] in FORBIDDEN]
    if bad: errors.append("forbidden veneer target present: "+repr(bad))

    # Any direct BL in the appended handler must stay inside the handler; external
    # calls are required to use validated literal veneers.
    direct_external=[]
    for x in ins:
        if x.mnemonic=="bl":
            t=imm(x.op_str)
            if t is not None and not (handler_addr<=t<handler_addr+handler_size):
                direct_external.append((x.address,t))
    if direct_external: errors.append("unexpected direct external BL: "+repr(direct_external))

    # 512 KiB GD32F303VET6 and application base 0x08010000 imply a theoretical
    # app-address ceiling of 0x08080000. This is capacity evidence only; loader
    # acceptance is still a hardware-validation item.
    if APP_BASE+len(out)>0x08080000:
        errors.append("output exceeds MCU flash address ceiling")

    report={
      "ok":not errors,
      "errors":errors,
      "source_sha256":h(src),
      "patched_sha256":h(out),
      "source_size":len(src),
      "patched_size":len(out),
      "changed_original_offsets":[hex(x) for x in changed],
      "hook":{"address":hex(HOOK_ADDR),"target":hex(hook_target) if hook_target is not None else None},
      "handler":{"address":hex(handler_addr),"size":handler_size,"instruction_count":len(ins)},
      "external_calls":[{"address":hex(x),"name":EXPECTED_CALLS[x]} for x in sorted(calls) if x in EXPECTED_CALLS],
      "stock_jumps":[hex(x) for x in sorted(jumps)],
      "forbidden_targets":bad,
      "direct_external_bl":direct_external,
      "flash_performed":False
    }
    Path(a.report).write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if not errors else 2)

if __name__=="__main__":
    main()