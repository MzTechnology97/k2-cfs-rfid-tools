#!/usr/bin/env python3
"""
Read-only CFS RFID diagnostic client for the exact G32 / 153 API v2 patch.

No write/tag-format/UID mutation operations are implemented.
RAW_TRANSCEIVE is intentionally unavailable in API v2.
"""
import argparse, json, sys, time

HEAD=0xF7
COMMAND=0x57
STATUS={
  0:"ok",
  1:"bad_request",
  2:"request_or_no_tag",
  3:"anticollision_failed",
  4:"select_failed",
  5:"authentication_failed",
  6:"read_failed",
}
SUB={"info":0,"cache":1,"poll":2,"read-block":3,"read-block-auth":4}

def crc8(data):
    crc=0
    for value in bytes(data):
        crc ^= value
        for _ in range(8):
            crc=((crc<<1)^0x07)&0xff if crc&0x80 else (crc<<1)&0xff
    return crc

def build_frame(address,opcode,data=b"",status=0):
    data=bytes(data)
    if not 0<=address<=0xff: raise ValueError("address out of range")
    if len(data)>0xfc: raise ValueError("payload too long")
    body=bytes((len(data)+3,status,opcode))+data
    return bytes((HEAD,address))+body+bytes((crc8(body),))

def parse_frame(frame):
    frame=bytes(frame)
    if len(frame)<6 or frame[0]!=HEAD: raise ValueError("invalid frame/header")
    total=frame[2]+3
    if len(frame)!=total: raise ValueError(f"length mismatch: got {len(frame)}, expected {total}")
    if crc8(frame[2:-1])!=frame[-1]: raise ValueError("CRC mismatch")
    return {
      "address":frame[1],
      "length":frame[2],
      "status":frame[3],
      "opcode":frame[4],
      "data":frame[5:-1],
      "raw":frame,
    }

def read_frame(ser,timeout):
    deadline=time.monotonic()+timeout
    buf=bytearray()
    while time.monotonic()<deadline:
        n=getattr(ser,"in_waiting",0)
        if n: buf.extend(ser.read(n))
        else:
            chunk=ser.read(1)
            if chunk: buf.extend(chunk)
            else: time.sleep(0.002)
        while True:
            try: start=buf.index(HEAD)
            except ValueError:
                buf.clear(); break
            if start: del buf[:start]
            if len(buf)<3: break
            total=buf[2]+3
            if total<6:
                del buf[0]; continue
            if len(buf)<total: break
            candidate=bytes(buf[:total]); del buf[:total]
            try: return parse_frame(candidate)
            except ValueError: continue
    raise TimeoutError("no valid CFS response")

def decode_info(data):
    if len(data)!=6: raise ValueError("INFO requires 6 bytes")
    return {
      "api_version":data[0],
      "physical_readers":data[1],
      "slots_per_reader":data[2],
      "capabilities":{
        "cached_tag_info":bool(data[3]&1),
        "poll":bool(data[3]&2),
        "read_block":bool(data[3]&4),
        "read_block_auth_a":bool(data[3]&8),
        "cascade_level_2":bool(data[3]&16),
        "raw_transceive":False,
        "write":False,
      },
      "max_block_or_page":data[4],
      "cache_record_size":data[5],
    }

def decode_tag_record(data):
    if len(data)!=16: raise ValueError("tag record requires 16 bytes")
    atqa=data[0:2]
    cl1=data[2:6]
    cl2=data[6:10]
    bcc=data[13]
    sak=data[14]
    cascade=(cl1[0]==0x88)
    if cascade:
        uid=cl1[1:4]+cl2
        bcc_calc=cl2[0]^cl2[1]^cl2[2]^cl2[3]
        bcc_scope="cl2"
    else:
        uid=cl1
        bcc_calc=cl1[0]^cl1[1]^cl1[2]^cl1[3]
        bcc_scope="cl1"
    tech="ISO14443A"
    hint=None
    if sak==0x08: hint="MIFARE Classic 1K-like"
    elif sak==0x18: hint="MIFARE Classic 4K-like"
    elif sak==0x00: hint="Type-2/Ultralight/NTAG-like or other ISO14443A"
    return {
      "present_hint":any(data),
      "technology":tech,
      "atqa_hex":atqa.hex(),
      "uid_hex":uid.hex(),
      "uid_length":len(uid),
      "cl1_raw_hex":cl1.hex(),
      "cl2_raw_hex":cl2.hex(),
      "cascade_detected_from_ct":cascade,
      "bcc_hex":f"{bcc:02x}",
      "bcc_scope":bcc_scope,
      "bcc_current_valid":bcc_calc==bcc,
      "sak_hex":f"{sak:02x}",
      "type_hint":hint,
      "cache_raw_hex":data.hex(),
      "cache_layout_note":"offset13 BCC is reused by stock CL1/CL2 anticollision; offset14 is final SAK",
    }

def payload_for(op,reader=0,slot=0,block=None,key=None):
    if op=="info": return bytes((0,))
    if op=="cache": return bytes((1,reader,slot))
    if op=="poll": return bytes((2,reader,slot))
    if op=="read-block":
        if block is None or not 0<=block<=255: raise ValueError("block/page must be 0..255")
        return bytes((3,reader,slot,block))
    if op=="read-block-auth":
        if block is None or not 0<=block<=63: raise ValueError("block must be 0..63")
        k=bytes.fromhex(key or "")
        if len(k)!=6: raise ValueError("Key A must be exactly 6 bytes / 12 hex digits")
        return bytes((4,reader,slot,block))+k
    raise ValueError("unsupported operation")

def transact(args,op,block=None,key=None):
    if not 0<=args.reader<2 or not 0<=args.slot<2:
        raise ValueError("reader and slot must each be 0 or 1")
    payload=payload_for(op,args.reader,args.slot,block,key)
    req=build_frame(args.address,COMMAND,payload)
    if args.print_frame:
        return {"request_hex":req.hex(),"operation":op}
    if not args.port: raise ValueError("--port is required unless --print-frame is used")
    try: import serial
    except ImportError as e:
        raise RuntimeError("pyserial required: python -m pip install pyserial") from e
    kwargs=dict(port=args.port,baudrate=args.baud,timeout=0,write_timeout=1)
    if sys.platform!="win32": kwargs["exclusive"]=True
    with serial.Serial(**kwargs) as ser:
        ser.reset_input_buffer()
        ser.write(req); ser.flush()
        resp=read_frame(ser,args.timeout)
    if resp["opcode"]!=COMMAND:
        raise RuntimeError(f"unexpected response opcode 0x{resp['opcode']:02x}")
    out={
      "operation":op,
      "status":resp["status"],
      "status_name":STATUS.get(resp["status"],"unknown"),
      "address":resp["address"],
      "response_hex":resp["raw"].hex(),
      "data_hex":resp["data"].hex(),
    }
    if resp["status"]==0:
        if op=="info": out["info"]=decode_info(resp["data"])
        elif op in ("cache","poll"): out["tag"]=decode_tag_record(resp["data"])
        elif op.startswith("read-block"):
            if len(resp["data"])!=16: raise RuntimeError("successful read did not return 16 bytes")
            out["index"]=block
            out["raw_16_hex"]=resp["data"].hex()
    return out

def render(obj,fmt):
    if fmt=="json": return json.dumps(obj,indent=2)
    if fmt=="hex":
        if "raw_16_hex" in obj: return obj["raw_16_hex"]
        if "tag" in obj: return obj["tag"]["cache_raw_hex"]
        if "data_hex" in obj: return obj["data_hex"]
        return obj.get("request_hex","")
    lines=[f"operation: {obj.get('operation','')}"]
    if "request_hex" in obj:
        lines.append("request: "+obj["request_hex"]); return "\n".join(lines)
    lines.append(f"status: {obj['status']} ({obj['status_name']})")
    if "info" in obj:
        i=obj["info"]
        lines += [
          f"API v{i['api_version']}, readers={i['physical_readers']}, slots/reader={i['slots_per_reader']}",
          f"max block/page={i['max_block_or_page']}, cache record={i['cache_record_size']} bytes",
          "capabilities: "+", ".join(k for k,v in i["capabilities"].items() if v),
        ]
    if "tag" in obj:
        t=obj["tag"]
        lines += [
          f"technology: {t['technology']}",
          f"ATQA: {t['atqa_hex']}",
          f"UID: {t['uid_hex']} ({t['uid_length']} bytes)",
          f"SAK: {t['sak_hex']}",
          f"BCC({t['bcc_scope']}): {t['bcc_hex']} valid={t['bcc_current_valid']}",
          f"CL1 raw: {t['cl1_raw_hex']}",
          f"CL2 raw: {t['cl2_raw_hex']}",
          f"cache raw: {t['cache_raw_hex']}",
        ]
        if t["type_hint"]: lines.append("type hint: "+t["type_hint"])
    if "raw_16_hex" in obj:
        lines += [f"index: {obj['index']}", "raw: "+obj["raw_16_hex"]]
    return "\n".join(lines)

def main():
    ap=argparse.ArgumentParser(description="CFS 153 generic read-only RFID diagnostics")
    ap.add_argument("--port")
    ap.add_argument("--baud",type=int,default=230400)
    ap.add_argument("--address",type=lambda x:int(x,0),default=1)
    ap.add_argument("--reader",type=int,default=0)
    ap.add_argument("--slot",type=int,default=0)
    ap.add_argument("--timeout",type=float,default=2.0)
    ap.add_argument("--format",choices=("human","json","hex"),default="human")
    ap.add_argument("--print-frame",action="store_true")
    ap.add_argument(
        "--allow-active-rf",
        action="store_true",
        help="explicitly allow commands that start an RF transaction; INFO/CACHE stay passive",
    )
    sub=ap.add_subparsers(dest="cmd",required=True)
    for x in ("info","cache","poll","uid"): sub.add_parser(x)
    p=sub.add_parser("read-block"); p.add_argument("block",type=lambda x:int(x,0))
    p=sub.add_parser("read-page"); p.add_argument("page",type=lambda x:int(x,0))
    p=sub.add_parser("read-block-auth"); p.add_argument("block",type=lambda x:int(x,0)); p.add_argument("key")
    p=sub.add_parser("read-range"); p.add_argument("start",type=lambda x:int(x,0)); p.add_argument("count",type=int); p.add_argument("--key")
    p=sub.add_parser("dump"); p.add_argument("--start",type=lambda x:int(x,0),default=0); p.add_argument("--count",type=int,default=64); p.add_argument("--key")
    sub.add_parser("raw-transceive")
    a=ap.parse_args()
    try:
        active={"poll","uid","read-page","read-block","read-block-auth","read-range","dump"}
        if a.cmd in active and not a.allow_active_rf and not a.print_frame:
            raise RuntimeError(
                "active RF command refused: rerun with --allow-active-rf after verifying stock CFS RFID is idle"
            )
        if a.cmd=="raw-transceive":
            raise RuntimeError("RAW_TRANSCEIVE is intentionally disabled in diagnostic API v2 pending RF error/collision/CRC mapping")
        if a.cmd=="uid":
            obj=transact(a,"poll")
        elif a.cmd=="read-page":
            obj=transact(a,"read-block",a.page)
            obj["operation"]="read-page"
            obj["note"]="FM17622 stock primitive emits 0x30 and returns 16 bytes; on Type-2-like tags this corresponds to a 4-page window"
        elif a.cmd in ("read-range","dump"):
            start=a.start
            count=a.count
            limit=64 if a.key else 256
            if count<1 or start<0 or start+count>limit:
                raise ValueError(f"range must stay within 0..{limit-1}")
            items=[]
            op="read-block-auth" if a.key else "read-block"
            for idx in range(start,start+count):
                x=transact(a,op,idx,a.key)
                items.append(x)
                if x.get("status",0)!=0: break
            obj={"operation":a.cmd,"start":start,"requested_count":count,"items":items}
            if a.format=="hex":
                print("\n".join(x.get("raw_16_hex","") for x in items if x.get("status")==0)); return
            if a.format=="human":
                print(f"{a.cmd}: {len(items)} result(s)")
                for x in items:
                    print(f"[{x.get('index','?'):02}] {x.get('status_name','')} {x.get('raw_16_hex','')}")
                return
        elif a.cmd=="read-block-auth":
            obj=transact(a,a.cmd,a.block,a.key)
        elif a.cmd=="read-block":
            obj=transact(a,a.cmd,a.block)
        else:
            obj=transact(a,"cache" if a.cmd=="cache" else a.cmd)
        print(render(obj,a.format))
        if isinstance(obj,dict) and obj.get("status",0)!=0: raise SystemExit(2)
    except (ValueError,RuntimeError,TimeoutError) as e:
        raise SystemExit(str(e))

if __name__=="__main__":
    main()