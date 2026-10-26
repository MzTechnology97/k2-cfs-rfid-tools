#!/usr/bin/env python3
"""Offline-only decoder for 0x57/0x15 experimental CFG6 snapshot."""
import argparse,json,math,struct
FMT = "<4s8BIIff4B"
# Stock instructions:
# 0x08018606: s0 = f32(RAM[0x200001AC]) * 0.0007886413368396461
# 0x0801B736: vneg.f32 s0, s0
# Coefficient from stock ROM at nominal address 0x080188B8.
STOCK_RAW_TO_MM = 0.0007886413368396461

assert struct.calcsize(FMT)==32
def decode(data):
 if len(data)!=32: raise ValueError(f"Expected 32 payload bytes, got {len(data)}")
 (magic,slot,active,box,hw,valid,kind,mode,latch,used,total,
  last,raw,initial,pct,stock_valid,status)=struct.unpack(FMT,data)
 if magic!=b"RDG1":raise ValueError("Invalid DIAG1 magic")
 if slot not in range(4):raise ValueError("Invalid MCU slot")
 current_mm = -raw * STOCK_RAW_TO_MM if math.isfinite(raw) else None
 delta_mm = current_mm-last if current_mm is not None and math.isfinite(last) else None
 return {
  "format":"RDG1","slot_zero_based":slot,"active_slot_zero_based":active,
  "box_state":box,"hw_secure_gate":hw,"runtime_valid":valid,
  "runtime_type":kind,"runtime_mode":mode,"runtime_latch":latch,
  "used_mm":used,"total_mm":total,"last_odometer_f32":last,
  "raw_cached_odometer_f32":raw,
  "odometer_normalized_current_approx_mm":current_mm,
  "odometer_delta_since_checkpoint_approx_mm":delta_mm,
  "initial_percent":initial,
  "cfs_percent_table":pct,"stock_getter_marker":stock_valid,
  "runtime_status":status,
  "type4_gate_conditions_allow":bool(hw==1 or (active==slot and valid==1
     and kind==4 and mode==1 and total>=10000 and 1<=initial<=100)),
  "cautions":[
   "Gate conditions are a snapshot, not a counter of actual executions.",
   "Normalized current is derived offline using the stock vneg and float coefficient.",
   "Snapshot is not atomic; small apparent deltas may be distorted by concurrent updates.",
   "CFS firmware percent may differ from Kalico interpolated percent.",
  ]}
if __name__=="__main__":
 parser=argparse.ArgumentParser()
 parser.add_argument("payload_hex",help="32-byte hex payload, without RS-485 frame")
 args=parser.parse_args()
 print(json.dumps(decode(bytes.fromhex(args.payload_hex.replace(" ",""))),indent=2))
