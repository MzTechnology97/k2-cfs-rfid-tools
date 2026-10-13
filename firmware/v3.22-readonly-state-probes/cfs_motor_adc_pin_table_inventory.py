#!/usr/bin/env python3
"""Inventory OEM CFS RT-Thread pin IDs for confirmed PCB motor/ADC wiring.

No hardware read or firmware writes. The original 112-record pin table
is parsed only from SHA-pinned, offline saved APP images. A match shows
a board API lookup-table entry, NOT proof that firmware actually
configures ADC, drives that motor or samples its current.

The real owner confirmed that their CFS uses the same physical wiring
as the pinned public historical PCB. This is reported wiring evidence,
not authenticated electrical activity. No MCU SET/RESET is authorized.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE, audited

TABLE_PC = 0x0802AD5C
NUM_RECORDS = 0x70
RECORD_BYTES = 16

PORT_BASES = {
    "A":0x40010800,
    "B":0x40010C00,
    "C":0x40011000,
    "D":0x40011400,
    "E":0x40011800,
}
BLDC={"PWM":"PE13","FG_tach":"PE11","F_R":"PE3","SS_brake":"PE4"}
BRUSHED={
 "M1":{"IN1":"PD3","IN2":"PD2","current":"PC5","adc_channel_candidate":15},
 "M2":{"IN1":"PD1","IN2":"PD0","current":"PC0","adc_channel_candidate":10},
 "M3":{"IN1":"PD15","IN2":"PD14","current":"PA1","adc_channel_candidate":1},
 "M4":{"IN1":"PD13","IN2":"PD12","current":"PA0","adc_channel_candidate":0},
}
LOOKUP_KNOWN={"PE3":0x43,"PE4":0x44,"PE11":0x4b}
OWNERS={
    p:[] for p in dict.fromkeys(
      list(BLDC.values())+
      [signal[key] for signal in BRUSHED.values()
       for key in ("IN1","IN2","current")]
    )
}


def inventory(image:bytes):
    audited(image)
    begin=TABLE_PC-LINK_BASE
    end=begin+NUM_RECORDS*RECORD_BYTES
    if not 0<=begin<end<=len(image):
        raise ValueError("saved CFS manufacturer pin table out of image bounds")
    rows=[]
    for logical in range(NUM_RECORDS):
        at=begin+logical*RECORD_BYTES
        pin_id,clock,port,mask,encoded=struct.unpack_from("<HHIII",image,at)
        if port not in PORT_BASES.values():
            continue
        if mask==0 or mask & (mask-1) or mask>=0x10000:
            continue
        port_char=next(name for name,base in PORT_BASES.items() if base==port)
        pad=f"P{port_char}{mask.bit_length()-1}"
        if pad not in OWNERS:
            continue
        if pin_id!=logical:
            # Does not match the original API key: do not treat as
            # a proved logical-id association.
            continue
        row={
          "physical_pad":pad,
          "oem_RTThread_logical_pin":hex(logical),
          "manufacturer_record_ROM":hex(TABLE_PC+logical*RECORD_BYTES),
          "record_clock_selector":hex(clock),
          "record_pin_encoding":hex(encoded),
          "original_oem_record_matches_exact_target_pad":True,
          "actual_GPIO_or_ADC_register_sampled":False,
        }
        rows.append(row)
        OWNERS[pad] # no mutation, only source ordering
    by_pad={pad:[] for pad in OWNERS}
    for row in rows:
        by_pad[row["physical_pad"]].append(row)
    for pad,logical in LOOKUP_KNOWN.items():
        if [int(v["oem_RTThread_logical_pin"],16) for v in by_pad[pad]]!=[logical]:
            raise ValueError(f"independently pinned PE3/PE4/PE11 RT pin lookup mismatch: {pad}")
    return {
      "physical_ROM_APP_link_base":hex(LINK_BASE),
      "manufacturer_pin_table_ROM":hex(TABLE_PC),
      "manufacturer_table_max_logical_records":NUM_RECORDS,
      "BLDC_external_PCB_and_operator_reported_pads":BLDC,
      "four_brushed_driver_pads_from_external_PCB":BRUSHED,
      "resolved_oem_logical_records_by_confirmed_physical_pad":by_pad,
      "unresolved_pads_not_in_112_record_oem_table":[pad for pad,items in by_pad.items() if not items],
      "installed_CFS_matches_historical_PCB_wiring_operator_reported":True,
      "installed_CFS_wiring_independently_electrically_measured":False,
      "ADC_input_channels_from_datasheet_not_oem_read_code":True,
      "ADC_read_path_and_calibration_authenticated":False,
      "M1_M2_actual_motor_command_control_paths_authenticated":False,
      "all_motors_physically_stopped_proven":False,
      "v323_MCU_write_or_flash_authorized":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=inventory(pinned(a.v313,"intermediate_v313"))
    new=inventory(pinned(a.v322,"running_v322"))
    if old!=new:
        raise ValueError("manufacturer physical pin table differs between pinned CFS versions")
    result={
      "v313_v322_physical_pin_table_agreement":True,
      "v322":new,
      "no_live_CFS_CM5_Kalico_access":True,
      "no_firmware_or_peripheral_mutation":True,
      "motor_write_safety_release":False,
    }
    payload=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(payload)
    print(payload,end="")


if __name__=="__main__":
    main()
