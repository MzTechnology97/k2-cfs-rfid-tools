#!/usr/bin/env python3
"""Reconcile legacy CFS Runtime Config units/motor effect with verified OEM ARM.

The OpenCFS PR47 research observed that some existing catalog names
misrepresent actual stock units/effects. This source-only regression
checks against two SHA-pinned OEM APP generations, and verifies the
latest v3.23 config write fence still denies motor-unsafe SET/RESET.
No host Kalico edits, no live MCU, no persistent firmware output.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path

from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE
from cfs_oem_four_brushed_motor_pin_provenance_audit import (
    decode_ram,inspect as original_motor_source,MOTOR_BASE,MOTOR_STRIDE,
)
from cfs_v323_raw_gpio_feeder_drive_snapshot_candidate import build as current_v323_build
from cfs_v323_safe_config_readonly_preview import invoke_host_config

OEM_DELAY=0x08021E28
OEM_WAIT_HUB_SENSOR=0x0800E85A
# Recovered physical instructions, NOT old nominal build-site addresses.
OEM_BRANCHES={
    0x0800E87E:("movs","r0, #0xa"),
    0x0800E880:("bl",f"#{OEM_DELAY:#x}"),
    0x080048C8:("mov.w","r1, #0x2bc"),
    0x080048CE:("bl",f"#{OEM_WAIT_HUB_SENSOR:#x}"),
    0x08004E10:("movs","r3, #0xa"),
    0x08004E14:("mov.w","r1, #0x3e8"),
    0x08004E1A:("bl",f"#{OEM_WAIT_HUB_SENSOR:#x}"),
    0x080042E6:("mov.w","r8, #0x12c"),
    0x080042EE:("mov","r1, r8"),
    0x080042F2:("bl",f"#{OEM_WAIT_HUB_SENSOR:#x}"),
    0x080048A4:("movs","r1, #0x32"),
    0x080048A8:("bl",f"#{OEM_WAIT_HUB_SENSOR:#x}"),
    0x080048BA:("mov.w","r7, #0x12c"),
    0x08005E54:("mov.w","r0, #0x1f4"),
    0x08005E58:("bl",f"#{OEM_DELAY:#x}"),
    0x08006072:("bl","#0x800d27a"),
    0x08006076:("movs","r0, #0x64"),
    0x08006078:("bl",f"#{OEM_DELAY:#x}"),
    0x0800607C:("adds","r4, r4, #1"),
    0x08006080:("blo","#0x800604e"),
    0x08010054:("push.w","{r4, r5, r6, r7, r8, lr}"),
    0x080101EA:("ldrb","r0, [r4, #4]"),
    0x080101EE:("bl","#0x8018eec"),
    0x08010204:("ldrb","r0, [r4, #4]"),
    0x08010206:("bl","#0x8018eec"),
    0x0801020A:("ldrb","r0, [r4, #5]"),
    0x0801020E:("bl","#0x8018eec"),
}
LEGACY_MOTOR_PINS=((0x32,0x33),(0x30,0x31),(0x3e,0x3f),(0x3c,0x3d))
LEGACY_PHYSICAL_FEEDER_PINS=((2,3),(0,1),(14,15),(12,13))
CONFIG_NO_EFFECT_FEEDER_SPEED_IDS=(0,4)
EFFECTIVE_IDS_IN_CURRENT_V323=(7,8)
STORAGE_ONLY_IDS_IN_CURRENT_V323=tuple(range(9,28))
OEM_10MS_POLL_IDS=(8,10)
OPEN_CFS_PORT_CHECKPOINT="40138228ebd31d0e46364667d5e7d80e7c0b9e5c"
APPEND_OLD_NOMINAL_TO_PHYSICAL_DELTA=0xD000

def decode_ins(app:bytes,pc:int)->tuple[str,str]:
    pos=pc-LINK_BASE
    if pos<0 or pos+4>len(app):
        raise ValueError("OEM site outside pinned original APP")
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    ins=next(decoder.disasm(app[pos:pos+4],pc,count=1),None)
    if not ins:
        raise ValueError(f"missing OEM Thumb instruction {pc:#x}")
    return ins.mnemonic,ins.op_str

def inspect_generation(app:bytes)->dict:
    for pc,exp in OEM_BRANCHES.items():
        got=decode_ins(app,pc)
        if got!=exp:
            raise ValueError(f"original OEM physical Thumb instruction {pc:#x}: {got}!={exp}")
    motor=original_motor_source(app)
    if len(motor["original_brushed_motor_records"])!=4:
        raise ValueError("four initialized feeder records not recovered")
    ram=decode_ram(app)
    records=[]
    for i,pair in enumerate(LEGACY_MOTOR_PINS):
        start=MOTOR_BASE-0x20000000 + i*MOTOR_STRIDE
        if tuple(ram[start+4:start+6])!=pair:
            raise ValueError("source feeder output pin pair changed")
        if ram[start]!=0 or any(struct.unpack_from("<I",ram,start+field)[0]
                               for field in (0x08,0x14)):
            raise ValueError("source feeder unexpectedly configured for PWM")
        if struct.unpack_from("<H",ram,start+0xA8)[0]!=0:
            raise ValueError("initial feeder commanded speed no longer zero")
        if struct.unpack_from("<H",ram,start+0xAA)[0]!=0:
            raise ValueError("initial feeder direction no longer zero")
        records.append({
            "slot":i,
            "OEM_motor_RAM_record":hex(MOTOR_BASE+i*MOTOR_STRIDE),
            "feeder_PWM_flag":0,
            "feeder_PWM_driver_pointers_zero":True,
            "original_pin_IDs":[hex(x) for x in pair],
            "physical_GPIOD_pins":[f"PD{x}" for x in LEGACY_PHYSICAL_FEEDER_PINS[i]],
            "last_commanded_speed_field":hex(MOTOR_BASE+i*MOTOR_STRIDE+0xA8),
            "direction_field":hex(MOTOR_BASE+i*MOTOR_STRIDE+0xAA),
            "speed_nonzero_is_proportional_control":False,
            "physical_rotation_measured":False,
        })
    return {
        "physical_ROM_site_CRC_checked":True,
        "CFS_original_sensor_poll_delay_ms":10,
        "id_8_initial_raw":700,
        "id_8_effective_timeout_approx_ms":700*10,
        "id_8_catalog_ms_unit_is_wrong":True,
        "id_10_initial_raw":1000,
        "id_10_effective_timeout_approx_ms":1000*10,
        "id_10_catalog_ms_unit_is_wrong":True,
        "id_26_original_builder_hook_nominal":"0x80112e6",
        "id_26_physical_hook_PC":"0x80042e6",
        "id_26_raw_default":300,
        "id_26_raw_register":"r8",
        "id_26_call_wait_hub_sensor":"0x80042f2",
        "id_26_timeout_approx_ms":3000,
        "id_26_catalog_ms_unit_is_wrong":True,
        "id_26_different_50poll_call_at":"0x80048a8",
        "id_26_different_50poll_timeout_approx_ms":500,
        "id_26_different_700poll_call_at":"0x80048ce",
        "id_26_different_700poll_timeout_approx_ms":7000,
        "id_26_source_r7_300_not_argument_for_0x80048a8":True,
        "id_19_physical_nominal_builder_hook":hex(0x08013078-APPEND_OLD_NOMINAL_TO_PHYSICAL_DELTA),
        "id_19_100ms_source_at":hex(0x08006076),
        "id_19_delay_CALL_at":hex(0x08006078),
        "different_500ms_DELAY_source":hex(0x08005E54),
        "different_500ms_DELAY_CALL":hex(0x08005E58),
        "id_19_source_is_100ms_delay_not_500ms":True,
        "id_19_wait_preceded_by_motor_stop":True,
        "id_0_and_id_4_stock_speed_is_effectively_binary_on_off":True,
        "id_0_and_id_4_stock_writable_speed_is_unproven":True,
        "four_oem_GPIO_feeder_records":records,
        "motor_turned_off_or_braked_is_physically_stationary_proof":False,
    }

def negatives(app:bytes)->list[str]:
    names=[]
    for pc,label in (
        (0x0800E87E,"change_sensor_loop_10ms"),
        (0x080048C8,"change_insert_sensor_raw700"),
        (0x08004E14,"change_parse_out_raw1000"),
        (0x08006076,"change_id19_100ms"),
        (0x08005E54,"change_separate_500ms"),
        (0x08006078,"corrupt_id19_delay_target"),
        (0x080101EE,"corrupt_feeder_direct_GPIO_writer"),
        (0x080042E6,"change_id26_original_300raw_source"),
        (0x080048A4,"change_other_50raw_sensor_source"),
        (0x080048BA,"change_unrelated_r7_300_source"),
    ):
        b=bytearray(app)
        b[pc-LINK_BASE]^=1
        try:inspect_generation(bytes(b))
        except ValueError:names.append(label)
        else:raise AssertionError("source mutation not detected "+label)
    if len(names)!=10:
        raise ValueError("expected 10 rejected OEM timing/GPIO corruptions")
    return names

def main()->None:
    p=argparse.ArgumentParser()
    for name in ("v313","v322","asm","linker","builder"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    v313=pinned(a.v313,"intermediate_v313")
    v322=pinned(a.v322,"running_v322")
    # Running OEM-v3.22-derived firmware has the original v3.13 ID8
    # MOV.W 700 replaced by an experimental Thumb BL to the config
    # wrapper, a known/authorized difference distinct from stock #700
    # site 0x080048C8, which remains unmodified in BOTH images.
    if decode_ins(v313,0x080042CA)!=("mov.w","r1, #0x2bc"):
        raise ValueError("v3.13 original ID8 callsite must initialize 700 raw polls")
    if decode_ins(v322,0x080042CA)!=("bl","#0x802e7cc"):
        raise ValueError("installed v3.22 ID8 wrapper at physical callsite has changed")
    # The old v3.14 source lists the exact ID26 R8 hook under nominal
    # old APP placement 0x08010000; physical position is minus 0xD000.
    if "(0x080112E6,'cfg26_r8_wrapper')" not in a.builder.read_text():
        raise ValueError("ID26 old nominal physical R8 hook mapping changed")
    first=inspect_generation(v313)
    second=inspect_generation(v322)
    if first!=second:
        raise ValueError("v3.13/v3.22 OEM motor/timing instructions differ")
    image,stage,syms=current_v323_build(
        v313,v322,a.asm.read_text(),a.linker.read_text(),
        a.builder.read_text(),a.builder
    )
    if (stage["new_gpio_latch_preview_APP_bytes"]!=178568 or
        stage["new_opcode"]!="0x57/0x18" or
        not stage["CONFIG_SET_RESET_fenced"]):
        raise ValueError("latest #52 source-only firmware baseline changed")
    # Host may ask SET even with apparently stopped GPIO and empty FG:
    # the current firmware must still deny all writes, even in idle.
    denied=[
        invoke_host_config(image,syms,cmd,state,0x35564643,0xffffffff)
        for state in (0,1,2,3,4,5) for cmd in (0x12,0x13)
    ]
    if len(denied)!=12 or any(x["status"]!=7 or
         x["sidecar_changed"] or x["nonstack_writes"] for x in denied):
        raise ValueError("OEM runtime CONFIG returned writable after findings")
    out={
        "source_checkpoints":{"OpenCFS_PR5":OPEN_CFS_PORT_CHECKPOINT,
                              "OEM_original_app_base":hex(LINK_BASE)},
        "source_v313_and_v322_match":True,
        "id8_physical_stock_source":"0x80042ca",
        "id8_stock_v313_700_RAW_polls_replaced_by_current_v322_BL":True,
        "id8_running_v322_hook_target":"0x802e7cc",
        "independent_other_700_raw_polls_callsite":"0x80048c8",
        "ID26_nominal_builder_R8_hook_matches_installed_physical":"0x80042e6",
        "OEM_findings":second,
        "OEM_negative_fixtures_rejected":negatives(v322),
        "current_v323_feature_candidate_APP_bytes":len(image),
        "current_v323_firmware_CONFIG_SET_RESET_denied_all_BOX_STATES":denied,
        "ids_8_and_10_over_wire_have_no_unit_or_format_change":True,
        "ids_0_and_4_should_be_readonly_on_GPIO_only_stock_feeders":True,
        "id_19_100ms_is_a_real_delay_hook_candidate_not_currently_enabled":True,
        "current_v323_effective_timing_ids":[7,8],
        "current_v323_advanced_storage_only_ids":list(STORAGE_ONLY_IDS_IN_CURRENT_V323),
        "current_Kalico_existing_extra_unchanged":True,
        "no_flash_or_MMIO_motor_actions":True,
        "no_release_approval":True,
        "persistent_binary_exported":False,
    }
    val=json.dumps(out,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(val)
    print(val,end="")
if __name__=="__main__":main()
