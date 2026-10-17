#!/usr/bin/env python3
"""CFS v3.23 *offline* final-image / loader-geometry preflight.

Fully rebuild the current v3.23 OEM+RFID+safe-readonly diagnostic
candidate from pinned v3.13/v3.22 APPs; validate image header/CRC,
vectors, preserved stock reader/secure code, physical Flash page
geometry, and MOTOR CONFIG SET/RESET fail-closed response.

This script does not output BIN/HEX/ELF, issue RS485/flash commands,
read production hardware, or edit Klipper/Kalico. Passing preflight
means only "syntactically reproducible image ready for controlled
hardware qualification", NOT safe/authorized to flash.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import struct

from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned,crc16_bypass
from cfs_app_real_link_base_audit import LINK_BASE,audited
from cfs_v323_raw_gpio_feeder_drive_snapshot_candidate import (
    build as build_latest, run as gpio_snapshot,
    GPIOD_OCTL, GPIOE_OCTL,
)
from cfs_v323_safe_config_readonly_preview import invoke_host_config

BOOT_START=0x08000000
APP_START=0x08003000
PARAM_START=0x0807F800
FLASH_END=0x08080000
PAGE=2048
HOST_CHUNK=128
FLASH_BUFFER=256
CRC_OFF=0x20C
LEN_OFF=0x20E
META_END=0x212
EXPECTED_BYTES=178568
EXPECTED_SHA="946197ff853762815d5e5d9b3c0827469b0a916ec49491334a65552bf58773d1"
EXPECTED_CRC=0xBA83
KNOWN_UNCHANGED_OEM_FUNCTIONS={
    # Original manufacturer RFID reader backend/init selectors and
    # secure dependent handlers: *must not* be silently rewritten.
    "reader_secure_select0":0x0800D624,
    "reader_secure_select1":0x0800D694,
    "secure_module_init":0x0800666E,
    "original_slot_removed_notifier":0x08005654,
    "original_remain_clear":0x0800DC70,
    "original_percent_set":0x080053E4,
    "original_secure_detect":0x0800D83E,
    "original_secure_consumption_writer":0x08015A42,
}

def check_geometry(start:int,image_len:int)->dict:
    """Hard fail on ALL loader, parameter, 512-KiB boundary overlaps."""
    if not isinstance(image_len,int) or image_len<=0:
        raise ValueError("nonpositive/noninteger image length")
    if start!=APP_START:
        raise ValueError("firmware must be a bare APP linked at original 0x08003000")
    end=start+image_len
    if end>PARAM_START or end>FLASH_END:
        raise ValueError("APP overlaps reserved parameter Flash or exceeds MCU physical Flash")
    first_page=(start-BOOT_START)//PAGE
    last_page=(end-1-BOOT_START)//PAGE
    page_range=list(range(first_page,last_page+1))
    if first_page!=6 or last_page>=255 or not page_range:
        raise ValueError("new image would erase loader or reserved parameter page")
    # The loader's 128-byte input transport and 256-byte buffered write
    # may pad final programming data. Conservatively require padded end
    # to remain below the reserved page too.
    padded_len=((image_len+FLASH_BUFFER-1)//FLASH_BUFFER)*FLASH_BUFFER
    if start+padded_len>PARAM_START:
        raise ValueError("256B buffered program may reach reserved parameter page")
    return {
        "app_start":hex(start),
        "end_exclusive":hex(end),
        "app_bytes":image_len,
        "first_2KiB_erase_page":first_page,
        "last_2KiB_erase_page":last_page,
        "erase_page_count":len(page_range),
        "last_2KiB_erase_page_start":hex(BOOT_START+last_page*PAGE),
        "first_param_erase_page":(PARAM_START-BOOT_START)//PAGE,
        "transport_chunk_count_128B":math.ceil(image_len/HOST_CHUNK),
        "buffered_program_count_256B":math.ceil(image_len/FLASH_BUFFER),
        "buffered_program_end_exclusive":hex(start+padded_len),
        "loader_pages_0_to_5_untouched_by_APP_geometry":True,
        "parameter_page_255_untouched_by_APP_geometry":True,
        "loader_acceptance_of_size_confirmed_on_installed_board":False,
        "image_can_be_flashing_authorized_from_geometry_alone":False,
    }

def inspect_header(image:bytes,original:bytes)->dict:
    if len(image)<META_END or len(image)!=EXPECTED_BYTES:
        raise ValueError("current v3.23 binary length differs from reviewed source")
    if LINK_BASE!=APP_START:
        raise ValueError("physical APP source base drift")
    if (len(original),hashlib.sha256(original).hexdigest())!=(
        178140,"40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7"
    ):
        raise ValueError("previous v3.22 flash-tested fallback unknown")
    image_sha=hashlib.sha256(image).hexdigest()
    if image_sha!=EXPECTED_SHA:
        raise ValueError("source-built candidate diverges from reviewed SHA")
    header_crc=struct.unpack_from("<H",image,CRC_OFF)[0]
    header_length=struct.unpack_from("<I",image,LEN_OFF)[0]
    tmp=bytearray(image)
    tmp[CRC_OFF:META_END]=bytes(META_END-CRC_OFF)
    recomputed_crc=crc16_bypass(tmp)
    if not header_crc==recomputed_crc==EXPECTED_CRC or header_length!=len(image):
        raise ValueError("OEM loader APP header CRC16/length is inconsistent")
    sp,reset=struct.unpack_from("<II",image,0)
    old_sp,old_reset=struct.unpack_from("<II",original,0)
    if (sp,reset)!=(old_sp,old_reset):
        raise ValueError("Cortex-M main stack or original reset trampoline changed")
    if not (0x20000000<=sp<=0x20010000) or reset&1!=1 or not (
        APP_START<=(reset&~1)<APP_START+len(image)):
        raise ValueError("bad OEM Thumb reset vector or initial SRAM SP")
    return {
        "manufacturer_original_v322_sha256":hashlib.sha256(original).hexdigest(),
        "trial_image_sha256":image_sha,
        "trial_image_length":len(image),
        "stored_header_length":header_length,
        "stored_header_crc16":hex(header_crc),
        "recomputed_header_crc16":hex(recomputed_crc),
        "MSP_unchanged_from_hardware_used_v322":hex(sp),
        "Thumb_reset_vector_unchanged_from_v322":hex(reset),
        "exact_full_v322_rollback_APP_source_available_offline":True,
        "rollback_transmission_hardware_validated":False,
    }

def verify_persistent_stock(image:bytes,original:bytes,syms:dict)->dict:
    same={}
    # Compare original manufacturer locations; all are outside our
    # separately audited appended ASM and patched inbound BL sites.
    for label,pc in KNOWN_UNCHANGED_OEM_FUNCTIONS.items():
        offset=pc-APP_START
        if not (0<=offset<min(len(original),len(image))-12):
            raise ValueError("original source function pointer outside APP")
        snippet=image[offset:offset+12]
        if snippet!=original[offset:offset+12]:
            raise ValueError("original reader/secure OEM routine modified: "+label)
        same[label]=hex(pc)
    code=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    for sym in ("op_config_v2_set","op_config_v2_reset"):
        pc=syms[sym]
        off=pc-APP_START
        inst=next(code.disasm(image[off:off+4],pc,count=1),None)
        if inst is None or (inst.mnemonic,inst.op_str)!=(
            "b.w",f"#{syms['status_busy']:#x}"):
            raise ValueError("first-test firmware CONFIG WRITE path unexpectedly active")
    if not all(name in syms for name in (
        "op_v323_readonly_snapshot","op_raw_pwm_enable_snapshot",
        "op_motor_command_fg_snapshot","op_raw_gpio_motor_latches",
        "legacy_type4_spool_removed_wrapper",
        "live_type4_usage_gate","live_usage_detect_secure_guard",
        "live_usage_write_secure_guard",
    )):
        raise ValueError("RFID+safe-diagnostic handler symbol missing")
    for literal, expected in (("gpio_d_out_ptr", GPIOD_OCTL),
                              ("gpio_e_out_ptr", GPIOE_OCTL)):
        if literal not in syms:
            raise ValueError("GPIO output source symbol not present")
        address = syms[literal] - APP_START
        if struct.unpack_from("<I", image, address)[0] != expected:
            raise ValueError("GPIO register source address changed: "+literal)
    return {
        "OEM_GPIO_sources_are_exact_and_read_only":True,
        "untouched_original_OEM_code_sites":same,
        "CONFIG_SET_RESET_firmware_entries_BW_redirect_to_busy":True,
        "both_manufacturer_secure_callsite_guards_present":True,
        "original_type4_lifecycle_and_readonly_diagnostic_entries_present":True,
    }

def negative_inputs(image:bytes,original:bytes,syms:dict)->list[str]:
    caught=[]
    tests=[
        ("loader_base",lambda:check_geometry(APP_START-PAGE,len(image))),
        ("param_page_overlap",lambda:check_geometry(APP_START,PARAM_START-APP_START+1)),
        ("zero_length",lambda:check_geometry(APP_START,0)),
        ("bad_length_header",lambda:inspect_header(
            image[:LEN_OFF]+bytes((image[LEN_OFF]^1,))+image[LEN_OFF+1:],original)),
        ("bad_checksum_header",lambda:inspect_header(
            image[:CRC_OFF]+bytes((image[CRC_OFF]^1,))+image[CRC_OFF+1:],original)),
        ("changed_reset_vector",lambda:inspect_header(
            image[:4]+bytes((image[4]^1,))+image[5:],original)),
        ("missing_final_app_byte",lambda:inspect_header(image[:-1],original)),
        ("modified_original_manufacturer_reader",lambda:inspect_header(
            image[:0x0800D624-APP_START]+bytes((image[0x0800D624-APP_START]^1,))+
            image[0x0800D624-APP_START+1:],original)),
        ("config_set_protection_removed",lambda:verify_persistent_stock(
            image[:syms["op_config_v2_set"]-APP_START]+b"\x00\xbf\x00\xbf"+
            image[syms["op_config_v2_set"]-APP_START+4:],original,syms)),
        ("config_reset_protection_removed",lambda:verify_persistent_stock(
            image[:syms["op_config_v2_reset"]-APP_START]+b"\x00\xbf\x00\xbf"+
            image[syms["op_config_v2_reset"]-APP_START+4:],original,syms)),
        ("gpio_port_D_latch_source_corrupted",lambda:verify_persistent_stock(
            image[:syms["gpio_d_out_ptr"]-APP_START]+struct.pack("<I",GPIOE_OCTL)+
            image[syms["gpio_d_out_ptr"]-APP_START+4:],original,syms)),
        ("gpio_port_E_latch_source_corrupted",lambda:verify_persistent_stock(
            image[:syms["gpio_e_out_ptr"]-APP_START]+struct.pack("<I",GPIOD_OCTL)+
            image[syms["gpio_e_out_ptr"]-APP_START+4:],original,syms)),
    ]
    for name,call in tests:
        try:call()
        except (ValueError,AssertionError):caught.append(name)
        else:raise AssertionError("unsafe image accepted: "+name)
    if len(caught)!=len(tests):
        raise ValueError("negative image rejection census changed")
    return caught

def main():
    args=argparse.ArgumentParser()
    for k in ("v313","v322","asm","linker","builder"):
        args.add_argument("--"+k,type=Path,required=True)
    args.add_argument("--json-out",type=Path)
    a=args.parse_args()
    v313=pinned(a.v313,"intermediate_v313")
    v322=pinned(a.v322,"running_v322")
    image,source_meta,syms=build_latest(
        v313,v322,a.asm.read_text(),a.linker.read_text(),
        a.builder.read_text(),a.builder,
    )
    g=check_geometry(APP_START,len(image))
    h=inspect_header(image,v322)
    stock=verify_persistent_stock(image,v322,syms)
    # Still execute actual assembled config response code under Unicorn,
    # not just compare entry branch bytes.
    denial=[]
    for state in range(6):
        for cmd in (0x12,0x13):
            check=invoke_host_config(image,syms,cmd,state,0x35564643,0xFFFFFFFF)
            if check["status"]!=7 or check["sidecar_changed"] or check["nonstack_writes"]:
                raise ValueError("unsafe first-test CONFIG write accepted")
            denial.append(check)
    if len(denial)!=12:
        raise ValueError("motor-unsafe config denial test census changed")
    # Four original ARM Thumb runtime GPIO-latch checks on the current
    # full candidate: no peripheral write, no stale CONFIG overrides.
    raw_cases=[
        ("all_zero", 0x0, 0x0, 4, 0x18),
        ("four_feeder_outputs", 0xF00F, 0x0, 4, 0x18),
        ("hub_direction_and_brake", 0x0, 0x18, 4, 0x18),
        ("invalid_request_length", 0xFFFFFFFF, 0xFFFFFFFF, 3, 0x18),
    ]
    runtime_gpio=[]
    for label,d,e,n,opcode in raw_cases:
        check=gpio_snapshot(image,syms,d,e,n,opcode)
        if check["nonstack_writes"]!=0 or check["physical_motor_stop_proven"]:
            raise ValueError("GPIO diagnostic became writable or falsely reports STOP")
        runtime_gpio.append({"case":label,**check})
    failures=negative_inputs(image,v322,syms)
    report={
        "release_track":"FIRST_HARDWARE_TEST_PREVIEW_NOT_APPROVED_FOR_FLASH",
        "candidate":source_meta,
        "image_header":h,
        "OEM_loader_geometry":g,
        "unmodified_manufacturer_code_and_guard":stock,
        "12_original_ARM_CONFIG_SET_RESET_denials_checked":True,
        "unsafe_image_mutations_rejected":failures,
        "latest_GPIO_latch_Thumb_snapshot_cases":runtime_gpio,
        "source_current_runtime_tuning_units_reviewed":True,
        "gpio_latches_are_motor_commands_not_STOP_feedback":True,
        "remaining_test_release_blockers":[
            "Installed loader read-only mode/identity & rollback power-cycle validation",
            "Dynamic OEM RFID execution, unload/runout & RT-Thread ISR races on real hardware",
            "No physical motor-stop interlock, so CONFIG SET/RESET remain denied",
        ],
        "advanced_speed_buffer_runtime_writes_qualified":False,
        "auto_load_custom_RAM_profile_after_CFS_boot":False,
        "Kalico_source_or_active_config_edited":False,
        "MCU_serial_flash_erase_motor_mmio_accessed":False,
        "firmware_BIN_ELF_HEX_written":False,
        "qualified_to_flash_on_users_only_CFS":False,
    }
    text=json.dumps(report,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(text)
    print(text,end="")
if __name__=="__main__":main()
