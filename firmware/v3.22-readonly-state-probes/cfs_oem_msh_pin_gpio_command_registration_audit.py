#!/usr/bin/env python3
"""Pin the original RT-Thread MSH 'pin' command registration and GPIO call chain.

Source-only v3.13 and v3.22 original APP, physical linked base 0x08003000.
Proves the OEM ROM command descriptor is [name, description, NULL, Thumb
handler], not [previous handler, name, desc, NULL]. 'pin' invokes the
0x08019028 parser, dispatches 'write' to 0x080190F0, and reaches the
OEM GPIO callback path, accepting a software-supplied logical pin ID.

Does NOT prove a shell is reachable over USB/UART/RS485/network; does
NOT prove GPIO ACL/whitelist, physical motor STOP, or MCU write safety.
No live CFS/CM5 printer configuration IO or firmware flash.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE
from cfs_oem_gpio_motor_tail_and_callback_audit import inspect as tail_audit

DESC_BASE=0x0802D970
STRIDE=16
COMMANDS=(
    ("box_aging_mode_test",0x08012BF8),
    ("adc",0x080188DA),
    ("pin",0x08019028),
    ("pwm",0x08019628),
    ("help",0x0801C2D8),
    ("ps",0x0801C304),
)
PIN_ENTRY=0x0802D990
PIN_HANDLER=0x08019028
PIN_MODE_DISPATCH=0x08018EC4
PIN_WRITE_ROUTINE=0x080190F0
PIN_WRITE_TAIL=0x08019156
GPIO_DISPATCH=0x08018EEC
COMMAND_OPTS={
    0x08019032:(0x08019324,b"num",0x2F0),
    0x0801903C:(0x08019328,b"mode",0x2E8),
    0x08019046:(0x08019330,b"read",0x2E8),
    0x08019050:(0x08019338,b"write",0x2E4),
}
PIN_OUTPUT_OPTIONS={
    0x0801910A:(0x08019388,b"high",0x27C),
    0x08019114:(0x08019390,b"on",0x278),
    0x0801911E:(0x08019394,b"low",0x274),
    0x08019128:(0x08019398,b"off",0x26C),
}
PARSER_SOURCE={
    0x08019028:("push","{r4, r5, r6, lr}"),
    0x0801902A:("mov","r4, r1"),
    0x0801902C:("mov","r5, r0"),
    0x0801902E:("cmp","r0, #3"),
    0x08019034:("ldr","r1, [r4, #4]"),
    0x08019036:("bl","#0x8020380"),
    0x0801903E:("ldr","r1, [r4, #4]"),
    0x08019040:("bl","#0x8020380"),
    0x08019048:("ldr","r1, [r4, #4]"),
    0x0801904A:("bl","#0x8020380"),
    0x08019052:("ldr","r1, [r4, #4]"),
    0x08019054:("bl","#0x8020380"),
    0x08019094:("mov","r1, r4"),
    0x08019096:("mov","r0, r5"),
    0x08019098:("pop.w","{r4, r5, r6, lr}"),
    0x0801909C:("b.w",f"#{PIN_WRITE_ROUTINE:#x}"),
    0x080190F0:("push","{r4, r5, r6, lr}"),
    0x080190F2:("mov","r4, r1"),
    0x080190F4:("cmp","r0, #4"),
    0x080190F8:("ldr","r0, [r4, #8]"),
    0x080190FA:("bl","#0x801c7e6"),
    0x08019104:("bl","#0x80268b8"),
    0x08019108:("mov","r5, r0"),
    0x0801910C:("ldr","r1, [r4, #0xc]"),
    0x0801910E:("bl","#0x8020380"),
    0x08019150:("mov","r0, r5"),
    0x08019152:("pop.w","{r4, r5, r6, lr}"),
    0x08019156:("b",f"#{GPIO_DISPATCH:#x}"),
}
HELP_STRINGS={
    0x08019194:b"pin [option] GPIO\n",
    0x080191E0:b"               e.g. MSH >pin mode GPIO output\n",
    0x08019240:b"               e.g. MSH >pin read GPIO\n",
    0x0801926C:b"               e.g. MSH >pin write GPIO high\n",
}

def rd32(b:bytes,pc:int)->int:
    off=pc-LINK_BASE
    if off<0 or off+4>len(b):raise ValueError("APP word out of range")
    return struct.unpack_from("<I",b,off)[0]
def get_raw(b:bytes,a:int,n:int)->bytes:
    off=a-LINK_BASE
    if off<0 or off+n>len(b):raise ValueError("ROM bytes out of range")
    return b[off:off+n]
def eqstr(b:bytes,at:int,value:bytes)->None:
    if get_raw(b,at,len(value)+1)!=value+b"\0":
        raise ValueError(f"OEM MSH string at {at:#x} not pinned")
def ins(b:bytes,pc:int,opcode:tuple[str,str]):
    d=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    found=next(d.disasm(get_raw(b,pc,4),pc,count=1),None)
    if found is None or (found.mnemonic,found.op_str)!=opcode:
        raise ValueError(f"OEM instruction at {pc:#x} expected {opcode},"
                         f" found {(found.mnemonic,found.op_str) if found else None}")
def check_adr(b:bytes,pc:int,target:int,word:bytes,imm:int)->None:
    ins(b,pc,("adr",f"r0, #{imm:#x}"))
    if ((pc+4)&~3)+imm!=target:
        raise ValueError("OEM MSH command parser ADR address mismatch")
    eqstr(b,target,word)

def inspect(b:bytes, *, verify_parent_audits:bool=True)->dict:
    if verify_parent_audits:
        t=tail_audit(b)
        if (t["unbounded_parameter_parser_gpio_tail"]!=hex(PIN_WRITE_TAIL)
            or t["source_emitted_GPIO_tail_call_sites"]!=18
            or t["pin_ops_ROM_Thumb_write_callback"]!="0x801ab91"):
            raise ValueError("manufacturer pin parser/callback audit base drift")
    records=[]
    for idx,(name,entry) in enumerate(COMMANDS):
        slot=DESC_BASE+idx*STRIDE
        nameptr=rd32(b,slot)
        descptr=rd32(b,slot+4)
        nullval=rd32(b,slot+8)
        funcptr=rd32(b,slot+12)
        if nullval!=0 or funcptr!=entry|1:
            raise ValueError(f"OEM ROM {name} MSH descriptor does not match [name,desc,NULL,handler]")
        eqstr(b,nameptr,name.encode("ascii"))
        if get_raw(b,descptr,1)==b"\0":
            raise ValueError("command documentation empty")
        if name=="pin":
            eqstr(b,descptr,b"pin [option]")
            if slot!=PIN_ENTRY or funcptr!=(PIN_HANDLER|1):
                raise ValueError("pin descriptor does not bind the GPIO handler")
        if name=="pwm":
            eqstr(b,descptr,b"pwm [option]")
            if funcptr!=(0x08019628|1):raise ValueError("PWM handler wrong")
        records.append({"name":name,"ROM_descriptor":hex(slot),
                        "source_handler_Thumb":hex(funcptr),
                        "ROM_name":hex(nameptr),"ROM_description":hex(descptr)})
    for pc,opcode in PARSER_SOURCE.items():ins(b,pc,opcode)
    for pc,(rom,word,imm) in COMMAND_OPTS.items():check_adr(b,pc,rom,word,imm)
    for pc,(rom,word,imm) in PIN_OUTPUT_OPTIONS.items():check_adr(b,pc,rom,word,imm)
    for pc,word in HELP_STRINGS.items():eqstr(b,pc,word)
    return {
        "original_APP_physical_link_base":hex(LINK_BASE),
        "registered_MSH_compatible_ROM_descriptor_count_checked":len(records),
        "original_descriptor_word_layout":["name_ptr","desc_ptr","zero","Thumb_handler"],
        "reviewed_ROM_export_records":records,
        "pin_source_registered_ROM_name":"pin",
        "pin_ROM_handler_Thumb_pointer":hex(PIN_HANDLER|1),
        "pwm_is_a_different_shell_command_and_handler":True,
        "pin_command_suboptions":[v[1].decode("ascii") for v in COMMAND_OPTS.values()],
        "pin_write_values":[v[1].decode("ascii") for v in PIN_OUTPUT_OPTIONS.values()],
        "pin_write_param_handler_reached_from_PIN_entry_by_direct_BW":True,
        "pin_write_software_parameter_B_to_GPIO_dispatch":hex(PIN_WRITE_TAIL),
        "source_has_MSH_usage_text":True,
        "source_contains_GPIO_write_command":True,
        "shell_dispatcher_runtime_registration_invoked":False,
        "MSH_available_over_any_external_interface_proven":False,
        "physical_motor_standstill_measured":False,
        "hardware_RFID_write_interlock_proven":False,
        "v323_flash_or_MCU_SET_RESET_approved":False,
    }

def negatives(b:bytes)->list[str]:
    tests=(
        ("pin_name_ROM",0x0802D66F),
        ("pin_description_ROM",0x0802D673),
        ("pin_command_ROM_name_field",PIN_ENTRY),
        ("pin_command_ROM_description_field",PIN_ENTRY+4),
        ("pin_command_ROM_reserved_field",PIN_ENTRY+8),
        ("pin_command_Thumb_handler",PIN_ENTRY+12),
        ("pwm_handler_must_stay_distinct",0x0802D9AC),
        ("pin_parser_entry",PIN_HANDLER),
        ("pin_write_subcommand",0x08019338),
        ("pin_parser_mode_subcommand",0x08019328),
        ("pin_parser_write_BW",0x0801909C),
        ("pin_parser_num_argv_ref",0x08019034),
        ("pin_write_arg_value",0x08019104),
        ("pin_write_high",0x08019388),
        ("pin_write_off",0x08019398),
        ("pin_write_tail_to_GPIO",PIN_WRITE_TAIL),
        ("MSH_pin_help_string",0x08019194),
        ("MSH_pin_write_help",0x0801926C),
    )
    got=[]
    for name,location in tests:
        wrong=bytearray(b);wrong[location-LINK_BASE]^=1
        try:inspect(bytes(wrong),verify_parent_audits=False)
        except ValueError:got.append(name)
        else:raise AssertionError(f"accepted corrupted command source {name}")
    if len(got)!=18:raise ValueError("MSH command fail-closed fixtures incomplete")
    return got

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v313",type=Path,required=True)
    parser.add_argument("--v322",type=Path,required=True)
    parser.add_argument("--self-test",action="store_true")
    parser.add_argument("--json-out",type=Path)
    args=parser.parse_args()
    old=pinned(args.v313,"intermediate_v313")
    new=pinned(args.v322,"running_v322")
    audited(old);audited(new)
    a,b=inspect(old),inspect(new)
    if a!=b:raise ValueError("original MSH command mapping differs between OEM and v3.22")
    out={"SHA_pinned_v313_v322_OEM_MSH_source_identical":True,
         "original_source_justification":b,
         "serial_console_or_other_external_interface_touched":False,
         "MCU_flash_release_authorized":False}
    if args.self_test:
        out["negative_mutations_rejected"]=negatives(new)
    body=json.dumps(out,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(body)
    print(body,end="")
if __name__=="__main__":main()
