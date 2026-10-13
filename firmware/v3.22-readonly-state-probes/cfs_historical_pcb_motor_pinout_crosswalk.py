#!/usr/bin/env python3
"""Cross-check original CFS firmware pin data with independent PCB reverse engineering.

Sources:
  - original SHA-pinned saved CFS v3.13 & v3.22 APP, linked 0x08003000
  - PUBLIC fake-name/cfs-reverse-engineering PCBs.md from one pinned Git blob

This deliberately separates: firmware pin *configuration*, historical
PCB *trace observation*, and UNPROVEN applicability to the user's
installed CFS board revision. No physical sensor measurements occur.

The PCB pinout identifies PE11 as BLDC driver FG tach output on its
studied board, PE13 as PWM input, PE3 F/R and PE4 brake. It also
shows 4 brushed motor inputs plus current-shunt amplifier pins.

Neither zero FG pulses nor zero current alone certifies mechanical
standstill. No MCU SET/RESET writes, motor actions, firmware flash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from flash_ram_phase2_audit import pinned
from cfs_pwm_timer_channel_register_provenance import inspect as pwm_channels
from cfs_motor_pulse_irq_provenance import analyze as gpio_irq

PUBLIC_GIT_BLOB_SHA1 = "8a8345e299e48221f3b4859e8a0d34eefb95672c"
PUBLIC_COMMIT = "21f9a813654b1feb6ba8597f0f48ed4650f51f3d"
PUBLIC_REPOSITORY = "fake-name/cfs-reverse-engineering"

BLDC = {"SS":"PE4", "FG":"PE11", "F/R":"PE3", "PWM":"PE13"}
BRUSHED = {
    "M1": {"IN 1":"PD3", "IN 2":"PD2", "current_feedback":"PC5"},
    "M2": {"IN 1":"PD1", "IN 2":"PD0", "current_feedback":"PC0"},
    "M3": {"IN 1":"PD15", "IN 2":"PD14", "current_feedback":"PA1"},
    "M4": {"IN 1":"PD13", "IN 2":"PD12", "current_feedback":"PA0"},
}
EXPECTED_PWM_OUTPUTS = {
    "pwm1":"PE13",
    "pwm3":"PD12",
    "pwm4":"PD13",
    "pwm5":"PD15",
    "pwm8":"PD14",
}


def markdown_section(text: str, heading: str) -> str:
    pattern = r"(?m)^#{3,6}\s+" + re.escape(heading) + r"\s*$"
    found = re.search(pattern, text)
    if found is None:
        raise ValueError(f"historical PCB heading not found: {heading}")
    rest=text[found.end():]
    nxt=re.search(r"(?m)^#{3,6}\s+",rest)
    return rest[:nxt.start()] if nxt else rest


def parse_rows(section: str) -> list[list[str]]:
    rows=[]
    for line in section.splitlines():
        if not line.strip().startswith("|"):
            continue
        fields=[c.strip() for c in line.strip().strip("|").split("|")]
        if fields and fields[0].startswith("---"):
            continue
        if any(f and set(f).issubset(set("-: ")) for f in fields):
            continue
        rows.append(fields)
    return rows


def verify_blob(raw: bytes) -> dict:
    sha=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    if sha!=PUBLIC_GIT_BLOB_SHA1:
        raise ValueError("independent CFS PCB doc blob differs from pinned upstream")
    return {
        "upstream_repository":PUBLIC_REPOSITORY,
        "upstream_commit":PUBLIC_COMMIT,
        "upstream_PCB_doc_git_blob_sha1":sha,
        "source_is_historical_independent_reverse_engineering":True,
        "document_is_current_installed_board_schematic":False,
    }


def pcb_pinout(document: str) -> dict:
    rows=parse_rows(markdown_section(document,"BLDC Motor Driver:"))
    bldc={}
    for fields in rows[1:]:
        if len(fields)>=3 and fields[0] in BLDC:
            bldc[fields[0]]=fields[2]
    if bldc!=BLDC:
        raise ValueError("PCB historical BLDC driver FG/PWM/SS/F-R mapping changed")

    motor_rows=parse_rows(markdown_section(document,"Motor driver pins"))
    if not motor_rows or len(motor_rows[0])!=5:
        raise ValueError("historical 4-motor driver PCB table missing")
    pin={}
    for col,motor in enumerate(("M1","M2","M3","M4"),start=1):
        pin[motor]={}
        for fields in motor_rows[1:]:
            if fields and fields[0] in ("IN 1","IN 2"):
                cell=fields[col]
                m=re.search(r"\((P[A-E]\d+)\)",cell)
                if m is None:
                    raise ValueError("unrecognized original brushed motor GPIO cell")
                pin[motor][fields[0]]=m.group(1)

    amps=parse_rows(markdown_section(document,"Current Feedback Pins"))
    for fields in amps[1:]:
        if len(fields)>=3 and fields[0] in BRUSHED:
            pin[fields[0]]["current_feedback"]=fields[2]
    if pin!=BRUSHED:
        raise ValueError("PCB original DC motor current-sense or input mapping changed")

    return {"historical_bldc":bldc,"historical_brushed_motors":pin}


def crosswalk(image:bytes, pcb:dict) -> dict:
    o=pwm_channels(image)
    irq=gpio_irq(image)
    mapping={p["RTThread_device_name"]:
             p["OEM_GPIO_AF_output"] for p in o["full_oem_timer_channel_register_map"]}
    if mapping!=EXPECTED_PWM_OUTPUTS:
        raise ValueError("OEM firmware PWM AF output pin map changed")
    other={p["logical_RT_Pin"]:p["physical_pin"]
           for p in irq["original_board_GPIO_mapping"]}
    if other!={"0x43":"PE3","0x44":"PE4","0x4b":"PE11"}:
        raise ValueError("OEM GD32 PE3/PE4/PE11 GPIO lookup table changed")
    if (mapping["pwm1"]!=pcb["historical_bldc"]["PWM"] or
        other["0x4b"]!=pcb["historical_bldc"]["FG"] or
        other["0x43"]!=pcb["historical_bldc"]["F/R"] or
        other["0x44"]!=pcb["historical_bldc"]["SS"]):
        raise ValueError("original firmware and historical board BLDC pin assignments differ")

    motor_matches={}
    pwm_pads=set(mapping.values())
    for motor,signals in pcb["historical_brushed_motors"].items():
        matches=[pin for pin in ("IN 1","IN 2") if signals[pin] in pwm_pads]
        motor_matches[motor]={
            "historical_driver_input_pins":[signals["IN 1"],signals["IN 2"]],
            "historical_analog_current_feedback_pad":signals["current_feedback"],
            "driver_inputs_also_in_five_oem_named_PWM_output_pins":matches,
            "analog_ADC_configuration_verified_in_saved_firmware":False,
            "actual_live_motor_current_verified":False,
            "current_equals_zero_means_safe_to_write":False,
        }
    if [len(motor_matches[k]["driver_inputs_also_in_five_oem_named_PWM_output_pins"])
        for k in ("M1","M2","M3","M4")] != [0,0,2,2]:
        raise ValueError("unexpected coverage of brushed driver inputs by five named PWM outputs")

    return {
        "saved_CFS_pwm_GPIO_matches_historical_BLDC_PWM":True,
        "saved_CFS_GPIO_IRQ_PE11_matches_historical_BLDC_FG_tach":True,
        "saved_CFS_PIN_PE3_PE4_match_historical_direction_brake":True,
        "four_brushed_motor_pins_historical_only":motor_matches,
        "four_current_feedback_analog_pads_from_external_PCB":(
            ["PC5","PC0","PA1","PA0"]
        ),
        "PWM_device_names_cover_all_brushed_driver_input_pins":False,
        "PE11_tach_feedback_proves_BLDC_rotor_stop_when_zero":False,
        "PE11_tach_covers_all_brushed_motors":False,
        "installed_CFS_PCB_revision_matching_historical_board_proven":False,
        "hardware_driver_current_and_energization_measured":False,
        "safe_to_authorize_MCU_motor_active_writes":False,
        "safe_to_flash_v323":False,
    }


def synthetic_safety_cases():
    scenarios=[
        ("BLDC_pwm_enabled_no_FG_pulses",True,False,None),
        ("BLDC_FG_pulses_pwm_off",False,True,None),
        ("BLDC_pwm_off_FG_quiet_current_unknown",False,False,None),
        ("brush_M1_current_zero_does_not_prove_deenergized",False,False,0),
        ("brush_M2_current_unknown",False,False,None),
        ("brush_M3_current_above_zero",False,False,235),
        ("brush_M4_current_zero_hall_not_proven",False,False,0),
        ("no_PCB_revision_authentication_even_if_all_quiet",False,False,0),
    ]
    out=[]
    for name, pwm, pulse, adc in scenarios:
        if pwm:
            reason="BLDC_commanded_or_energized_without_confirmed_rotation"
        elif pulse:
            reason="BLDC_tach_activity_after_output_command"
        elif adc is None:
            reason="brushed_current_feedback_missing"
        elif adc!=0:
            reason="brushed_current_detected_unverified_calibration"
        else:
            reason="zero_current_unsafe_without_driver_and_mechanical_confirmation"
        out.append({
            "scenario":name,
            "synthetic_BLDC_PWM_output_on":pwm,
            "synthetic_BLDC_FG_pulses_seen":pulse,
            "synthetic_raw_brushed_ADC":adc,
            "rejection_reason":reason,
            "physical_all_motors_stopped_PROVEN":False,
            "MCU_write_authorized":False,
        })
    assert len(out)==8 and not any(x["MCU_write_authorized"] for x in out)
    return out


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pcb-md",required=True,type=Path)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    raw=a.pcb_md.read_bytes()
    upstream=verify_blob(raw)
    contents=raw.decode("utf-8")
    pins=pcb_pinout(contents)
    # Test tampering the PCB analysis itself; reject changed FG/current-sense
    # observations without ever committing or flashing vendor binaries.
    broken=contents.replace("| FG          | p.42       | PE11        |",
                            "| FG          | p.42       | PE10        |",1)
    if broken==contents:
        raise ValueError("PCB FG row changed unexpectedly")
    try:pcb_pinout(broken)
    except ValueError:pass
    else:raise AssertionError("altered external FG pinout accepted")
    broken=contents.replace("| M1    | p.34   | PC5         |",
                            "| M1    | p.34   | PC6         |",1)
    if broken==contents:
        raise ValueError("PCB analog current row changed unexpectedly")
    try:pcb_pinout(broken)
    except ValueError:pass
    else:raise AssertionError("altered external current pinout accepted")

    v313=crosswalk(pinned(a.v313,"intermediate_v313"),pins)
    v322=crosswalk(pinned(a.v322,"running_v322"),pins)
    if v313!=v322:
        raise ValueError("OEM firmware pinout crosswalk differs in pinned versions")
    result={
        "independent_source_integrity":upstream,
        "historical_PCB_pinout":pins,
        "pinned_v313_and_v322_original_ROM_crosswalk_equal":True,
        "crosswalk":v322,
        "tampered_historical_PCB_pinout_cases_rejected":2,
        "synthetic_stop_safety_cases":synthetic_safety_cases(),
        "actual_installed_CFS_board_or_wiring_observed":False,
        "current_motor_driver_ADC_values_read":False,
        "v323_MCU_safety_guard_implemented":False,
        "v323_flash_authorized":False,
        "real_CFS_CM5_or_Kalico_access":False,
    }
    payload=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(payload)
    print(payload,end="")


if __name__=="__main__":
    main()
