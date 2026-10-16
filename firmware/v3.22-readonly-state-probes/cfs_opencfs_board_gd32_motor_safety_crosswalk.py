#!/usr/bin/env python3
"""Audit new OpenCFS GD32F303 port map against exact saved OEM CFS ROM.

This is an immutable independent crosswalk for the OpenCFS draft PR #5
checkpoint ca73d2ec (16 Oct 2026), NOT an import of its board drivers.
Reads two SHA-pinned saved Creality applications only; proves wiring
identity/RS485 source and distinguishes motor commands from physical stop.

No GPIO, ADC, motors, CFS physical RS485, GitHub changes, CM5 Kalico
operations, firmware BIN or linker/flash activity.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited,LINK_BASE
from cfs_oem_four_brushed_motor_pin_provenance_audit import inspect as motor_records
from cfs_motor_adc_pin_table_inventory import inventory as pin_table
from cfs_motor_multisignal_observation_plan import manifest as motor_feedback
from cfs_motor_pulse_irq_provenance import pinned_thumb as pulse_source

OPEN_CFS_BOARD_COMMIT="ca73d2ec99b6b03b9a2c98b4613f32224641e5ec"
SOURCE_PATHS=(
    "cpp/board/k2cfs/board_io.hpp",
    "docs/spec/06-motors-sensors.md",
    "docs/spec/10-board-port.md",
)
# Public OpenCFS board IO constants observed and reviewed independently.
# Physical pin association is corroborated with original OEM ROM and SRAM.
OPEN_CFS_K2_BOARD_FEEDER_IN1=("PD3","PD1","PD15","PD13")
OPEN_CFS_K2_BOARD_FEEDER_IN2=("PD2","PD0","PD14","PD12")
OPEN_CFS_ADC_CHANNELS=(15,10,1,0)
OPEN_CFS_ADC_PINS=("PC5","PC0","PA1","PA0")
# Remaining discrepancy in the OpenCFS *older* docs/spec/06 motor table.
OPEN_CFS_OLDER_MOTOR_DOC_IN1=("PD2","PD0","PD14","PD12")
OPEN_CFS_OLDER_MOTOR_DOC_IN2=("PD3","PD1","PD15","PD13")
OPEN_CFS_OLDER_DOC_ADC_PINS=("PC5","PC1","PA1","PA0")
OEM_PULSE_IN="PE11"
OEM_HUB_PWM="PE13"
OEM_HUB_BRAKE="PE4"
OEM_HUB_DIRECTION="PE3"

def compare_board_mapping(saved:bytes)->dict:
    audited(saved)
    record=motor_records(saved)
    pins=pin_table(saved)
    feedback=motor_feedback(saved)
    pulse_source(saved)
    if len(record["original_brushed_motor_records"])!=4:
        raise ValueError("OEM four-feeder source evidence missing")
    if not pins["all_16_operator_confirmed_pads_resolved_from_oem_ROM"]:
        raise ValueError("OEM 16 motor/ADC/FG PCB pads no longer source-grounded")
    expected_input_pairs=[]
    observed_input_pairs=[]
    entries=[]
    for i,row in enumerate(record["original_brushed_motor_records"]):
        actual=tuple(x["physical_GPIO"] for x in row["GPIO_board_mapping"])
        observed_input_pairs.append(actual)
        expected=frozenset((OPEN_CFS_K2_BOARD_FEEDER_IN1[i],OPEN_CFS_K2_BOARD_FEEDER_IN2[i]))
        if frozenset(actual)!=expected or len(actual)!=2:
            raise ValueError("public OpenCFS GPIO pair disagrees with OEM motor record")
        expected_input_pairs.append(tuple(sorted(expected)))
        if OPEN_CFS_ADC_PINS[i] not in pins["resolved_oem_logical_records_by_confirmed_physical_pad"]:
            raise ValueError("OpenCFS current/ADC input not in original OEM ROM mapping")
        if len(pins["resolved_oem_logical_records_by_confirmed_physical_pad"][OPEN_CFS_ADC_PINS[i]])!=1:
            raise ValueError("OpenCFS ADC hardware pad unexpectedly ambiguous")
        entries.append({
            "feeder_slot":i,
            "OEM_initialized_motor_RAM_record":row["initial_motor_object_RAM"],
            "OEM_original_record_pin_pair":actual,
            "OpenCFS_board_IN1":OPEN_CFS_K2_BOARD_FEEDER_IN1[i],
            "OpenCFS_board_IN2":OPEN_CFS_K2_BOARD_FEEDER_IN2[i],
            "OpenCFS_current_monitor_pad":OPEN_CFS_ADC_PINS[i],
            "OpenCFS_ADC_channel_peripheral_association":OPEN_CFS_ADC_CHANNELS[i],
            "OEM_pin_ID_wiring_mapping_matches_board":True,
            "IN1_IN2_polarity_and_FORWARD_direction_electrically_verified":False,
            "ADC_per_motor_bounded_live_conversion_sequence_proven":False,
        })
    if feedback["gpio_pulse_input"]!=OEM_PULSE_IN:
        raise ValueError("source-proved OEM pulse GPIO differs from OpenCFS")
    if feedback["unique_timer_channel_pairs"]!=5:
        raise ValueError("source-proved OEM 5 PWM channels missing")
    pwm=feedback["pwm_command_output_registers"]
    if [x["gpio_output"] for x in pwm]!=["PE13","PD12","PD13","PD15","PD14"]:
        raise ValueError("source-proved OEM PWM port mapping changed")
    if "pwm1"!=pwm[0]["device"]:
        raise ValueError("source-proved OEM hub PWM device no longer mapped")
    if feedback["gpio_pulse_pin_id"]!="0x4b":
        raise ValueError("source-proved OEM hub FG interrupt GPIO no longer mapped")
    if (feedback["pulse_counter_RAM"],feedback["previous_counter_RAM"])!=(
        "0x20004990","0x20004994"
    ):
        raise ValueError("source-proved OEM hub FG pulse counter RAM changed")
    doc_mismatches=[
        {
          "kind":"IN1_IN2_label_reversed_for_every_feeder_in_old_spec_06",
          "older_spec_IN1":list(OPEN_CFS_OLDER_MOTOR_DOC_IN1),
          "older_spec_IN2":list(OPEN_CFS_OLDER_MOTOR_DOC_IN2),
          "OpenCFS_new_board_port_IN1":list(OPEN_CFS_K2_BOARD_FEEDER_IN1),
          "OpenCFS_new_board_port_IN2":list(OPEN_CFS_K2_BOARD_FEEDER_IN2),
          "physical_direction_can_be_claimed_without_CFS_electrical_test":False,
        },
        {
          "kind":"older_motor_spec_claims_PC1_instead_of_PC0_for_slot_B",
          "older_spec_current_pin":OPEN_CFS_OLDER_DOC_ADC_PINS[1],
          "OEM_and_board_port_current_pin":OPEN_CFS_ADC_PINS[1],
          "slot_B_OEM_ADC_channel":OPEN_CFS_ADC_CHANNELS[1],
          "older_spec_current_pin_is_LCD_chip_select_on_new_board_map":True,
        },
    ]
    if OPEN_CFS_OLDER_MOTOR_DOC_IN1 != OPEN_CFS_K2_BOARD_FEEDER_IN2:
        raise ValueError("outdated motor spec IN1/IN2 discrepancy no longer present")
    if OPEN_CFS_OLDER_DOC_ADC_PINS[1]!="PC1" or OPEN_CFS_ADC_PINS[1]!="PC0":
        raise ValueError("stale ADC discrepancy observation changed")
    if not all(x["OEM_pin_ID_wiring_mapping_matches_board"] for x in entries):
        raise ValueError("board mismatch")
    return {
        "OpenCFS_current_public_board_checkpoint":OPEN_CFS_BOARD_COMMIT,
        "OpenCFS_file_evidence":list(SOURCE_PATHS),
        "four_OEM_motor_records_and_public_OpenCFS_GPIO_pairs_agree":True,
        "four_motor_board_pin_crosswalk":entries,
        "OEM_PWM_register_channels":[
            {"pin":p["gpio_output"],"timer":p["timer"],"channel":p["channel"],
             "purpose":"command output, not rotor stop feedback"}
            for p in pwm
        ],
        "OEM_hub_FG_counter_RAM":"0x20004990",
        "OEM_hub_PWM":OEM_HUB_PWM,
        "OEM_hub_brake":OEM_HUB_BRAKE,
        "OEM_hub_direction":OEM_HUB_DIRECTION,
        "OEM_hub_FG":OEM_PULSE_IN,
        "documented_OpenCFS_PR5_discrepancies":doc_mismatches,
        "any_automated_gpio_motor_set_command_allowed":False,
        "zero_FG_pulses_proves_motor_stopped":False,
        "ADC_ripple_below_threshold_proves_motor_stopped":False,
        "BLOCKED_flag_proves_motor_stopped":False,
        "OEM_BOX_STATE_IDLE_proves_motor_stopped":False,
        "actual_physical_motor_energization_or_motion_measured":False,
        "installed_CFS_FLASH_or_motors_accessed":False,
        "v323_motor_write_and_firmware_flash_authorized":False,
    }

def negative_fixture_tests(source:dict)->list[str]:
    bad=[
        ("slotA_wrong_Pin",{"OPEN_CFS_K2_BOARD_FEEDER_IN1":("PD7","PD1","PD15","PD13")}),
        ("slotB_wrong_ADC",{"OPEN_CFS_ADC_PINS":("PC5","PC1","PA1","PA0")}),
        ("slotC_wrong_Pin",{"OPEN_CFS_K2_BOARD_FEEDER_IN2":("PD2","PD0","PD12","PD12")}),
        ("slotD_wrong_Pin",{"OPEN_CFS_K2_BOARD_FEEDER_IN1":("PD3","PD1","PD15","PD10")}),
    ]
    # Rather than dynamically updating source-repository constants, emulate
    # each incorrect board binding, and check it conflicts with the verified
    # immutable OEM physical pin pair or original pin-ROM lookup.
    entries=source["four_motor_board_pin_crosswalk"]
    rejected=[]
    for name,deltas in bad:
        if "OPEN_CFS_K2_BOARD_FEEDER_IN1" in deltas:
            proposed=deltas["OPEN_CFS_K2_BOARD_FEEDER_IN1"]
            if any(frozenset((proposed[i],OPEN_CFS_K2_BOARD_FEEDER_IN2[i]))!=
                   frozenset(entries[i]["OEM_original_record_pin_pair"])
                   for i in range(4)):
                rejected.append(name)
        if "OPEN_CFS_K2_BOARD_FEEDER_IN2" in deltas:
            proposed=deltas["OPEN_CFS_K2_BOARD_FEEDER_IN2"]
            if any(frozenset((OPEN_CFS_K2_BOARD_FEEDER_IN1[i],proposed[i]))!=
                   frozenset(entries[i]["OEM_original_record_pin_pair"])
                   for i in range(4)):
                rejected.append(name)
        if "OPEN_CFS_ADC_PINS" in deltas:
            proposed=deltas["OPEN_CFS_ADC_PINS"]
            if any(proposed[i]!=OPEN_CFS_ADC_PINS[i] for i in range(4)):
                rejected.append(name)

    if len(rejected)!=len(bad):
        raise ValueError("unsafe published board rewire mutants not rejected")
    return rejected

def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=compare_board_mapping(pinned(a.v313,"intermediate_v313"))
    new=compare_board_mapping(pinned(a.v322,"running_v322"))
    if old!=new:raise ValueError("OEM motor, ADC or IRQ evidence diverged")
    result={
        "two_original_qualified_generations_match":True,
        "crosswalk":new,
        "no_kernel_or_CFS_IO":True,
        "no_installable_firmware_image_produced":True,
    }
    if a.self_test:
        result["synthetic_miswired_board_mutations_rejected"]=negative_fixture_tests(new)
    t=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(t)
    print(t,end="")
if __name__=="__main__":main()
