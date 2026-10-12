#!/usr/bin/env python3
"""CFS v3.23 Flash/RAM RELEASE decision after correcting saved APP link base.

All image bytes are SHA-pinned; this is a READ-ONLY preflight. A positive
'valid v3.22 APP image' does not imply a safe v3.23 image exists.

The old 0x08010000 ROM-base assumption incorrectly placed the v3.22 image
end at 0x0803B7DC (36B below unverified policy 0x0803B800).
Actual image begins at 0x08003000; its end is 0x0802E7DC.
Arithmetic room increases by 0xD000, but no verified maximum app
partition, RAM ownership, motor-idle guard or full hardware regression
has been supplied. Therefore do not permit v3.23 flash.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE

FLASH_PAGE_BYTES = 2048
FLASH_BASE = 0x08000000
TOTAL_FLASH_END = 0x08080000
FAST_FETCH_END = 0x08040000
PREVIOUS_ASSUMED_APP_BASE = 0x08010000
UNVERIFIED_OLD_POLICY_END = 0x0803B800
NOMINAL_SRAM_END = 0x20010000
CURRENT_HEAP_START = 0x20006F28
PROPOSED_RING_BYTES = 512
PROPOSED_NOMINAL_HEAP_START = CURRENT_HEAP_START + PROPOSED_RING_BYTES
VALIDATED_APP_LENGTH = 178140
EXPECTED_END = 0x0802E7DC

def readiness(current: bytes, old: bytes) -> dict:
    x=audited(current)
    previous=audited(old)
    if not (x["five_names_in_expected_historical_order_proven"] and
            previous["five_names_in_expected_historical_order_proven"]):
        raise ValueError("original named CFS PWM devices were not reconstructed")
    if len(current)!=VALIDATED_APP_LENGTH:
        raise ValueError("unexpected v3.22 source size")
    real_end=LINK_BASE+len(current)
    old_end=PREVIOUS_ASSUMED_APP_BASE+len(current)
    if real_end!=EXPECTED_END:
        raise ValueError("corrected physical APP end unexpected")
    real_last=(real_end-1-FLASH_BASE)//FLASH_PAGE_BYTES
    old_last=(old_end-1-FLASH_BASE)//FLASH_PAGE_BYTES
    if (real_last,old_last)!=(92,118):
        raise ValueError("original 2 KiB page arithmetic changed")
    old_gap=UNVERIFIED_OLD_POLICY_END-old_end
    new_gap=UNVERIFIED_OLD_POLICY_END-real_end
    if (old_gap,new_gap)!=(36,53284):
        raise ValueError("arithmetic old policy headroom inconsistent")
    nominal_heap_bytes=NOMINAL_SRAM_END-CURRENT_HEAP_START
    reduced_heap=NOMINAL_SRAM_END-PROPOSED_NOMINAL_HEAP_START
    assert nominal_heap_bytes==37080 and reduced_heap==36568

    gates={
        "exact_v322_offline_build_SHA_accepted": True,
        "corrected_saved_APP_link_base_verified": True,
        "five_v322_PWM_name_pointers_reconstructed": True,
        "manufacturer_three_PWM_callback_entries_are_real_prologues": True,
        "bootloader_app_partition_and_flash_page_ownership_authenticated": False,
        "loader_accepts_expanded_v323_image_size_proven": False,
        "current_deployed_CFS_bootloader_and_APP_bytes_authenticated": False,
        "physical_motor_idle_detection_independent_of_BOX_STATE_proven": False,
        "MCU_SET_RESET_busy_guard_atomic_under_motor_task_transitions": False,
        "MCU_RAM_event_ring_no_heap_stack_DMA_IRQ_overlap_proven": False,
        "hook_IRQ_FPU_registers_and_latency_hardware_validated": False,
        "v323_complete_binary_offline_regressions_and_recovery_proven": False,
        "v323_hardware_regression_Creality_and_third_party_RFID_passed": False,
    }
    required_release=tuple(k for k in gates if not k.endswith((
        "_SHA_accepted","_verified","_reconstructed","_prologues"
    )))
    # Do not rely on the awkward suffix heuristic as a safety gate: list
    # required criteria independently and fail if any field disappears.
    mandatory=(
        "bootloader_app_partition_and_flash_page_ownership_authenticated",
        "loader_accepts_expanded_v323_image_size_proven",
        "current_deployed_CFS_bootloader_and_APP_bytes_authenticated",
        "physical_motor_idle_detection_independent_of_BOX_STATE_proven",
        "MCU_SET_RESET_busy_guard_atomic_under_motor_task_transitions",
        "MCU_RAM_event_ring_no_heap_stack_DMA_IRQ_overlap_proven",
        "hook_IRQ_FPU_registers_and_latency_hardware_validated",
        "v323_complete_binary_offline_regressions_and_recovery_proven",
        "v323_hardware_regression_Creality_and_third_party_RFID_passed",
    )
    if len(set(mandatory))!=len(mandatory) or any(k not in gates for k in mandatory):
        raise AssertionError("v3.23 release gate definitions incomplete")
    allowed=all(gates[k] for k in mandatory)
    assert not allowed, "DO NOT permit release with no authenticated motor guard"
    return {
        "reference":"CFS v3.22 exact saved APP, NOT an installed v3.23 firmware",
        "flash":{
            "actual_app_link_base":hex(LINK_BASE),
            "v322_APP_bytes":len(current),
            "actual_v322_APP_end_exclusive":hex(real_end),
            "actual_last_2KiB_page_index":real_last,
            "old_incorrect_app_link_base":hex(PREVIOUS_ASSUMED_APP_BASE),
            "old_incorrect_last_2KiB_page_index":old_last,
            "old_incorrect_v322_APP_end_exclusive":hex(old_end),
            "arbitrary_historical_policy_limit_NOT_LOADER_PROVEN":hex(UNVERIFIED_OLD_POLICY_END),
            "corrected_bytes_to_arbitrary_old_policy_NOT_CERTIFIED_FREE":new_gap,
            "old_incorrect_bytes_to_policy":old_gap,
            "corrected_arithmetic_bytes_to_fast_fetch_boundary_NOT_CERTIFIED_FREE":FAST_FETCH_END-real_end,
            "total_512KiB_flash_END_NOT_LOADER_LIMIT":hex(TOTAL_FLASH_END),
            "2KiB_page_geometry":FLASH_PAGE_BYTES,
            "physical_actual_reserved_page_map_proven":False,
        },
        "RAM":{
            "installed_v322_heap_start_literal":hex(CURRENT_HEAP_START),
            "nominal_heap_bytes_not_measured":nominal_heap_bytes,
            "proposed_unallocated_512byte_ring_start":hex(CURRENT_HEAP_START),
            "proposed_unallocated_512byte_ring_end_exclusive":hex(PROPOSED_NOMINAL_HEAP_START),
            "nominal_heap_bytes_if_ring_reserved_and_heap_moved_NOT_VERIFIED":reduced_heap,
            "actual_task_stack_peak_DMA_and_allocator_safety_measured":False,
        },
        "gates":gates,
        "required_release_gates":list(mandatory),
        "required_gates_met":sum(bool(gates[k]) for k in mandatory),
        "total_required_release_gates":len(mandatory),
        "v323_release_candidate_binary_exists_as_part_of_this_audit":False,
        "approve_v323_firmware_flash":allowed,
        "approve_v323_motor_active_writes":False,
        "performed_device_or_CM5_actions":False,
        "modified_original_firmware_bytes":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    result=readiness(pinned(a.v322,"running_v322"),pinned(a.v313,"intermediate_v313"))
    output=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(output)
    print(output,end="")

if __name__=="__main__":
    main()
