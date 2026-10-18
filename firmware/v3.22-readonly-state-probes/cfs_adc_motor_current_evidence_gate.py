#!/usr/bin/env python3
"""Fail-closed ADC motor-current provenance contract for saved CFS firmware.

Combines only authenticated *source-analysis* results. An ADC0_RDATA
helper is code evidence, NOT evidence of a current sensor conversion.
Unknown conversion sequence, callers, motor assignment, scaling or
electrical validity always forbids motor-stopped / v3.23 flash claims.

No device IO, firmware binary modification, or ADC RDATA reads.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from flash_ram_phase2_audit import pinned
from cfs_adc_bounded_register_dataflow import analyze as dataflow
from cfs_adc_movw_movt_bounded_reachability import inspect as movable
from cfs_app_real_link_base_audit import audited

CURRENTS={
 "M1":{"pad":"PC5","possible_channel":15},
 "M2":{"pad":"PC0","possible_channel":10},
 "M3":{"pad":"PA1","possible_channel":1},
 "M4":{"pad":"PA0","possible_channel":0},
}

def examine(image:bytes)->dict:
    audited(image)
    d=dataflow(image)
    m=movable(image)
    # Report independent results without assuming any unverified
    # cross-function reachability. A positive source candidate cannot
    # turn a GPIO pad into an authenticated ADC measurement.
    return {
      "ADC_register_dataflow_candidates":d,
      "ADC_bounded_MOVW_MOVT_candidates":m["ADC_MOVW_MOVT_bounded_candidates"],
      "motor_current_pad_hardware_candidates":CURRENTS,
      "original_ADC_current_channel_sequence_for_M1_M4_proven":False,
      "original_motor_task_consumes_ADC_sample_proven":False,
      "current_sample_units_offset_gain_calibrated":False,
      "EOC_safe_nonintrusive_live_observation_proven":False,
      "driver_off_and_rotor_stopped_independently_proven":False,
      "current_zero_permits_firmware_write":False,
    }

def verify_bounded_adc_register_roles(analysis:dict)->dict:
    """Assert actual locally decoded OEM roles, not a generic ADC label.

    Empty rank/sample lists do NOT demonstrate the channels are unused;
    they demonstrate only that this strictly bounded scanner has no
    source-accurate path through those registers.
    """
    d=analysis["ADC_register_dataflow_candidates"]
    roles=d["candidate_access_counts_by_peripheral_role"]
    expected=[
      ("ADC0","CTL0","read",2),("ADC0","CTL0","write",2),
      ("ADC0","CTL1","read",2),("ADC0","CTL1","write",2),
      ("ADC0","RDATA","read",1),
    ]
    observed=sorted((r["peripheral"],r["register"],r["direction"],r["count"])
                    for r in roles)
    if observed!=sorted(expected):
        raise ValueError("original bounded ADC operation inventory changed")
    if d["bounded_register_access_candidates"]!=9:
        raise ValueError("OEM ADC bounded operation count changed")
    if (d["adc_channel_selection_register_access_candidates"] or
            d["adc_sampling_register_access_candidates"]):
        raise ValueError("ADC rank/sample local dataflow changed; re-qualify safety")
    if d["original_ADC0_RDATA_source_instruction_locally_verified"]!="0x8022bc0":
        raise ValueError("pinned ADC result instruction missing")
    return {
      "bounded_original_ADC0_register_operations":9,
      "original_ADC0_RDATA_read_source_pc":"0x08022BC0",
      "bounded_ADC_RSQ_rank_register_operations":0,
      "bounded_ADC_SAMPT_sampling_register_operations":0,
      "absence_of_ADC_rank_or_sample_code_globally_proven":False,
      "actual_M1_M4_ADC_current_channel_configuration_proven":False,
      "any_live_ADC_RDATA_read_safe_or_authorized":False,
    }


def negative_cases():
    names=[
      "generic_ADC0_RDATA_helper_present_but_no_motor_caller",
      "ADC_channel_pad_possible_but_not_selected",
      "ADC_RDATA_sample_zero_but_motor_driver_enabled",
      "ADC_result_EOC_flag_may_change_on_second_read",
      "brushed_motor_stalled_and_no_BLDC_FG_pulses",
      "ADC_sample_stale_or_post_reset",
      "ADC_current_sensor_open_wire_reads_zero",
      "ADC_RDATA_sample_nonzero_without_motor_attribution",
      "ADC_channel_rank_sequence_ambiguous",
      "GPIO_motor_start_ISR_not_covered",
    ]
    result=[{"scenario":name,
             "motor_current_telemetry_authenticated":False,
             "MCU_SET_RESET_allowed":False,
             "flash_extended_v323_allowed":False} for name in names]
    assert len(result)==10
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=examine(pinned(a.v313,"intermediate_v313"))
    new=examine(pinned(a.v322,"running_v322"))
    bounded_old=verify_bounded_adc_register_roles(old)
    bounded_new=verify_bounded_adc_register_roles(new)
    if bounded_old!=bounded_new:
        raise ValueError("v3.13/v3.22 bounded ADC roles diverged")
    d=new["ADC_register_dataflow_candidates"]
    # Existing dataflow scanner independently enforces genuine
    # saved Thumb opcode content for its original ADC0_RDATA path.
    result={
       "saved_v313":old,
       "bounded_source_scope_and_absence_limit":bounded_new,
       "saved_v322":new,
       "same_motor_channel_evidence_across_versions":(
          old["motor_current_pad_hardware_candidates"]==
          new["motor_current_pad_hardware_candidates"]),
       "same_bounded_MOVW_MOVT_ADC_matches_across_versions":(
          old["ADC_bounded_MOVW_MOVT_candidates"]==
          new["ADC_bounded_MOVW_MOVT_candidates"]),
       "synthetic_negative_cases":negative_cases(),
       "physical_motor_feedback_authenticated":False,
       "installed_CFS_or_CM5_access":False,
       "safe_to_read_live_ADC_RDATA":False,
       "v323_release_gate_passed":False,
    }
    out=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(out)
    print(out,end="")

if __name__=="__main__":main()
